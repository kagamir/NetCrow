//! Client connection lifecycle and multiplexed TCP streams.
use crate::{
    auth,
    config::{ClientConfig, RelayEndpoint},
    protocol::{self, Frame, Route, CHUNK_SIZE, INITIAL_CREDITS, QUEUE_SIZE, VERSION},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use rand::Rng;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::TcpStream,
    sync::{mpsc, oneshot, watch, Semaphore},
    task::JoinSet,
    time::{self, Instant},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, http::header::HOST, Message},
    WebSocketStream,
};
use tokio_util::sync::CancellationToken;

type Socket = WebSocketStream<TlsStream<TcpStream>>;
type OpenReply = oneshot::Sender<Result<DuplexStream>>;

struct OpenRequest {
    destinations: Vec<SocketAddr>,
    deadline: Instant,
    reply: OpenReply,
}

/// A proxy connection owns its actual TCP or multiplexed stream directly.
/// No detached task is needed to adapt direct traffic to a tunnel-shaped stream.
pub trait ProxyIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ProxyIo for T {}
pub type ProxyStream = Box<dyn ProxyIo>;

/// A bounded, wake-on-demand router shared by SOCKS5 and HTTP listeners.
#[derive(Clone)]
pub struct ClientHandle {
    requests: mpsc::Sender<OpenRequest>,
    disabled: watch::Receiver<bool>,
    routes: watch::Receiver<Option<Vec<Route>>>,
    proxy_subnets: Option<Arc<[IpNet]>>,
    own_id: Arc<str>,
    timeout: Duration,
    connect_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
enum DestinationPolicy {
    Tunnel(Vec<SocketAddr>),
    Direct(Vec<SocketAddr>),
}

/// If any DNS answer is selected, only selected answers may enter the tunnel.
/// Explicit subnet policy does not depend on whether a route currently exists.
fn destination_policy(
    destinations: &[SocketAddr],
    explicit_subnets: Option<&[IpNet]>,
    routes: &[Route],
    own_id: &str,
) -> DestinationPolicy {
    let selected: Vec<_> = destinations
        .iter()
        .copied()
        .filter(|destination| match explicit_subnets {
            Some(subnets) => subnets
                .iter()
                .any(|subnet| subnet.contains(&destination.ip())),
            None => routes
                .iter()
                .any(|route| route.peer != own_id && route.subnet.contains(&destination.ip())),
        })
        .collect();
    if selected.is_empty() {
        DestinationPolicy::Direct(destinations.to_vec())
    } else {
        DestinationPolicy::Tunnel(selected)
    }
}

impl ClientHandle {
    /// Resolve once, tunnel selected subnets, and connect all other IPs locally.
    /// A selected destination never falls back to a direct connection on failure.
    pub async fn open(&self, host: &str, port: u16) -> Result<ProxyStream> {
        ensure!(port != 0, "destination port must be nonzero");
        let deadline = Instant::now() + self.timeout;
        time::timeout_at(deadline, async {
            let destinations: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .context("resolve destination")?
                .collect();
            ensure!(!destinations.is_empty(), "destination has no addresses");
            let policy = if let Some(subnets) = &self.proxy_subnets {
                destination_policy(&destinations, Some(subnets), &[], &self.own_id)
            } else {
                // Unknown routes must not turn potentially shared private IPs
                // into direct traffic. Keep the last snapshot across disconnects.
                let mut routes = self.routes.clone();
                loop {
                    let snapshot = routes.borrow().clone();
                    if let Some(snapshot) = snapshot {
                        break destination_policy(&destinations, None, &snapshot, &self.own_id);
                    }
                    routes
                        .changed()
                        .await
                        .context("route discovery stopped before first snapshot")?;
                }
            };
            match policy {
                DestinationPolicy::Direct(destinations) => {
                    let socket = connect_direct(&destinations, self.connect_timeout).await?;
                    Ok(Box::new(socket) as ProxyStream)
                }
                DestinationPolicy::Tunnel(destinations) => {
                    ensure!(!*self.disabled.borrow(), "client is remotely disabled");
                    let (reply, receiver) = oneshot::channel();
                    self.requests
                        .send(OpenRequest {
                            destinations,
                            deadline,
                            reply,
                        })
                        .await
                        .map_err(|_| anyhow!("client stopped"))?;
                    let tunnel = receiver
                        .await
                        .map_err(|_| anyhow!("connection request cancelled"))??;
                    Ok(Box::new(tunnel) as ProxyStream)
                }
            }
        })
        .await
        .context("connection request timed out")?
    }
}

/// The already-resolved addresses are used directly; DNS is never repeated.
async fn connect_direct(
    destinations: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let mut last_error = anyhow!("destination has no addresses");
    for destination in destinations {
        match time::timeout(connect_timeout, TcpStream::connect(destination)).await {
            Ok(Ok(socket)) => return Ok(socket),
            Ok(Err(error)) => last_error = error.into(),
            Err(error) => last_error = error.into(),
        }
    }
    Err(last_error).context("direct destination connection failed")
}

pub async fn run(config: ClientConfig) -> Result<()> {
    config.validate()?;
    let endpoint = config.relay_endpoint()?;
    let tls = crate::tls::client_config_for_relay(&config.tls, endpoint.enable_sni)?;
    let disabled = crate::control::spawn(config.control.clone());
    let (requests, receiver) = mpsc::channel(QUEUE_SIZE);
    let (routes, route_snapshot) = watch::channel(None);
    let handle = ClientHandle {
        requests,
        disabled: disabled.clone(),
        routes: route_snapshot,
        proxy_subnets: config.proxy_subnets.clone().map(Arc::from),
        own_id: Arc::from(config.id.as_str()),
        timeout: Duration::from_secs(config.connection.open_timeout_secs),
        connect_timeout: Duration::from_secs(config.connection.connect_timeout_secs),
    };
    let proxy = crate::proxy::serve(config.socks5_listen, config.http_listen, handle);
    let manager = manage(config, endpoint, tls, receiver, disabled, routes);
    tokio::select! {
        result = proxy => result.context("proxy listeners stopped"),
        result = manager => result,
    }
}

async fn wait_disabled(disabled: &mut watch::Receiver<bool>) {
    loop {
        if *disabled.borrow_and_update() {
            return;
        }
        if disabled.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn manage(
    config: ClientConfig,
    endpoint: RelayEndpoint,
    tls: Arc<rustls::ClientConfig>,
    mut requests: mpsc::Receiver<OpenRequest>,
    mut disabled: watch::Receiver<bool>,
    route_snapshot: watch::Sender<Option<Vec<Route>>>,
) -> Result<()> {
    // Hash exact configuration bytes once, not on every reconnect.
    let wire_token = auth::token_digest(&config.token);
    let mut pending = VecDeque::new();
    let mut last_activity = Instant::now();
    let mut asleep = false;
    let mut delay = Duration::ZERO;
    let mut next_id = 1_u64;
    loop {
        if *disabled.borrow() {
            tracing::info!("remote control disabled client");
            for request in pending.drain(..) {
                let request: OpenRequest = request;
                let _ = request
                    .reply
                    .send(Err(anyhow!("client is remotely disabled")));
            }
            while *disabled.borrow_and_update() {
                tokio::select! {
                    request = requests.recv() => match request {
                        Some(request) => { let _ = request.reply.send(Err(anyhow!("client is remotely disabled"))); }
                        None => return Ok(()),
                    },
                    changed = disabled.changed() => {
                        if changed.is_err() { bail!("control channel stopped while disabled"); }
                    }
                }
            }
            tracing::info!("remote control enabled client");
            last_activity = Instant::now();
            asleep = false;
            delay = Duration::ZERO;
        }
        pending.retain(|request| !request.reply.is_closed() && request.deadline > Instant::now());
        if !delay.is_zero() {
            tokio::select! {
                _ = wait_disabled(&mut disabled) => continue,
                request = requests.recv() => match request {
                    Some(request) if !request.reply.is_closed() => {
                        if pending.len() >= config.connection.max_streams {
                            let _ = request.reply.send(Err(anyhow!("maximum pending streams reached")));
                        } else {
                            pending.push_back(request);
                            last_activity = Instant::now();
                            asleep = false;
                        }
                    },
                    Some(_) => continue,
                    None => return Ok(()),
                },
                _ = time::sleep(delay) => {},
            }
        }
        if asleep {
            tracing::info!("checking pending requests");
        }
        let connection = tokio::select! {
            _ = wait_disabled(&mut disabled) => continue,
            result = time::timeout(
                Duration::from_secs(config.connection.connect_timeout_secs),
                connect(&config, &endpoint, &wire_token, tls.clone()),
            ) => result.context("WSS connection timed out").and_then(|r| r),
        };
        let outcome = match connection {
            Ok((socket, routes)) => {
                route_snapshot.send_replace(Some(routes.clone()));
                tracing::info!("WSS connected");
                session(
                    &config,
                    socket,
                    routes,
                    &route_snapshot,
                    &mut pending,
                    &mut requests,
                    &mut disabled,
                    &mut last_activity,
                    &mut next_id,
                    asleep,
                )
                .await
            }
            Err(error) => {
                tracing::warn!(error = %error, "WSS connection failed");
                SessionExit::Reconnect
            }
        };
        match outcome {
            SessionExit::Disabled => {
                delay = Duration::ZERO;
            }
            SessionExit::Sleep => {
                tracing::info!("entering sleep");
                asleep = true;
                delay = Duration::from_secs(config.connection.sleep_secs);
            }
            SessionExit::Reconnect => {
                // Preserve the sleep schedule after a failed check. Active clients reconnect.
                let seconds = if asleep {
                    config.connection.sleep_secs
                } else {
                    config.connection.reconnect_secs
                };
                let jitter = rand::thread_rng().gen_range(0..=250);
                delay = Duration::from_secs(seconds) + Duration::from_millis(jitter);
            }
        }
    }
}

async fn connect(
    config: &ClientConfig,
    endpoint: &RelayEndpoint,
    wire_token: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(Socket, Vec<Route>)> {
    let mut request = endpoint
        .websocket_uri
        .as_str()
        .into_client_request()
        .context("build relay WebSocket request")?;
    request.headers_mut().insert(
        HOST,
        endpoint
            .websocket_host
            .parse()
            .context("invalid relay HTTP Host")?,
    );
    // TCP destination and WebSocket path come from relay_addr. HTTP Host and
    // TLS name are independent; suppressing SNI never disables TLS trust.
    let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .context("connect relay TCP")?;
    let stream = TlsConnector::from(tls)
        .connect(endpoint.server_name.clone(), stream)
        .await
        .context("connect relay TLS")?;
    let (mut socket, _) = tokio_tungstenite::client_async_with_config(
        request,
        stream,
        Some(protocol::websocket_config()),
    )
    .await
    .context("upgrade relay WebSocket")?;
    socket
        .send(protocol::encode(&Frame::Hello {
            version: VERSION,
            id: config.id.clone(),
            token: wire_token.to_owned(),
            subnets: config.shared_subnets.clone(),
        })?)
        .await?;
    loop {
        match socket
            .next()
            .await
            .context("relay closed before welcome")??
        {
            Message::Binary(bytes) => match protocol::decode(&bytes)? {
                Frame::Welcome { routes } => return Ok((socket, routes)),
                Frame::Error { message } => bail!("relay rejected client: {message}"),
                _ => bail!("expected relay welcome"),
            },
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
            Message::Pong(_) => {}
            _ => bail!("unexpected message before welcome"),
        }
    }
}

enum SessionExit {
    Disabled,
    Sleep,
    Reconnect,
}
enum IncomingData {
    Bytes(Vec<u8>),
    HalfClose,
    Close,
}
enum WorkerEvent {
    Outgoing(Frame),
    Connected(u64, Result<TcpStream>),
    Finished(u64),
    WriterFailed,
}
enum StreamPhase {
    Opening {
        reply: OpenReply,
        local: DuplexStream,
        tunnel: DuplexStream,
        deadline: Instant,
    },
    Connecting,
    Established(mpsc::Sender<IncomingData>),
}
struct StreamEntry {
    phase: StreamPhase,
    cancel: CancellationToken,
    remote_half_closed: bool,
    credits: Arc<FlowControl>,
}

/// Permits count unsent chunks; outstanding counts chunks actually sent. Tracking
/// both avoids accepting a bogus grant while a reader holds a permit at EOF.
struct FlowControl {
    semaphore: Semaphore,
    outstanding: AtomicUsize,
}
impl FlowControl {
    fn new() -> Self {
        Self {
            semaphore: Semaphore::new(INITIAL_CREDITS),
            outstanding: AtomicUsize::new(0),
        }
    }
    fn grant(&self, frames: usize) -> Result<()> {
        ensure!(
            frames > 0 && frames <= INITIAL_CREDITS,
            "invalid credit grant"
        );
        let mut sent = self.outstanding.load(Ordering::Acquire);
        loop {
            let remaining = sent
                .checked_sub(frames)
                .ok_or_else(|| anyhow!("credit grant exceeds outstanding data"))?;
            match self.outstanding.compare_exchange_weak(
                sent,
                remaining,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => sent = current,
            }
        }
        self.semaphore.add_permits(frames);
        Ok(())
    }
}

fn queue_frame(sender: &mpsc::Sender<Message>, frame: Frame) -> Result<()> {
    sender
        .try_send(protocol::encode(&frame)?)
        .map_err(|_| anyhow!("WSS writer queue exhausted"))
}

fn select_destination(
    destinations: &[SocketAddr],
    routes: &[Route],
    own_id: &str,
) -> Option<SocketAddr> {
    destinations.iter().copied().find(|destination| {
        routes
            .iter()
            .any(|route| route.peer != own_id && route.subnet.contains(&destination.ip()))
    })
}

#[allow(clippy::too_many_arguments)]
async fn session(
    config: &ClientConfig,
    socket: Socket,
    mut routes: Vec<Route>,
    route_snapshot: &watch::Sender<Option<Vec<Route>>>,
    pending: &mut VecDeque<OpenRequest>,
    requests: &mut mpsc::Receiver<OpenRequest>,
    disabled: &mut watch::Receiver<bool>,
    last_activity: &mut Instant,
    next_id: &mut u64,
    mut probe: bool,
) -> SessionExit {
    let (mut writer, mut reader) = socket.split();
    let (wire_tx, mut wire_rx) = mpsc::channel::<Message>(QUEUE_SIZE);
    let (events_tx, mut events_rx) = mpsc::channel::<WorkerEvent>(QUEUE_SIZE);
    let mut workers = JoinSet::new();
    let event_sender = events_tx.clone();
    let write_timeout = Duration::from_secs(config.connection.connect_timeout_secs);
    workers.spawn(async move {
        while let Some(message) = wire_rx.recv().await {
            if !matches!(
                time::timeout(write_timeout, writer.send(message)).await,
                Ok(Ok(()))
            ) {
                let _ = event_sender.send(WorkerEvent::WriterFailed).await;
                return;
            }
        }
    });
    let mut streams: HashMap<u64, StreamEntry> = HashMap::new();
    let mut heartbeat = time::interval(Duration::from_secs(config.connection.heartbeat_secs));
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut housekeeping = time::interval(Duration::from_millis(100));
    housekeeping.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let started = Instant::now();
    let mut last_rx = started;
    let outcome = 'session: loop {
        if *disabled.borrow() {
            break SessionExit::Disabled;
        }
        while wire_tx.capacity() > 0 {
            let Some(request) = pending.pop_front() else {
                break;
            };
            if request.reply.is_closed() || request.deadline <= Instant::now() {
                continue;
            }
            *last_activity = Instant::now();
            probe = false;
            if streams.len() >= config.connection.max_streams {
                let _ = request.reply.send(Err(anyhow!("maximum streams reached")));
                continue;
            }
            let Some(destination) = select_destination(&request.destinations, &routes, &config.id)
            else {
                let _ = request.reply.send(Err(anyhow!(
                    "destination is outside advertised remote subnets"
                )));
                continue;
            };
            let id = *next_id;
            *next_id = next_id.checked_add(2).unwrap_or(1);
            if streams.contains_key(&id) {
                break 'session SessionExit::Reconnect;
            }
            let (local, tunnel) = tokio::io::duplex(CHUNK_SIZE * 4);
            streams.insert(
                id,
                StreamEntry {
                    phase: StreamPhase::Opening {
                        reply: request.reply,
                        local,
                        tunnel,
                        deadline: request.deadline,
                    },
                    cancel: CancellationToken::new(),
                    remote_half_closed: false,
                    credits: Arc::new(FlowControl::new()),
                },
            );
            if queue_frame(&wire_tx, Frame::Open { id, destination }).is_err() {
                break 'session SessionExit::Reconnect;
            }
        }
        tokio::select! {
            _ = wait_disabled(disabled) => break SessionExit::Disabled,
            request = requests.recv(), if pending.len() < QUEUE_SIZE => match request {
                Some(request) => pending.push_back(request),
                None => break SessionExit::Reconnect,
            },
            event = events_rx.recv(), if wire_tx.capacity() > 0 => {
                let Some(event) = event else { break SessionExit::Reconnect; };
                match event {
                    WorkerEvent::WriterFailed => break SessionExit::Reconnect,
                    WorkerEvent::Outgoing(frame) => {
                        let id = match &frame {
                            Frame::Data { id, .. } | Frame::HalfClose { id } | Frame::Credit { id, .. } => *id,
                            _ => unreachable!(),
                        };
                        if !streams.contains_key(&id) { continue; }
                        if matches!(&frame, Frame::Data { bytes, .. } if !bytes.is_empty()) {
                            *last_activity = Instant::now(); probe = false;
                        }
                        if queue_frame(&wire_tx, frame).is_err() { break SessionExit::Reconnect; }
                    }
                    WorkerEvent::Finished(id) => {
                        if let Some(entry) = streams.remove(&id) {
                            entry.cancel.cancel();
                            if queue_frame(&wire_tx, Frame::Close { id }).is_err() { break SessionExit::Reconnect; }
                        }
                    }
                    WorkerEvent::Connected(id, result) => {
                        let Some(entry) = streams.get_mut(&id) else { continue; };
                        if !matches!(entry.phase, StreamPhase::Connecting) { break SessionExit::Reconnect; }
                        match result {
                            Ok(socket) => {
                                if queue_frame(&wire_tx, Frame::Opened { id, error: None }).is_err() { break SessionExit::Reconnect; }
                                entry.phase = StreamPhase::Established(spawn_stream(
                                    &mut workers, id, socket, events_tx.clone(), entry.cancel.clone(), entry.credits.clone()));
                            }
                            Err(error) => {
                                tracing::debug!(%error, "shared destination connection failed");
                                streams.remove(&id);
                                if queue_frame(&wire_tx, Frame::Opened { id, error: Some("destination connection failed".into()) }).is_err() { break SessionExit::Reconnect; }
                            }
                        }
                    }
                }
            },
            incoming = reader.next(), if wire_tx.capacity() > 0 => {
                let message = match incoming {
                    Some(Ok(message)) => message,
                    Some(Err(error)) => { tracing::debug!(%error, "WSS read failed"); break SessionExit::Reconnect; }
                    None => break SessionExit::Reconnect,
                };
                last_rx = Instant::now();
                match message {
                    Message::Binary(bytes) => {
                        let frame = match protocol::decode(&bytes) {
                            Ok(frame) => frame,
                            Err(error) => { tracing::warn!(%error, "invalid relay frame"); break SessionExit::Reconnect; }
                        };
                        match frame {
                            Frame::Routes { routes: updated } => {
                                route_snapshot.send_replace(Some(updated.clone()));
                                routes = updated;
                            },
                            Frame::Incoming { id, destination } => {
                                if id % 2 != 0 || streams.contains_key(&id) { break SessionExit::Reconnect; }
                                if streams.len() >= config.connection.max_streams || destination.port() == 0 || !config.shared_subnets.iter().any(|net| net.contains(&destination.ip())) {
                                    if queue_frame(&wire_tx, Frame::Opened { id, error: Some("destination not allowed or client at capacity".into()) }).is_err() { break SessionExit::Reconnect; }
                                    continue;
                                }
                                *last_activity = Instant::now(); probe = false;
                                let cancel = CancellationToken::new();
                                streams.insert(id, StreamEntry { phase: StreamPhase::Connecting, cancel: cancel.clone(), remote_half_closed: false, credits: Arc::new(FlowControl::new()) });
                                let sender = events_tx.clone();
                                let timeout = Duration::from_secs(config.connection.connect_timeout_secs);
                                workers.spawn(async move {
                                    tokio::select! {
                                        _ = cancel.cancelled() => {},
                                        result = time::timeout(timeout, TcpStream::connect(destination)) => {
                                            let result = result.context("destination connection timed out").and_then(|r| r.context("connect destination"));
                                            let _ = sender.send(WorkerEvent::Connected(id, result)).await;
                                        }
                                    }
                                });
                            }
                            Frame::Opened { id, error } => {
                                let Some(entry) = streams.remove(&id) else { continue; };
                                let StreamPhase::Opening { reply, local, tunnel, .. } = entry.phase else {
                                    entry.cancel.cancel(); break SessionExit::Reconnect;
                                };
                                if let Some(error) = error {
                                    let _ = reply.send(Err(anyhow!("remote open failed: {error}")));
                                } else if reply.send(Ok(local)).is_ok() {
                                    let inbound = spawn_stream(&mut workers, id, tunnel, events_tx.clone(), entry.cancel.clone(), entry.credits.clone());
                                    streams.insert(id, StreamEntry { phase: StreamPhase::Established(inbound), cancel: entry.cancel, remote_half_closed: false, credits: entry.credits });
                                } else if queue_frame(&wire_tx, Frame::Close { id }).is_err() { break SessionExit::Reconnect; }
                            }
                            Frame::Data { id, bytes } => {
                                let Some(entry) = streams.get(&id) else { continue; };
                                let StreamPhase::Established(sender) = &entry.phase else { break SessionExit::Reconnect; };
                                if entry.remote_half_closed { break SessionExit::Reconnect; }
                                if !bytes.is_empty() { *last_activity = Instant::now(); probe = false; }
                                if sender.try_send(IncomingData::Bytes(bytes)).is_err() {
                                    if let Some(entry) = streams.remove(&id) { entry.cancel.cancel(); }
                                    if queue_frame(&wire_tx, Frame::Close { id }).is_err() { break SessionExit::Reconnect; }
                                }
                            }
                            Frame::HalfClose { id } => {
                                let Some(entry) = streams.get_mut(&id) else { continue; };
                                let StreamPhase::Established(sender) = &entry.phase else { break SessionExit::Reconnect; };
                                if entry.remote_half_closed { continue; }
                                entry.remote_half_closed = true;
                                if sender.try_send(IncomingData::HalfClose).is_err() {
                                    if let Some(entry) = streams.remove(&id) { entry.cancel.cancel(); }
                                    if queue_frame(&wire_tx, Frame::Close { id }).is_err() { break SessionExit::Reconnect; }
                                }
                            }
                            Frame::Credit { id, frames } => {
                                let Some(entry) = streams.get(&id) else { continue; };
                                if !matches!(entry.phase, StreamPhase::Established(_)) || frames == 0 || frames as usize > INITIAL_CREDITS {
                                    break SessionExit::Reconnect;
                                }
                                if entry.credits.grant(frames as usize).is_err() { break SessionExit::Reconnect; }
                            }
                            Frame::Close { id } => {
                                if let Some(entry) = streams.remove(&id) {
                                    // Preserve preceding data already queued for the local socket.
                                    // A remote Close must not discard the tail of a TCP response.
                                    if let StreamPhase::Established(sender) = entry.phase {
                                        if sender.try_send(IncomingData::Close).is_err() { entry.cancel.cancel(); }
                                    } else { entry.cancel.cancel(); }
                                }
                            }
                            Frame::Error { message } => {
                                tracing::warn!(%message, "relay error"); break SessionExit::Reconnect;
                            }
                            _ => break SessionExit::Reconnect,
                        }
                    }
                    Message::Ping(bytes) => {
                        if wire_tx.try_send(Message::Pong(bytes)).is_err() { break SessionExit::Reconnect; }
                    }
                    Message::Pong(_) => {},
                    Message::Close(_) => break SessionExit::Reconnect,
                    _ => break SessionExit::Reconnect,
                }
            },
            _ = heartbeat.tick(), if wire_tx.capacity() > 0 => {
                if wire_tx.try_send(Message::Ping(Vec::new().into())).is_err() { break SessionExit::Reconnect; }
            },
            _ = housekeeping.tick() => {
                if last_rx.elapsed() >= Duration::from_secs(config.connection.heartbeat_timeout_secs) {
                    tracing::warn!("relay heartbeat timed out"); break SessionExit::Reconnect;
                }
                let expired: Vec<u64> = streams.iter().filter_map(|(id, entry)| match &entry.phase {
                    StreamPhase::Opening { reply, deadline, .. } if reply.is_closed() || *deadline <= Instant::now() => Some(*id),
                    _ => None,
                }).collect();
                for id in expired.into_iter().take(wire_tx.capacity()) {
                    if let Some(entry) = streams.remove(&id) { entry.cancel.cancel(); }
                    if queue_frame(&wire_tx, Frame::Close { id }).is_err() { break 'session SessionExit::Reconnect; }
                }
                let idle = config.connection.idle_secs > 0 && last_activity.elapsed() >= Duration::from_secs(config.connection.idle_secs);
                if (probe && started.elapsed() >= Duration::from_secs(config.connection.probe_secs)) || (!probe && idle) {
                    break SessionExit::Sleep;
                }
            },
            capacity = wire_tx.reserve(), if wire_tx.capacity() == 0 => {
                if capacity.is_err() { break SessionExit::Reconnect; }
            },
            _ = workers.join_next(), if !workers.is_empty() => {},
        }
    };
    for (_, entry) in streams {
        entry.cancel.cancel();
    }
    workers.abort_all();
    // Dropping both WebSocket halves immediately tears down the long connection.
    outcome
}

fn spawn_stream<S>(
    workers: &mut JoinSet<()>,
    id: u64,
    socket: S,
    events: mpsc::Sender<WorkerEvent>,
    cancel: CancellationToken,
    credits: Arc<FlowControl>,
) -> mpsc::Sender<IncomingData>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut incoming) = mpsc::channel(QUEUE_SIZE);
    workers.spawn(async move {
        let (mut read, mut write) = tokio::io::split(socket);
        let stop_upload = CancellationToken::new();
        let upload = async {
            let mut buffer = vec![0; CHUNK_SIZE];
            loop {
                let permit = tokio::select! {
                    _ = stop_upload.cancelled() => return Ok::<(), anyhow::Error>(()),
                    permit = credits.semaphore.acquire() => permit.map_err(|_| anyhow!("stream credit closed"))?,
                };
                let n = tokio::select! {
                    _ = stop_upload.cancelled() => return Ok::<(), anyhow::Error>(()),
                    n = read.read(&mut buffer) => n?,
                };
                if n > 0 { permit.forget(); credits.outstanding.fetch_add(1, Ordering::AcqRel); }
                let frame = if n == 0 {
                    Frame::HalfClose { id }
                } else {
                    Frame::Data {
                        id,
                        bytes: buffer[..n].to_vec(),
                    }
                };
                events
                    .send(WorkerEvent::Outgoing(frame))
                    .await
                    .map_err(|_| anyhow!("session ended"))?;
                if n == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        };
        let download = async {
            while let Some(frame) = incoming.recv().await {
                match frame {
                    IncomingData::Bytes(bytes) => {
                        write.write_all(&bytes).await?;
                        events.send(WorkerEvent::Outgoing(Frame::Credit { id, frames: 1 })).await
                            .map_err(|_| anyhow!("session ended"))?;
                    },
                    IncomingData::Close => {
                        write.shutdown().await?;
                        stop_upload.cancel();
                        return Ok::<(), anyhow::Error>(());
                    },
                    IncomingData::HalfClose => {
                        write.shutdown().await?;
                        return Ok::<(), anyhow::Error>(());
                    }
                }
            }
            bail!("stream closed");
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = async { tokio::try_join!(upload, download) } => {
                if let Err(error) = result { tracing::debug!(%error, "TCP stream ended"); }
            }
        }
        let _ = events.send(WorkerEvent::Finished(id)).await;
    });
    sender
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    // Tungstenite fixes the handshake callback's error type to an HTTP response.
    #[allow(clippy::result_large_err)]
    async fn relay_transport_host_and_path_are_independent_of_sni() {
        time::timeout(Duration::from_secs(10), async {
            for (host, sni, relay_host, expected_sni, expected_host) in [
                (
                    "127.0.0.1",
                    Some("virtual.example"),
                    None,
                    Some("virtual.example"),
                    "127.0.0.1",
                ),
                (
                    "127.0.0.1",
                    Some("virtual.example"),
                    Some("front.example:9443"),
                    Some("virtual.example"),
                    "front.example:9443",
                ),
                ("localhost", None, None, Some("localhost"), "localhost"),
                ("localhost", Some(""), None, None, "localhost"),
                (
                    "localhost",
                    Some(""),
                    Some("front.example"),
                    None,
                    "front.example",
                ),
                ("127.0.0.1", None, None, None, "127.0.0.1"),
                (
                    "127.0.0.1",
                    None,
                    Some("[2001:db8::5]:9443"),
                    None,
                    "[2001:db8::5]:9443",
                ),
            ] {
                let directory = tempfile::tempdir().unwrap();
                let identity = crate::config::ServerTls {
                    cert_path: directory.path().join("cert.pem"),
                    key_path: directory.path().join("key.pem"),
                    names: vec!["virtual.example".into(), "localhost".into()],
                };
                let server_tls = crate::tls::server_config(&identity).unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let path = "/edge/netcrow%2Ftest";
                let sni_config = sni
                    .map(|name| format!("relay_sni='{name}'\n"))
                    .unwrap_or_default();
                let host_config = relay_host
                    .map(|name| format!("relay_host='{name}'\n"))
                    .unwrap_or_default();
                let mut config: ClientConfig = toml::from_str(&format!(
                    "id='test-peer'\ntoken='raw token'\nrelay_addr='{host}:{}{path}'\n{sni_config}{host_config}",
                    address.port()
                ))
                .unwrap();
                config.tls.spki_sha256 =
                    Some(crate::tls::certificate_pin(&identity.cert_path).unwrap());
                config.validate().unwrap();
                let endpoint = config.relay_endpoint().unwrap();
                let tls =
                    crate::tls::client_config_for_relay(&config.tls, endpoint.enable_sni).unwrap();
                let (request_tx, request_rx) = oneshot::channel();
                let routes = vec![Route {
                    peer: "other-peer".into(),
                    subnet: "10.1.0.0/16".parse().unwrap(),
                    online: true,
                }];
                let expected_routes = routes.clone();
                let server = tokio::spawn(async move {
                    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
                    let (stream, _) = listener.accept().await.unwrap();
                    let stream = tokio_rustls::TlsAcceptor::from(server_tls)
                        .accept(stream)
                        .await
                        .unwrap();
                    let observed_sni = stream.get_ref().1.server_name().map(str::to_owned);
                    let mut websocket = tokio_tungstenite::accept_hdr_async_with_config(
                        stream,
                        move |request: &Request, response: Response| {
                            assert_eq!(request.headers().get_all(HOST).iter().count(), 1);
                            request_tx
                                .send((
                                    request.headers()["host"].to_str().unwrap().to_owned(),
                                    request.uri().path().to_owned(),
                                ))
                                .unwrap();
                            Ok(response)
                        },
                        Some(protocol::websocket_config()),
                    )
                    .await
                    .unwrap();
                    let Message::Binary(bytes) = websocket.next().await.unwrap().unwrap() else {
                        panic!("expected binary authentication frame");
                    };
                    let Frame::Hello {
                        version,
                        id,
                        token,
                        subnets,
                    } = protocol::decode(&bytes).unwrap()
                    else {
                        panic!("expected authentication hello");
                    };
                    assert_eq!(version, VERSION);
                    assert_eq!(id, "test-peer");
                    assert_eq!(token, auth::token_digest("raw token"));
                    assert!(subnets.is_empty());
                    websocket
                        .send(protocol::encode(&Frame::Welcome { routes }).unwrap())
                        .await
                        .unwrap();
                    observed_sni
                });
                let (socket, received_routes) =
                    connect(&config, &endpoint, &auth::token_digest(&config.token), tls)
                        .await
                        .unwrap();
                assert_eq!(socket.get_ref().get_ref().0.peer_addr().unwrap(), address);
                assert_eq!(received_routes, expected_routes);
                assert_eq!(
                    request_rx.await.unwrap(),
                    (expected_host.into(), path.into())
                );
                assert_eq!(server.await.unwrap().as_deref(), expected_sni);
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn routing_never_falls_back_to_internet_or_own_subnet() {
        let routes = vec![
            Route {
                peer: "other".into(),
                subnet: "192.168.10.0/24".parse().unwrap(),
                online: false,
            },
            Route {
                peer: "me".into(),
                subnet: "10.0.0.0/8".parse().unwrap(),
                online: true,
            },
        ];
        assert!(select_destination(&["8.8.8.8:443".parse().unwrap()], &routes, "me").is_none());
        assert!(select_destination(&["10.0.0.1:80".parse().unwrap()], &routes, "me").is_none());
        assert_eq!(
            select_destination(
                &[
                    "8.8.8.8:443".parse().unwrap(),
                    "192.168.10.1:80".parse().unwrap()
                ],
                &routes,
                "me"
            ),
            Some("192.168.10.1:80".parse().unwrap())
        );
    }

    struct RoutingHarness {
        handle: ClientHandle,
        requests: mpsc::Receiver<OpenRequest>,
        routes: watch::Sender<Option<Vec<Route>>>,
        disabled: watch::Sender<bool>,
    }

    fn routing_harness(
        explicit: Option<Vec<IpNet>>,
        snapshot: Option<Vec<Route>>,
        disabled: bool,
    ) -> RoutingHarness {
        let (requests, receiver) = mpsc::channel(QUEUE_SIZE);
        let (routes, snapshot) = watch::channel(snapshot);
        let (disabled, state) = watch::channel(disabled);
        RoutingHarness {
            handle: ClientHandle {
                requests,
                disabled: state,
                routes: snapshot,
                proxy_subnets: explicit.map(Arc::from),
                own_id: Arc::from("me"),
                timeout: Duration::from_secs(2),
                connect_timeout: Duration::from_millis(200),
            },
            requests: receiver,
            routes,
            disabled,
        }
    }

    #[test]
    fn policy_prefers_selected_dns_answers_and_distinguishes_empty_override() {
        let destinations: Vec<SocketAddr> = [
            "8.8.8.8:443",
            "10.0.0.1:443",
            "192.168.10.1:443",
            "[fd00::1]:443",
        ]
        .into_iter()
        .map(|value| value.parse().unwrap())
        .collect();
        let routes = vec![
            Route {
                peer: "me".into(),
                subnet: "10.0.0.0/8".parse().unwrap(),
                online: true,
            },
            Route {
                peer: "other".into(),
                subnet: "192.168.10.0/24".parse().unwrap(),
                online: false,
            },
            Route {
                peer: "other".into(),
                subnet: "fd00::/64".parse().unwrap(),
                online: false,
            },
        ];
        assert_eq!(
            destination_policy(&destinations, None, &routes, "me"),
            DestinationPolicy::Tunnel(destinations[2..].to_vec())
        );
        assert_eq!(
            destination_policy(&destinations[..2], None, &routes, "me"),
            DestinationPolicy::Direct(destinations[..2].to_vec())
        );
        assert_eq!(
            destination_policy(&destinations, Some(&[]), &routes, "me"),
            DestinationPolicy::Direct(destinations.clone())
        );
        let explicit = ["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            destination_policy(&destinations, Some(&explicit), &[], "me"),
            DestinationPolicy::Tunnel(vec![destinations[1]])
        );
    }

    #[tokio::test]
    async fn explicit_direct_works_without_routes_or_wake_and_survives_disable() {
        time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let mut harness =
                routing_harness(Some(vec!["10.0.0.0/8".parse().unwrap()]), None, false);
            let (client, server) = tokio::join!(
                harness.handle.open("127.0.0.1", destination.port()),
                listener.accept()
            );
            let mut client = client.unwrap();
            let (mut server, _) = server.unwrap();
            harness.disabled.send_replace(true);
            client.write_all(b"existing direct stream").await.unwrap();
            let mut received = [0; 22];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"existing direct stream");
            let (client, server) = tokio::join!(
                harness.handle.open("127.0.0.1", destination.port()),
                listener.accept()
            );
            assert!(
                client.is_ok(),
                "disabled tunnels must not disable direct routing"
            );
            assert!(server.is_ok());
            assert!(
                matches!(
                    harness.requests.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ),
                "direct traffic must not wake the connection manager"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn default_waits_for_snapshot_and_keeps_selected_cache_after_disconnect() {
        time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let mut harness = routing_harness(None, None, false);
            let handle = harness.handle.clone();
            let opening =
                tokio::spawn(async move { handle.open("127.0.0.1", destination.port()).await });
            time::sleep(Duration::from_millis(20)).await;
            assert!(
                !opening.is_finished(),
                "unknown routes must not become direct traffic"
            );
            assert!(matches!(
                harness.requests.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            harness.routes.send_replace(Some(vec![Route {
                peer: "other".into(),
                subnet: "127.0.0.1/32".parse().unwrap(),
                online: false,
            }]));
            let request = harness.requests.recv().await.unwrap();
            assert_eq!(request.destinations, vec![destination]);
            request.reply.send(Err(anyhow!("remote unavailable"))).ok();
            assert!(opening.await.unwrap().is_err());
            drop(harness.routes);
            let handle = harness.handle.clone();
            let opening =
                tokio::spawn(async move { handle.open("127.0.0.1", destination.port()).await });
            let request = harness.requests.recv().await.unwrap();
            request
                .reply
                .send(Err(anyhow!("route no longer available")))
                .ok();
            assert!(opening.await.unwrap().is_err());
            assert!(
                time::timeout(Duration::from_millis(25), listener.accept())
                    .await
                    .is_err(),
                "selected errors must never fall back to direct TCP"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn explicit_selected_without_route_is_tunnel_only_and_disable_rejects_it() {
        time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let mut harness = routing_harness(
                Some(vec!["127.0.0.1/32".parse().unwrap()]),
                Some(vec![]),
                false,
            );
            let handle = harness.handle.clone();
            let opening =
                tokio::spawn(async move { handle.open("127.0.0.1", destination.port()).await });
            let request = harness.requests.recv().await.unwrap();
            assert_eq!(request.destinations, vec![destination]);
            request.reply.send(Err(anyhow!("no advertised route"))).ok();
            assert!(opening.await.unwrap().is_err());
            harness.disabled.send_replace(true);
            let error = harness
                .handle
                .open("127.0.0.1", destination.port())
                .await
                .err()
                .expect("selected disabled destination must fail");
            assert!(error.to_string().contains("disabled"));
            assert!(matches!(
                harness.requests.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert!(time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn default_unknown_route_snapshot_obeys_open_timeout() {
        let mut harness = routing_harness(None, None, true);
        let started = Instant::now();
        let error = harness
            .handle
            .open("127.0.0.1", 9)
            .await
            .err()
            .expect("unknown routes must time out");
        assert!(error.to_string().contains("timed out"));
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert!(matches!(
            harness.requests.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn direct_retries_already_resolved_candidates() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = unavailable.local_addr().unwrap();
        let available = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = available.local_addr().unwrap();
        drop(unavailable);
        let stream = connect_direct(&[first, second], Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), second);
    }

    #[tokio::test]
    async fn stream_preserves_half_close_and_reverse_response() {
        let (mut application, pump) = tokio::io::duplex(4096);
        let (events, mut receiver) = mpsc::channel(QUEUE_SIZE);
        let mut workers = JoinSet::new();
        let incoming = spawn_stream(
            &mut workers,
            1,
            pump,
            events,
            CancellationToken::new(),
            Arc::new(FlowControl::new()),
        );
        application.write_all(b"request").await.unwrap();
        application.shutdown().await.unwrap();
        let mut uploaded = Vec::new();
        loop {
            match receiver.recv().await.unwrap() {
                WorkerEvent::Outgoing(Frame::Data { bytes, .. }) => uploaded.extend(bytes),
                WorkerEvent::Outgoing(Frame::HalfClose { .. }) => break,
                _ => panic!("unexpected stream event"),
            }
        }
        assert_eq!(uploaded, b"request");
        incoming
            .send(IncomingData::Bytes(b"response after EOF".to_vec()))
            .await
            .unwrap();
        incoming.send(IncomingData::HalfClose).await.unwrap();
        let mut response = Vec::new();
        application.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after EOF");
    }

    #[tokio::test]
    async fn credit_window_backpressures_one_stream_without_blocking_another() {
        time::timeout(Duration::from_secs(5), async {
            let (mut application, pump) = tokio::io::duplex(CHUNK_SIZE * 2);
            let (events, mut receiver) = mpsc::channel(QUEUE_SIZE);
            let credits = Arc::new(FlowControl::new());
            let mut workers = JoinSet::new();
            let incoming = spawn_stream(
                &mut workers,
                1,
                pump,
                events.clone(),
                CancellationToken::new(),
                credits.clone(),
            );
            let payload = vec![0x7d; CHUNK_SIZE * INITIAL_CREDITS * 3];
            let expected = payload.clone();
            let producer = tokio::spawn(async move {
                application.write_all(&payload).await.unwrap();
                application.shutdown().await.unwrap();
                application
            });
            let mut received = Vec::new();
            for _ in 0..INITIAL_CREDITS {
                match receiver.recv().await.unwrap() {
                    WorkerEvent::Outgoing(Frame::Data { id: 1, bytes }) => received.extend(bytes),
                    _ => panic!("expected stream data"),
                }
            }
            assert!(time::timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err());
            assert!(
                !producer.is_finished(),
                "writer must backpressure at credit limit"
            );

            // A second stream and its independent credit budget still progress.
            let (mut fast_application, fast_pump) = tokio::io::duplex(1024);
            let _fast_incoming = spawn_stream(
                &mut workers,
                3,
                fast_pump,
                events,
                CancellationToken::new(),
                Arc::new(FlowControl::new()),
            );
            fast_application.write_all(b"independent").await.unwrap();
            match receiver.recv().await.unwrap() {
                WorkerEvent::Outgoing(Frame::Data { id: 3, bytes }) => {
                    assert_eq!(bytes, b"independent")
                }
                _ => panic!("blocked stream interfered with another stream"),
            }
            credits.grant(INITIAL_CREDITS).unwrap();
            loop {
                match receiver.recv().await.unwrap() {
                    WorkerEvent::Outgoing(Frame::Data { id: 1, bytes }) => {
                        received.extend(bytes);
                        credits.grant(1).unwrap();
                    }
                    WorkerEvent::Outgoing(Frame::HalfClose { id: 1 }) => break,
                    _ => panic!("unexpected stream event"),
                }
            }
            assert_eq!(received, expected);
            incoming.send(IncomingData::HalfClose).await.unwrap();
            let mut application = producer.await.unwrap();
            let mut response = Vec::new();
            application.read_to_end(&mut response).await.unwrap();
            assert!(
                credits.grant(1).is_err(),
                "unsolicited grants must be rejected"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn remote_close_drains_queued_response_before_shutting_down() {
        time::timeout(Duration::from_secs(5), async {
            let (mut application, pump) = tokio::io::duplex(1024);
            let (events, _receiver) = mpsc::channel(QUEUE_SIZE);
            let mut workers = JoinSet::new();
            let incoming = spawn_stream(
                &mut workers,
                1,
                pump,
                events,
                CancellationToken::new(),
                Arc::new(FlowControl::new()),
            );
            for _ in 0..INITIAL_CREDITS {
                incoming
                    .send(IncomingData::Bytes(vec![0x42; CHUNK_SIZE]))
                    .await
                    .unwrap();
            }
            incoming.send(IncomingData::Close).await.unwrap();
            let mut response = Vec::new();
            application.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![0x42; INITIAL_CREDITS * CHUNK_SIZE]);
        })
        .await
        .unwrap();
    }
}
