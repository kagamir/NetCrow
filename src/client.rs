//! Client connection lifecycle and multiplexed TCP streams.
use crate::{
    config::ClientConfig,
    protocol::{self, Frame, Route, CHUNK_SIZE, INITIAL_CREDITS, QUEUE_SIZE, VERSION},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
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
use tokio_tungstenite::{tungstenite::Message, Connector, MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type OpenReply = oneshot::Sender<Result<DuplexStream>>;

struct OpenRequest {
    destinations: Vec<SocketAddr>,
    deadline: Instant,
    reply: OpenReply,
}

/// A bounded, wake-on-demand entry point shared by the local proxy listeners.
#[derive(Clone)]
pub struct ClientHandle {
    requests: mpsc::Sender<OpenRequest>,
    disabled: watch::Receiver<bool>,
    timeout: Duration,
}

impl ClientHandle {
    /// Resolve locally and request a TCP stream through an advertised remote subnet.
    /// There is deliberately no direct Internet fallback.
    pub async fn open(&self, host: &str, port: u16) -> Result<DuplexStream> {
        ensure!(!*self.disabled.borrow(), "client is remotely disabled");
        ensure!(port != 0, "destination port must be nonzero");
        let deadline = Instant::now() + self.timeout;
        time::timeout_at(deadline, async {
            let destinations: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .context("resolve destination")?
                .take(64)
                .collect();
            ensure!(!destinations.is_empty(), "destination has no addresses");
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
            receiver
                .await
                .map_err(|_| anyhow!("connection request cancelled"))?
        })
        .await
        .context("connection request timed out")?
    }
}

pub async fn run(config: ClientConfig) -> Result<()> {
    config.validate()?;
    let tls = crate::tls::client_config(&config.tls)?;
    let disabled = crate::control::spawn(config.control.clone());
    let (requests, receiver) = mpsc::channel(QUEUE_SIZE);
    let handle = ClientHandle {
        requests,
        disabled: disabled.clone(),
        timeout: Duration::from_secs(config.connection.open_timeout_secs),
    };
    let proxy = crate::proxy::serve(config.socks5_listen, config.http_listen, handle);
    let manager = manage(config, tls, receiver, disabled);
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
    tls: Arc<rustls::ClientConfig>,
    mut requests: mpsc::Receiver<OpenRequest>,
    mut disabled: watch::Receiver<bool>,
) -> Result<()> {
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
                connect(&config, tls.clone()),
            ) => result.context("WSS connection timed out").and_then(|r| r),
        };
        let outcome = match connection {
            Ok((socket, routes)) => {
                tracing::info!("WSS connected");
                session(
                    &config,
                    socket,
                    routes,
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
    tls: Arc<rustls::ClientConfig>,
) -> Result<(Socket, Vec<Route>)> {
    let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
        config.relay_url.as_str(),
        Some(protocol::websocket_config()),
        false,
        Some(Connector::Rustls(tls)),
    )
    .await
    .context("connect WSS")?;
    socket
        .send(protocol::encode(&Frame::Hello {
            version: VERSION,
            id: config.id.clone(),
            token: config.token.clone(),
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
                            Frame::Routes { routes: updated } => routes = updated,
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
