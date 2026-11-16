//! Authenticated, relay-only stream switching. The relay never dials advertised targets.
use crate::{
    config::RelayConfig,
    protocol::{self, Frame, Route, VERSION},
    tls,
};
use anyhow::{bail, ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::{self, Instant},
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{accept_async_with_config, tungstenite::Message};
use tokio_util::sync::CancellationToken;

const HANDSHAKE_LIMIT: usize = 128;
const HEADER_LIMIT: usize = 16 * 1024;

#[derive(Clone)]
struct Session {
    generation: u64,
    tx: mpsc::Sender<Message>,
    cancel: CancellationToken,
}
struct Peer {
    subnets: Vec<IpNet>,
    session: Option<Session>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Endpoint {
    peer: String,
    id: u64,
}
struct Stream {
    source: Endpoint,
    target: Endpoint,
    destination: SocketAddr,
    opened: bool,
    delivered: bool,
    source_eof: bool,
    target_eof: bool,
    source_credit: usize,
    target_credit: usize,
    deadline: Instant,
}
struct State {
    config: Arc<RelayConfig>,
    peers: HashMap<String, Peer>,
    streams: HashMap<u64, Stream>,
    index: HashMap<Endpoint, u64>,
    next_stream: u64,
    next_generation: u64,
}

impl State {
    fn new(config: Arc<RelayConfig>) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            streams: HashMap::new(),
            index: HashMap::new(),
            next_stream: 2,
            next_generation: 1,
        }
    }
    fn routes(&self) -> Vec<Route> {
        let mut routes: Vec<_> = self
            .peers
            .iter()
            .flat_map(|(id, peer)| {
                peer.subnets.iter().map(move |subnet| Route {
                    peer: id.clone(),
                    subnet: *subnet,
                    online: peer
                        .session
                        .as_ref()
                        .is_some_and(|s| !s.cancel.is_cancelled()),
                })
            })
            .collect();
        routes.sort_by(|a, b| {
            a.peer
                .cmp(&b.peer)
                .then_with(|| a.subnet.to_string().cmp(&b.subnet.to_string()))
        });
        routes
    }
    fn send(&self, peer: &str, frame: Frame) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.session.as_ref())
            .is_some_and(|session| {
                let Ok(message) = protocol::encode(&frame) else {
                    session.cancel.cancel();
                    return false;
                };
                if session.cancel.is_cancelled() || session.tx.try_send(message).is_err() {
                    session.cancel.cancel();
                    false
                } else {
                    true
                }
            })
    }
    fn broadcast_routes(&self) {
        let routes = self.routes();
        for peer in self.peers.keys() {
            self.send(
                peer,
                Frame::Routes {
                    routes: routes.clone(),
                },
            );
        }
    }
    fn authenticate(&self, version: u16, id: &str, token: &str, subnets: &[IpNet]) -> Result<()> {
        ensure!(version == VERSION, "unsupported protocol version");
        ensure!(subnets.len() <= 64, "too many advertisements");
        let peer = self
            .config
            .peers
            .iter()
            .find(|p| p.id == id)
            .context("authentication failed")?;
        ensure!(
            bool::from(peer.token.as_bytes().ct_eq(token.as_bytes())),
            "authentication failed"
        );
        ensure!(
            subnets.iter().all(|n| peer
                .allowed_subnets
                .iter()
                .any(|allowed| contains_subnet(allowed, n))),
            "advertisement outside allowed_subnets"
        );
        ensure!(
            !self.peers.get(id).is_some_and(|p| p.session.is_some()),
            "peer already connected"
        );
        for subnet in subnets {
            ensure!(
                !self.peers.iter().any(|(owner, p)| owner != id
                    && p.subnets
                        .iter()
                        .any(|other| other.trunc() == subnet.trunc())),
                "subnet already advertised by another peer"
            );
        }
        let mut routes = self.routes();
        routes.retain(|route| route.peer != id);
        routes.extend(subnets.iter().map(|subnet| Route {
            peer: id.to_owned(),
            subnet: *subnet,
            online: true,
        }));
        protocol::encode(&Frame::Welcome { routes })
            .context("route table exceeds protocol limit")?;
        Ok(())
    }
    fn register(
        &mut self,
        id: String,
        subnets: Vec<IpNet>,
        tx: mpsc::Sender<Message>,
        cancel: CancellationToken,
    ) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        let mut subnets: Vec<_> = subnets.into_iter().map(|net| net.trunc()).collect();
        subnets.sort_by_key(|net| net.to_string());
        subnets.dedup();
        self.peers.insert(
            id.clone(),
            Peer {
                subnets,
                session: Some(Session {
                    generation,
                    tx,
                    cancel,
                }),
            },
        );
        // Welcome must precede pending incoming requests on the same ordered channel.
        self.send(
            &id,
            Frame::Welcome {
                routes: self.routes(),
            },
        );
        let pending: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, s)| s.target.peer == id && !s.delivered)
            .map(|(key, _)| *key)
            .collect();
        for key in pending {
            let stream = &self.streams[&key];
            let still_allowed = self.peers[&id]
                .subnets
                .iter()
                .any(|n| n.contains(&stream.destination.ip()));
            if !still_allowed {
                self.fail_stream(key, "target withdrew subnet");
                continue;
            }
            let frame = Frame::Incoming {
                id: stream.target.id,
                destination: stream.destination,
            };
            if self.send(&id, frame) {
                self.streams.get_mut(&key).unwrap().delivered = true;
            }
        }
        self.broadcast_routes();
        generation
    }
    fn is_current(&self, id: &str, generation: u64) -> bool {
        self.peers
            .get(id)
            .and_then(|p| p.session.as_ref())
            .is_some_and(|s| s.generation == generation && !s.cancel.is_cancelled())
    }
    fn choose_peer(&self, source: &str, ip: IpAddr) -> Option<String> {
        self.peers
            .iter()
            .filter(|(id, _)| id.as_str() != source)
            .flat_map(|(id, p)| {
                p.subnets
                    .iter()
                    .filter(move |net| net.contains(&ip))
                    .map(move |net| (net.prefix_len(), id))
            })
            .max_by(|(pa, ia), (pb, ib)| pa.cmp(pb).then_with(|| ib.cmp(ia)))
            .map(|(_, id)| id.clone())
    }
    fn peer_stream_count(&self, peer: &str) -> usize {
        self.streams
            .values()
            .filter(|s| s.source.peer == peer || s.target.peer == peer)
            .count()
    }
    fn open(&mut self, peer: &str, id: u64, destination: SocketAddr) -> Result<()> {
        ensure!(id % 2 == 1, "outgoing stream IDs must be odd");
        let source = Endpoint {
            peer: peer.to_owned(),
            id,
        };
        ensure!(!self.index.contains_key(&source), "duplicate stream ID");
        let Some(target_peer) = self.choose_peer(peer, destination.ip()) else {
            self.send(
                peer,
                Frame::Opened {
                    id,
                    error: Some("destination has no shared route".into()),
                },
            );
            return Ok(());
        };
        if destination.port() == 0
            || self.peer_stream_count(peer) >= self.config.max_streams_per_peer
            || self.peer_stream_count(&target_peer) >= self.config.max_streams_per_peer
        {
            self.send(
                peer,
                Frame::Opened {
                    id,
                    error: Some("stream limit reached or invalid port".into()),
                },
            );
            return Ok(());
        }
        let key = self.next_stream;
        self.next_stream = self
            .next_stream
            .checked_add(2)
            .context("stream ID space exhausted")?;
        let target = Endpoint {
            peer: target_peer,
            id: key,
        };
        let delivered = self.send(
            &target.peer,
            Frame::Incoming {
                id: key,
                destination,
            },
        );
        self.index.insert(source.clone(), key);
        self.index.insert(target.clone(), key);
        self.streams.insert(
            key,
            Stream {
                source,
                target,
                destination,
                opened: false,
                delivered,
                source_eof: false,
                target_eof: false,
                source_credit: protocol::INITIAL_CREDITS,
                target_credit: protocol::INITIAL_CREDITS,
                deadline: Instant::now() + Duration::from_secs(self.config.pending_timeout_secs),
            },
        );
        Ok(())
    }
    fn remove_stream(&mut self, key: u64) -> Option<Stream> {
        let stream = self.streams.remove(&key)?;
        self.index.remove(&stream.source);
        self.index.remove(&stream.target);
        Some(stream)
    }
    fn fail_stream(&mut self, key: u64, reason: &str) {
        if let Some(stream) = self.remove_stream(key) {
            if stream.opened {
                self.send(
                    &stream.source.peer,
                    Frame::Close {
                        id: stream.source.id,
                    },
                );
            } else {
                self.send(
                    &stream.source.peer,
                    Frame::Opened {
                        id: stream.source.id,
                        error: Some(reason.into()),
                    },
                );
            }
            if stream.delivered {
                self.send(
                    &stream.target.peer,
                    Frame::Close {
                        id: stream.target.id,
                    },
                );
            }
        }
    }
    fn handle(&mut self, peer: &str, generation: u64, frame: Frame) -> Result<()> {
        ensure!(
            self.is_current(peer, generation),
            "session is no longer current"
        );
        if let Frame::Open { id, destination } = frame {
            return self.open(peer, id, destination);
        }
        let id = match &frame {
            Frame::Opened { id, .. }
            | Frame::Data { id, .. }
            | Frame::Credit { id, .. }
            | Frame::HalfClose { id }
            | Frame::Close { id } => *id,
            _ => bail!("unexpected client frame"),
        };
        let endpoint = Endpoint {
            peer: peer.to_owned(),
            id,
        };
        let Some(key) = self.index.get(&endpoint).copied() else {
            // Cancellation can race frames already in flight. Unknown IDs never forward anywhere.
            return Ok(());
        };
        let stream = self.streams.get_mut(&key).unwrap();
        let from_source = endpoint == stream.source;
        let other = if from_source {
            stream.target.clone()
        } else {
            stream.source.clone()
        };
        match frame {
            Frame::Opened { error, .. } => {
                ensure!(
                    !error.as_ref().is_some_and(|message| message.len() > 1024),
                    "open error too long"
                );
                ensure!(
                    !from_source && stream.delivered && !stream.opened,
                    "unexpected open response"
                );
                if error.is_some() {
                    self.remove_stream(key);
                } else {
                    stream.opened = true;
                }
                if !self.send(
                    &other.peer,
                    Frame::Opened {
                        id: other.id,
                        error,
                    },
                ) {
                    self.fail_stream(key, "source disconnected");
                }
            }
            Frame::Data { bytes, .. } => {
                ensure!(
                    stream.opened
                        && !(if from_source {
                            stream.source_eof
                        } else {
                            stream.target_eof
                        }),
                    "data outside an open stream"
                );
                let credit = if from_source {
                    &mut stream.source_credit
                } else {
                    &mut stream.target_credit
                };
                ensure!(*credit > 0, "stream receive window exhausted");
                *credit -= 1;
                if !self.send(
                    &other.peer,
                    Frame::Data {
                        id: other.id,
                        bytes,
                    },
                ) {
                    self.fail_stream(key, "peer disconnected");
                }
            }
            Frame::Credit { frames, .. } => {
                ensure!(stream.opened, "credit before stream opened");
                let frames = frames as usize;
                ensure!(
                    frames > 0 && frames <= protocol::INITIAL_CREDITS,
                    "invalid credit amount"
                );
                // Credit acknowledges data received from the opposite endpoint.
                let credit = if from_source {
                    &mut stream.target_credit
                } else {
                    &mut stream.source_credit
                };
                ensure!(
                    *credit + frames <= protocol::INITIAL_CREDITS,
                    "credit exceeds outstanding data"
                );
                *credit += frames;
                if !self.send(
                    &other.peer,
                    Frame::Credit {
                        id: other.id,
                        frames: frames as u32,
                    },
                ) {
                    self.fail_stream(key, "peer disconnected");
                }
            }
            Frame::HalfClose { .. } => {
                ensure!(stream.opened, "half-close before stream opened");
                if (from_source && stream.source_eof) || (!from_source && stream.target_eof) {
                    return Ok(());
                }
                if from_source {
                    stream.source_eof = true;
                } else {
                    stream.target_eof = true;
                }
                let finished = stream.source_eof && stream.target_eof;
                if !self.send(&other.peer, Frame::HalfClose { id: other.id }) {
                    self.fail_stream(key, "peer disconnected");
                } else if finished {
                    self.remove_stream(key);
                }
            }
            Frame::Close { .. } => {
                self.remove_stream(key);
                self.send(&other.peer, Frame::Close { id: other.id });
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    fn disconnect(&mut self, peer: &str, generation: u64) {
        let Some(current) = self.peers.get_mut(peer) else {
            return;
        };
        if !current
            .session
            .as_ref()
            .is_some_and(|s| s.generation == generation)
        {
            return;
        }
        if let Some(session) = current.session.take() {
            session.cancel.cancel();
        }
        let doomed: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, s)| s.source.peer == peer || (s.target.peer == peer && s.delivered))
            .map(|(key, _)| *key)
            .collect();
        for key in doomed {
            self.fail_stream(key, "peer disconnected");
        }
        self.broadcast_routes();
    }
    fn expire_pending(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.opened && s.deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.fail_stream(key, "target connection timed out");
        }
    }
}
fn contains_subnet(allowed: &IpNet, claimed: &IpNet) -> bool {
    allowed.prefix_len() <= claimed.prefix_len() && allowed.contains(&claimed.network())
}

/// Start the TLS/WebSocket relay and run until interrupted.
pub async fn run(config: RelayConfig) -> Result<()> {
    config.validate()?;
    let acceptor = TlsAcceptor::from(tls::server_config(&config.tls)?);
    let listener = TcpListener::bind(config.listen)
        .await
        .context("bind relay")?;
    tracing::info!(listen = %listener.local_addr()?, "relay listening");
    let config = Arc::new(config);
    let state = Arc::new(Mutex::new(State::new(config.clone())));
    let handshakes = Arc::new(Semaphore::new(HANDSHAKE_LIMIT));
    let mut connections = JoinSet::new();
    let mut sweep = time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, address) = accepted?;
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue; };
                let (config, state, acceptor) = (config.clone(), state.clone(), acceptor.clone());
                connections.spawn(async move {
                    if let Err(error) = serve(stream, acceptor, config, state, permit).await {
                        tracing::debug!(%address, %error, "relay connection ended");
                    }
                });
            }
            _ = sweep.tick() => { state.lock().unwrap().expire_pending(); }
            _ = connections.join_next(), if !connections.is_empty() => {}
            _ = tokio::signal::ctrl_c() => { break; }
        }
    }
    for peer in state.lock().unwrap().peers.values() {
        if let Some(session) = &peer.session {
            session.cancel.cancel();
        }
    }
    connections.abort_all();
    Ok(())
}

async fn serve(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    config: Arc<RelayConfig>,
    state: Arc<Mutex<State>>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut ws, id, token, subnets, version) = time::timeout(Duration::from_secs(10), async {
        let mut tls = acceptor.accept(stream).await?;
        let header = read_header(&mut tls).await?;
        if !is_websocket_request(&header, &config.websocket_path) {
            tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\nConnection: close\r\n\r\nNot Found\n").await?;
            tls.shutdown().await?;
            bail!("not a WebSocket endpoint request");
        }
        let prefixed = Prefixed { prefix: std::io::Cursor::new(header), inner: tls };
        let mut ws = accept_async_with_config(prefixed, Some(protocol::websocket_config())).await?;
        let first = ws.next().await.context("connection closed before hello")??;
        let Message::Binary(bytes) = first else { bail!("expected binary hello"); };
        let Frame::Hello { version, id, token, subnets } = protocol::decode(&bytes)? else { bail!("expected hello"); };
        Ok::<_, anyhow::Error>((ws, id, token, subnets, version))
    }).await.context("handshake timed out")??;
    let cancel = CancellationToken::new();
    // At most one receive window of Data and one of returning Credit per stream
    // can be in flight. Keep extra slots for open/close and route/control frames.
    // Unlike a fixed 64-frame queue, this does not truncate ordinary concurrent
    // transfers merely because one consumer applies TCP backpressure.
    let capacity = config
        .max_streams_per_peer
        .checked_mul(2 * protocol::INITIAL_CREDITS + 6)
        .and_then(|n| n.checked_add(protocol::QUEUE_SIZE))
        .context("relay queue capacity overflow")?;
    let (tx, mut rx) = mpsc::channel(capacity);
    let registered = {
        let mut state = state.lock().unwrap();
        state
            .authenticate(version, &id, &token, &subnets)
            .map(|()| state.register(id.clone(), subnets, tx.clone(), cancel.clone()))
    };
    let generation = match registered {
        Ok(generation) => generation,
        Err(error) => {
            let _ = time::timeout(
                Duration::from_secs(2),
                ws.send(protocol::encode(&Frame::Error {
                    message: error.to_string(),
                })?),
            )
            .await;
            return Err(error);
        }
    };
    drop(permit);
    tracing::info!(peer = %id, "peer connected");
    let (mut sink, mut source) = ws.split();
    let writer_cancel = cancel.clone();
    let deadline = Duration::from_secs(config.peer_timeout_secs);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = writer_cancel.cancelled() => break,
                next = rx.recv() => {
                    let Some(message) = next else { break; };
                    match time::timeout(deadline, sink.send(message)).await {
                        Ok(Ok(())) => {}, _ => break,
                    }
                }
            }
        }
        writer_cancel.cancel();
    });
    let outcome: Result<()> = async {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                next = time::timeout(deadline, source.next()) => {
                    match next.context("peer heartbeat timed out")? {
                        Some(Ok(Message::Binary(bytes))) => { state.lock().unwrap().handle(&id, generation, protocol::decode(&bytes)?)?; }
                        Some(Ok(Message::Ping(bytes))) => { if tx.try_send(Message::Pong(bytes)).is_err() { bail!("peer write queue full"); } }
                        Some(Ok(Message::Pong(_))) => {},
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(_)) => bail!("expected binary protocol frames"),
                        Some(Err(error)) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(())
    }.await;
    cancel.cancel();
    writer.abort();
    let _ = writer.await;
    state.lock().unwrap().disconnect(&id, generation);
    tracing::info!(peer = %id, "peer disconnected");
    outcome
}

async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    loop {
        ensure!(header.len() < HEADER_LIMIT, "HTTP header too large");
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
}
fn is_websocket_request(header: &[u8], path: &str) -> bool {
    let Ok(text) = std::str::from_utf8(header) else {
        return false;
    };
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split_whitespace();
    if request.next() != Some("GET")
        || request.next() != Some(path)
        || request.next() != Some("HTTP/1.1")
    {
        return false;
    }
    lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket")
        })
    })
}
struct Prefixed<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}
impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if (self.prefix.position() as usize) < self.prefix.get_ref().len() {
            let start = self.prefix.position() as usize;
            let end = (start + buffer.remaining()).min(self.prefix.get_ref().len());
            buffer.put_slice(&self.prefix.get_ref()[start..end]);
            self.prefix.set_position(end as u64);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> State {
        let config: RelayConfig = toml::from_str(
            r#"
listen = "127.0.0.1:0"
pending_timeout_secs = 2
[[peers]]
id = "a"
token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed_subnets = ["10.0.0.0/8"]
[[peers]]
id = "b"
token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
allowed_subnets = ["10.0.0.0/8"]
[[peers]]
id = "c"
token = "cccccccccccccccccccccccccccccccc"
allowed_subnets = []
"#,
        )
        .unwrap();
        State::new(Arc::new(config))
    }
    fn register(state: &mut State, id: &str, subnets: &[&str]) -> (u64, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(512);
        let generation = state.register(
            id.into(),
            subnets.iter().map(|s| s.parse().unwrap()).collect(),
            tx,
            CancellationToken::new(),
        );
        (generation, rx)
    }
    #[test]
    fn most_specific_route_including_sleeping_peers() {
        let mut state = state();
        let (_, _a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let (generation, _b) = register(&mut state, "b", &["10.1.0.0/16"]);
        state.disconnect("b", generation);
        assert_eq!(
            state.choose_peer("c", "10.1.2.3".parse().unwrap()),
            Some("b".into())
        );
        assert_eq!(
            state.choose_peer("c", "10.2.2.3".parse().unwrap()),
            Some("a".into())
        );
        assert_eq!(state.choose_peer("a", "10.2.2.3".parse().unwrap()), None);
    }
    #[test]
    fn authentication_and_subnet_boundaries() {
        let state = state();
        let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(state
            .authenticate(VERSION, "a", token, &["10.1.0.0/16".parse().unwrap()])
            .is_ok());
        assert!(state.authenticate(VERSION, "a", "wrong", &[]).is_err());
        assert!(state
            .authenticate(VERSION, "a", token, &["0.0.0.0/0".parse().unwrap()])
            .is_err());
        assert!(state
            .authenticate(VERSION, "a", token, &["::/0".parse().unwrap()])
            .is_err());
    }
    #[test]
    fn offline_pending_delivered_after_welcome_and_removed_with_source() {
        let mut state = state();
        let (a_gen, _a) = register(&mut state, "a", &["10.0.0.0/8"]);
        state.disconnect("a", a_gen);
        let (c_gen, _c) = register(&mut state, "c", &[]);
        state.open("c", 1, "10.0.1.2:80".parse().unwrap()).unwrap();
        assert!(!state.streams[&2].delivered);
        let (_, mut a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let Message::Binary(first) = a.try_recv().unwrap() else {
            panic!();
        };
        assert!(matches!(
            protocol::decode(&first).unwrap(),
            Frame::Welcome { .. }
        ));
        let Message::Binary(second) = a.try_recv().unwrap() else {
            panic!();
        };
        assert!(matches!(
            protocol::decode(&second).unwrap(),
            Frame::Incoming { id: 2, .. }
        ));
        state.disconnect("c", c_gen);
        assert!(state.streams.is_empty());
        assert!(state.index.is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn pending_expiry_and_stale_disconnect() {
        let mut state = state();
        let (a_gen, _a) = register(&mut state, "a", &["10.0.0.0/8"]);
        state.disconnect("a", a_gen);
        let (c_gen, _c) = register(&mut state, "c", &[]);
        state.open("c", 1, "10.1.2.3:80".parse().unwrap()).unwrap();
        time::advance(Duration::from_secs(3)).await;
        state.expire_pending();
        assert!(state.streams.is_empty());
        state.disconnect("c", c_gen.wrapping_sub(1));
        assert!(state.is_current("c", c_gen));
    }
    #[test]
    fn data_requires_destination_acceptance() {
        let mut state = state();
        let (_, _a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let (generation, _c) = register(&mut state, "c", &[]);
        state.open("c", 1, "10.1.2.3:80".parse().unwrap()).unwrap();
        assert!(state
            .handle(
                "c",
                generation,
                Frame::Data {
                    id: 1,
                    bytes: vec![1]
                }
            )
            .is_err());
        assert!(state
            .handle("c", generation, Frame::Opened { id: 1, error: None })
            .is_err());
    }
    #[test]
    fn half_close_preserves_other_direction_until_both_finish() {
        let mut state = state();
        let (a_gen, mut a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let (c_gen, mut c) = register(&mut state, "c", &[]);
        while a.try_recv().is_ok() {}
        while c.try_recv().is_ok() {}
        state.open("c", 1, "10.1.2.3:80".parse().unwrap()).unwrap();
        state
            .handle("a", a_gen, Frame::Opened { id: 2, error: None })
            .unwrap();
        state
            .handle("c", c_gen, Frame::HalfClose { id: 1 })
            .unwrap();
        assert_eq!(state.streams.len(), 1);
        state
            .handle(
                "a",
                a_gen,
                Frame::Data {
                    id: 2,
                    bytes: b"response".to_vec(),
                },
            )
            .unwrap();
        state
            .handle("a", a_gen, Frame::HalfClose { id: 2 })
            .unwrap();
        assert!(state.streams.is_empty());
    }
    #[test]
    fn overflowing_peer_queue_cancels_the_session() {
        let mut state = state();
        let (tx, _rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        state.register("a".into(), vec![], tx, cancel.clone());
        // Welcome fills the queue; route broadcast cannot be queued.
        assert!(cancel.is_cancelled());
    }
    #[test]
    fn duplicate_advertisements_are_rejected_but_overlap_is_allowed() {
        let mut state = state();
        let (_, _a) = register(&mut state, "a", &["10.1.0.0/16"]);
        let token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(state
            .authenticate(VERSION, "b", token, &["10.1.2.3/16".parse().unwrap()])
            .is_err());
        assert!(state
            .authenticate(VERSION, "b", token, &["10.1.2.0/24".parse().unwrap()])
            .is_ok());
    }
    #[test]
    fn websocket_endpoint_matches_exact_path() {
        assert!(is_websocket_request(
            b"GET /netcrow HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
            "/netcrow"
        ));
        assert!(!is_websocket_request(
            b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
            "/netcrow"
        ));
        assert!(!is_websocket_request(
            b"GET /netcrow HTTP/1.1\r\n\r\n",
            "/netcrow"
        ));
    }
    #[test]
    fn receive_window_requires_credit_and_forwards_rewritten_id() {
        let mut state = state();
        let (a_gen, mut a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let (c_gen, mut c) = register(&mut state, "c", &[]);
        state.open("c", 1, "10.1.2.3:80".parse().unwrap()).unwrap();
        state
            .handle("a", a_gen, Frame::Opened { id: 2, error: None })
            .unwrap();
        while a.try_recv().is_ok() {}
        while c.try_recv().is_ok() {}
        for _ in 0..protocol::INITIAL_CREDITS {
            state
                .handle(
                    "c",
                    c_gen,
                    Frame::Data {
                        id: 1,
                        bytes: vec![1],
                    },
                )
                .unwrap();
        }
        assert!(state
            .handle(
                "c",
                c_gen,
                Frame::Data {
                    id: 1,
                    bytes: vec![1]
                }
            )
            .is_err());
        state
            .handle("a", a_gen, Frame::Credit { id: 2, frames: 1 })
            .unwrap();
        let Message::Binary(bytes) = c.try_recv().unwrap() else {
            panic!();
        };
        assert!(matches!(
            protocol::decode(&bytes).unwrap(),
            Frame::Credit { id: 1, frames: 1 }
        ));
        state
            .handle(
                "c",
                c_gen,
                Frame::Data {
                    id: 1,
                    bytes: vec![1],
                },
            )
            .unwrap();
        assert!(state
            .handle(
                "c",
                c_gen,
                Frame::Data {
                    id: 1,
                    bytes: vec![1]
                }
            )
            .is_err());
    }
    #[test]
    fn excessive_credit_and_duplicate_halfclose_cannot_fill_peer_queue() {
        let mut state = state();
        let (a_gen, mut a) = register(&mut state, "a", &["10.0.0.0/8"]);
        let (c_gen, _c) = register(&mut state, "c", &[]);
        state.open("c", 1, "10.1.2.3:80".parse().unwrap()).unwrap();
        state
            .handle("a", a_gen, Frame::Opened { id: 2, error: None })
            .unwrap();
        assert!(state
            .handle("a", a_gen, Frame::Credit { id: 2, frames: 1 })
            .is_err());
        assert!(state
            .handle("a", a_gen, Frame::Credit { id: 2, frames: 0 })
            .is_err());
        while a.try_recv().is_ok() {}
        state
            .handle("c", c_gen, Frame::HalfClose { id: 1 })
            .unwrap();
        a.try_recv().unwrap();
        for _ in 0..100 {
            state
                .handle("c", c_gen, Frame::HalfClose { id: 1 })
                .unwrap();
        }
        assert!(a.try_recv().is_err());
    }
}
