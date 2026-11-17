//! Local TCP proxies. Every destination is opened through the client router.
use crate::client::ClientHandle;
use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::HashSet,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{self, AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

const MAX_HEADER: usize = 32 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 256;

/// Bind both configured listeners before accepting requests. Dropping this future
/// also drops its JoinSet, cancelling all listener and accepted-connection tasks.
pub async fn serve(
    socks: Option<SocketAddr>,
    http: Option<SocketAddr>,
    handle: ClientHandle,
) -> Result<()> {
    let mut listeners = Vec::new();
    for (address, kind) in [(socks, Kind::Socks), (http, Kind::Http)] {
        if let Some(address) = address {
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("bind proxy {address}"))?;
            tracing::info!(%address, ?kind, "proxy listening");
            listeners.push((listener, kind));
        }
    }
    if listeners.is_empty() {
        std::future::pending::<()>().await;
    }
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    for (listener, kind) in listeners {
        let handle = handle.clone();
        let permits = permits.clone();
        tasks.spawn(async move { accept_loop(listener, kind, handle, permits).await });
    }
    match tasks.join_next().await {
        Some(result) => result.context("proxy listener task")?,
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Socks,
    Http,
}

async fn accept_loop(
    listener: TcpListener,
    kind: Kind,
    handle: ClientHandle,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let handle = handle.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let result = match kind { Kind::Socks => socks_connection(stream, handle).await, Kind::Http => http_connection(stream, handle).await };
                    if let Err(error) = result { tracing::debug!(%error, ?kind, "proxy connection ended"); }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn socks_target(stream: &mut TcpStream) -> Result<(String, u16)> {
    ensure!(stream.read_u8().await? == 5, "SOCKS version must be 5");
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0; count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        bail!("SOCKS client did not offer no-authentication mode");
    }
    stream.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        socks_reply(stream, 1).await?;
        bail!("invalid SOCKS request");
    }
    if header[1] != 1 {
        socks_reply(stream, 7).await?;
        bail!("only SOCKS CONNECT is supported");
    }
    let host = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                socks_reply(stream, 8).await?;
                bail!("empty SOCKS hostname");
            }
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            match String::from_utf8(bytes) {
                Ok(host)
                    if !host
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) =>
                {
                    host
                }
                _ => {
                    socks_reply(stream, 8).await?;
                    bail!("invalid SOCKS hostname");
                }
            }
        }
        _ => {
            socks_reply(stream, 8).await?;
            bail!("unsupported SOCKS address type");
        }
    };
    let port = stream.read_u16().await?;
    if port == 0 {
        socks_reply(stream, 1).await?;
        bail!("invalid destination port");
    }
    Ok((host, port))
}

async fn socks_reply(stream: &mut TcpStream, status: u8) -> Result<()> {
    // No local TCP binding is exposed by this multiplexed proxy.
    stream
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn socks_connection(mut stream: TcpStream, handle: ClientHandle) -> Result<()> {
    let (host, port) = timeout(HANDSHAKE_TIMEOUT, socks_target(&mut stream))
        .await
        .context("SOCKS handshake timed out")??;
    let mut tunnel = match handle.open(&host, port).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            socks_reply(&mut stream, 4).await?;
            return Err(error);
        }
    };
    socks_reply(&mut stream, 0).await?;
    io::copy_bidirectional(&mut stream, &mut tunnel).await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    Empty,
    Length(u64),
    Chunked,
}

#[derive(Debug)]
struct HttpRequest {
    host: String,
    port: u16,
    connect: bool,
    header: Vec<u8>,
    body: Body,
}

fn url_host(url: &url::Url) -> Result<String> {
    Ok(match url.host().context("missing target host")? {
        url::Host::Domain(value) => value.to_owned(),
        url::Host::Ipv4(value) => value.to_string(),
        url::Host::Ipv6(value) => value.to_string(),
    })
}

fn parse_http(header: &[u8]) -> Result<HttpRequest> {
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut slots);
    ensure!(
        matches!(request.parse(header)?, httparse::Status::Complete(n) if n == header.len()),
        "incomplete HTTP headers"
    );
    let method = request.method.context("missing method")?;
    let target = request.path.context("missing target")?;
    ensure!(
        matches!(request.version, Some(0 | 1)),
        "unsupported HTTP version"
    );
    let mut length = None;
    let mut transfer_encoding = None;
    let mut hosts = 0;
    let mut connection_tokens = HashSet::new();
    for h in request.headers.iter() {
        if h.name.eq_ignore_ascii_case("host") {
            hosts += 1;
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "multiple Content-Length fields");
            let value = std::str::from_utf8(h.value)?.trim();
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid Content-Length"
            );
            length = Some(value.parse::<u64>()?);
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(
                transfer_encoding.is_none(),
                "multiple Transfer-Encoding fields"
            );
            transfer_encoding = Some(std::str::from_utf8(h.value)?.trim().to_ascii_lowercase());
        }
        if h.name.eq_ignore_ascii_case("connection")
            || h.name.eq_ignore_ascii_case("proxy-connection")
        {
            for token in std::str::from_utf8(h.value)?.split(',') {
                let token = token.trim().to_ascii_lowercase();
                ensure!(
                    !matches!(
                        token.as_str(),
                        "host" | "content-length" | "transfer-encoding"
                    ),
                    "Connection nominates framing header"
                );
                connection_tokens.insert(token);
            }
        }
    }
    ensure!(hosts <= 1, "multiple Host fields");
    ensure!(
        length.is_none() || transfer_encoding.is_none(),
        "conflicting HTTP message framing"
    );
    if let Some(encoding) = &transfer_encoding {
        ensure!(
            encoding == "chunked",
            "only chunked transfer encoding is supported"
        );
    }
    let body = match (length, transfer_encoding) {
        (Some(n), _) => Body::Length(n),
        (_, Some(_)) => Body::Chunked,
        _ => Body::Empty,
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        ensure!(
            !target.contains(['/', '?', '#', '@']),
            "CONNECT requires host:port authority"
        );
        let url = url::Url::parse(&format!("http://{target}/"))?;
        let port = target
            .rsplit(':')
            .next()
            .context("missing CONNECT port")?
            .parse::<u16>()
            .context("CONNECT requires explicit port")?;
        ensure!(port > 0 && target.contains(':'), "invalid CONNECT port");
        ensure!(
            matches!(body, Body::Empty | Body::Length(0)),
            "CONNECT body is not supported"
        );
        return Ok(HttpRequest {
            host: url_host(&url)?,
            port,
            connect: true,
            header: Vec::new(),
            body,
        });
    }
    let url = url::Url::parse(target).context("HTTP proxy requires an absolute http:// URI")?;
    ensure!(
        url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "only absolute HTTP URIs without credentials or fragment are supported"
    );
    let host = url_host(&url)?;
    let port = url.port_or_known_default().context("missing HTTP port")?;
    ensure!(port > 0, "invalid HTTP port");
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut output =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n")
            .into_bytes();
    for h in request.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "keep-alive"
                | "upgrade"
                | "te"
                | "trailer"
        ) || connection_tokens.contains(&name)
        {
            continue;
        }
        output.extend_from_slice(h.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(h.value);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(HttpRequest {
        host,
        port,
        connect: false,
        header: output,
        body,
    })
}

async fn read_http_header(stream: &mut TcpStream) -> Result<(HttpRequest, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        ensure!(n > 0, "connection closed during HTTP headers");
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = index + 4;
            ensure!(end <= MAX_HEADER, "HTTP headers too large");
            return Ok((parse_http(&bytes[..end])?, bytes[end..].to_vec()));
        }
        ensure!(bytes.len() < MAX_HEADER, "HTTP headers too large");
    }
}

async fn http_error(stream: &mut TcpStream, status: &str) -> Result<()> {
    stream
        .write_all(
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn http_connection(mut stream: TcpStream, handle: ClientHandle) -> Result<()> {
    let (request, buffered) = match timeout(HANDSHAKE_TIMEOUT, read_http_header(&mut stream)).await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            http_error(&mut stream, "400 Bad Request").await?;
            return Err(error);
        }
        Err(error) => {
            http_error(&mut stream, "408 Request Timeout").await?;
            return Err(error.into());
        }
    };
    let mut tunnel = match handle.open(&request.host, request.port).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            http_error(&mut stream, "502 Bad Gateway").await?;
            return Err(error);
        }
    };
    if request.connect {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tunnel.write_all(&buffered).await?;
        io::copy_bidirectional(&mut stream, &mut tunnel).await?;
        return Ok(());
    }
    tunnel.write_all(&request.header).await?;
    // Forward exactly one framed request; pipelined bytes are never treated as
    // arbitrary tunnel data. This also prevents a second Host from changing the
    // destination without another route check.
    let (client_read, mut client_write) = stream.into_split();
    let (mut remote_read, mut remote_write) = io::split(tunnel);
    let mut reader = BufReader::new(Cursor::new(buffered).chain(client_read));
    let upload = async {
        forward_body(&mut reader, &mut remote_write, request.body).await?;
        remote_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        io::copy(&mut remote_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => { result?; download.await?; }
        result = &mut download => { result?; }
    }
    Ok(())
}

async fn exact_bytes<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    count: u64,
) -> Result<()> {
    ensure!(
        io::copy(&mut reader.take(count), writer).await? == count,
        "truncated HTTP body"
    );
    Ok(())
}

async fn line<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        ensure!(bytes.len() < limit, "HTTP body line too long");
        let byte = reader.read_u8().await?;
        bytes.push(byte);
        if byte == b'\n' {
            ensure!(bytes.ends_with(b"\r\n"), "HTTP body requires CRLF");
            return Ok(bytes);
        }
    }
}

async fn forward_body<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    body: Body,
) -> Result<()> {
    match body {
        Body::Empty => {}
        Body::Length(count) => exact_bytes(reader, writer, count).await?,
        Body::Chunked => loop {
            let raw = line(reader, 8192).await?;
            let value = std::str::from_utf8(&raw[..raw.len() - 2])?
                .split(';')
                .next()
                .unwrap_or("");
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid chunk size"
            );
            let size = u64::from_str_radix(value, 16)?;
            writer.write_all(format!("{size:x}\r\n").as_bytes()).await?;
            if size == 0 {
                let mut trailers = Vec::new();
                loop {
                    let next = line(reader, 8192).await?;
                    trailers.extend_from_slice(&next);
                    ensure!(trailers.len() <= MAX_HEADER, "HTTP trailers too large");
                    if next == b"\r\n" {
                        break;
                    }
                }
                let mut slots = [httparse::EMPTY_HEADER; 128];
                let httparse::Status::Complete((_, headers)) =
                    httparse::parse_headers(&trailers, &mut slots)?
                else {
                    bail!("invalid HTTP trailers");
                };
                for h in headers {
                    let name = h.name.to_ascii_lowercase();
                    ensure!(
                        !matches!(
                            name.as_str(),
                            "host"
                                | "content-length"
                                | "transfer-encoding"
                                | "connection"
                                | "trailer"
                                | "proxy-authorization"
                                | "proxy-connection"
                        ),
                        "forbidden HTTP trailer"
                    );
                    writer.write_all(h.name.as_bytes()).await?;
                    writer.write_all(b": ").await?;
                    writer.write_all(h.value).await?;
                    writer.write_all(b"\r\n").await?;
                }
                writer.write_all(b"\r\n").await?;
                break;
            }
            exact_bytes(reader, writer, size).await?;
            let mut end = [0; 2];
            reader.read_exact(&mut end).await?;
            ensure!(end == *b"\r\n", "invalid chunk boundary");
            writer.write_all(b"\r\n").await?;
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn socks_domain_handshake_preserves_following_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let target = socks_target(&mut stream).await.unwrap();
            let mut payload = [0; 5];
            stream.read_exact(&mut payload).await.unwrap();
            (target, payload)
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut negotiation = [0; 2];
        stream.read_exact(&mut negotiation).await.unwrap();
        assert_eq!(negotiation, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443_u16.to_be_bytes());
        request.extend_from_slice(b"hello");
        stream.write_all(&request).await.unwrap();
        let (target, payload) = server.await.unwrap();
        assert_eq!(target, ("example.com".into(), 443));
        assert_eq!(payload, *b"hello");
    }
    #[tokio::test]
    async fn socks_rejects_udp_with_command_not_supported_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(socks_target(&mut stream).await.is_err());
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&[5, 1, 0, 5, 3, 0, 1]).await.unwrap();
        let mut replies = [0; 12];
        stream.read_exact(&mut replies).await.unwrap();
        assert_eq!(&replies[..4], &[5, 0, 5, 7]);
        server.await.unwrap();
    }
    #[test]
    fn rewrites_absolute_uri_and_strips_proxy_credentials() {
        let request = parse_http(b"GET http://192.168.1.1:8080/a?q=1 HTTP/1.1\r\nHost: wrong.example\r\nProxy-Authorization: secret\r\nConnection: keep-alive, X-Hop\r\nX-Hop: hidden\r\nUser-Agent: test\r\n\r\n").unwrap();
        assert_eq!((request.host.as_str(), request.port), ("192.168.1.1", 8080));
        let output = String::from_utf8(request.header).unwrap();
        assert!(output
            .starts_with("GET /a?q=1 HTTP/1.1\r\nHost: 192.168.1.1:8080\r\nConnection: close\r\n"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("X-Hop"));
        assert!(output.contains("User-Agent: test"));
    }
    #[test]
    fn connect_ipv6_and_explicit_port() {
        let request =
            parse_http(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n")
                .unwrap();
        assert_eq!(
            (request.host.as_str(), request.port, request.connect),
            ("2001:db8::1", 443, true)
        );
        assert!(parse_http(b"CONNECT example.com HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"CONNECT evil@example.com:443 HTTP/1.1\r\n\r\n").is_err());
    }
    #[test]
    fn rejects_ambiguous_message_framing() {
        for headers in [
            "Content-Length: 1\r\nTransfer-Encoding: chunked",
            "Content-Length: 1\r\nContent-Length: 2",
            "Content-Length: +1",
            "Transfer-Encoding: gzip, chunked",
            "Connection: content-length",
            "Host: a\r\nHost: b",
        ] {
            let raw = format!("POST http://192.168.1.1/ HTTP/1.1\r\n{headers}\r\n\r\n");
            assert!(parse_http(raw.as_bytes()).is_err(), "accepted {headers}");
        }
    }
    #[tokio::test]
    async fn body_framing_does_not_forward_pipelined_requests() {
        let mut input = BufReader::new(Cursor::new(b"helloGET /other HTTP/1.1\r\n\r\n"));
        let mut output = Vec::new();
        forward_body(&mut input, &mut output, Body::Length(5))
            .await
            .unwrap();
        assert_eq!(output, b"hello");
        let mut input = BufReader::new(Cursor::new(
            b"5;extension=value\r\nhello\r\n0\r\nX-Sum: 5\r\n\r\nGET /other HTTP/1.1\r\n\r\n",
        ));
        let mut output = Vec::new();
        forward_body(&mut input, &mut output, Body::Chunked)
            .await
            .unwrap();
        assert_eq!(output, b"5\r\nhello\r\n0\r\nX-Sum: 5\r\n\r\n");
    }
    #[tokio::test]
    async fn rejects_truncated_body_and_invalid_chunk_boundaries() {
        let mut input = BufReader::new(Cursor::new(b"hi"));
        let mut output = Vec::new();
        assert!(forward_body(&mut input, &mut output, Body::Length(5))
            .await
            .is_err());
        let mut input = BufReader::new(Cursor::new(b"2\r\nhiXX0\r\n\r\n"));
        assert!(forward_body(&mut input, &mut output, Body::Chunked)
            .await
            .is_err());
    }
}
