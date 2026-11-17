use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

fn heartbeat() -> u64 {
    20
}
fn heartbeat_timeout() -> u64 {
    60
}
fn sleep() -> u64 {
    10
}
fn idle() -> u64 {
    600
}
fn reconnect() -> u64 {
    3
}
fn open_timeout() -> u64 {
    90
}
fn connect_timeout() -> u64 {
    10
}
fn probe() -> u64 {
    2
}
fn max_streams() -> usize {
    256
}
fn path() -> String {
    "/netcrow".into()
}
fn cert() -> PathBuf {
    "netcrow-cert.pem".into()
}
fn key() -> PathBuf {
    "netcrow-key.pem".into()
}
fn names() -> Vec<String> {
    vec!["localhost".into()]
}
fn control_interval() -> u64 {
    60
}
fn max_body() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    #[serde(default = "path")]
    pub websocket_path: String,
    #[serde(default)]
    pub tls: ServerTls,
    pub peers: Vec<PeerConfig>,
    #[serde(default = "open_timeout")]
    pub pending_timeout_secs: u64,
    #[serde(default = "max_streams")]
    pub max_streams_per_peer: usize,
    #[serde(default = "heartbeat_timeout")]
    pub peer_timeout_secs: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub id: String,
    pub token: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    #[serde(default = "cert")]
    pub cert_path: PathBuf,
    #[serde(default = "key")]
    pub key_path: PathBuf,
    #[serde(default = "names")]
    pub names: Vec<String>,
}
impl Default for ServerTls {
    fn default() -> Self {
        Self {
            cert_path: cert(),
            key_path: key(),
            names: names(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub id: String,
    pub token: String,
    /// Dial address and literal WebSocket path, e.g. relay.example.com:443/netcrow.
    pub relay_addr: String,
    /// Omitted: verify the dial host. Empty: omit SNI but still verify that host.
    #[serde(default)]
    pub relay_sni: Option<String>,
    #[serde(default)]
    pub shared_subnets: Vec<IpNet>,
    /// Omitted: all learned remote routes. An explicit empty list selects direct only.
    #[serde(default)]
    pub proxy_subnets: Option<Vec<IpNet>>,
    #[serde(default)]
    pub socks5_listen: Option<SocketAddr>,
    #[serde(default)]
    pub http_listen: Option<SocketAddr>,
    #[serde(default)]
    pub allow_remote_proxy: bool,
    #[serde(default)]
    pub tls: ClientTls,
    #[serde(default)]
    pub connection: ConnectionConfig,
    #[serde(default)]
    pub control: Option<ControlConfig>,
}
/// Separates the TCP/WebSocket destination from TLS identity and SNI policy.
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    pub host: String,
    pub port: u16,
    pub websocket_uri: String,
    pub server_name: ServerName<'static>,
    pub enable_sni: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub spki_sha256: Option<String>,
    pub ca_cert_path: Option<PathBuf>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    #[serde(default = "idle")]
    pub idle_secs: u64,
    #[serde(default = "sleep")]
    pub sleep_secs: u64,
    #[serde(default = "probe")]
    pub probe_secs: u64,
    #[serde(default = "heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default = "heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "reconnect")]
    pub reconnect_secs: u64,
    #[serde(default = "open_timeout")]
    pub open_timeout_secs: u64,
    #[serde(default = "connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "max_streams")]
    pub max_streams: usize,
}
impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            idle_secs: idle(),
            sleep_secs: sleep(),
            probe_secs: probe(),
            heartbeat_secs: heartbeat(),
            heartbeat_timeout_secs: heartbeat_timeout(),
            reconnect_secs: reconnect(),
            open_timeout_secs: open_timeout(),
            connect_timeout_secs: connect_timeout(),
            max_streams: max_streams(),
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    #[serde(default)]
    pub initially_disabled: bool,
    #[serde(default = "control_interval")]
    pub interval_secs: u64,
    #[serde(default = "connect_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "max_body")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub disable: Vec<PageRule>,
    #[serde(default)]
    pub enable: Vec<PageRule>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRule {
    pub url: String,
    pub regex: Option<String>,
    pub keyword: Option<String>,
}

pub fn load_relay(path: &Path) -> Result<RelayConfig> {
    let mut config: RelayConfig = read(path)?;
    resolve_path(path, &mut config.tls.cert_path);
    resolve_path(path, &mut config.tls.key_path);
    config.validate()?;
    Ok(config)
}
pub fn load_client(path: &Path) -> Result<ClientConfig> {
    let mut config: ClientConfig = read(path)?;
    if let Some(p) = &mut config.tls.ca_cert_path {
        resolve_path(path, p);
    }
    config.validate()?;
    Ok(config)
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    toml::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("invalid configuration")
}
fn resolve_path(config_path: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = config_path.parent().unwrap_or(Path::new(".")).join(&*path);
    }
}
fn identity(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid peer id"
    );
    Ok(())
}
impl RelayConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.peers.is_empty() && self.peers.len() <= 256,
            "configure 1..256 peers"
        );
        ensure!(
            self.websocket_path.starts_with('/') && !self.websocket_path.contains('?'),
            "invalid websocket_path"
        );
        ensure!(
            self.pending_timeout_secs > 0
                && self.peer_timeout_secs > 0
                && (1..=4096).contains(&self.max_streams_per_peer),
            "relay intervals must be positive and max_streams_per_peer must be 1..4096"
        );
        let mut ids = HashSet::new();
        for peer in &self.peers {
            identity(&peer.id)?;
            ensure!(ids.insert(&peer.id), "duplicate peer id");
        }
        Ok(())
    }
}
fn normalize_host(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && !value.chars().any(|c| c.is_whitespace() || c.is_control())
            && !value.contains(['/', '?', '#', '@', '\\', '%', '[', ']']),
        "host must be a DNS name or an unbracketed IP address"
    );
    let host = if let Ok(address) = value.parse::<IpAddr>() {
        address.to_string()
    } else {
        ensure!(
            !value.contains(':'),
            "host names must not contain a scheme or port"
        );
        url::Host::parse(value)
            .context("invalid DNS name or IP address")?
            .to_string()
    };
    ServerName::try_from(host.clone()).context("invalid TLS host identity")?;
    Ok(host)
}

fn validate_websocket_path(value: &str) -> Result<()> {
    ensure!(value.starts_with('/'), "WebSocket path must begin with /");
    let bytes = value.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        if byte == b'%' {
            ensure!(
                position + 2 < bytes.len()
                    && bytes[position + 1].is_ascii_hexdigit()
                    && bytes[position + 2].is_ascii_hexdigit(),
                "WebSocket path contains an invalid percent escape"
            );
            position += 3;
        } else {
            ensure!(
                byte.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&byte),
                "WebSocket path must use URI path characters; percent-encode other bytes"
            );
            position += 1;
        }
    }
    Ok(())
}

impl ClientConfig {
    pub fn relay_endpoint(&self) -> Result<RelayEndpoint> {
        ensure!(
            !self.relay_addr.chars().any(|c| c.is_whitespace() || c.is_control())
                && !self.relay_addr.contains(['?', '#', '\\']),
            "relay_addr must be host:port/path without scheme, credentials, whitespace, query or fragment"
        );
        let (authority, suffix) = self
            .relay_addr
            .split_once('/')
            .context("relay_addr must include an explicit port and a path beginning with /")?;
        ensure!(
            !authority.contains('@'),
            "relay_addr must not contain credentials"
        );
        let websocket_path = format!("/{suffix}");
        validate_websocket_path(&websocket_path)?;
        let (host, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (literal, remainder) = bracketed
                .split_once(']')
                .context("relay_addr IPv6 addresses must use [address]:port/path")?;
            let address: Ipv6Addr = literal.parse().context("invalid relay_addr IPv6 address")?;
            let port = remainder
                .strip_prefix(':')
                .context("relay_addr must include an explicit port")?;
            (address.to_string(), port)
        } else {
            let (host, port) = authority
                .rsplit_once(':')
                .context("relay_addr must include an explicit port")?;
            ensure!(
                !host.contains(':') && !host.contains(['[', ']']),
                "relay_addr IPv6 addresses must use [address]:port/path"
            );
            (
                normalize_host(host).context("invalid relay_addr host")?,
                port,
            )
        };
        ensure!(
            !port_text.is_empty() && port_text.bytes().all(|byte| byte.is_ascii_digit()),
            "relay_addr port must be an integer from 1 to 65535"
        );
        let port: u16 = port_text
            .parse()
            .context("relay_addr port must be from 1 to 65535")?;
        ensure!(port != 0, "relay_addr port must be from 1 to 65535");
        let authority_host = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.clone()
        };
        // Construct from the parsed authority, without URL path normalization.
        // In particular, keep :443, dot segments and percent-encoded bytes intact.
        let websocket_uri = format!("wss://{authority_host}:{port}{websocket_path}");
        let uri: tokio_tungstenite::tungstenite::http::Uri = websocket_uri
            .parse()
            .context("relay_addr does not produce a valid WebSocket URI")?;
        ensure!(
            uri.scheme_str() == Some("wss")
                && uri
                    .path_and_query()
                    .is_some_and(|path| path.as_str() == websocket_path),
            "relay_addr must preserve its literal WebSocket path"
        );
        let identity = match self.relay_sni.as_deref() {
            Some(override_name) if !override_name.is_empty() => {
                normalize_host(override_name).context("invalid relay_sni name")?
            }
            _ => host.clone(),
        };
        let server_name = ServerName::try_from(identity)
            .context("TLS identity must be a valid DNS name or IP address")?;
        Ok(RelayEndpoint {
            host,
            port,
            websocket_uri,
            server_name,
            enable_sni: self.relay_sni.as_deref() != Some(""),
        })
    }

    pub fn validate(&self) -> Result<()> {
        identity(&self.id)?;
        self.relay_endpoint()?;
        ensure!(self.shared_subnets.len() <= 64, "too many shared subnets");
        for addr in [self.socks5_listen, self.http_listen].into_iter().flatten() {
            ensure!(
                addr.ip().is_loopback() || self.allow_remote_proxy,
                "non-loopback proxy listener requires allow_remote_proxy=true"
            );
        }
        let c = &self.connection;
        ensure!(
            c.sleep_secs > 0
                && c.probe_secs > 0
                && c.heartbeat_secs > 0
                && c.reconnect_secs > 0
                && c.open_timeout_secs > 0
                && c.connect_timeout_secs > 0
                && c.max_streams > 0,
            "connection intervals and limits must be positive (except idle_secs)"
        );
        ensure!(
            c.heartbeat_timeout_secs > c.heartbeat_secs,
            "heartbeat_timeout_secs must exceed heartbeat_secs"
        );
        ensure!(c.max_streams <= 4096, "max_streams must not exceed 4096");
        ensure!(
            self.tls.spki_sha256.is_none() || self.tls.ca_cert_path.is_none(),
            "choose either public-key pin or custom CA"
        );
        if let Some(control) = &self.control {
            ensure!(
                control.interval_secs > 0 && control.timeout_secs > 0 && control.max_body_bytes > 0,
                "control limits must be positive"
            );
            for rule in control.disable.iter().chain(&control.enable) {
                let url = url::Url::parse(&rule.url)?;
                if !matches!(url.scheme(), "http" | "https") {
                    bail!("control URL must be HTTP(S)");
                }
                ensure!(
                    url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none(),
                    "control URL must have a host and no userinfo or fragment"
                );
                match (&rule.regex, &rule.keyword) {
                    (Some(pattern), None) => {
                        regex::Regex::new(pattern).context("invalid control regex")?;
                    }
                    (None, Some(keyword)) => {
                        ensure!(!keyword.is_empty(), "control keyword must not be empty");
                    }
                    _ => bail!("control rule must set exactly one of regex or keyword"),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client(text: &str) -> ClientConfig {
        toml::from_str(&format!("id='home'\ntoken='0123456789abcdef0123456789abcdef'\nrelay_addr='localhost:443/netcrow'\n{text}")).unwrap()
    }
    #[test]
    fn idle_zero_keeps_other_liveness_limits() {
        assert!(client("[connection]\nidle_secs=0").validate().is_ok());
        assert!(client("[connection]\nheartbeat_secs=0").validate().is_err());
        assert!(client("[connection]\nheartbeat_timeout_secs=10")
            .validate()
            .is_err());
    }
    #[test]
    fn remote_proxy_requires_explicit_opt_in() {
        assert!(client("socks5_listen='0.0.0.0:1080'").validate().is_err());
        assert!(
            client("socks5_listen='0.0.0.0:1080'\nallow_remote_proxy=true")
                .validate()
                .is_ok()
        );
    }
    #[test]
    fn configuration_typos_are_not_silent() {
        assert!(toml::from_str::<ConnectionConfig>("idle_sec=0").is_err());
    }
    #[test]
    fn relay_endpoints_preserve_explicit_ports_and_literal_paths() {
        let default = client("").relay_endpoint().unwrap();
        assert_eq!(default.host, "localhost");
        assert_eq!(default.port, 443);
        assert_eq!(default.websocket_uri, "wss://localhost:443/netcrow");
        assert_eq!(default.server_name.to_str(), "localhost");
        assert!(default.enable_sni);
        for (address, host, port, uri) in [
            (
                "EXAMPLE.COM:443/",
                "example.com",
                443,
                "wss://example.com:443/",
            ),
            (
                "127.0.0.1:8443/tunnel",
                "127.0.0.1",
                8443,
                "wss://127.0.0.1:8443/tunnel",
            ),
            (
                "[2001:0db8::1]:65535/a/../%2f%2E/",
                "2001:db8::1",
                65535,
                "wss://[2001:db8::1]:65535/a/../%2f%2E/",
            ),
            (
                "bücher.example:1/socket",
                "xn--bcher-kva.example",
                1,
                "wss://xn--bcher-kva.example:1/socket",
            ),
            (
                "example.com:443/a@b/http://x",
                "example.com",
                443,
                "wss://example.com:443/a@b/http://x",
            ),
        ] {
            let mut config = client("");
            config.relay_addr = address.into();
            let endpoint = config.relay_endpoint().unwrap();
            assert_eq!(endpoint.host, host);
            assert_eq!(endpoint.port, port);
            assert_eq!(endpoint.websocket_uri, uri);
            assert_eq!(endpoint.server_name.to_str(), host);
        }
    }

    #[test]
    fn sni_override_and_disabled_sni_keep_independent_certificate_identity() {
        let mut config = client("");
        config.relay_addr = "127.0.0.1:443/netcrow".into();
        let default = config.relay_endpoint().unwrap();
        assert!(matches!(default.server_name, ServerName::IpAddress(_)));
        config.relay_sni = Some("RELAY.EXAMPLE.COM".into());
        let overridden = config.relay_endpoint().unwrap();
        assert!(overridden.enable_sni);
        assert_eq!(overridden.server_name.to_str(), "relay.example.com");
        assert_eq!(overridden.host, "127.0.0.1");
        assert_eq!(overridden.websocket_uri, "wss://127.0.0.1:443/netcrow");
        config.relay_sni = Some(String::new());
        let omitted = config.relay_endpoint().unwrap();
        assert!(!omitted.enable_sni);
        assert_eq!(omitted.server_name, default.server_name);
        config.relay_addr = "Example.com:443/netcrow".into();
        let omitted = config.relay_endpoint().unwrap();
        assert!(!omitted.enable_sni);
        assert_eq!(omitted.server_name.to_str(), "example.com");
        config.relay_sni = Some("2001:db8::2".into());
        let ip_override = config.relay_endpoint().unwrap();
        assert!(matches!(ip_override.server_name, ServerName::IpAddress(_)));
        assert_eq!(ip_override.host, "example.com");
    }

    #[test]
    fn invalid_relay_addresses_and_paths_are_rejected() {
        for address in [
            "",
            "localhost",
            "localhost/netcrow",
            "localhost:443",
            "localhost:/netcrow",
            "localhost:0/netcrow",
            "localhost:65536/netcrow",
            "localhost:+443/netcrow",
            "localhost:-1/netcrow",
            ":443/netcrow",
            "user@localhost:443/netcrow",
            "user:pass@localhost:443/netcrow",
            "wss://localhost:443/netcrow",
            "ws://localhost:443/netcrow",
            "2001:db8::1:443/netcrow",
            "[::1]/netcrow",
            "[::1]:443:80/netcrow",
            "[127.0.0.1]:443/netcrow",
            "[fe80::1%eth0]:443/netcrow",
            " localhost:443/netcrow",
            "localhost:443/netcrow ",
            "localhost:443/a\nb",
            "localhost:443/a\rb",
            "localhost:443/a\tb",
            "localhost:443/path?query",
            "localhost:443/path#fragment",
            "localhost:443/path\\other",
            "localhost:443/%",
            "localhost:443/%0",
            "localhost:443/%GG",
            "localhost:443/路径",
            "localhost:443/<path>",
            "localhost:443/{path}",
            "bad..host:443/netcrow",
            "%6cocalhost:443/netcrow",
        ] {
            let mut config = client("");
            config.relay_addr = address.into();
            assert!(
                config.validate().is_err(),
                "accepted invalid address {address:?}"
            );
        }
    }

    #[test]
    fn invalid_sni_overrides_and_removed_fields_are_rejected() {
        for name in [
            " ",
            "relay.example:443",
            "https://relay.example",
            "bad..host",
            "[::1]",
            "a/b",
            "a?b",
            "a#b",
            "a\nb",
            "a\0b",
        ] {
            let mut config = client("");
            config.relay_sni = Some(name.into());
            assert!(config.validate().is_err(), "accepted invalid SNI {name:?}");
        }
        for removed in [
            "relay_url='wss://localhost/netcrow'",
            "relay_path='/netcrow'",
        ] {
            assert!(toml::from_str::<ClientConfig>(&format!(
                "id='home'\ntoken=''\nrelay_addr='localhost:443/netcrow'\n{removed}"
            ))
            .is_err());
        }
        assert!(
            toml::from_str::<ClientConfig>("id='home'\ntoken=''\nrelay_sni='localhost'").is_err()
        );
    }
    #[test]
    fn tokens_preserve_arbitrary_utf8_without_length_limits() {
        for token in [
            String::new(),
            "x".into(),
            " 中文🔑\"'\\\n\r\t\0 ".into(),
            "长".repeat(100_000),
        ] {
            let literal = toml::Value::String(token.clone()).to_string();
            let client: ClientConfig = toml::from_str(&format!(
                "id='home'\ntoken={literal}\nrelay_addr='localhost:443/netcrow'"
            ))
            .unwrap();
            let relay: RelayConfig = toml::from_str(&format!(
                "listen='127.0.0.1:8443'\n[[peers]]\nid='home'\ntoken={literal}"
            ))
            .unwrap();
            assert!(client.validate().is_ok());
            assert!(relay.validate().is_ok());
            assert_eq!(client.token, token);
            assert_eq!(relay.peers[0].token, token);
        }
    }
    #[test]
    fn control_rules_require_one_valid_matcher() {
        for kind in ["disable", "enable"] {
            let config = |matcher: &str| {
                client(&format!(
                    "[[control.{kind}]]\nurl='https://example.com/control'\n{matcher}"
                ))
            };
            assert!(config("regex='^STOP$'").validate().is_ok());
            assert!(config("keyword='停用[office].*'").validate().is_ok());
            assert!(config("").validate().is_err());
            assert!(config("regex='STOP'\nkeyword='STOP'").validate().is_err());
            assert!(config("keyword=''").validate().is_err());
            assert!(config("regex='['").validate().is_err());
        }
    }
    #[test]
    fn proxy_subnets_distinguish_automatic_and_explicit_selection() {
        assert!(client("").proxy_subnets.is_none());
        assert_eq!(client("proxy_subnets=[]").proxy_subnets, Some(vec![]));
        let configured = client("proxy_subnets=['192.168.1.0/24', 'fd00::/8']");
        assert!(configured.validate().is_ok());
        assert_eq!(configured.proxy_subnets.unwrap().len(), 2);
    }
}
