use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

fn heartbeat() -> u64 {
    20
}
fn heartbeat_timeout() -> u64 {
    60
}
fn sleep() -> u64 {
    60
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
    #[serde(default)]
    pub allowed_subnets: Vec<IpNet>,
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
    pub relay_url: String,
    #[serde(default)]
    pub shared_subnets: Vec<IpNet>,
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
    pub regex: String,
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
fn identity(id: &str, token: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid peer id"
    );
    ensure!(
        token.len() >= 32 && token.len() <= 256,
        "tokens must be 32..256 bytes"
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
            identity(&peer.id, &peer.token)?;
            ensure!(ids.insert(&peer.id), "duplicate peer id");
            ensure!(peer.allowed_subnets.len() <= 64, "too many allowed subnets");
        }
        Ok(())
    }
}
impl ClientConfig {
    pub fn validate(&self) -> Result<()> {
        identity(&self.id, &self.token)?;
        let url = url::Url::parse(&self.relay_url)?;
        ensure!(
            url.scheme() == "wss"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "relay_url must be a wss URL without credentials or fragment"
        );
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
                regex::Regex::new(&rule.regex).context("invalid control regex")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client(text: &str) -> ClientConfig {
        toml::from_str(&format!("id='home'\ntoken='0123456789abcdef0123456789abcdef'\nrelay_url='wss://localhost/netcrow'\n{text}")).unwrap()
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
    fn plaintext_relay_is_rejected() {
        let mut c = client("");
        c.relay_url = "ws://localhost/netcrow".into();
        assert!(c.validate().is_err());
    }
}
