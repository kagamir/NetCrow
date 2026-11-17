//! Remote configuration conditions control only tunnel availability, never execute commands.
use crate::config::{ControlConfig, PageRule};
use anyhow::{ensure, Context, Result};
use futures_util::StreamExt;
use regex::Regex;
use std::time::Duration;
use tokio::sync::watch;

struct Rule {
    url: String,
    pattern: Regex,
}
impl Rule {
    fn compile(rule: PageRule) -> Result<Self> {
        Ok(Self {
            url: rule.url,
            pattern: Regex::new(&rule.regex)?,
        })
    }
}

/// The receiver is immediately initialized, before any tunnel can connect.
/// Fetch errors leave state unchanged; disable matches always take priority.
pub fn spawn(config: Option<ControlConfig>) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(config.as_ref().is_some_and(|c| c.initially_disabled));
    tokio::spawn(async move {
        if let Some(config) = config {
            if let Err(error) = poll(config, tx).await {
                tracing::error!(%error, "control poller stopped");
            }
        } else {
            // Keep watch sender alive: a closed watch channel must not cause a busy loop.
            tx.closed().await;
        }
    });
    rx
}

async fn poll(config: ControlConfig, tx: watch::Sender<bool>) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(3))
        .no_proxy()
        .build()?;
    let disable = config
        .disable
        .into_iter()
        .map(Rule::compile)
        .collect::<Result<Vec<_>>>()?;
    let enable = config
        .enable
        .into_iter()
        .map(Rule::compile)
        .collect::<Result<Vec<_>>>()?;
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _ = tx.closed() => return Ok(()), _ = interval.tick() => {} }
        // Check disable conditions first. If any disable fetch fails, do not revive:
        // a missing higher-priority condition is not evidence of permission to connect.
        let cycle = async {
            let mut disable_failed = false;
            for rule in &disable {
                match matches(&client, rule, config.max_body_bytes).await {
                    Ok(true) => return Some(true),
                    Ok(false) => {}
                    Err(error) => {
                        disable_failed = true;
                        tracing::warn!(%error, "disable condition fetch failed; preserving state");
                    }
                }
            }
            if disable_failed {
                return None;
            }
            for rule in &enable {
                match matches(&client, rule, config.max_body_bytes).await {
                    Ok(true) => return Some(false),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "enable condition fetch failed; preserving state")
                    }
                }
            }
            None
        };
        let next = tokio::select! { _ = tx.closed() => return Ok(()), next = cycle => next };
        if let Some(disabled) = next {
            tx.send_if_modified(|current| {
                if *current == disabled {
                    return false;
                }
                *current = disabled;
                tracing::info!(disabled, "remote control state changed");
                true
            });
        }
    }
}

async fn matches(client: &reqwest::Client, rule: &Rule, limit: usize) -> Result<bool> {
    let response = client
        .get(&rule.url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("fetch control page")?
        .error_for_status()
        .map_err(reqwest::Error::without_url)?;
    if let Some(len) = response.content_length() {
        ensure!(len <= limit as u64, "control response exceeds byte limit");
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(reqwest::Error::without_url)?;
        ensure!(
            chunk.len() <= limit.saturating_sub(body.len()),
            "control response exceeds byte limit"
        );
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body).context("control response is not UTF-8")?;
    Ok(rule.pattern.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disabled_state_is_set_before_first_poll() {
        let config = ControlConfig {
            initially_disabled: true,
            interval_secs: 60,
            timeout_secs: 1,
            max_body_bytes: 1024,
            disable: vec![],
            enable: vec![],
        };
        let rx = spawn(Some(config));
        assert!(*rx.borrow());
    }
    #[tokio::test]
    async fn absent_control_stays_enabled_and_watch_open() {
        let mut rx = spawn(None);
        assert!(!*rx.borrow());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), rx.changed())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn http_errors_do_not_log_control_url_secrets() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/status?token=private-control-secret",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let received = socket.read(&mut bytes).await.unwrap();
            assert!(received > 0);
            socket.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let rule = Rule {
            url,
            pattern: Regex::new("enabled").unwrap(),
        };
        let error = matches(&client, &rule, 1024).await.unwrap_err();
        assert!(!format!("{error:#}").contains("private-control-secret"));
        server.await.unwrap();
    }
}
