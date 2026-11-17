//! Remote configuration conditions control only tunnel availability, never execute commands.
use crate::config::{ControlConfig, PageRule};
use anyhow::{bail, ensure, Context, Result};
use futures_util::StreamExt;
use regex::Regex;
use std::time::Duration;
use tokio::sync::watch;

struct Rule {
    url: String,
    matcher: Matcher,
}

enum Matcher {
    Regex(Regex),
    Keyword(String),
}

impl Matcher {
    fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Regex(pattern) => pattern.is_match(text),
            Self::Keyword(keyword) => text.contains(keyword),
        }
    }
}

impl Rule {
    fn compile(rule: PageRule) -> Result<Self> {
        let matcher = match (rule.regex, rule.keyword) {
            (Some(pattern), None) => {
                Matcher::Regex(Regex::new(&pattern).context("invalid control regex")?)
            }
            (None, Some(keyword)) => {
                ensure!(!keyword.is_empty(), "control keyword must not be empty");
                Matcher::Keyword(keyword)
            }
            _ => bail!("control rule must set exactly one of regex or keyword"),
        };
        Ok(Self {
            url: rule.url,
            matcher,
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
        let cycle = evaluate(&client, &disable, &enable, config.max_body_bytes);
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

async fn evaluate(
    client: &reqwest::Client,
    disable: &[Rule],
    enable: &[Rule],
    limit: usize,
) -> Option<bool> {
    // Check disable conditions first. If any disable fetch fails, do not revive:
    // a missing higher-priority condition is not evidence of permission to connect.
    let mut disable_failed = false;
    for rule in disable {
        match matches(client, rule, limit).await {
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
    for rule in enable {
        match matches(client, rule, limit).await {
            Ok(true) => return Some(false),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "enable condition fetch failed; preserving state")
            }
        }
    }
    None
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
    Ok(rule.matcher.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn keyword_rule(url: String, keyword: &str) -> Rule {
        Rule::compile(PageRule {
            url,
            regex: None,
            keyword: Some(keyword.into()),
        })
        .unwrap()
    }

    #[test]
    fn keyword_is_a_complete_literal_substring() {
        let rule = keyword_rule("http://localhost/".into(), "复活[1].*");
        assert!(rule.matcher.is_match("页面内容：复活[1].*，已更新"));
        assert!(!rule.matcher.is_match("页面内容：复活1任意文字"));
        assert!(!rule
            .matcher
            .is_match("页面内容：复活[1].，缺少最后一个字符"));
        assert!(!rule.matcher.is_match("页面内容：复<b>活</b>[1].*"));

        let rule = keyword_rule("http://localhost/".into(), "ENABLE");
        assert!(rule.matcher.is_match("status=ENABLED"));
        assert!(!rule.matcher.is_match("status=enabled"));
        let rule = keyword_rule("http://localhost/".into(), " enable ");
        assert!(rule.matcher.is_match("<p> enable </p>"));
        assert!(!rule.matcher.is_match("<p>enable</p>"));
        let rule = keyword_rule("http://localhost/".into(), "A&B");
        assert!(!rule.matcher.is_match("A&amp;B"));
    }

    #[test]
    fn compile_rejects_missing_ambiguous_and_empty_keywords() {
        for (regex, keyword) in [
            (None, None),
            (Some("enabled"), Some("enabled")),
            (None, Some("")),
            (Some("[invalid"), None),
        ] {
            assert!(Rule::compile(PageRule {
                url: "http://localhost/".into(),
                regex: regex.map(str::to_owned),
                keyword: keyword.map(str::to_owned),
            })
            .is_err());
        }
    }

    #[test]
    fn regex_rules_retain_pattern_semantics() {
        let rule = Rule::compile(PageRule {
            url: "http://localhost/".into(),
            regex: Some(r"(?i)^status=(enabled|ready)\s*$".into()),
            keyword: None,
        })
        .unwrap();
        assert!(rule.matcher.is_match("STATUS=READY\n"));
        assert!(!rule.matcher.is_match("prefixSTATUS=READY"));
        assert!(Rule::compile(PageRule {
            url: "http://localhost/".into(),
            regex: Some(String::new()),
            keyword: None,
        })
        .unwrap()
        .matcher
        .is_match(""));
    }

    struct TestServer {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl TestServer {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let observed = requests.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    loop {
                        let byte = socket.read_u8().await.unwrap();
                        request.push(byte);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                        assert!(request.len() < 4096);
                    }
                    let path = std::str::from_utf8(&request)
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    observed.lock().unwrap().push(path.to_owned());
                    let (status, body): (&str, &[u8]) = match path {
                        "/both" => ("200 OK", b"DISABLE ENABLE"),
                        "/enable" => ("200 OK", b"ENABLE"),
                        "/none" => ("200 OK", b"unrelated page text"),
                        "/invalid-utf8" => ("200 OK", b"ENABLE\xff"),
                        _ => ("500 Internal Server Error", b"ENABLE"),
                    };
                    socket
                        .write_all(
                            format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes(),
                        )
                        .await
                        .unwrap();
                    socket.write_all(body).await.unwrap();
                }
            });
            Self {
                url,
                requests,
                task,
            }
        }

        fn rule(&self, path: &str, keyword: &str) -> Rule {
            keyword_rule(format!("{}{path}", self.url), keyword)
        }

        fn take_requests(&self) -> Vec<String> {
            std::mem::take(&mut *self.requests.lock().unwrap())
        }
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn keyword_can_span_http_chunks_and_utf8_boundaries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = [0; 4096];
            assert!(socket.read(&mut received).await.unwrap() > 0);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let body = "before复活[1].*after".as_bytes();
            // Byte 7 is inside the three-byte UTF-8 character 复. The keyword
            // and the code point both cross HTTP chunk boundaries.
            for chunk in [&body[..7], &body[7..13], &body[13..]] {
                socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                socket.write_all(chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });
        assert!(
            matches(&http_client(), &keyword_rule(url, "复活[1].*"), 1024)
                .await
                .unwrap()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn disable_keyword_takes_priority_and_fetch_errors_preserve_state() {
        let server = TestServer::start().await;
        let client = http_client();
        let disable = [server.rule("/both", "DISABLE")];
        let enable = [server.rule("/enable", "ENABLE")];
        assert_eq!(evaluate(&client, &disable, &enable, 1024).await, Some(true));
        assert_eq!(server.take_requests(), ["/both"]);

        let disable = [server.rule("/error", "DISABLE")];
        assert_eq!(evaluate(&client, &disable, &enable, 1024).await, None);
        assert_eq!(server.take_requests(), ["/error"]);

        let disable = [
            server.rule("/error", "DISABLE"),
            server.rule("/both", "DISABLE"),
        ];
        assert_eq!(evaluate(&client, &disable, &enable, 1024).await, Some(true));
        assert_eq!(server.take_requests(), ["/error", "/both"]);

        let disable = [server.rule("/none", "DISABLE")];
        assert_eq!(
            evaluate(&client, &disable, &enable, 1024).await,
            Some(false)
        );
        assert_eq!(server.take_requests(), ["/none", "/enable"]);

        let enable = [server.rule("/error", "ENABLE")];
        assert_eq!(evaluate(&client, &disable, &enable, 1024).await, None);
        assert_eq!(server.take_requests(), ["/none", "/error"]);

        let enable = [server.rule("/none", "ENABLE")];
        assert_eq!(evaluate(&client, &disable, &enable, 1024).await, None);
        assert_eq!(server.take_requests(), ["/none", "/none"]);
    }

    #[tokio::test]
    async fn keyword_match_still_requires_valid_bounded_utf8_body() {
        let server = TestServer::start().await;
        let client = http_client();
        assert!(
            matches(&client, &server.rule("/invalid-utf8", "ENABLE"), 1024)
                .await
                .is_err()
        );
        assert!(matches(&client, &server.rule("/enable", "ENABLE"), 5)
            .await
            .is_err());
    }

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
            matcher: Matcher::Regex(Regex::new("enabled").unwrap()),
        };
        let error = matches(&client, &rule, 1024).await.unwrap_err();
        assert!(!format!("{error:#}").contains("private-control-secret"));
        server.await.unwrap();
    }
}
