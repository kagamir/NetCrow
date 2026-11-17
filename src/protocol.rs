use anyhow::{bail, Result};
use bincode::Options;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};

// Version 2 authenticates with SHA-256 digests of the configured raw tokens.
pub const VERSION: u16 = 2;
pub const CHUNK_SIZE: usize = 16 * 1024;
pub const MAX_MESSAGE: usize = 256 * 1024;
pub const QUEUE_SIZE: usize = 64;
/// Per-stream data-frame window; two spare queues keep control frames flowing.
pub const INITIAL_CREDITS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub peer: String,
    pub subnet: IpNet,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    Hello {
        version: u16,
        id: String,
        /// Lowercase SHA-256 hex digest, never the raw configuration token.
        token: String,
        subnets: Vec<IpNet>,
    },
    Welcome {
        routes: Vec<Route>,
    },
    Routes {
        routes: Vec<Route>,
    },
    Open {
        id: u64,
        destination: SocketAddr,
    },
    Incoming {
        id: u64,
        destination: SocketAddr,
    },
    Opened {
        id: u64,
        error: Option<String>,
    },
    Data {
        id: u64,
        bytes: Vec<u8>,
    },
    Credit {
        id: u64,
        frames: u32,
    },
    HalfClose {
        id: u64,
    },
    Close {
        id: u64,
    },
    Error {
        message: String,
    },
}

pub fn encode(frame: &Frame) -> Result<Message> {
    let bytes = bincode::DefaultOptions::new()
        .with_limit(MAX_MESSAGE as u64)
        .serialize(frame)?;
    if bytes.len() > MAX_MESSAGE {
        bail!("frame too large");
    }
    Ok(Message::Binary(bytes.into()))
}

pub fn decode(bytes: &[u8]) -> Result<Frame> {
    if bytes.len() > MAX_MESSAGE {
        bail!("frame too large");
    }
    let frame: Frame = bincode::DefaultOptions::new()
        .with_limit(MAX_MESSAGE as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)?;
    if let Frame::Data { bytes, .. } = &frame {
        if bytes.len() > CHUNK_SIZE {
            bail!("data chunk too large");
        }
    }
    Ok(frame)
}

pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversized_data_and_trailing_bytes() {
        let Message::Binary(bytes) = encode(&Frame::Data {
            id: 1,
            bytes: vec![0; CHUNK_SIZE + 1],
        })
        .unwrap() else {
            panic!()
        };
        assert!(decode(&bytes).is_err());
        let Message::Binary(bytes) = encode(&Frame::Close { id: 1 }).unwrap() else {
            panic!()
        };
        let mut bytes = bytes.to_vec();
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }
}
