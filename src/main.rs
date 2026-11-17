use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use netcrow::{client, config, relay, tls};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "netcrow",
    version,
    about = "Relay-only subnet sharing over WSS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Start the public WSS relay.
    Relay {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Start a subnet-sharing client and optional local proxies.
    Client {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Print the SHA-256 SPKI fingerprint of a PEM certificate.
    Fingerprint {
        #[arg(long)]
        cert: PathBuf,
    },
    /// Validate configuration without opening any network listeners.
    Check {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, value_enum)]
        mode: Mode,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Client,
    Relay,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netcrow=info".into()),
        )
        .with_target(false)
        .init();
    match Cli::parse().command {
        Command::Relay { config: path } => {
            let config = config::load_relay(&path)?;
            tokio::select! { result = relay::run(config) => result?, _ = tokio::signal::ctrl_c() => {} }
        }
        Command::Client { config: path } => {
            let config = config::load_client(&path)?;
            tokio::select! { result = client::run(config) => result?, _ = tokio::signal::ctrl_c() => {} }
        }
        Command::Fingerprint { cert } => println!("{}", tls::certificate_pin(&cert)?),
        Command::Check { config: path, mode } => {
            match mode {
                Mode::Client => {
                    let c = config::load_client(&path)?;
                    let endpoint = c.relay_endpoint()?;
                    tls::client_config_for_relay(&c.tls, endpoint.enable_sni)?;
                }
                Mode::Relay => {
                    config::load_relay(&path)?;
                }
            }
            println!("configuration valid");
        }
    }
    Ok(())
}
