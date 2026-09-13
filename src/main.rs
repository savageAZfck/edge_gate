mod audit;
mod blind;
mod config;
mod dedup;
mod filter;
mod meter;
mod proxy;
mod tarpit;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "edge_gate",
    about = "Local LLM edge gateway: dedup, blind, filter, meter, audit"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the gateway.
    Serve {
        /// Config file (TOML).
        #[arg(short, long, default_value = "edge_gate.toml")]
        config: std::path::PathBuf,
    },
    /// Verify the audit ledger chain and exit.
    Verify {
        /// Ledger path.
        #[arg(short, long, default_value = "edge_gate_ledger.jsonl")]
        ledger: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify { ledger } => {
            let (n, bad) = audit::verify(&ledger)?;
            match bad {
                None => println!("{n} entries verified, chain intact"),
                Some(line) => {
                    println!("CHAIN BROKEN at line {line} ({n} good entries before it)");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Serve { config } => {
            let cfg = config::Config::load(&config)?;
            let listen: SocketAddr = cfg.listen.parse()?;
            let default_upstream = cfg
                .upstreams
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "default".into());
            let audit = audit::Audit::open(&cfg.audit.path)?;
            audit.record(
                "boot",
                serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "listen": cfg.listen}),
            );
            let state = Arc::new(proxy::AppState {
                blinder: blind::Blinder::new(&cfg.blinding.patterns),
                deduper: cfg
                    .dedup
                    .enabled
                    .then(|| dedup::Deduper::new(cfg.dedup.min_similarity, cfg.dedup.cache_size)),
                filter: Arc::new(filter::OutputFilter::new(if cfg.filter.enabled {
                    &cfg.filter.blocklist
                } else {
                    &[]
                })),
                meter: meter::Meter::new(&cfg.costs),
                tarpit: cfg.tarpit.enabled.then(|| {
                    tarpit::Tarpit::new(
                        cfg.tarpit.requests_per_second,
                        cfg.tarpit.burst,
                        cfg.tarpit.delay_ms,
                    )
                }),
                client: reqwest::Client::new(),
                default_upstream,
                audit,
                cfg,
            });
            let app = proxy::router(state);
            println!("edge_gate listening on http://{listen}");
            axum::serve(
                tokio::net::TcpListener::bind(listen).await?,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}
