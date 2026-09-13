use clap::{Parser, Subcommand};
use edge_gate::{audit, blind, config, dedup, filter, meter, proxy, tarpit};
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
        /// Optional checkpoint file — also proves the checkpointed tip
        /// is still present in the chain.
        #[arg(long)]
        checkpoint: Option<std::path::PathBuf>,
    },
    /// Write a tamper-evident checkpoint of the ledger tip.
    Checkpoint {
        #[arg(short, long, default_value = "edge_gate_ledger.jsonl")]
        ledger: std::path::PathBuf,
        #[arg(short, long, default_value = "edge_gate_checkpoint.json")]
        out: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify { ledger, checkpoint } => {
            let (n, bad) = audit::verify(&ledger)?;
            match bad {
                None => println!("{n} entries verified, chain intact"),
                Some(line) => {
                    println!("CHAIN BROKEN at line {line} ({n} good entries before it)");
                    std::process::exit(1);
                }
            }
            if let Some(cp) = checkpoint {
                match audit::checkpoint_holds(&ledger, &cp) {
                    Ok(true) => {
                        println!("checkpoint tip present — history back to checkpoint intact")
                    }
                    Ok(false) => {
                        println!("CHECKPOINT FAILED: checkpointed tip is not in the chain");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        println!("checkpoint unreadable: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Cmd::Checkpoint { ledger, out } => {
            let cp = audit::checkpoint(&ledger, &out)?;
            println!(
                "checkpoint written: {} entries, tip {}",
                cp["entries"],
                &cp["tip_hash"].as_str().unwrap_or("")[..16]
            );
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
                blinder: blind::Blinder::new(
                    &cfg.blinding.patterns,
                    cfg.blinding.builtin,
                    cfg.blinding.unblind_response,
                ),
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
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
                println!("\nedge_gate shutting down");
            })
            .await?;
        }
    }
    Ok(())
}
