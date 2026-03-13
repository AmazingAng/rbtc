mod checkpoints;
mod config;
mod headers_sync;
mod ibd;
mod node;
mod rpc;
mod rpc_auth;
mod utxo_cache;
mod validation_interface;

use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

use config::Args;
use node::Node;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse_with_config();
    if args.script_threads > 0 {
        std::env::set_var("RBTC_SCRIPT_THREADS", args.script_threads.to_string());
    }
    std::env::set_var("RBTC_SCRIPT_CACHE_SIZE", args.script_cache_size.to_string());
    tracing::info!("rbtc starting on {}", args.network);

    let node = Node::new(args).await?;
    node.run().await?;

    Ok(())
}
