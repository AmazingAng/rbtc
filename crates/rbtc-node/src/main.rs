mod config;
mod node;
mod ibd;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

use config::Args;
use node::Node;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    tracing::info!("rbtc starting on {}", args.network);

    let node = Node::new(args).await?;
    node.run().await?;

    Ok(())
}
