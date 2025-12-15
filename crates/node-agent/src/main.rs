use node_agent::config;
use node_agent::runner::{self, AgentOptions};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = config::load()?;
    let agent = runner::start_agent(cfg, AgentOptions::default()).await?;

    runner::wait_for_shutdown_signal().await;
    info!("shutdown signal received, stopping agent");
    agent.shutdown().await
}
