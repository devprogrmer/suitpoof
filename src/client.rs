use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = candy_tunnel::config::Config::from_file("client.toml")?;
    candy_tunnel::app::run_client(cfg.into()).await
}
