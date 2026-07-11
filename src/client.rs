//! suitspoof client.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use crate::{app, logging};
use crate::config::Config;

#[derive(Parser, Debug)]
#[clap(name = "client", about = "suitspoof client")]
struct Cli {
    /// Path to TOML config file
    config: String,

    /// Password to verify license against
    #[clap(short, long)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let cfg = Config::from_file(&cli.config).await?;

    logging::init_logging(&cfg.log_level);
    logging::print_banner("client", env!("CARGO_PKG_VERSION"));

    if let Some(password) = &cli.password {
        app::verify_license(password).await?;
    }

    let cfg = Arc::new(cfg);
    app::run_client(cfg).await?;

    log::debug!("suitspoof client shutting down");

    Ok(())
}
