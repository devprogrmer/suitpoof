use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use suitspoof::app::{run_client, verify_license};
use suitspoof::config::Config;
use suitspoof::logging::{init_logging, log_tune_summary, print_banner};
use suitspoof::tuning::{apply_auto_tune, effective_runtime_threads};

#[derive(Parser, Debug)]
#[command(name = "client", about = "suitspoof client (TUN interface)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    /// Override log level.
    #[arg(short, long)]
    log_level: Option<String>,

    /// Allow any source IP (bypass allowlist) for check mode.
    #[arg(long)]
    check_allow_any: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut cfg = Config::from_file(&args.config)?;
    let level = args
        .log_level
        .as_deref()
        .unwrap_or(cfg.log_level.as_str());
    init_logging(level);
    print_banner("client", env!("CARGO_PKG_VERSION"));

    let summary = apply_auto_tune(&mut cfg);
    if let Some(s) = &summary {
        log_tune_summary(s);
    }

    let cfg = Arc::new(cfg);
    let threads = effective_runtime_threads(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cfg, args.check_allow_any))
}

async fn async_main(cfg: Arc<Config>, check_allow_any: bool) -> Result<()> {
    let password = rpassword::prompt_password("License password: ")?;
    verify_license(&password).await?;

    if cfg.check_mode {
        let check_opts = suitspoof::check::CheckOptions {
            ips_path: cfg.check_ips_path.clone(),
            out_path: cfg.check_output_path.clone(),
            timeout: cfg.check_timeout,
            workers: cfg.check_workers,
        };
        suitspoof::check::run_spoof_check(cfg.clone(), check_opts).await?;
        return Ok(());
    }

    run_client(cfg, check_allow_any).await
}
