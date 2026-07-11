//! Logging setup using [`simplelog`].
//!
//! Provides:
//! - Coloured terminal output via `TermLogger`
//! - Optional simultaneous file logging via `WriteLogger`
//! - The same startup banner and auto-tune summary helpers as before
//!
//! Output format (terminal):
//!
//! Level colours (simplelog built-in):
//!   ERROR → red   WARN → yellow   INFO → cyan   DEBUG → blue   TRACE → white

use simplelog::{
    ColorChoice, CombinedLogger, Config, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode, WriteLogger,
};

use crate::tuning::TuningSummary;

// ── ANSI helpers (banner only) ────────────────────────────────────────────────

const RESET:  &str = "\x1b[0m";
const DIM:    &str = "\x1b[2m";
const BOLD:   &str = "\x1b[1m";
const CYAN:   &str = "\x1b[1;96m";
const YELLOW: &str = "\x1b[1;93m";

// ── Logger ────────────────────────────────────────────────────────────────────

pub fn init_logging(level: &str) {
    let level = level.parse::<LevelFilter>().unwrap_or(LevelFilter::Info);

    let mut loggers: Vec<Box<dyn simplelog::SharedLogger>> = vec![];

    let log_config = ConfigBuilder::new()
        .set_time_to_local(true)
        .set_time_format_custom(simplelog::format_description!(
            "[hour]:[minute]:[second]"
        ))
        .build();

    loggers.push(TermLogger::new(
        level,
        log_config.clone(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ));

    if let Ok(file_path) = std::env::var("LOG_FILE") {
        loggers.push(WriteLogger::new(
            level,
            log_config,
            std::fs::File::create(file_path).expect("failed to create log file"),
        ));
    }

    CombinedLogger::init(loggers).expect("failed to init logging");
}

// ── Banner ────────────────────────────────────────────────────────────────────

pub fn print_banner(name: &str, version: &str) {
    let _ = simplelog::info!(" ");
    let _ = simplelog::info!(
        "{}  {} {} {} {} {}",
        CYAN,
        name,
        version,
        DIM,
        env!("CARGO_PKG_AUTHORS"),
        RESET,
    );
    let _ = simplelog::info!(" ");
}

pub fn log_tune_summary(summary: &TuningSummary) {
    log::info!("{}Auto-tune summary:{}", YELLOW, RESET);
    for line in summary.lines() {
        log::info!("{}  - {}{}", YELLOW, line, RESET);
    }
    log::info!(" ");
}
