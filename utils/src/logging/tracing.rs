use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use std::fs::{create_dir_all, OpenOptions};

use crate::config::LoggingConfig;

pub fn start_tracing(config: &LoggingConfig) -> anyhow::Result<()> {
    create_dir_all(&config.path)?;
    let level: LevelFilter = config.level.parse().unwrap_or(Level::DEBUG.into());
    let error_logs = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{}/error.log", &config.path))?;
    let logs = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{}/logs.log", &config.path))?;
    tracing_subscriber::registry()
        // .with(filtered_layer)
        .with(
            // log-error file, to log the errors that arise
            fmt::layer()
                .with_ansi(false)
                .with_writer(error_logs)
                .with_filter(LevelFilter::ERROR),
        )
        .with(
            // log-debug file, to log the debug
            fmt::layer()
                .with_ansi(false)
                .with_writer(logs)
                .with_filter(level),
        )
        .with(fmt::Layer::default().with_filter(level))
        .init();
    Ok(())
}
