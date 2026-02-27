//! Logging module for Aegis-Reflector

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize logging with tracing
///
/// Returns a guard that must be kept alive for the duration of the program
pub fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use std::path::PathBuf;

    // Get log directory
    let log_dir = get_log_directory();
    std::fs::create_dir_all(&log_dir).ok();

    // Create file appender
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        &log_dir,
        "aegis-reflector.log",
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Initialize subscriber
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_thread_ids(true)
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(true)
        )
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    guard
}

fn get_log_directory() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("ProgramData")
            .map(|p| PathBuf::from(p).join("Aegis-Reflector").join("logs"))
            .unwrap_or_else(|_| PathBuf::from("C:/ProgramData/Aegis-Reflector/logs"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/log/aegis-reflector")
    }
}
