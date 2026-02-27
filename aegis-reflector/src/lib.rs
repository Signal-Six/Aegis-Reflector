//! Aegis-Reflector - AI-Driven Antivirus Suite
//!
//! This module provides the core functionality for an AI-driven antivirus
//! that scans for CVE vulnerabilities, detects anomalies using ML, and
//! provides a browser-based terminal interface.

pub mod engine;
pub mod intelligence;
pub mod database;
pub mod terminal;
pub mod logging;

/// Re-export commonly used types
pub use engine::anomaly_detector::AnomalyDetector;
pub use engine::decision_engine::{DecisionEngine, ThreatLevel};
pub use database::Database;
pub use terminal::TerminalServer;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub database_path: String,
    pub model_path: String,
    pub terminal_port: u16,
    pub watch_paths: Vec<String>,
    pub scan_interval_hours: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_path: "aegis_reflector.db".to_string(),
            model_path: "model/isolation_forest_8bit.onnx".to_string(),
            terminal_port: 8080,
            watch_paths: vec![
                std::env::temp_dir().to_string_lossy().to_string(),
                std::env::var("USERPROFILE")
                    .map(|p| format!("{}/Downloads", p))
                    .unwrap_or_else(|_| "C:/Users".to_string()),
            ],
            scan_interval_hours: 24,
        }
    }
}
