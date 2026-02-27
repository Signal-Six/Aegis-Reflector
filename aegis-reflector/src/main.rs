//! Aegis-Reflector - Main Entry Point
//!
//! This application runs as a Windows service for 24/7 protection.

use std::env;
use std::path::PathBuf;

use aegis_reflector::{Config, Database};
use aegis_reflector::engine::{AnomalyDetector, DecisionEngine, FileMonitor};
use aegis_reflector::intelligence::ThreatIntelligence;
use aegis_reflector::terminal::TerminalServer;
use aegis_reflector::logging::init_logging;

use tracing::{info, error, warn};

mod service {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_service::{
        define_windows_service,
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceStatus, ServiceType},
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    pub fn run() -> Result<(), windows_service::Error> {
        let service_name = OsString::from("AegisReflector")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: windows_service::service::ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(30),
        };

        // Run as console app if not running as a service
        if env::args().nth(1).as_deref() == Some("run") {
            super::run_main()?;
            return Ok(());
        }

        // Otherwise run as Windows service
        let service = move || {
            let event = service_control_handler::setup_handler(move |control| {
                match control {
                    ServiceControl::Stop => {
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented
                }
            }).unwrap();

            // Start the main application
            if let Err(e) = super::run_main() {
                error!("Service error: {}", e);
            }

            ServiceControlHandlerResult::NoError
        };

        service::ServiceDispatcher::new(service_name)
            .map_err(|e| windows_service::Error::StartFailed(e.to_string()))?
            .run(service)
    }
}

async fn run_service(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting Aegis-Reflector service...");

    // Initialize database
    let db = Database::new(&config.database_path)?;
    db.initialize()?;
    info!("Database initialized");

    // Initialize anomaly detector
    let detector = match AnomalyDetector::new(&config.model_path) {
        Ok(d) => {
            info!("Anomaly detector loaded");
            Some(d)
        }
        Err(e) => {
            warn!("Could not load anomaly detector: {}", e);
            None
        }
    };

    // Initialize decision engine
    let decision_engine = DecisionEngine::new(detector, db.clone());
    info!("Decision engine initialized");

    // Initialize file monitor
    let mut file_monitor = FileMonitor::new(config.watch_paths.clone());
    info!("File monitor initialized for paths: {:?}", config.watch_paths);

    // Initialize threat intelligence
    let threat_intel = ThreatIntelligence::new(db.clone());
    info!("Threat intelligence module initialized");

    // Initialize terminal server
    let terminal = TerminalServer::new(config.terminal_port, db.clone());
    let terminal_handle = tokio::spawn(async move {
        if let Err(e) = terminal.run().await {
            error!("Terminal server error: {}", e);
        }
    });

    // Start daily CVE scan scheduler
    let scan_handle = tokio::spawn(async move {
        loop {
            info!("Running daily threat intelligence scan...");
            if let Err(e) = threat_intel.run_daily_scan().await {
                error!("Threat scan error: {}", e);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
        }
    });

    // Main monitoring loop
    loop {
        match file_monitor.check_events() {
            Ok(events) => {
                for event in events {
                    info!("File event: {:?}", event);
                    // Process file through decision engine
                    if let Some(ref detector) = decision_engine.anomaly_detector() {
                        match decision_engine.evaluate_file(&event.path, detector).await {
                            Ok(decision) => {
                                if decision.threat_level >= aegis_reflector::engine::ThreatLevel::High {
                                    info!("Threat detected: {:?} - {}", decision.threat_level, decision.details);
                                    // Log to database
                                    if let Err(e) = db.log_threat(&event.path, &decision.details, decision.threat_level as i32) {
                                        error!("Failed to log threat: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Error evaluating file: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("File monitor error: {}", e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Wait for handles (they run forever)
    let _ = terminal_handle.await;
    let _ = scan_handle.await;

    Ok(())
}

fn run_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    let _guard = init_logging();

    info!("Aegis-Reflector starting...");

    // Load configuration
    let config = Config::default();

    // Set up runtime
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        run_service(config).await
    })
}

fn get_exe_path() -> PathBuf {
    env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("aegis-reflector.exe"))
}

fn main() {
    // Check command line arguments
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("install") => {
            // TODO: Implement service installation
            println!("Installing Aegis-Reflector service...");
        }
        Some("uninstall") => {
            // TODO: Implement service uninstallation
            println!("Uninstalling Aegis-Reflector service...");
        }
        Some("run") => {
            // Run as console application
            if let Err(e) = run_main() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            // Try to run as Windows service
            if let Err(e) = service::run() {
                eprintln!("Service error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
