//! Terminal UI Module
//!
//! Provides a browser-based terminal interface via WebSocket

pub mod websocket;

use crate::database::{Database, DatabaseStats};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Terminal server for WebSocket connections
pub struct TerminalServer {
    port: u16,
    database: Arc<Database>,
    event_tx: broadcast::Sender<TerminalEvent>,
}

impl TerminalServer {
    /// Create a new terminal server
    pub fn new(port: u16, database: Arc<Database>) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            port,
            database,
            event_tx,
        }
    }

    /// Run the terminal server
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting terminal server on port {}", self.port);

        // Start HTTP server with WebSocket support
        let db = self.database.clone();

        actix_web::HttpServer::new(move || {
            use actix_web::{web, App, HttpResponse};

            App::new()
                .app_data(web::Data::new(db.clone()))
                .route("/", web::get().to(websocket::index))
                .route("/ws", web::get().to(websocket::ws_handler))
                .route("/api/stats", web::get().to(api::get_stats))
                .route("/api/threats", web::get().to(api::get_threats))
                .route("/api/actions", web::get().to(api::get_actions))
                .route("/api/veto", web::post().to(api::veto_threat))
                .route("/api/reverse", web::post().to(api::reverse_action))
                .route("/api/scan", web::post().to(api::trigger_scan))
        })
        .bind(("0.0.0.0", self.port))?
        .run()
        .await?;

        Ok(())
    }

    /// Get the event broadcast channel
    pub fn events(&self) -> broadcast::Sender<TerminalEvent> {
        self.event_tx.clone()
    }
}

/// Terminal events for broadcasting
#[derive(Debug, Clone)]
pub enum TerminalEvent {
    ThreatDetected(String),
    ActionTaken(String),
    ScanStarted,
    ScanCompleted,
    StatusUpdate(String),
}

/// API handlers module
mod api {
    use actix_web::{web, HttpResponse, Result};
    use crate::database::Database;

    /// Get database statistics
    pub async fn get_stats(db: web::Data<Database>) -> Result<HttpResponse> {
        match db.get_stats() {
            Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
            Err(e) => Ok(HttpResponse::InternalServerError().json(e.to_string())),
        }
    }

    /// Get recent threats
    pub async fn get_threats(db: web::Data<Database>) -> Result<HttpResponse> {
        match db.get_recent_threats(50) {
            Ok(threats) => Ok(HttpResponse::Ok().json(threats)),
            Err(e) => Ok(HttpResponse::InternalServerError().json(e.to_string())),
        }
    }

    /// Get action logs
    pub async fn get_actions(db: web::Data<Database>) -> Result<HttpResponse> {
        match db.get_action_logs(50) {
            Ok(actions) => Ok(HttpResponse::Ok().json(actions)),
            Err(e) => Ok(HttpResponse::InternalServerError().json(e.to_string())),
        }
    }

    /// Veto a detected threat
    pub async fn veto_threat(
        db: web::Data<Database>,
        req: web::Json<VetoRequest>,
    ) -> Result<HttpResponse> {
        match db.veto_threat(req.threat_id) {
            Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))),
            Err(e) => Ok(HttpResponse::InternalServerError().json(e.to_string())),
        }
    }

    /// Reverse an action
    pub async fn reverse_action(
        db: web::Data<Database>,
        req: web::Json<ReverseRequest>,
    ) -> Result<HttpResponse> {
        match db.reverse_action(req.action_id) {
            Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))),
            Err(e) => Ok(HttpResponse::InternalServerError().json(e.to_string())),
        }
    }

    /// Trigger a manual scan
    pub async fn trigger_scan() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok().json(serde_json::json!({"status": "scan_started"})))
    }
}

#[derive(actix_web::Deserialize, serde::Serialize)]
pub struct VetoRequest {
    pub threat_id: i64,
}

#[derive(actix_web::Deserialize, serde::Serialize)]
pub struct ReverseRequest {
    pub action_id: i64,
}
