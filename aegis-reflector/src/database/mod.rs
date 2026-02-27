//! Database module for Aegis-Reflector

pub mod schema;

use rusqlite::{Connection, params, Result as SqlResult};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Database not initialized")]
    NotInitialized,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// CVE vulnerability record
#[derive(Debug, Clone)]
pub struct CveRecord {
    pub id: i64,
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f32,
    pub published_date: String,
    pub affected_products: String,
    pub is_known_exploited: bool,
}

/// Detected threat record
#[derive(Debug, Clone)]
pub struct ThreatRecord {
    pub id: i64,
    pub file_path: String,
    pub threat_level: i32,
    pub details: String,
    pub detected_at: String,
    pub action_taken: String,
    pub user_vetoed: bool,
}

/// Action log entry
#[derive(Debug, Clone)]
pub struct ActionLog {
    pub id: i64,
    pub target: String,
    pub action: String,
    pub details: String,
    pub timestamp: String,
    pub reversed: bool,
}

/// Database wrapper
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open or create a database
    pub fn new(path: &str) -> Result<Self, DatabaseError> {
        let conn = Connection::open(path)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Initialize database schema
    pub fn initialize(&self) -> Result<(), DatabaseError> {
        let conn = self.conn.lock().unwrap();

        // Create CVEs table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL DEFAULT 0.0,
                published_date TEXT,
                affected_products TEXT,
                is_known_exploited INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create detected threats table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS detected_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                threat_level INTEGER NOT NULL,
                details TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_taken TEXT DEFAULT 'None',
                user_vetoed INTEGER DEFAULT 0
            )",
            [],
        )?;

        // Create action log table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reversed INTEGER DEFAULT 0
            )",
            [],
        )?;

        // Create breach records table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT,
                breach_date TEXT,
                description TEXT,
                data_types TEXT,
                is_verified INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threats_file_path ON detected_threats(file_path)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_action_log_timestamp ON action_log(timestamp)",
            [],
        )?;

        Ok(())
    }

    /// Insert or update a CVE record
    pub fn upsert_cve(&self, record: &CveRecord) -> Result<i64, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cves (cve_id, description, severity, cvss_score, published_date, affected_products, is_known_exploited)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(cve_id) DO UPDATE SET
                description = excluded.description,
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                published_date = excluded.published_date,
                affected_products = excluded.affected_products,
                is_known_exploited = excluded.is_known_exploited",
            params![
                record.cve_id,
                record.description,
                record.severity,
                record.cvss_score,
                record.published_date,
                record.affected_products,
                record.is_known_exploited as i32,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get CVEs by severity
    pub fn get_cves_by_severity(&self, severity: &str) -> Result<Vec<CveRecord>, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, description, severity, cvss_score, published_date, affected_products, is_known_exploited
             FROM cves WHERE severity = ?1 ORDER BY cvss_score DESC LIMIT 100"
        )?;

        let records = stmt.query_map([severity], |row| {
            Ok(CveRecord {
                id: row.get(0)?,
                cve_id: row.get(1)?,
                description: row.get(2)?,
                severity: row.get(3)?,
                cvss_score: row.get(4)?,
                published_date: row.get(5)?,
                affected_products: row.get(6)?,
                is_known_exploited: row.get::<_, i32>(7)? != 0,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Get recent CVEs
    pub fn get_recent_cves(&self, limit: usize) -> Result<Vec<CveRecord>, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, description, severity, cvss_score, published_date, affected_products, is_known_exploited
             FROM cves ORDER BY published_date DESC LIMIT ?1"
        )?;

        let records = stmt.query_map([limit as i64], |row| {
            Ok(CveRecord {
                id: row.get(0)?,
                cve_id: row.get(1)?,
                description: row.get(2)?,
                severity: row.get(3)?,
                cvss_score: row.get(4)?,
                published_date: row.get(5)?,
                affected_products: row.get(6)?,
                is_known_exploited: row.get::<_, i32>(7)? != 0,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Log a detected threat
    pub fn log_threat(&self, file_path: &str, details: &str, threat_level: i32) -> Result<i64, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO detected_threats (file_path, threat_level, details, action_taken)
             VALUES (?1, ?2, ?3, 'Detected')",
            params![file_path, threat_level, details],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get recent threats
    pub fn get_recent_threats(&self, limit: usize) -> Result<Vec<ThreatRecord>, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_path, threat_level, details, detected_at, action_taken, user_vetoed
             FROM detected_threats ORDER BY detected_at DESC LIMIT ?1"
        )?;

        let records = stmt.query_map([limit as i64], |row| {
            Ok(ThreatRecord {
                id: row.get(0)?,
                file_path: row.get(1)?,
                threat_level: row.get(2)?,
                details: row.get(3)?,
                detected_at: row.get(4)?,
                action_taken: row.get(5)?,
                user_vetoed: row.get::<_, i32>(6)? != 0,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Log an action
    pub fn log_action(&self, target: &str, action: &str, details: &str) -> Result<i64, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO action_log (target, action, details) VALUES (?1, ?2, ?3)",
            params![target, action, details],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get action logs
    pub fn get_action_logs(&self, limit: usize) -> Result<Vec<ActionLog>, DatabaseError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target, action, details, timestamp, reversed
             FROM action_log ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let records = stmt.query_map([limit as i64], |row| {
            Ok(ActionLog {
                id: row.get(0)?,
                target: row.get(1)?,
                action: row.get(2)?,
                details: row.get(3)?,
                timestamp: row.get(4)?,
                reversed: row.get::<_, i32>(5)? != 0,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Reverse an action
    pub fn reverse_action(&self, action_id: i64) -> Result<(), DatabaseError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE action_log SET reversed = 1 WHERE id = ?1",
            params![action_id],
        )?;
        Ok(())
    }

    /// Veto a detected threat
    pub fn veto_threat(&self, threat_id: i64) -> Result<(), DatabaseError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE detected_threats SET user_vetoed = 1 WHERE id = ?1",
            params![threat_id],
        )?;
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> Result<DatabaseStats, DatabaseError> {
        let conn = self.conn.lock().unwrap();

        let cve_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cves", [], |row| row.get(0)
        )?;

        let threat_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM detected_threats WHERE threat_level >= 3", [], |row| row.get(0)
        )?;

        let action_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM action_log", [], |row| row.get(0)
        )?;

        let known_exploited: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE is_known_exploited = 1", [], |row| row.get(0)
        )?;

        Ok(DatabaseStats {
            cve_count,
            high_threat_count: threat_count,
            action_count,
            known_exploited_count: known_exploited,
        })
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub cve_count: i64,
    pub high_threat_count: i64,
    pub action_count: i64,
    pub known_exploited_count: i64,
}
