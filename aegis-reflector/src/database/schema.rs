//! Database schema module

/// Schema constants and initialization SQL
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Initialize database with schema version tracking
pub const INIT_SQL: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CVEs table
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    severity TEXT,
    cvss_score REAL DEFAULT 0.0,
    published_date TEXT,
    affected_products TEXT,
    is_known_exploited INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Detected threats table
CREATE TABLE IF NOT EXISTS detected_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    threat_level INTEGER NOT NULL,
    details TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action_taken TEXT DEFAULT 'None',
    user_vetoed INTEGER DEFAULT 0
);

-- Action log table
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reversed INTEGER DEFAULT 0
);

-- Breach records table
CREATE TABLE IF NOT EXISTS breaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT,
    breach_date TEXT,
    description TEXT,
    data_types TEXT,
    is_verified INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_threats_file_path ON detected_threats(file_path);
CREATE INDEX IF NOT EXISTS idx_threats_level ON detected_threats(threat_level);
CREATE INDEX IF NOT EXISTS idx_action_log_timestamp ON action_log(timestamp);
"#;
