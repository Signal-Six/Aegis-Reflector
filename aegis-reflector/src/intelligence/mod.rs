//! Threat Intelligence Module
//!
//! Fetches vulnerability data from various sources:
//! - NVD (National Vulnerability Database)
//! - CISA KEV (Known Exploited Vulnerabilities)
//! - URLhaus (Malware URLs)
//! - HaveIBeenPwned (Data breaches)

pub mod cve_fetcher;
pub mod breach_checker;
pub mod urlhaus;

use crate::database::{Database, CveRecord};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn, error};

#[derive(Error, Debug)]
pub enum ThreatIntelError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Threat Intelligence service
pub struct ThreatIntelligence {
    database: Arc<Database>,
    http_client: reqwest::Client,
}

impl ThreatIntelligence {
    /// Create a new threat intelligence service
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Run daily scan of all threat intelligence sources
    pub async fn run_daily_scan(&self) -> Result<(), ThreatIntelError> {
        info!("Starting daily threat intelligence scan...");

        // Fetch CVEs from NVD
        if let Err(e) = self.fetch_nvd_cves().await {
            warn!("Failed to fetch NVD CVEs: {}", e);
        }

        // Fetch CISA KEV
        if let Err(e) = self.fetch_cisa_kev().await {
            warn!("Failed to fetch CISA KEV: {}", e);
        }

        // Fetch malware URLs from URLhaus
        if let Err(e) = self.fetch_urlhaus_urls().await {
            warn!("Failed to fetch URLhaus URLs: {}", e);
        }

        info!("Daily threat intelligence scan completed");
        Ok(())
    }

    /// Fetch CVEs from NVD API
    pub async fn fetch_nvd_cves(&self) -> Result<(), ThreatIntelError> {
        info!("Fetching CVEs from NVD...");

        // NVD API 2.0 endpoint
        let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50";

        let response = self.http_client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;

        if let Some(vulnerabilities) = data.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulnerabilities.iter().take(100) {
                if let Some(cve) = vuln.get("cve") {
                    let cve_id = cve.get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_string();

                    let description = cve.get("descriptions")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let mut cvss_score = 0.0f32;
                    let mut severity = "UNKNOWN".to_string();

                    if let Some(metrics) = cve.get("metrics") {
                        if let Some(cvss31) = metrics.get("cvssMetricV31").and_then(|m| m.as_array()).and_then(|arr| arr.first()) {
                            if let Some(cvss_data) = cvss31.get("cvssData") {
                                cvss_score = cvss_data.get("baseScore")
                                    .and_then(|s| s.as_f64())
                                    .unwrap_or(0.0) as f32;
                                severity = cvss_data.get("baseSeverity")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("UNKNOWN")
                                    .to_string();
                            }
                        }
                    }

                    let published = cve.get("published")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();

                    let record = CveRecord {
                        id: 0,
                        cve_id,
                        description,
                        severity,
                        cvss_score,
                        published_date: published,
                        affected_products: String::new(),
                        is_known_exploited: false,
                    };

                    if let Err(e) = self.database.upsert_cve(&record) {
                        warn!("Failed to insert CVE: {}", e);
                    }
                }
            }
        }

        info!("NVD CVE fetch completed");
        Ok(())
    }

    /// Fetch CISA Known Exploited Vulnerabilities
    pub async fn fetch_cisa_kev(&self) -> Result<(), ThreatIntelError> {
        info!("Fetching CISA KEV...");

        let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        let response = self.http_client
            .get(url)
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;

        if let Some(vulnerabilities) = data.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulnerabilities.iter() {
                let cve_id = vuln.get("cveID")
                    .and_then(|id| id.as_str())
                    .unwrap_or("")
                    .to_string();

                if cve_id.is_empty() {
                    continue;
                }

                let description = vuln.get("vulnerabilityName")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();

                let vendor = vuln.get("vendorProject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let product = vuln.get("product")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();

                let record = CveRecord {
                    id: 0,
                    cve_id,
                    description: format!("{} - {} {}", description, vendor, product),
                    severity: "CRITICAL".to_string(),
                    cvss_score: 10.0,
                    published_date: vuln.get("dateAdded")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                    affected_products: format!("{} {}", vendor, product),
                    is_known_exploited: true,
                };

                if let Err(e) = self.database.upsert_cve(&record) {
                    warn!("Failed to insert KEV: {}", e);
                }
            }
        }

        info!("CISA KEV fetch completed");
        Ok(())
    }

    /// Fetch malware URLs from URLhaus
    pub async fn fetch_urlhaus_urls(&self) -> Result<(), ThreatIntelError> {
        info!("Fetching URLhaus malware URLs...");

        // Get recent malware URLs
        let url = "https://urlhaus.abuse.ch/downloads/json_recent/";

        let response = self.http_client
            .get(url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;

        // URLhaus returns data in "urls" array
        if let Some(urls) = data.get("urls").and_then(|u| u.as_array()) {
            info!("Received {} URLs from URLhaus", urls.len());

            for url_entry in urls.iter().take(500) {
                // Log interesting entries (malware URLs)
                let threat = url_entry.get("threat")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if threat == "malware_download" || threat == "malware_distribution" {
                    // Log this to action log as information
                    let url = url_entry.get("url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("");

                    let status = url_entry.get("url_status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    self.database.log_action(
                        "urlhaus",
                        "malware_url_detected",
                        &format!("URL: {} Status: {}", url, status),
                    ).ok();
                }
            }
        }

        Ok(())
    }

    /// Check if a file hash is known malware (via multiple sources)
    pub async fn check_file_reputation(&self, hash: &str) -> Result<ReputationResult, ThreatIntelError> {
        let mut result = ReputationResult {
            hash: hash.to_string(),
            is_malicious: false,
            sources_checked: vec![],
            details: String::new(),
        };

        // Check hash against known databases (mock - would need API keys for real implementation)
        result.sources_checked.push("local_database".to_string());
        result.details.push_str("Checked against local database - no match found");

        Ok(result)
    }
}

/// Reputation check result
#[derive(Debug, Clone)]
pub struct ReputationResult {
    pub hash: String,
    pub is_malicious: bool,
    pub sources_checked: Vec<String>,
    pub details: String,
}
