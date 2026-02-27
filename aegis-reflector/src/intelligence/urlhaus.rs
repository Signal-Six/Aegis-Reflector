//! URLhaus Module
//!
//! Integration with URLhaus API for malware URL tracking

use serde::{Deserialize, Serialize};

/// URLhaus API response
#[derive(Debug, Deserialize)]
pub struct UrlhausResponse {
    pub query_status: String,
    pub urlhaus_reference: Option<String>,
    pub urls: Option<Vec<UrlhausEntry>>,
    pub count: Option<usize>,
}

/// URLhaus URL entry
#[derive(Debug, Deserialize)]
pub struct UrlhausEntry {
    pub id: String,
    pub dateadded: String,
    pub url: String,
    pub url_status: String,
    pub threat: String,
    pub tags: Vec<String>,
    pub urlhaus_link: String,
    pub reporter: String,
    #[serde(rename = "class")]
    pub classification: Option<String>,
    pub subtype: Option<String>,
    pub payload: Option<UrlhausPayload>,
}

/// URLhaus payload information
#[derive(Debug, Deserialize)]
pub struct UrlhausPayload {
    pub url: Option<String>,
    pub status: Option<String>,
}

/// URL status enumeration
#[derive(Debug, Clone, Serialize)]
pub enum UrlStatus {
    Online,
    Offline,
    Unknown,
}

impl From<&str> for UrlStatus {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "online" => UrlStatus::Online,
            "offline" => UrlStatus::Offline,
            _ => UrlStatus::Unknown,
        }
    }
}

/// Malware URL record for database storage
#[derive(Debug, Clone, Serialize)]
pub struct MalwareUrlRecord {
    pub url: String,
    pub status: String,
    pub threat_type: String,
    pub tags: Vec<String>,
    pub first_seen: String,
}
