//! CVE Fetcher Module
//!
//! Fetches CVE data from NVD and CISA

use serde::{Deserialize, Serialize};

/// NVD API response structures
#[derive(Debug, Deserialize)]
pub struct NvdResponse {
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i32,
    pub startIndex: i32,
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
pub struct NvdCve {
    pub id: String,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    pub configurations: Option<Vec<NvdConfiguration>>,
    pub references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<NvdCvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssMetric {
    pub cvssData: NvdCvssData,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
    #[serde(rename = "attackVector")]
    pub attack_vector: Option<String>,
    #[serde(rename = "attackComplexity")]
    pub attack_complexity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssMetricV2 {
    pub cvssData: NvdCvssDataV2,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssDataV2 {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "severity")]
    pub severity: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
pub struct NvdNode {
    pub cpeMatch: Option<Vec<NvdCpeMatch>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeMatch {
    pub criteria: String,
    pub vulnerable: bool,
}

#[derive(Debug, Deserialize)]
pub struct NvdReference {
    pub url: String,
    pub source: Option<String>,
}

/// CISA KEV response structures
#[derive(Debug, Deserialize)]
pub struct CisaKevResponse {
    pub title: String,
    pub catalogVersion: String,
    pub dateReleased: String,
    pub vulnerabilities: Vec<CisaKevEntry>,
}

#[derive(Debug, Deserialize)]
pub struct CisaKevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "requiredAction")]
    pub required_action: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    pub product: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub known_ransomware_campaign_use: String,
}

/// Convert NVD severity to internal severity
pub fn map_severity(severity: &str) -> &'static str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" => "LOW",
        _ => "UNKNOWN",
    }
}
