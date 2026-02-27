//! Breach Checker Module
//!
//! Integration with HaveIBeenPwned API for data breach checking

use serde::{Deserialize, Serialize};

/// HaveIBeenPwned API response structures
#[derive(Debug, Deserialize)]
pub struct BreachResponse {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub added_date: String,
    pub modified_date: String,
    pub pwn_count: u64,
    pub description: String,
    pub logo_path: String,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_sensitive: bool,
    pub is_fabricated: bool,
    pub is_spam_list: bool,
    pub is_retired: bool,
    pub is_malware: bool,
    pub is_subscription_list: bool,
}

#[derive(Debug, Deserialize)]
pub struct PasteResponse {
    pub id: String,
    pub source: String,
    pub title: String,
    pub date: String,
    pub email_count: u64,
}

/// Breach check result
#[derive(Debug, Clone, Serialize)]
pub struct BreachCheckResult {
    pub email: String,
    pub breached: bool,
    pub breach_count: usize,
    pub breaches: Vec<BreachInfo>,
}

/// Breach information summary
#[derive(Debug, Clone, Serialize)]
pub struct BreachInfo {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
}

impl From<&BreachResponse> for BreachInfo {
    fn from(breach: &BreachResponse) -> Self {
        Self {
            name: breach.name.clone(),
            title: breach.title.clone(),
            domain: breach.domain.clone(),
            breach_date: breach.breach_date.clone(),
            data_classes: breach.data_classes.clone(),
            is_verified: breach.is_verified,
        }
    }
}
