//! Decision Engine for threat evaluation

use crate::engine::anomaly_detector::{AnomalyDetector, AnomalyResult, FeatureExtractor};
use crate::database::Database;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecisionError {
    #[error("File access error: {0}")]
    FileAccessError(String),
    #[error("Detection error: {0}")]
    DetectionError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, i32)]
pub enum ThreatLevel {
    /// No threat detected
    Safe = 0,
    /// Low threat - monitor only
    Low = 1,
    /// Medium threat - user notification
    Medium = 2,
    /// High threat - auto-quarantine recommended
    High = 3,
    /// Critical threat - immediate action required
    Critical = 4,
}

impl ThreatLevel {
    /// Determine threat level from anomaly score
    pub fn from_score(score: f32) -> Self {
        if score >= 0.8 {
            ThreatLevel::Critical
        } else if score >= 0.6 {
            ThreatLevel::High
        } else if score >= 0.4 {
            ThreatLevel::Medium
        } else if score >= 0.2 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Safe
        }
    }
}

/// Result of a threat decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDecision {
    /// Path to the evaluated file
    pub file_path: String,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Anomaly detection result
    pub anomaly_result: AnomalyResult,
    /// Human-readable details
    pub details: String,
    /// Recommended action
    pub recommended_action: Action,
    /// Timestamp of decision
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Actions that can be taken on a detected threat
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Action {
    /// Continue monitoring
    Monitor,
    /// Log for review
    Log,
    /// Notify user
    Notify,
    /// Quarantine the file
    Quarantine,
    /// Delete the file
    Delete,
}

impl Action {
    pub fn from_threat_level(level: ThreatLevel) -> Self {
        match level {
            ThreatLevel::Safe => Action::Monitor,
            ThreatLevel::Low => Action::Log,
            ThreatLevel::Medium => Action::Notify,
            ThreatLevel::High => Action::Quarantine,
            ThreatLevel::Critical => Action::Delete,
        }
    }
}

/// Decision Engine that coordinates threat detection
pub struct DecisionEngine {
    anomaly_detector: Option<AnomalyDetector>,
    database: Database,
}

impl DecisionEngine {
    /// Create a new decision engine
    pub fn new(detector: Option<AnomalyDetector>, database: Database) -> Self {
        Self {
            anomaly_detector: detector,
            database,
        }
    }

    /// Evaluate a file for threats
    pub async fn evaluate_file(
        &self,
        path: &Path,
        detector: &AnomalyDetector,
    ) -> Result<ThreatDecision, DecisionError> {
        // Extract features from the file
        let features = FeatureExtractor::extract_from_file(path)
            .map_err(|e| DecisionError::FileAccessError(e.to_string()))?;

        // Run anomaly detection
        let anomaly_result = detector
            .detect(&features)
            .map_err(|e| DecisionError::DetectionError(e.to_string()))?;

        // Determine threat level
        let threat_level = ThreatLevel::from_score(anomaly_result.score);

        // Generate details
        let details = format!(
            "Anomaly score: {:.2} (confidence: {:.2}%), is_anomaly: {}",
            anomaly_result.score,
            anomaly_result.confidence * 100.0,
            anomaly_result.is_anomaly
        );

        let recommended_action = Action::from_threat_level(threat_level);

        Ok(ThreatDecision {
            file_path: path.to_string_lossy().to_string(),
            threat_level,
            anomaly_result,
            details,
            recommended_action,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Evaluate raw features
    pub fn evaluate_features(&self, features: &[f32]) -> Result<ThreatDecision, DecisionError> {
        let detector = self.anomaly_detector.as_ref()
            .ok_or_else(|| DecisionError::DetectionError("No detector available".to_string()))?;

        let anomaly_result = detector
            .detect(features)
            .map_err(|e| DecisionError::DetectionError(e.to_string()))?;

        let threat_level = ThreatLevel::from_score(anomaly_result.score);
        let recommended_action = Action::from_threat_level(threat_level);

        Ok(ThreatDecision {
            file_path: "memory".to_string(),
            threat_level,
            anomaly_result,
            details: format!("Anomaly score: {:.2}", anomaly_result.score),
            recommended_action,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Get the anomaly detector reference
    pub fn anomaly_detector(&self) -> Option<&AnomalyDetector> {
        self.anomaly_detector.as_ref()
    }

    /// Log a decision to the database
    pub fn log_decision(&self, decision: &ThreatDecision) -> Result<(), DecisionError> {
        self.database
            .log_action(
                &decision.file_path,
                &format!("{:?}", decision.threat_level),
                &decision.details,
            )
            .map_err(|e| DecisionError::DatabaseError(e.to_string()))
    }
}
