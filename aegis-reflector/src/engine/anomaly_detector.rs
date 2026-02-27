//! Anomaly Detection Engine
//!
//! This module provides anomaly detection using heuristic analysis
//! for malware detection. ONNX model support can be enabled later.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnomalyError {
    #[error("Detection error: {0}")]
    DetectionError(String),
    #[error("Invalid input features: {0}")]
    InvalidInput(String),
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Anomaly score (higher = more anomalous)
    pub score: f32,
    /// Whether the sample is considered an anomaly
    pub is_anomaly: bool,
    /// Confidence of the prediction
    pub confidence: f32,
}

/// Feature extractor for file-based anomaly detection
#[derive(Debug, Clone)]
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract features from a file for anomaly detection
    ///
    /// This extracts various statistical features from the file that can be
    /// used for malware detection.
    pub fn extract_from_file(path: &Path) -> Result<Vec<f32>, std::io::Error> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len() as f32;

        // Read file contents for analysis
        let mut buffer = vec![0u8; file_size.min(1024 * 1024) as usize]; // Read up to 1MB
        let bytes_read = file.read(&mut buffer)?;
        buffer.truncate(bytes_read);

        // Extract features
        let mut features = Vec::with_capacity(20);

        // File size (normalized)
        features.push(file_size.log2().clamp(0.0, 31.0) / 31.0);

        // Entropy
        let entropy = calculate_entropy(&buffer);
        features.push(entropy);

        // Byte frequency features
        let byte_counts = calculate_byte_frequencies(&buffer);
        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count() as f32 / 256.0;
        features.push(unique_bytes);

        // High byte ratio (typically higher in executable/malware)
        let high_byte_ratio = byte_counts[128..].iter().sum::<u32>() as f32 / bytes_read.max(1) as f32;
        features.push(high_byte_ratio);

        // Null byte ratio
        let null_ratio = byte_counts[0] as f32 / bytes_read.max(1) as f32;
        features.push(null_ratio);

        // Printable ASCII ratio
        let printable = byte_counts[32..127].iter().sum::<u32>() as f32 / bytes_read.max(1) as f32;
        features.push(printable);

        // Section alignment patterns (PE files)
        let dos_header_sig = buffer.get(0..2) == b"MZ";
        features.push(if dos_header_sig { 1.0 } else { 0.0 });

        // PE\\
        let pe_header = buffer.get(0x3C..0x40).map(|b| {
            if b.len() == 4 {
                let offset = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                buffer.get(offset..offset + 4) == b"PE\0\0"
            } else {
                false
            }
        }).unwrap_or(false);
        features.push(if pe_header { 1.0 } else { 0.0 });

        // Section count (simplified)
        features.push(0.0); // Placeholder for section count

        // Import/Export counts
        features.push(0.0); // Placeholder
        features.push(0.0); // Placeholder

        // Resource section indicators
        features.push(0.0); // Placeholder

        // Code section size ratio
        features.push(0.0); // Placeholder

        // Strings analysis
        let string_count = count_strings(&buffer);
        features.push((string_count as f32 / 100.0).clamp(0.0, 1.0));

        // Suspicious API calls (simplified)
        let suspicious_patterns = count_suspicious_patterns(&buffer);
        features.push((suspicious_patterns as f32 / 10.0).clamp(0.0, 1.0));

        // Padding patterns
        features.push(0.0); // Placeholder

        // Average byte value
        let avg_byte = buffer.iter().map(|&b| b as f32).sum::<f32>() / bytes_read.max(1) as f32 / 255.0;
        features.push(avg_byte);

        // Byte standard deviation
        let variance = buffer.iter()
            .map(|&b| (b as f32 - avg_byte * 255.0).powi(2))
            .sum::<f32>() / bytes_read.max(1) as f32;
        features.push((variance.sqrt() / 128.0).clamp(0.0, 1.0));

        // Ensure we have exactly 20 features
        while features.len() < 20 {
            features.push(0.0);
        }
        features.truncate(20);

        Ok(features)
    }

    /// Create a feature vector from raw bytes
    pub fn extract_from_bytes(data: &[u8]) -> Vec<f32> {
        let file_size = data.len() as f32;
        let mut features = Vec::with_capacity(20);

        // File size (normalized)
        features.push(file_size.log2().clamp(0.0, 31.0) / 31.0);

        // Entropy
        let entropy = calculate_entropy(data);
        features.push(entropy);

        // Byte frequency features
        let byte_counts = calculate_byte_frequencies(data);
        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count() as f32 / 256.0;
        features.push(unique_bytes);

        // High byte ratio
        let high_byte_ratio = byte_counts[128..].iter().sum::<u32>() as f32 / data.len().max(1) as f32;
        features.push(high_byte_ratio);

        // Null byte ratio
        let null_ratio = byte_counts[0] as f32 / data.len().max(1) as f32;
        features.push(null_ratio);

        // Printable ASCII ratio
        let printable = byte_counts[32..127].iter().sum::<u32>() as f32 / data.len().max(1) as f32;
        features.push(printable);

        // PE indicators
        let dos_header_sig = data.get(0..2) == b"MZ";
        features.push(if dos_header_sig { 1.0 } else { 0.0 });

        let pe_header = data.get(0x3C..0x40).map(|b| {
            if b.len() == 4 {
                let offset = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                data.get(offset..offset + 4) == b"PE\0\0"
            } else {
                false
            }
        }).unwrap_or(false);
        features.push(if pe_header { 1.0 } else { 0.0 });

        // Placeholders for remaining features
        for _ in 0..12 {
            features.push(0.0);
        }

        features.truncate(20);
        features
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy / 8.0 // Normalize to 0-1 range
}

/// Calculate byte frequency distribution
fn calculate_byte_frequencies(data: &[u8]) -> [u32; 256] {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    counts
}

/// Count potential strings in data
fn count_strings(data: &[u8]) -> usize {
    let mut count = 0;
    let mut in_string = false;
    let mut string_len = 0;

    for &byte in data {
        if byte >= 32 && byte < 127 {
            string_len += 1;
            if string_len >= 4 {
                in_string = true;
            }
        } else {
            if in_string {
                count += 1;
            }
            in_string = false;
            string_len = 0;
        }
    }

    count
}

/// Count suspicious patterns that may indicate malware
fn count_suspicious_patterns(data: &[u8]) -> usize {
    let patterns = [
        b"CreateRemoteThread",
        b"VirtualAlloc",
        b"WriteProcessMemory",
        b"GetProcAddress",
        b"LoadLibrary",
        b"WinExec",
        b"ShellExecute",
        b"CreateProcess",
        b"URLDownloadToFile",
        b"powershell",
    ];

    let data_str = String::from_utf8_lossy(data);
    patterns.iter().filter(|p| data_str.contains(&String::from_utf8_lossy(p))).count()
}

/// Anomaly Detector using heuristic analysis
pub struct AnomalyDetector {
    model_path: String,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(model_path: &str) -> Result<Self, AnomalyError> {
        // Currently using heuristic-based detection
        // ONNX model loading can be added later
        Ok(Self {
            model_path: model_path.to_string(),
        })
    }

    /// Run anomaly detection on a feature vector
    pub fn detect(&self, features: &[f32]) -> Result<AnomalyResult, AnomalyError> {
        if features.len() != 20 {
            return Err(AnomalyError::InvalidInput(
                format!("Expected 20 features, got {}", features.len())
            ));
        }

        // Use heuristic-based detection
        Ok(self.heuristic_detection(features))
    }

    /// Heuristic-based anomaly detection as fallback
    fn heuristic_detection(&self, features: &[f32]) -> AnomalyResult {
        let mut anomaly_score = 0.0f32;

        // File entropy (index 1) - higher entropy often indicates encryption/packing
        let entropy = features.get(1).copied().unwrap_or(0.0);
        if entropy > 0.8 {
            anomaly_score += 0.3;
        } else if entropy > 0.7 {
            anomaly_score += 0.15;
        }

        // High byte ratio (index 3)
        let high_byte = features.get(3).copied().unwrap_or(0.0);
        if high_byte > 0.7 {
            anomaly_score += 0.25;
        }

        // PE executable indicators (indices 6, 7)
        let is_pe = features.get(6).copied().unwrap_or(0.0) > 0.5
            && features.get(7).copied().unwrap_or(0.0) > 0.5;
        if is_pe {
            anomaly_score += 0.2;
        }

        // Suspicious patterns (index 16)
        let suspicious = features.get(16).copied().unwrap_or(0.0);
        if suspicious > 0.3 {
            anomaly_score += 0.3;
        }

        // Null byte ratio (index 4) - low may indicate encrypted/packed
        let null_ratio = features.get(4).copied().unwrap_or(0.0);
        if null_ratio < 0.01 && entropy > 0.6 {
            anomaly_score += 0.15;
        }

        // Cap score
        anomaly_score = anomaly_score.min(1.0);

        AnomalyResult {
            score: anomaly_score,
            is_anomaly: anomaly_score > 0.5,
            confidence: if anomaly_score > 0.7 { 0.9 } else { anomaly_score },
        }
    }

    /// Check if the detector is ready
    pub fn is_loaded(&self) -> bool {
        true
    }

    /// Get model path
    pub fn model_path(&self) -> &str {
        &self.model_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extraction() {
        let data = b"Hello World! This is a test file with some content.";
        let features = FeatureExtractor::extract_from_bytes(data);
        assert_eq!(features.len(), 20);
    }

    #[test]
    fn test_entropy() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1);
    }
}
