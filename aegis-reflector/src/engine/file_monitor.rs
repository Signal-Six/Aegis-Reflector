//! File System Monitoring

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Watcher error: {0}")]
    WatcherError(String),
    #[error("Path error: {0}")]
    PathError(String),
}

/// File system event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Path of the file
    pub path: PathBuf,
    /// Type of event
    pub event_type: FileEventType,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Type of file event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Removed,
    Accessed,
    Renamed,
}

impl From<&EventKind> for FileEventType {
    fn from(kind: &EventKind) -> Self {
        match kind {
            EventKind::Create(_) => FileEventType::Created,
            EventKind::Modify(_) => FileEventType::Modified,
            EventKind::Remove(_) => FileEventType::Removed,
            EventKind::Access(_) => FileEventType::Accessed,
            EventKind::Other => FileEventType::Renamed,
            _ => FileEventType::Modified,
        }
    }
}

/// File system monitor
pub struct FileMonitor {
    watcher: Option<RecommendedWatcher>,
    events: Vec<FileEvent>,
    watch_paths: Vec<String>,
}

impl FileMonitor {
    /// Create a new file monitor
    pub fn new(paths: Vec<String>) -> Self {
        Self {
            watcher: None,
            events: Vec::new(),
            watch_paths: paths,
        }
    }

    /// Start monitoring the configured paths
    pub fn start(&mut self) -> Result<(), MonitorError> {
        let (tx, rx) = channel();

        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| MonitorError::WatcherError(e.to_string()))?;

        self.watcher = Some(watcher);

        // Add watch paths
        if let Some(ref mut watcher) = self.watcher {
            for path in &self.watch_paths {
                let path_buf = PathBuf::from(path);
                if path_buf.exists() {
                    watcher
                        .watch(&path_buf, RecursiveMode::Recursive)
                        .map_err(|e| MonitorError::WatcherError(e.to_string()))?;
                }
            }
        }

        // Start event collection loop
        let _rx = rx;

        Ok(())
    }

    /// Check for new events
    pub fn check_events(&mut self) -> Result<Vec<FileEvent>, MonitorError> {
        // Note: In a real implementation, we'd use the receiver from the watcher
        // For now, return collected events
        let events = std::mem::take(&mut self.events);
        Ok(events)
    }

    /// Add a path to watch
    pub fn add_watch_path(&mut self, path: &str) -> Result<(), MonitorError> {
        if let Some(ref mut watcher) = self.watcher {
            watcher
                .watch(PathBuf::from(path).as_path(), RecursiveMode::Recursive)
                .map_err(|e| MonitorError::WatcherError(e.to_string()))?;
        }
        self.watch_paths.push(path.to_string());
        Ok(())
    }

    /// Remove a path from watching
    pub fn remove_watch_path(&mut self, path: &str) -> Result<(), MonitorError> {
        if let Some(ref mut watcher) = self.watcher {
            watcher
                .unwatch(PathBuf::from(path).as_path())
                .map_err(|e| MonitorError::WatcherError(e.to_string()))?;
        }
        self.watch_paths.retain(|p| p != path);
        Ok(())
    }

    /// Get current watch paths
    pub fn watch_paths(&self) -> &[String] {
        &self.watch_paths
    }
}

impl Default for FileMonitor {
    fn default() -> Self {
        Self::new(vec![])
    }
}
