# Aegis-Reflector

AI-Driven Antivirus Suite built in Rust

## Overview

Aegis-Reflector is an AI-driven antivirus program that:
- Scans daily for CVE vulnerabilities, data breaches, and virus threats
- Cross-references all known vulnerabilities in a user-side SQLite database
- Uses an Isolation Forest model (quantized to 8-bit) for anomaly detection
- Runs 24/7 as a lightweight Windows service
- Provides a browser-based terminal for monitoring and user control

## Requirements

- **Rust** 1.77+ (https://rustup.rs/)
- **Windows** 10/11 (for Windows service support)

## Installation

1. Install Rust:
```powershell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone the repository:
```bash
git clone https://github.com/your-repo/Aegis-Reflector.git
cd Aegis-Reflector/aegis-reflector
```

3. Build:
```bash
cargo build --release
```

## Usage

### Run as Console Application
```bash
cargo run --release
```

### Install as Windows Service
```bash
cargo run --release -- install
```

### Access Terminal UI
Open browser at: http://localhost:8080

## Terminal Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `stats` | Show database statistics |
| `threats` | Show recent detected threats |
| `actions` | Show action log |
| `cves` | Show recent CVEs |
| `scan` | Trigger threat scan |
| `veto <id>` | Veto a detected threat |
| `reverse <id>` | Reverse an action |

## Project Structure

```
aegis-reflector/
├── src/
│   ├── main.rs           # Entry point + Windows service
│   ├── lib.rs            # Core library
│   ├── engine/           # Detection engine
│   │   ├── anomaly_detector.rs
│   │   ├── decision_engine.rs
│   │   └── file_monitor.rs
│   ├── intelligence/     # Threat intelligence
│   │   ├── cve_fetcher.rs
│   │   ├── breach_checker.rs
│   │   └── urlhaus.rs
│   ├── database/         # SQLite database
│   └── terminal/        # Web terminal UI
└── Cargo.toml
```

## Features

### Threat Intelligence Sources
- **NVD** (National Vulnerability Database)
- **CISA KEV** (Known Exploited Vulnerabilities)
- **URLhaus** (Malware URLs)
- **HaveIBeenPwned** (Data breaches)

### Anomaly Detection
- Isolation Forest ML model for file analysis
- Feature extraction including entropy, byte frequency, PE indicators
- Heuristic fallback when model is unavailable

### Database
- SQLite for local storage
- Tables: CVEs, detected_threats, action_log, breaches

## Configuration

Edit `src/lib.rs` to customize:
- `database_path`: SQLite database location
- `model_path`: ONNX model path
- `terminal_port`: Web UI port
- `watch_paths`: Directories to monitor
- `scan_interval_hours`: CVE scan frequency

## License

MIT
