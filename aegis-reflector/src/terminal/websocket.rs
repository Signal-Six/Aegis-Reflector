//! WebSocket Handler for Terminal

use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_ws::{Message, Session, WebSocketContext};
use crate::database::Database;
use futures::StreamExt;
use tokio::sync::broadcast;

/// WebSocket index page
pub async fn index() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(INDEX_HTML))
}

/// WebSocket handler
pub async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    db: web::Data<Database>,
    event_tx: web::Data<broadcast::Sender<crate::terminal::TerminalEvent>>,
) -> Result<HttpResponse, actix_ws::Error> {
    let (response, session, stream) = actix_ws::handle(&req, stream)?;

    let mut ctx = WebSocketContext::new(session, stream);
    let db = db.get_ref().clone();
    let tx = event_tx.get_ref().clone();

    // Spawn async task to handle WebSocket
    tokio::spawn(async move {
        handle_websocket(&mut ctx, &db, &tx).await;
    });

    Ok(response)
}

async fn handle_websocket(
    ctx: &mut WebSocketContext<()>,
    db: &Database,
    _tx: &broadcast::Sender<crate::terminal::TerminalEvent>,
) {
    // Send welcome message
    let welcome = r#"{
        "type": "welcome",
        "message": "Aegis-Reflector Terminal v0.1.0",
        "commands": ["help", "stats", "threats", "actions", "cves", "scan", "veto", "reverse"]
    }"#;
    ctx.text(welcome).await.ok();

    // Handle messages
    let mut msg_stream = ctx.messages();

    while let Some(msg) = msg_stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let response = process_command(&text, db).await;
                ctx.text(&response).await.ok();
            }
            Ok(Message::Close(_)) => {
                break;
            }
            Err(_) => {
                break;
            }
            _ => {}
        }
    }
}

/// Process terminal commands
async fn process_command(command: &str, db: &Database) -> String {
    let parts: Vec<&str> = command.trim().split_whitespace().collect();
    let cmd = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

    match cmd.as_str() {
        "help" => {
            r#"{
                "type": "help",
                "commands": {
                    "help": "Show this help message",
                    "stats": "Show database statistics",
                    "threats": "Show recent threats",
                    "actions": "Show action log",
                    "cves": "Show recent CVEs",
                    "scan": "Trigger threat scan",
                    "veto <id>": "Veto a threat",
                    "reverse <id>": "Reverse an action",
                    "clear": "Clear terminal"
                }
            }"#.to_string()
        }
        "stats" => {
            match db.get_stats() {
                Ok(stats) => {
                    format!(r#"{{
                        "type": "stats",
                        "data": {{
                            "cve_count": {},
                            "high_threat_count": {},
                            "action_count": {},
                            "known_exploited_count": {}
                        }}
                    }}"#, stats.cve_count, stats.high_threat_count, stats.action_count, stats.known_exploited_count)
                }
                Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
            }
        }
        "threats" => {
            match db.get_recent_threats(20) {
                Ok(threats) => {
                    let threats_json: String = threats.iter().map(|t| {
                        format!(r#"{{"id":{},"file":"{}","level":{},"details":"{}"}}"#,
                            t.id, t.file_path, t.threat_level, t.details)
                    }).collect::<Vec<_>>().join(",");
                    format!(r#"{{"type":"threats","data":[{}]}}"#, threats_json)
                }
                Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
            }
        }
        "actions" => {
            match db.get_action_logs(20) {
                Ok(actions) => {
                    let actions_json: String = actions.iter().map(|a| {
                        format!(r#"{{"id":{},"target":"{}","action":"{}","reversed":{}}}"#,
                            a.id, a.target, a.action, a.reversed)
                    }).collect::<Vec<_>>().join(",");
                    format!(r#"{{"type":"actions","data":[{}]}}"#, actions_json)
                }
                Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
            }
        }
        "cves" => {
            match db.get_recent_cves(20) {
                Ok(cves) => {
                    let cves_json: String = cves.iter().map(|c| {
                        format!(r#"{{"id":"{}","severity":"{}","score":{}}}"#,
                            c.cve_id, c.severity, c.cvss_score)
                    }).collect::<Vec<_>>().join(",");
                    format!(r#"{{"type":"cves","data":[{}]}}"#, cves_json)
                }
                Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
            }
        }
        "scan" => {
            r#"{"type": "scan", "message": "Scan started"}"#.to_string()
        }
        "veto" => {
            if parts.len() < 2 {
                return r#"{"type": "error", "message": "Usage: veto <threat_id>"}"#.to_string();
            }
            if let Ok(id) = parts[1].parse::<i64>() {
                match db.veto_threat(id) {
                    Ok(_) => format!(r#"{{"type": "veto", "message": "Threat {} vetoed"}}"#, id),
                    Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
                }
            } else {
                r#"{"type": "error", "message": "Invalid ID"}"#.to_string()
            }
        }
        "reverse" => {
            if parts.len() < 2 {
                return r#"{"type": "error", "message": "Usage: reverse <action_id>"}"#.to_string();
            }
            if let Ok(id) = parts[1].parse::<i64>() {
                match db.reverse_action(id) {
                    Ok(_) => format!(r#"{{"type": "reverse", "message": "Action {} reversed"}}"#, id),
                    Err(e) => format!(r#"{{"type": "error", "message": "{}"}}"#, e),
                }
            } else {
                r#"{"type": "error", "message": "Invalid ID"}"#.to_string()
            }
        }
        "clear" => {
            r#"{"type": "clear"}"#.to_string()
        }
        "" => String::new(),
        _ => format!(r#"{{"type": "error", "message": "Unknown command: {}"}}"#, cmd),
    }
}

/// HTML for the terminal interface
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Aegis-Reflector Terminal</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        #header {
            background: #161b22;
            padding: 10px 20px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        #header h1 {
            font-size: 18px;
            color: #58a6ff;
        }
        #status {
            font-size: 12px;
            color: #3fb950;
        }
        #terminal {
            flex: 1;
            overflow: hidden;
            padding: 10px;
        }
        #input-line {
            display: flex;
            padding: 10px;
            background: #161b22;
            border-top: 1px solid #30363d;
        }
        #prompt {
            color: #58a6ff;
            margin-right: 10px;
        }
        #command {
            flex: 1;
            background: transparent;
            border: none;
            color: #c9d1d9;
            font-family: inherit;
            font-size: 14px;
            outline: none;
        }
        .output { white-space: pre-wrap; margin: 5px 0; }
        .error { color: #f85149; }
        .success { color: #3fb950; }
        .info { color: #58a6ff; }
        .warning { color: #d29922; }
    </style>
</head>
<body>
    <div id="header">
        <h1>Aegis-Reflector Terminal</h1>
        <span id="status">Connected</span>
    </div>
    <div id="terminal"></div>
    <div id="input-line">
        <span id="prompt">aegis></span>
        <input type="text" id="command" autofocus>
    </div>

    <script>
        const terminal = document.getElementById('terminal');
        const command = document.getElementById('command');
        const status = document.getElementById('status');

        // Connect to WebSocket
        const ws = new WebSocket(location.origin.replace('http', 'ws') + '/ws');

        ws.onopen = () => {
            status.textContent = 'Connected';
            status.style.color = '#3fb950';
        };

        ws.onclose = () => {
            status.textContent = 'Disconnected';
            status.style.color = '#f85149';
        };

        ws.onerror = () => {
            status.textContent = 'Error';
            status.style.color = '#f85149';
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleMessage(data);
            } catch (e) {
                output(event.data, 'output');
            }
        };

        function handleMessage(data) {
            switch (data.type) {
                case 'welcome':
                case 'help':
                case 'stats':
                case 'threats':
                case 'actions':
                case 'cves':
                case 'scan':
                case 'veto':
                case 'reverse':
                case 'clear':
                    output(JSON.stringify(data, null, 2), 'info');
                    break;
                case 'error':
                    output(data.message, 'error');
                    break;
                default:
                    output(event.data, 'output');
            }
        }

        function output(text, type) {
            const div = document.createElement('div');
            div.className = 'output ' + type;
            div.textContent = text;
            terminal.appendChild(div);
            terminal.scrollTop = terminal.scrollHeight;
        }

        command.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const cmd = command.value.trim();
                if (cmd) {
                    output('aegis> ' + cmd, 'output');
                    ws.send(cmd);
                }
                command.value = '';
            }
        });

        // Focus command input on click
        document.addEventListener('click', () => command.focus());
    </script>
</body>
</html>"#;
