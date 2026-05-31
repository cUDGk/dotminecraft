//! Local control endpoint for the Fabric MOD (SPEC §11).
//!
//! The MOD never touches keys or libp2p. It opens a TCP connection to this agent on
//! localhost and sends one line of JSON per request; the agent resolves the name, stands
//! up a connect tunnel on an ephemeral local port, and replies with that port. The MOD
//! then rewrites the server address to `127.0.0.1:<port>`.
//!
//! Protocol (newline-delimited JSON, one request → one response):
//!   -> {"op":"ping"}                                       <- {"ok":true}
//!   -> {"op":"resolve","name":"x.y.minecraft","token":T}  <- {"ok":true,"listen":"127.0.0.1:53412"}
//!                                                          <- {"ok":false,"error":"..."}
//!
//! Bound to 127.0.0.1 on a **random ephemeral port**, with the port and a random `token`
//! written to an owner-only `control.json` in the config dir. `resolve` requires the token.
//! Together these stop another local process from (a) squatting a fixed port to impersonate
//! the agent, or (b) snooping the port via `netstat` and driving tunnels — it can't read the
//! 0600 token file. The MOD reads `control.json` to learn where to connect.

use crate::keystore;
use crate::tunnel;
use anyhow::{Context, Result};
use mc_tunnel_core::Name;
use mc_tunnel_net::{Control, NetConfig, NetHandle, PeerId};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    token: String,
}

/// 128-bit random control token, hex-encoded.
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("getrandom failed: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// name -> (local tunnel port, publisher peer). The peer lets the `rtt` op report the live
/// ping to that publisher; the port lets repeat resolves reuse the existing tunnel.
type TunnelMap = Arc<Mutex<HashMap<String, (u16, PeerId)>>>;

/// Run the agent. `control_port` 0 (the default) picks a random ephemeral port; a non-zero
/// value pins it (advanced). The chosen port and a random token are written to control.json.
pub async fn run(secret: [u8; 32], net_cfg: NetConfig, control_port: u16) -> Result<()> {
    let (handle, p2p_control) = mc_tunnel_net::spawn(secret, net_cfg).await?;
    let listener = TcpListener::bind(("127.0.0.1", control_port))
        .await
        .with_context(|| format!("binding agent control port 127.0.0.1:{control_port}"))?;
    let port = listener.local_addr()?.port();

    let token: Arc<String> = Arc::new(random_token()?);
    let control_path = keystore::config_dir()?.join("control.json");
    std::fs::create_dir_all(keystore::config_dir()?).ok();
    keystore::write_owner_only(
        &control_path,
        json!({ "port": port, "token": token.as_str() })
            .to_string()
            .as_bytes(),
    )
    .context("writing control.json")?;

    let tunnels: TunnelMap = Arc::new(Mutex::new(HashMap::new()));
    eprintln!(
        "mc-tunnel agent ready. Control: 127.0.0.1:{port} (token in {})",
        control_path.display()
    );
    eprintln!("Press Ctrl-C to stop.");

    let result = loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (sock, _) = match accepted { Ok(v) => v, Err(e) => break Err(e.into()) };
                let handle = handle.clone();
                let p2p_control = p2p_control.clone();
                let tunnels = tunnels.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(sock, handle, p2p_control, tunnels, token).await {
                        tracing::debug!(error = %e, "agent control connection ended");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down.");
                break Ok(());
            }
        }
    };
    // Don't leave a stale control file pointing at a dead port.
    let _ = std::fs::remove_file(&control_path);
    result
}

/// Handle one control connection: read line-delimited requests, answer each.
async fn serve_conn(
    sock: TcpStream,
    handle: NetHandle,
    p2p_control: Control,
    tunnels: TunnelMap,
    token: Arc<String>,
) -> Result<()> {
    // Cap total bytes per connection so a buggy/hostile local process can't make us buffer
    // an unbounded line (DoS). Resolve requests are tiny; 64 KiB is plenty.
    const MAX_CONN_BYTES: u64 = 64 * 1024;
    let (read, mut write) = sock.into_split();
    let mut lines = BufReader::new(read.take(MAX_CONN_BYTES)).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line) {
            Ok(req) => handle_request(req, &handle, &p2p_control, &tunnels, &token).await,
            Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
        };
        let mut bytes = serde_json::to_vec(&resp)?;
        bytes.push(b'\n');
        write.write_all(&bytes).await?;
    }
    Ok(())
}

/// Constant-time-ish token check (both are short hex strings; compare full length).
fn token_ok(expected: &str, given: &str) -> bool {
    expected.len() == given.len()
        && expected
            .bytes()
            .zip(given.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

async fn handle_request(
    req: Request,
    handle: &NetHandle,
    p2p_control: &Control,
    tunnels: &TunnelMap,
    token: &str,
) -> serde_json::Value {
    match req.op.as_str() {
        // Liveness only — no token needed, leaks nothing.
        "ping" => json!({"ok": true}),
        "resolve" => {
            if !token_ok(token, &req.token) {
                return json!({"ok": false, "error": "unauthorized (bad or missing token)"});
            }
            match resolve_and_tunnel(&req.name, handle, p2p_control, tunnels).await {
                Ok(port) => {
                    json!({"ok": true, "name": req.name, "listen": format!("127.0.0.1:{port}")})
                }
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        // Live ping (ms) to the publisher serving `name` — the real-time tunnel latency.
        "rtt" => {
            if !token_ok(token, &req.token) {
                return json!({"ok": false, "error": "unauthorized"});
            }
            let peer = match Name::parse(&req.name) {
                Ok(n) => tunnels.lock().await.get(&n.to_string()).map(|(_, p)| *p),
                Err(_) => None,
            };
            match peer.and_then(|p| handle.rtt_ms(&p)) {
                Some(ms) => json!({"ok": true, "rtt_ms": ms}),
                None => json!({"ok": true, "rtt_ms": -1}),
            }
        }
        other => json!({"ok": false, "error": format!("unknown op: {other}")}),
    }
}

/// Resolve `name` (if not already tunneled) and return the local port serving it.
async fn resolve_and_tunnel(
    name_str: &str,
    handle: &NetHandle,
    p2p_control: &Control,
    tunnels: &TunnelMap,
) -> Result<u16> {
    let name = Name::parse(name_str).context("invalid address")?;
    let key = name.to_string();

    // Fast path: an existing tunnel for this name.
    if let Some((port, _)) = tunnels.lock().await.get(&key).copied() {
        return Ok(port);
    }

    let peer = tunnel::establish(handle, &name).await?;
    // Ephemeral localhost port; the OS picks it and we report it back.
    let listener = TcpListener::bind(("127.0.0.1", 0u16))
        .await
        .context("binding ephemeral local port")?;
    let port = listener.local_addr()?.port();

    let handle = handle.clone();
    let p2p_control = p2p_control.clone();
    tokio::spawn(async move {
        if let Err(e) = mc_tunnel_proxy::run_connect(handle, p2p_control, listener, peer).await {
            tracing::warn!(error = %e, "tunnel listener exited");
        }
    });

    tunnels.lock().await.insert(key, (port, peer));
    tracing::info!(%name, port, "tunnel established");
    Ok(port)
}
