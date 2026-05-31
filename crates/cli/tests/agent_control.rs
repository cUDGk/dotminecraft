//! Black-box robustness test of the *real shipped* agent binary's control endpoint against
//! hostile local input: garbage, oversized lines, malformed JSON, and unauthorized resolves
//! must all be handled without crashing the agent, and `resolve` must require the token.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mc-tunnel")
}

/// Send one request, read one '\n'-terminated reply (or None). Blocking std sockets.
fn send_and_recv(port: u16, payload: &[u8]) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(payload).ok()?;
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                out.push(byte[0]);
                if out.len() > 100_000 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn ping_ok(port: u16) -> bool {
    send_and_recv(port, b"{\"op\":\"ping\"}\n")
        .map(|r| r.contains("\"ok\":true"))
        .unwrap_or(false)
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn agent_survives_hostile_control_input() {
    // Isolated home so we don't touch the real profile; mDNS off to avoid LAN multicast.
    let home: PathBuf =
        std::env::temp_dir().join(format!("mc-tunnel-agenttest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.toml"), "[network]\nmdns = false\n").unwrap();

    // init an identity in that home (file or keyring, keyed by this home path).
    let init = Command::new(bin())
        .args(["init", "--force"])
        .env("MC_TUNNEL_HOME", &home)
        .output()
        .expect("run init");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // start the agent.
    let child = Command::new(bin())
        .args(["agent"])
        .env("MC_TUNNEL_HOME", &home)
        .env("RUST_LOG", "off")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn agent");
    let _killer = Killer(child);

    // wait for control.json (port + token).
    let control = home.join("control.json");
    let deadline = Instant::now() + Duration::from_secs(15);
    let (port, _token) = loop {
        if let Ok(text) = std::fs::read_to_string(&control) {
            if let Some(p) = parse_port(&text) {
                break (p, ());
            }
        }
        assert!(Instant::now() < deadline, "agent never wrote control.json");
        std::thread::sleep(Duration::from_millis(200));
    };

    // baseline: it answers ping.
    assert!(ping_ok(port), "agent should answer ping");

    // --- hostile inputs; none may crash the agent ---

    // 1. raw garbage, no JSON.
    let r = send_and_recv(port, b"this is not json at all\n").unwrap_or_default();
    assert!(
        r.contains("\"ok\":false"),
        "garbage should get an error, got {r:?}"
    );
    assert!(ping_ok(port), "agent alive after garbage");

    // 2. oversized line (over the 64 KiB per-connection cap).
    let mut big = vec![b'a'; 66 * 1024];
    big.push(b'\n');
    let _ = send_and_recv(port, &big); // response irrelevant; must not crash
    assert!(ping_ok(port), "agent alive after oversized input");

    // 3. malformed JSON (looks like JSON, isn't valid).
    let r = send_and_recv(port, b"{\"op\": \"resolve\", \n").unwrap_or_default();
    assert!(
        r.contains("\"ok\":false"),
        "malformed json should error, got {r:?}"
    );
    assert!(ping_ok(port), "agent alive after malformed json");

    // 4. resolve without a token -> unauthorized.
    let r = send_and_recv(
        port,
        b"{\"op\":\"resolve\",\"name\":\"abcdefghijklmnop.minecraft\"}\n",
    )
    .unwrap_or_default();
    assert!(
        r.contains("unauthorized"),
        "resolve w/o token must be rejected, got {r:?}"
    );

    // 5. resolve with a wrong token -> unauthorized.
    let r = send_and_recv(
        port,
        b"{\"op\":\"resolve\",\"name\":\"abcdefghijklmnop.minecraft\",\"token\":\"deadbeef\"}\n",
    )
    .unwrap_or_default();
    assert!(
        r.contains("unauthorized"),
        "resolve w/ wrong token must be rejected, got {r:?}"
    );

    // 6. unknown op.
    let r = send_and_recv(port, b"{\"op\":\"frobnicate\"}\n").unwrap_or_default();
    assert!(
        r.contains("\"ok\":false"),
        "unknown op should error, got {r:?}"
    );

    // still alive after everything.
    assert!(ping_ok(port), "agent must survive all hostile input");

    // cleanup the identity (best effort).
    let _ = Command::new(bin())
        .args(["forget"])
        .env("MC_TUNNEL_HOME", &home)
        .output();
    let _ = std::fs::remove_dir_all(&home);
}

/// Minimal extraction of `"port":N` from control.json without pulling in a JSON dep.
fn parse_port(text: &str) -> Option<u16> {
    let i = text.find("\"port\"")?;
    let rest = &text[i + 6..];
    let colon = rest.find(':')?;
    let digits: String = rest[colon + 1..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}
