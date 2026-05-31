//! Orchestration for the networked subcommands: wire the core (records/identity), the
//! net layer (DHT/streams), and the proxy together. SPEC §5–§6.

use anyhow::{bail, Context, Result};
use mc_tunnel_core::name::keyid_from_pubkey;
use mc_tunnel_core::record::{dht_key, Record, RecordBody};
use mc_tunnel_core::{Identity, Name, RECORD_VERSION};
use mc_tunnel_net::{self as net, NetConfig, NetHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Record validity (SPEC §5.2). Publisher re-puts every `TTL/2`.
const RECORD_TTL: u32 = 600;
/// Allowed |ts - now| when verifying a record (SPEC §5.2 suggests ±300s).
const MAX_SKEW: u64 = 300;
/// How long `connect` keeps retrying the DHT before giving up.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(45);

fn now_secs() -> u64 {
    // System clock is the freshness reference; a wildly wrong clock just means records
    // look stale, which fails closed (rejected), not open.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Options that shape a [`NetConfig`], pulled from `[network]` config + role.
pub struct NetOpts<'a> {
    pub bootstrap: &'a [String],
    pub relays: &'a [String],
    pub use_ipfs_dht: bool,
    pub enable_mdns: bool,
    /// Reserve relay slots (publishers do; connect/doctor don't need to).
    pub reserve: bool,
    /// Run as a relay server (the `relay` subcommand only).
    pub relay_server: bool,
}

fn parse_addrs(strs: &[String]) -> Result<Vec<mc_tunnel_net::Multiaddr>> {
    strs.iter().map(|s| net::parse_multiaddr(s)).collect()
}

/// Build a [`NetConfig`] from config strings and the caller's role.
pub fn net_config(opts: NetOpts) -> Result<NetConfig> {
    if opts.use_ipfs_dht {
        // Be honest: we don't wire the public IPFS DHT yet (SPEC §5.3 marks it optional).
        tracing::warn!(
            "use_ipfs_dht is set but not implemented yet; using configured bootstrap only"
        );
    }
    let bootstrap = parse_addrs(opts.bootstrap)?;
    // Reserve on explicit relays, or fall back to bootstrap nodes (small setups often
    // run one box as both). Only publishers reserve.
    let reserve_relays = if !opts.reserve {
        Vec::new()
    } else if opts.relays.is_empty() {
        bootstrap.clone()
    } else {
        parse_addrs(opts.relays)?
    };
    Ok(NetConfig {
        bootstrap,
        listen: Vec::new(),
        reserve_relays,
        relay_server: opts.relay_server,
        enable_mdns: opts.enable_mdns,
    })
}

/// relay: run a public relay + DHT node so NAT'd peers can be reached and so the network
/// has a bootstrap point (SPEC §5.3). Prints its dialable addresses and runs until Ctrl-C.
pub async fn relay(identity: Identity, listen_port: u16, enable_mdns: bool) -> Result<()> {
    let secret = *identity.secret_bytes();
    let net_cfg = NetConfig {
        bootstrap: Vec::new(),
        // Fixed ports so the printed multiaddr is stable to paste into others' config.
        listen: vec![
            net::parse_multiaddr(&format!("/ip4/0.0.0.0/tcp/{listen_port}"))?,
            net::parse_multiaddr(&format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1"))?,
        ],
        reserve_relays: Vec::new(),
        relay_server: true,
        enable_mdns,
    };
    let (handle, _control) = net::spawn(secret, net_cfg).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let info = handle.doctor().await?;

    eprintln!("Relay/bootstrap node running.");
    eprintln!("  peer id : {}", info.peer_id);
    eprintln!("Add one of these to other nodes' config.toml [network] bootstrap:");
    for a in &info.listen_addrs {
        if !a.contains("/0.0.0.0/") && !a.contains("/::/") {
            eprintln!("  {a}/p2p/{}", info.peer_id);
        }
    }
    eprintln!("Press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await.ok();
    eprintln!("\nShutting down.");
    Ok(())
}

/// Collect the addresses we should advertise in our record: concrete, dialable
/// listen/external addrs (drop unspecified 0.0.0.0 / :: which no one can dial).
async fn advertised_addrs(handle: &NetHandle) -> Result<Vec<String>> {
    let info = handle.doctor().await?;
    let mut addrs: Vec<String> = info
        .listen_addrs
        .into_iter()
        .chain(info.external_addrs)
        .filter(|a| !a.contains("/0.0.0.0/") && !a.contains("/::/"))
        .collect();
    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

/// Sign a fresh location record for `identity`.
fn build_record(identity: &Identity, vanity: &str, peer_id: String, addrs: Vec<String>) -> Record {
    let body = RecordBody {
        v: RECORD_VERSION,
        pubkey: identity.public_bytes(),
        peer_id,
        addrs,
        vanity: vanity.to_string(),
        ts: now_secs(),
        ttl: RECORD_TTL,
    };
    Record::sign(body, identity.signing_key())
}

/// publish: expose a local MC server under this identity's name. Runs until Ctrl-C.
pub async fn publish(
    identity: Identity,
    net_cfg: NetConfig,
    keyid_len: usize,
    target: String,
    vanity: String,
    max_conns: usize,
    max_conn_rate: u32,
) -> Result<()> {
    let secret = *identity.secret_bytes(); // copy; net::spawn consumes & zeroizes it
    let (handle, control) = net::spawn(secret, net_cfg).await?;

    let keyid = keyid_from_pubkey(&identity.public_bytes(), keyid_len);
    let name = identity.name(&vanity, keyid_len).context("deriving name")?;
    let dk = dht_key(&keyid).to_vec();
    let peer_id = handle.peer_id().to_string();

    // Let listeners and (on LAN) mDNS settle so the first record carries real addrs.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Initial put + periodic refresh every TTL/2 (SPEC §5.2).
    let republish = {
        let handle = handle.clone();
        let identity_pub = identity.public_bytes();
        let vanity = vanity.clone();
        let dk = dk.clone();
        let peer_id = peer_id.clone();
        // We re-sign each round (fresh ts) using a fresh Identity rebuilt from the secret.
        let mut secret_copy = secret;
        // Until the first successful put we retry quickly (a put needs at least one DHT
        // peer, which mDNS/bootstrap supply only after a few seconds). After success we
        // refresh on the slow TTL/2 cadence (SPEC §5.2).
        const RETRY: Duration = Duration::from_secs(5);
        let refresh = Duration::from_secs((RECORD_TTL / 2) as u64);
        tokio::spawn(async move {
            // `signer` (an Identity) holds the key in a SigningKey that zeroizes on drop;
            // scrub the raw byte copy now that it has served its purpose.
            let signer = Identity::from_secret_bytes(&secret_copy);
            zeroize::Zeroize::zeroize(&mut secret_copy);
            debug_assert_eq!(signer.public_bytes(), identity_pub);
            loop {
                let delay = match advertised_addrs(&handle).await {
                    Ok(addrs) if !addrs.is_empty() => {
                        let rec = build_record(&signer, &vanity, peer_id.clone(), addrs);
                        match handle.put_record(dk.clone(), rec.to_bytes()).await {
                            Ok(()) => {
                                tracing::info!("record published/refreshed");
                                refresh
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "publish failed (likely no DHT peer yet); retrying");
                                RETRY
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::warn!("no dialable address yet; retrying");
                        RETRY
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "could not gather addresses; retrying");
                        RETRY
                    }
                };
                tokio::time::sleep(delay).await;
            }
        })
    };

    eprintln!("Publishing: {name}");
    eprintln!("  keyid   : {}", name.keyid);
    eprintln!("  peer id : {peer_id}");
    eprintln!("  target  : {target}");
    eprintln!("Share this address; connect with:  mc-tunnel connect {name}");
    eprintln!("Press Ctrl-C to stop.");

    // Run the inbound proxy until Ctrl-C, then tear down cleanly.
    tokio::select! {
        r = mc_tunnel_proxy::run_publish(control, target, max_conns, max_conn_rate) => r?,
        _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down."),
    }
    republish.abort();
    Ok(())
}

/// Resolve a name to a verified record, retrying while the DHT populates.
async fn resolve(handle: &NetHandle, name: &Name) -> Result<Record> {
    let dk = dht_key(&name.keyid).to_vec();
    let deadline = tokio::time::Instant::now() + RESOLVE_TIMEOUT;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        // The DHT may return several records for this key, including junk a third party
        // stored to disrupt resolution. Accept the first one that passes full §5.2
        // verification; silently skip the rest. Only a record signed by the real key (and
        // matching the keyid) can pass, so poisoning degrades to "keep looking", not a
        // hard failure.
        let candidates = handle.get_record(dk.clone()).await?;
        if let Some(rec) =
            mc_tunnel_core::record::select_verified(&candidates, &name.keyid, now_secs(), MAX_SKEW)
        {
            return Ok(rec);
        }
        if !candidates.is_empty() {
            tracing::warn!(
                count = candidates.len(),
                "found record(s) for {name} but none verified (possible poisoning); retrying"
            );
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "could not resolve {name} within {}s (no record in the DHT — is the publisher running and on a reachable network?)",
                RESOLVE_TIMEOUT.as_secs()
            );
        }
        tracing::debug!(attempt, "record not found yet; retrying");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Resolve a name, bind the network identity to the signed pubkey, and dial the
/// publisher's advertised addresses. Returns the verified peer to tunnel to. Shared by
/// the `connect` command and the `agent` control endpoint.
pub async fn establish(handle: &NetHandle, name: &Name) -> Result<mc_tunnel_net::PeerId> {
    let rec = resolve(handle, name).await?;

    // Bind the network identity (peer_id we'll dial) to the signed pubkey. Without this
    // a valid-but-misdirecting record could point us at an unrelated peer.
    let peer = net::peer_id_from_ed25519(&rec.body.pubkey)?;
    if peer.to_string() != rec.body.peer_id {
        bail!("record peer_id does not match its signed pubkey — refusing to connect");
    }

    // Seed the swarm with the publisher's advertised addresses, then connect.
    for a in &rec.body.addrs {
        if let Ok(addr) = net::parse_multiaddr(a) {
            let _ = handle.dial(addr).await;
        }
    }
    Ok(peer)
}

/// Warn if a proxy listen address is reachable from outside this machine (SPEC §9.6).
/// Default is loopback; exposing the port turns this host into an open relay into the
/// remote server for anyone who can reach the address.
fn warn_if_exposed(listen: &str) {
    let exposed = match listen.parse::<std::net::SocketAddr>() {
        Ok(addr) => !addr.ip().is_loopback(),
        // If it doesn't parse as ip:port (e.g. a hostname), don't assume loopback.
        Err(_) => !listen.starts_with("127.") && !listen.starts_with("[::1]"),
    };
    if exposed {
        tracing::warn!(%listen, "listening on a non-loopback address — this exposes the tunnel to your whole network");
    }
}

/// connect: resolve a name and open a local port that tunnels to the publisher.
pub async fn connect(
    secret: [u8; 32],
    net_cfg: NetConfig,
    name_str: String,
    listen: String,
) -> Result<()> {
    let name = Name::parse(&name_str).context("invalid address")?;
    let (handle, control) = net::spawn(secret, net_cfg).await?;

    eprintln!("Resolving {name} ...");
    let peer = establish(&handle, &name).await?;

    warn_if_exposed(&listen);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding local listen address {listen}"))?;

    eprintln!("Resolved to peer {peer}");
    eprintln!("Local port : {listen}");
    eprintln!("Add a Minecraft server pointing at {listen} and join.");
    eprintln!("Press Ctrl-C to stop.");

    tokio::select! {
        r = mc_tunnel_proxy::run_connect(handle, control, listener, peer) => r?,
        _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down."),
    }
    Ok(())
}

/// doctor: print connectivity diagnostics (SPEC §7.1).
pub async fn doctor(secret: [u8; 32], net_cfg: NetConfig, json: bool) -> Result<()> {
    let (handle, _control) = net::spawn(secret, net_cfg).await?;
    // Give listeners / autonat / mDNS a few seconds to report something useful.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let info = handle.doctor().await?;

    if json {
        let addrs = info
            .listen_addrs
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(",");
        let ext = info
            .external_addrs
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            r#"{{"peer_id":"{}","connected_peers":{},"nat_status":"{}","listen_addrs":[{}],"external_addrs":[{}]}}"#,
            info.peer_id, info.connected_peers, info.nat_status, addrs, ext
        );
    } else {
        eprintln!("peer id          : {}", info.peer_id);
        eprintln!("connected peers  : {}", info.connected_peers);
        eprintln!("NAT status       : {}", info.nat_status);
        eprintln!("listen addrs     :");
        for a in &info.listen_addrs {
            eprintln!("  {a}");
        }
        eprintln!("external addrs   :");
        if info.external_addrs.is_empty() {
            eprintln!("  (none confirmed yet)");
        }
        for a in &info.external_addrs {
            eprintln!("  {a}");
        }
    }
    Ok(())
}
