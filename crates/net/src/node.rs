//! The network task and its command handle.
//!
//! libp2p's `Swarm` is `!Sync` and must be polled from a single place, so we own it in
//! one tokio task and talk to it over an mpsc channel. Proxy code never touches the
//! swarm directly: it uses a cloned [`libp2p_stream::Control`] to open/accept streams,
//! and this handle for DHT put/get and diagnostics.

use crate::behaviour::{Behaviour, BehaviourEvent};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use libp2p::kad;
use libp2p::kad::store::RecordStore;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Latest libp2p ping RTT (ms) per peer, shared lock-free-ish between the swarm task and
/// `NetHandle` readers (brief locks only). Powers the live ping readout in the MOD.
type RttMap = Arc<Mutex<HashMap<PeerId, u64>>>;

/// Custom protocol for the tunnel data streams. SPEC §6.1.
pub const TUNNEL_PROTOCOL: &str = "/mc-tunnel/1.0.0";

/// How far into the future a record's timestamp may be before a storage node refuses it.
/// Generous (10 min) to tolerate honest clock skew while bounding future-dated replays.
const MAX_FUTURE_SKEW: u64 = 600;

/// Current unix time in seconds (storage-side freshness reference).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How the node should listen and bootstrap.
#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Bootstrap nodes (each multiaddr must end in `/p2p/<PeerId>`).
    pub bootstrap: Vec<Multiaddr>,
    /// Extra explicit listen addresses; if empty we listen on TCP+QUIC on all ifaces.
    pub listen: Vec<Multiaddr>,
    /// Relay nodes to reserve a circuit slot on, so we are reachable through them while
    /// behind NAT (SPEC §5.1). Each must end in `/p2p/<PeerId>`.
    pub reserve_relays: Vec<Multiaddr>,
    /// Run as a relay *server* (public bootstrap/relay nodes only).
    pub relay_server: bool,
    /// Enable mDNS LAN discovery (default on; off to force the WAN/bootstrap path).
    pub enable_mdns: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            listen: Vec::new(),
            reserve_relays: Vec::new(),
            relay_server: false,
            enable_mdns: true,
        }
    }
}

/// A point-in-time view for the `doctor` command. SPEC §7.1.
#[derive(Clone, Debug, Default)]
pub struct DoctorInfo {
    pub peer_id: String,
    pub listen_addrs: Vec<String>,
    pub external_addrs: Vec<String>,
    pub connected_peers: usize,
    pub nat_status: String,
}

/// Reply channel for a DHT get: ALL records found under the key. The caller verifies
/// each and picks a valid one — returning every candidate (not just the first) is what
/// stops a poisoned record stored under the same key from causing a resolution failure.
type GetResp = oneshot::Sender<Result<Vec<Vec<u8>>>>;
/// In-flight get: its reply channel plus the records accumulated so far for that query.
type PendingGet = HashMap<kad::QueryId, (GetResp, Vec<Vec<u8>>)>;

enum Command {
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        resp: oneshot::Sender<Result<()>>,
    },
    GetRecord {
        key: Vec<u8>,
        resp: GetResp,
    },
    Dial {
        addr: Multiaddr,
        resp: oneshot::Sender<Result<()>>,
    },
    Doctor {
        resp: oneshot::Sender<DoctorInfo>,
    },
}

/// Cloneable handle used by the rest of the daemon to drive the network task.
#[derive(Clone)]
pub struct NetHandle {
    tx: mpsc::Sender<Command>,
    peer_id: PeerId,
    rtt: RttMap,
}

impl NetHandle {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Latest libp2p ping RTT (ms) to `peer`, or `None` if not measured / disconnected.
    pub fn rtt_ms(&self, peer: &PeerId) -> Option<u64> {
        self.rtt.lock().ok()?.get(peer).copied()
    }

    /// Store a signed record in the DHT (Quorum::One — hobby net, best-effort).
    pub async fn put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let (resp, rx) = oneshot::channel();
        self.tx
            .send(Command::PutRecord { key, value, resp })
            .await
            .map_err(closed)?;
        rx.await.map_err(closed)?
    }

    /// Resolve a DHT key to *every* record found under it. An empty Vec means "not found".
    /// The caller must verify each candidate; multiple results can include junk a third
    /// party stored under the same key, so the caller picks the first that verifies.
    pub async fn get_record(&self, key: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        let (resp, rx) = oneshot::channel();
        self.tx
            .send(Command::GetRecord { key, resp })
            .await
            .map_err(closed)?;
        rx.await.map_err(closed)?
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        let (resp, rx) = oneshot::channel();
        self.tx
            .send(Command::Dial { addr, resp })
            .await
            .map_err(closed)?;
        rx.await.map_err(closed)?
    }

    pub async fn doctor(&self) -> Result<DoctorInfo> {
        let (resp, rx) = oneshot::channel();
        self.tx
            .send(Command::Doctor { resp })
            .await
            .map_err(closed)?;
        rx.await.map_err(closed)
    }
}

fn closed<T>(_: T) -> anyhow::Error {
    anyhow!("network task has shut down")
}

/// Build the libp2p identity keypair from the same 32 ed25519 secret bytes the core
/// `Identity` uses. This ties PeerId, keyid, and record signatures to one key (SPEC §5.1).
fn keypair_from_secret(mut secret: [u8; 32]) -> Result<identity::Keypair> {
    // `ed25519_from_bytes` zeroizes the input buffer for us.
    let kp = identity::Keypair::ed25519_from_bytes(&mut secret)
        .context("constructing libp2p ed25519 keypair from secret bytes")?;
    Ok(kp)
}

/// Build the swarm, start listening, and spawn the event-loop task.
///
/// Returns a [`NetHandle`] for commands and a [`libp2p_stream::Control`] for the proxy.
pub async fn spawn(
    secret: [u8; 32],
    cfg: NetConfig,
) -> Result<(NetHandle, libp2p_stream::Control)> {
    let keypair = keypair_from_secret(secret)?;
    let peer_id = keypair.public().to_peer_id();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            Behaviour::new(
                key.public().to_peer_id(),
                key.public(),
                relay_client,
                cfg.relay_server,
                cfg.enable_mdns,
            )
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Grab a Control for the proxy before the swarm moves into its task.
    let control = swarm.behaviour().stream.new_control();

    start_listening(&mut swarm, &cfg)?;
    add_bootstrap(&mut swarm, &cfg);
    reserve_relays(&mut swarm, &cfg);

    let rtt: RttMap = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx) = mpsc::channel::<Command>(64);
    tokio::spawn(event_loop(swarm, rx, rtt.clone()));

    Ok((NetHandle { tx, peer_id, rtt }, control))
}

fn start_listening(swarm: &mut Swarm<Behaviour>, cfg: &NetConfig) -> Result<()> {
    if cfg.listen.is_empty() {
        // Default: all interfaces, ephemeral port, on both TCP and QUIC.
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    } else {
        for addr in &cfg.listen {
            swarm.listen_on(addr.clone())?;
        }
    }
    Ok(())
}

fn add_bootstrap(swarm: &mut Swarm<Behaviour>, cfg: &NetConfig) {
    let mut added = 0;
    for addr in &cfg.bootstrap {
        if let Some(peer) = peer_id_from_multiaddr(addr) {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
            added += 1;
        } else {
            tracing::warn!(%addr, "bootstrap multiaddr has no /p2p/<peer-id>; skipping");
        }
    }
    if added > 0 {
        // Best-effort: failure just means we have no peers yet.
        let _ = swarm.behaviour_mut().kad.bootstrap();
    }
}

/// Ask each configured relay for a reservation so we become reachable at a
/// `/<relay>/p2p-circuit/...` address even behind NAT (SPEC §5.1). The resulting circuit
/// address shows up as one of our listen addresses and gets advertised in our record.
fn reserve_relays(swarm: &mut Swarm<Behaviour>, cfg: &NetConfig) {
    for relay in &cfg.reserve_relays {
        if let Some(peer) = peer_id_from_multiaddr(relay) {
            // Teach kad/the swarm how to reach the relay before listening through it.
            swarm.behaviour_mut().kad.add_address(&peer, relay.clone());
        }
        let circuit = relay.clone().with(libp2p::multiaddr::Protocol::P2pCircuit);
        match swarm.listen_on(circuit.clone()) {
            Ok(_) => tracing::info!(%circuit, "requesting relay reservation"),
            Err(e) => tracing::warn!(%relay, error = %e, "failed to request relay reservation"),
        }
    }
}

/// Validate an inbound DHT record before storing it: it must parse (size-capped), be
/// validly signed, and have its storage key cryptographically bound to the signer's key.
/// Returns the parsed record (so the caller can compare timestamps) or `None` to reject.
fn validate_inbound_record(record: &kad::Record) -> Option<mc_tunnel_core::record::Record> {
    let key: [u8; 32] = record.key.as_ref().try_into().ok()?; // 32-byte SHA-256 keys only
    let rec = mc_tunnel_core::record::Record::from_bytes(&record.value).ok()?;
    mc_tunnel_core::record::authorizes_storage_key(&rec, &key).then_some(rec)
}

/// Is `ts` strictly newer than the timestamp of any record we already store under `key`?
/// (No stored record, or an unparsable one, counts as "yes, store the new one".)
fn is_newer_than_stored(swarm: &mut Swarm<Behaviour>, key: &kad::RecordKey, ts: u64) -> bool {
    match swarm.behaviour_mut().kad.store_mut().get(key) {
        Some(existing) => mc_tunnel_core::record::Record::from_bytes(&existing.value)
            .map(|r| ts > r.body.ts)
            .unwrap_or(true),
        None => true,
    }
}

/// Extract the trailing PeerId from a multiaddr's `/p2p/<id>` component.
fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

async fn event_loop(mut swarm: Swarm<Behaviour>, mut rx: mpsc::Receiver<Command>, rtt: RttMap) {
    // Query correlation: map a kad QueryId to the waiting caller.
    let mut pending_put: HashMap<kad::QueryId, oneshot::Sender<Result<()>>> = HashMap::new();
    let mut pending_get: PendingGet = HashMap::new();
    let mut external_addrs: Vec<Multiaddr> = Vec::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(c) => handle_command(&mut swarm, c, &mut pending_put, &mut pending_get, &external_addrs),
                None => break, // all handles dropped -> shut down
            },
            event = swarm.select_next_some() => {
                handle_event(&mut swarm, event, &mut pending_put, &mut pending_get, &mut external_addrs, &rtt);
            }
        }
    }
}

fn handle_command(
    swarm: &mut Swarm<Behaviour>,
    cmd: Command,
    pending_put: &mut HashMap<kad::QueryId, oneshot::Sender<Result<()>>>,
    pending_get: &mut PendingGet,
    external_addrs: &[Multiaddr],
) {
    match cmd {
        Command::PutRecord { key, value, resp } => {
            // Expire the record at ts+ttl so stale locations age out of the DHT.
            let expires = mc_tunnel_core::record::Record::from_bytes(&value)
                .ok()
                .map(|r| Instant::now() + Duration::from_secs(r.body.ttl as u64));
            let record = kad::Record {
                key: kad::RecordKey::new(&key),
                value,
                publisher: None,
                expires,
            };
            match swarm
                .behaviour_mut()
                .kad
                .put_record(record, kad::Quorum::One)
            {
                Ok(qid) => {
                    pending_put.insert(qid, resp);
                }
                Err(e) => {
                    let _ = resp.send(Err(anyhow!("put_record failed: {e}")));
                }
            }
        }
        Command::GetRecord { key, resp } => {
            let qid = swarm
                .behaviour_mut()
                .kad
                .get_record(kad::RecordKey::new(&key));
            pending_get.insert(qid, (resp, Vec::new()));
        }
        Command::Dial { addr, resp } => {
            let r = swarm.dial(addr).map_err(|e| anyhow!("dial failed: {e}"));
            let _ = resp.send(r);
        }
        Command::Doctor { resp } => {
            let listen_addrs = swarm.listeners().map(|a| a.to_string()).collect();
            let nat_status = format!("{:?}", swarm.behaviour().autonat.nat_status());
            let info = DoctorInfo {
                peer_id: swarm.local_peer_id().to_string(),
                listen_addrs,
                external_addrs: external_addrs.iter().map(|a| a.to_string()).collect(),
                connected_peers: swarm.connected_peers().count(),
                nat_status,
            };
            let _ = resp.send(info);
        }
    }
}

fn handle_event(
    swarm: &mut Swarm<Behaviour>,
    event: SwarmEvent<BehaviourEvent>,
    pending_put: &mut HashMap<kad::QueryId, oneshot::Sender<Result<()>>>,
    pending_get: &mut PendingGet,
    external_addrs: &mut Vec<Multiaddr>,
    rtt: &RttMap,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!(%address, "listening");
        }
        // Record the live ping RTT to each peer for the MOD's real-time readout.
        SwarmEvent::Behaviour(BehaviourEvent::Ping(libp2p::ping::Event {
            peer,
            result: Ok(rtt_dur),
            ..
        })) => {
            if let Ok(mut m) = rtt.lock() {
                m.insert(peer, rtt_dur.as_millis() as u64);
            }
        }
        // Forget a peer's RTT once it fully disconnects, so stale values aren't shown.
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established: 0,
            ..
        } => {
            if let Ok(mut m) = rtt.lock() {
                m.remove(&peer_id);
            }
        }
        SwarmEvent::ExternalAddrConfirmed { address } => {
            if !external_addrs.contains(&address) {
                external_addrs.push(address);
            }
        }
        // A relay accepted our reservation: we're now reachable through it.
        SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
            libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            tracing::info!(%relay_peer_id, "relay reservation accepted");
        }
        // Hole punching upgraded a relayed connection to a direct one.
        SwarmEvent::Behaviour(BehaviourEvent::Dcutr(ev)) => {
            tracing::debug!(remote = %ev.remote_peer_id, result = ?ev.result, "dcutr hole-punch");
        }
        // identify tells us a peer's addresses -> feed kad so the DHT can route.
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            for addr in info.listen_addrs {
                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
            }
        }
        // LAN discovery: register the peer in kad and dial it so the local DHT forms.
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(list))) => {
            for (peer, addr) in list {
                tracing::debug!(%peer, %addr, "mdns discovered peer");
                swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
                let _ = swarm.dial(addr);
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            id,
            result,
            ..
        })) => handle_kad_result(id, result, pending_put, pending_get),
        // Inbound record (filtering is on): store only if validly signed, key-bound to the
        // signer, AND strictly newer than what we hold. The newer-than check stops a
        // replayed older (but still signed) record from overwriting the owner's current
        // location (SPEC §5.2 freshness; found via external review).
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest {
            request:
                kad::InboundRequest::PutRecord {
                    record: Some(record),
                    ..
                },
        })) => match validate_inbound_record(&record) {
            // Reject records dated too far in the FUTURE before the newer-than check, so a
            // clock-skewed or replayed future-ts record can't get stored and then block the
            // owner's correctly-dated records via newer-than (availability edge, ext review).
            Some(rec) if rec.body.ts > now_secs().saturating_add(MAX_FUTURE_SKEW) => {
                tracing::debug!(
                    ts = rec.body.ts,
                    "dropped inbound record: timestamp too far in the future"
                );
            }
            Some(rec) if is_newer_than_stored(swarm, &record.key, rec.body.ts) => {
                let mut record = record;
                record.expires = Some(Instant::now() + Duration::from_secs(rec.body.ttl as u64));
                let _ = swarm.behaviour_mut().kad.store_mut().put(record);
            }
            Some(_) => tracing::debug!("dropped inbound record: not newer than stored"),
            None => tracing::debug!("dropped inbound record: bad signature or unbound key"),
        },
        _ => {}
    }
}

fn handle_kad_result(
    id: kad::QueryId,
    result: kad::QueryResult,
    pending_put: &mut HashMap<kad::QueryId, oneshot::Sender<Result<()>>>,
    pending_get: &mut PendingGet,
) {
    match result {
        kad::QueryResult::PutRecord(res) => {
            if let Some(resp) = pending_put.remove(&id) {
                let _ = resp.send(res.map(|_| ()).map_err(|e| anyhow!("put failed: {e}")));
            }
        }
        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
            // Accumulate every candidate; the query keeps running. A poisoned record
            // stored under the same key by a third party shows up here too, so we must
            // not commit to the first one — the caller verifies and picks a valid one.
            // Drop oversized payloads up front so a peer can't grow our buffer (DoS).
            let value = peer_record.record.value;
            if value.len() <= mc_tunnel_core::record::MAX_RECORD_BYTES {
                if let Some((_, acc)) = pending_get.get_mut(&id) {
                    acc.push(value);
                }
            }
        }
        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord {
            ..
        })) => {
            // Query finished: hand back everything we collected (possibly empty).
            if let Some((resp, acc)) = pending_get.remove(&id) {
                let _ = resp.send(Ok(acc));
            }
        }
        kad::QueryResult::GetRecord(Err(e)) => {
            // Quorum/timeout/not-found aren't hard errors — return whatever we gathered so
            // the caller can verify it or retry within its own deadline (SPEC §5.2).
            if let Some((resp, acc)) = pending_get.remove(&id) {
                tracing::debug!(error = %e, "get_record query ended early");
                let _ = resp.send(Ok(acc));
            }
        }
        _ => {}
    }
}
