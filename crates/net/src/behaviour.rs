//! The combined libp2p behaviour. SPEC §5.1: we ride the off-the-shelf protocols and
//! add only a custom *stream* protocol for the tunnel itself.

use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, identify, kad, mdns, ping, relay, PeerId};

/// identify protocol name (distinct from the tunnel stream protocol).
pub const IDENTIFY_PROTO: &str = "/mc-tunnel/id/1.0.0";

/// agent string advertised over identify.
pub const AGENT_VERSION: &str = concat!("mc-tunnel/", env!("CARGO_PKG_VERSION"));

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Kademlia DHT: stores and resolves signed location records.
    pub kad: kad::Behaviour<MemoryStore>,
    /// Tells peers our observed address and learns theirs (feeds kad + autonat).
    pub identify: identify::Behaviour,
    /// Liveness / RTT, also keeps relayed connections from idling out.
    pub ping: ping::Behaviour,
    /// Lets us reserve a slot on a relay and be dialed through it (NAT case).
    pub relay_client: relay::client::Behaviour,
    /// Relay *server*: only enabled on public bootstrap/relay nodes so home nodes don't
    /// offer a service they can't provide (and don't widen their attack surface).
    pub relay_server: Toggle<relay::Behaviour>,
    /// Upgrades a relayed connection to a direct one via hole punching.
    pub dcutr: dcutr::Behaviour,
    /// Learns whether we are publicly reachable.
    pub autonat: autonat::Behaviour,
    /// LAN peer discovery so two nodes on the same network bootstrap the DHT with no
    /// external infrastructure. Toggleable (off when only the WAN path is wanted).
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Raw bidirectional streams for the `/mc-tunnel/1.0.0` proxy protocol.
    pub stream: libp2p_stream::Behaviour,
}

impl Behaviour {
    /// Construct the behaviour. `relay_client` is handed in by the SwarmBuilder because
    /// it is paired with the relay client transport.
    pub fn new(
        peer_id: PeerId,
        pubkey: libp2p::identity::PublicKey,
        relay_client: relay::client::Behaviour,
        enable_relay_server: bool,
        enable_mdns: bool,
    ) -> Self {
        // Validate every inbound record before storing it (anti-poisoning, SPEC §9): with
        // FilterBoth the node stores an inbound record only if node.rs explicitly accepts
        // it, so a third party can't overwrite a name's record with junk.
        let mut kad_config = kad::Config::default();
        kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
        let mut kad = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);
        // Act as a full DHT node so we can store records and answer queries.
        kad.set_mode(Some(kad::Mode::Server));

        let relay_server = Toggle::from(
            enable_relay_server.then(|| relay::Behaviour::new(peer_id, relay::Config::default())),
        );

        let mdns = Toggle::from(enable_mdns.then(|| {
            mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .expect("mdns init only fails if no network interface is available")
        }));

        Self {
            kad,
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTO.to_string(), pubkey)
                    .with_agent_version(AGENT_VERSION.to_string()),
            ),
            // Ping every 2s so the connect side has a near-real-time RTT to show (the
            // default 15s is too slow for a live ping readout).
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(std::time::Duration::from_secs(2)),
            ),
            relay_client,
            relay_server,
            dcutr: dcutr::Behaviour::new(peer_id),
            autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
            mdns,
            stream: libp2p_stream::Behaviour::new(),
        }
    }
}
