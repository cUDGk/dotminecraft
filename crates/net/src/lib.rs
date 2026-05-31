//! libp2p networking layer for mc-tunnel: swarm construction, Kademlia DHT put/get,
//! NAT traversal, and the custom tunnel stream protocol. SPEC §5.
//!
//! The rest of the daemon talks to the network only through [`NetHandle`] (commands)
//! and a [`libp2p_stream::Control`] (opening/accepting tunnel streams), so the swarm
//! stays confined to one task.

pub mod behaviour;
pub mod node;

pub use node::{spawn, DoctorInfo, NetConfig, NetHandle, TUNNEL_PROTOCOL};

// Re-export the libp2p types callers need so they don't depend on libp2p directly.
pub use libp2p::{Multiaddr, PeerId, Stream, StreamProtocol};
pub use libp2p_stream::Control;

/// Derive the libp2p [`PeerId`] that corresponds to an ed25519 verifying key. Used by
/// the connect side to confirm a record's `peer_id` is bound to its signed `pubkey`,
/// closing the gap between "who signed this" and "who I'll actually dial".
pub fn peer_id_from_ed25519(pubkey: &[u8; 32]) -> anyhow::Result<PeerId> {
    let ed = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey)
        .map_err(|e| anyhow::anyhow!("invalid ed25519 public key: {e}"))?;
    let pk: libp2p::identity::PublicKey = ed.into();
    Ok(pk.to_peer_id())
}

/// Parse a multiaddr from a string (so callers needn't depend on libp2p).
pub fn parse_multiaddr(s: &str) -> anyhow::Result<Multiaddr> {
    s.parse::<Multiaddr>()
        .map_err(|e| anyhow::anyhow!("invalid multiaddr {s:?}: {e}"))
}
