//! Cryptographic core of mc-tunnel.
//!
//! This crate owns everything that makes a name *self-certifying*: deriving a
//! `keyid` from an ed25519 public key, parsing/formatting `[vanity].[keyid].minecraft`
//! addresses, and signing/verifying the DHT records that bind a name to a current
//! network location. It has **no networking** so it stays small, deterministic, and
//! heavily testable — the parts an attacker can poke at live here.
//!
//! Security posture (see SPEC §9): no `unsafe`, every external byte string is length-
//! and signature-checked before it is trusted, and the `keyid <-> pubkey` equality is
//! never skipped.

pub mod error;
pub mod identity;
pub mod name;
pub mod record;

pub use error::CoreError;
pub use identity::Identity;
pub use name::{keyid_from_pubkey, keyid_full_from_pubkey, Name};
pub use record::{dht_key, Record, RecordBody};

/// Default `keyid` length in base32 chars. 26 chars = 130 bits — comfortably past the
/// birthday bound for accidental collisions and far beyond brute-force impersonation,
/// while a full address still fits well under Minecraft's 128-char server-address field
/// (max possible name = 8 vanity + 26 + ".minecraft" = 45 chars). SPEC §4.2 calls this the
/// "Tor-grade" tier. Dial down to 16 (80 bits) or up to 52 (260 bits) with `--keyid-len`.
pub const DEFAULT_KEYID_LEN: usize = 26;

/// Minimum accepted `keyid` length. 16 base32 chars = 80 bits is the security floor the
/// design commits to; shorter names would be trivially hijackable, so they are rejected
/// everywhere (derivation, parsing, CLI).
pub const MIN_KEYID_LEN: usize = 16;

/// Maximum `keyid` length: 52 base32 chars covers the full 256-bit SHA-256. SPEC §4.2.
pub const MAX_KEYID_LEN: usize = 52;

/// Fixed address suffix.
pub const SUFFIX: &str = "minecraft";

/// Domain-separation prefix folded into the DHT key. SPEC §5.2.
pub const DHT_KEY_PREFIX: &str = "mc-tunnel:v1:";

/// Current record protocol version.
pub const RECORD_VERSION: u8 = 1;
