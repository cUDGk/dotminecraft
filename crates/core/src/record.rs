//! Signed DHT records: the binding between a name and a current network location.
//! SPEC §5.2. The `connect` side trusts a record only after all four checks pass.

use crate::error::VerifyError;
use crate::name::keyid_matches_pubkey;
use crate::{DHT_KEY_PREFIX, RECORD_VERSION};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hard cap on a serialized record. A malicious DHT peer must not be able to make us
/// allocate unbounded memory (SPEC §9.2). 8 KiB is generous for ~a handful of multiaddrs.
pub const MAX_RECORD_BYTES: usize = 8 * 1024;

/// The signed body. Field order here *is* the canonical byte order (ciborium serializes
/// struct fields in declaration order), so both sides must use this exact struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordBody {
    /// Protocol version.
    pub v: u8,
    /// ed25519 verifying key — lets connect side recompute keyid and check the sig.
    #[serde(with = "serde_bytes")]
    pub pubkey: [u8; 32],
    /// libp2p PeerId (string form).
    pub peer_id: String,
    /// Currently reachable multiaddrs (may include relay addrs).
    pub addrs: Vec<String>,
    /// Optional vanity label (SPEC §4.3 mode A). Empty string if none.
    pub vanity: String,
    /// Unix seconds when issued (replay defense).
    pub ts: u64,
    /// Validity in seconds.
    pub ttl: u32,
}

impl RecordBody {
    /// Deterministic CBOR bytes that get signed/verified. Never include the signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Serializing a plain struct to a fixed-capacity Vec cannot fail.
        ciborium::into_writer(self, &mut buf)
            .expect("CBOR serialization of RecordBody is infallible");
        buf
    }
}

/// A `RecordBody` plus its detached ed25519 signature, as stored in the DHT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub body: RecordBody,
    /// ed25519 signature over `body.canonical_bytes()`.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

impl Record {
    /// Sign a body with the publisher's signing key.
    pub fn sign(body: RecordBody, signing_key: &SigningKey) -> Self {
        let sig = ed25519_dalek::Signer::sign(signing_key, &body.canonical_bytes());
        Self {
            body,
            sig: sig.to_bytes(),
        }
    }

    /// Serialize for storage in the DHT.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization of Record is infallible");
        buf
    }

    /// Parse an untrusted record from the wire. Enforces the size cap *before*
    /// deserializing (SPEC §9.2).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(VerifyError::TooLarge(MAX_RECORD_BYTES));
        }
        ciborium::from_reader(bytes).map_err(|e| VerifyError::Malformed(e.to_string()))
    }

    /// Full verification per SPEC §5.2. Order matters: cheap structural checks first,
    /// signature next, then identity binding, then freshness.
    ///
    /// - `expected_keyid`: the keyid the user actually asked to connect to.
    /// - `now`: current unix seconds (injected so this stays pure/testable).
    /// - `max_skew`: allowed |ts - now| in seconds (SPEC suggests ±300).
    pub fn verify(&self, expected_keyid: &str, now: u64, max_skew: u64) -> Result<(), VerifyError> {
        // 0. version
        if self.body.v != RECORD_VERSION {
            return Err(VerifyError::UnsupportedVersion(self.body.v));
        }

        // 1. signature over canonical body, by the embedded pubkey
        let vk =
            VerifyingKey::from_bytes(&self.body.pubkey).map_err(|_| VerifyError::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig);
        vk.verify(&self.body.canonical_bytes(), &sig)
            .map_err(|_| VerifyError::BadSignature)?;

        // 2. keyid <-> pubkey binding (anti-impersonation, never skip — SPEC §9.4)
        if !keyid_matches_pubkey(expected_keyid, &self.body.pubkey) {
            return Err(VerifyError::KeyidMismatch);
        }

        // 3. freshness / replay defense
        let skew = now.abs_diff(self.body.ts);
        if skew > max_skew {
            return Err(VerifyError::StaleTimestamp {
                ts: self.body.ts,
                now,
                skew: max_skew,
            });
        }

        Ok(())
    }

    /// Version + signature only (no keyid/freshness). Used where the keyid isn't known —
    /// e.g. a DHT node validating an inbound record before storing it.
    pub fn signature_valid(&self) -> bool {
        if self.body.v != RECORD_VERSION {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&self.body.pubkey) else {
            return false;
        };
        let sig = Signature::from_bytes(&self.sig);
        vk.verify(&self.body.canonical_bytes(), &sig).is_ok()
    }
}

/// Should a DHT node store `record` under `storage_key`?
///
/// True iff the record is validly signed AND its pubkey legitimately maps to `storage_key`
/// — i.e. there is a keyid length `L` with `dht_key(keyid(pubkey)[:L]) == storage_key`.
/// This lets honest nodes refuse to store a record under a name that isn't the signer's,
/// so a third party cannot *overwrite* a victim's record with junk (anti-poisoning at the
/// storage layer, SPEC §9). Freshness is deliberately not checked here: storage nodes may
/// have clock skew, and the resolving side enforces freshness anyway.
pub fn authorizes_storage_key(record: &Record, storage_key: &[u8; 32]) -> bool {
    if !record.signature_valid() {
        return false;
    }
    let full = crate::name::keyid_full_from_pubkey(&record.body.pubkey);
    // 52 cheap hash checks; only the true key owner can satisfy any of them.
    (1..=full.len()).any(|l| &dht_key(&full[..l]) == storage_key)
}

/// From a set of candidate serialized records (as a DHT lookup returns — possibly
/// including junk a third party stored under the same key to disrupt resolution), return
/// the first that parses *and* passes full §5.2 verification for `expected_keyid`.
///
/// This is the anti-poisoning step (SPEC §9): only a record signed by the real key and
/// matching the keyid can pass, so an attacker who lacks the key cannot derail resolution
/// — at worst they add candidates we skip.
pub fn select_verified(
    candidates: &[Vec<u8>],
    expected_keyid: &str,
    now: u64,
    max_skew: u64,
) -> Option<Record> {
    candidates
        .iter()
        .filter_map(|bytes| {
            let rec = Record::from_bytes(bytes).ok()?;
            rec.verify(expected_keyid, now, max_skew).ok()?;
            Some(rec)
        })
        // SPEC §5.2 step 4: among verified records, take the newest. Picking the *first*
        // valid one would let a replayed older (but still in-skew) record win over the
        // owner's current location.
        .max_by_key(|rec| rec.body.ts)
}

/// DHT key for a name: `SHA-256("mc-tunnel:v1:" || keyid)`.
///
/// **Deviation from SPEC §5.2 (which says `keyid_full`):** the connecting side only has
/// the *truncated* keyid that appears in the typed address — it cannot recompute the full
/// 52-char hash without the pubkey, which it only learns *after* fetching the record.
/// Using `keyid_full` would make the key impossible to form on the connect side. So both
/// sides derive the key from the keyid exactly as it appears in the name. The collision
/// space then equals the keyid length, which the user dials up with `--keyid-len` — the
/// same knob that governs every other security margin, so nothing is weakened.
pub fn dht_key(keyid: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DHT_KEY_PREFIX.as_bytes());
    hasher.update(keyid.as_bytes());
    hasher.finalize().into()
}
