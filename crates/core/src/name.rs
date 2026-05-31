//! Self-certifying name derivation and parsing. SPEC §4.
//!
//! A name is `[vanity].[keyid].minecraft`. The `keyid` is the security-bearing part:
//! `base32_nopad_lower(SHA-256(pubkey))[:len]`. The charset is Tor's (a-z2-7): all
//! letters plus the digits 2-7. Because the only digits are 2-7, there is no `0` or `1`
//! to be confused with the letters `o`/`l` (which themselves are valid characters).

use crate::error::CoreError;
use crate::{DEFAULT_KEYID_LEN, MAX_KEYID_LEN, MIN_KEYID_LEN, SUFFIX};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

/// Lowercase RFC4648 base32 of `SHA-256(pubkey)`, full 52 chars. The DHT key is
/// derived from this (SPEC §5.2: use the full hash to maximize the collision space).
pub fn keyid_full_from_pubkey(pubkey: &[u8; 32]) -> String {
    let h = Sha256::digest(pubkey);
    // BASE32_NOPAD is uppercase A-Z2-7; lowercase to match the name charset.
    BASE32_NOPAD.encode(&h).to_ascii_lowercase()
}

/// The truncated `keyid` of `len` base32 chars used in the visible address.
pub fn keyid_from_pubkey(pubkey: &[u8; 32], len: usize) -> String {
    let mut full = keyid_full_from_pubkey(pubkey);
    full.truncate(len);
    full
}

/// Is `c` a valid lowercase base32 (a-z2-7) character?
fn is_base32_lower(c: char) -> bool {
    matches!(c, 'a'..='z' | '2'..='7')
}

fn check_keyid_len(len: usize) -> Result<(), CoreError> {
    if (MIN_KEYID_LEN..=MAX_KEYID_LEN).contains(&len) {
        Ok(())
    } else {
        Err(CoreError::KeyidLen {
            len,
            min: MIN_KEYID_LEN,
            max: MAX_KEYID_LEN,
        })
    }
}

/// A parsed `[vanity].[keyid].minecraft` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// 0..=8 char optional label. Empty string means "no vanity".
    pub vanity: String,
    /// The keyid as it appeared in the address (its length is the effective keyid_len).
    pub keyid: String,
}

impl Name {
    /// Build a name from an ed25519 public key, truncating the keyid to `keyid_len`.
    pub fn from_pubkey(
        pubkey: &[u8; 32],
        vanity: &str,
        keyid_len: usize,
    ) -> Result<Self, CoreError> {
        check_keyid_len(keyid_len)?;
        validate_vanity(vanity)?;
        Ok(Self {
            vanity: vanity.to_string(),
            keyid: keyid_from_pubkey(pubkey, keyid_len),
        })
    }

    /// The keyid length, which is also the number of hash bits / 5 the name commits to.
    pub fn keyid_len(&self) -> usize {
        self.keyid.len()
    }

    /// Parse and validate a textual address. Rejects anything outside the charset so
    /// callers never feed attacker-controlled junk into the DHT lookup.
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let input = input.trim().to_ascii_lowercase();
        let labels: Vec<&str> = input.split('.').collect();

        // Last label must be the fixed suffix.
        let (suffix, rest) = labels.split_last().ok_or(CoreError::EmptyLabel)?;
        if *suffix != SUFFIX {
            return Err(CoreError::BadSuffix(SUFFIX));
        }

        match rest {
            // keyid.minecraft
            [keyid] => {
                let keyid = validate_keyid(keyid)?;
                Ok(Self {
                    vanity: String::new(),
                    keyid,
                })
            }
            // vanity.keyid.minecraft
            [vanity, keyid] => {
                validate_vanity(vanity)?;
                let keyid = validate_keyid(keyid)?;
                Ok(Self {
                    vanity: (*vanity).to_string(),
                    keyid,
                })
            }
            [] => Err(CoreError::EmptyLabel),
            _ => Err(CoreError::TooManyLabels),
        }
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.vanity.is_empty() {
            write!(f, "{}.{}", self.keyid, SUFFIX)
        } else {
            write!(f, "{}.{}.{}", self.vanity, self.keyid, SUFFIX)
        }
    }
}

fn validate_keyid(keyid: &str) -> Result<String, CoreError> {
    if keyid.is_empty() {
        return Err(CoreError::EmptyLabel);
    }
    check_keyid_len(keyid.len())?;
    if !keyid.chars().all(is_base32_lower) {
        return Err(CoreError::KeyidCharset);
    }
    Ok(keyid.to_string())
}

/// Vanity rules (SPEC §4.1): 0..=8 chars, same base32 charset so it round-trips cleanly.
fn validate_vanity(vanity: &str) -> Result<(), CoreError> {
    if vanity.is_empty() {
        return Ok(());
    }
    if vanity.len() > 8 {
        return Err(CoreError::VanityTooLong(vanity.len()));
    }
    if !vanity.chars().all(is_base32_lower) {
        return Err(CoreError::VanityCharset);
    }
    Ok(())
}

/// Verify that `keyid` is genuinely the prefix of `SHA-256(pubkey)` — the heart of
/// anti-impersonation (SPEC §4.4 / §9.4). Length-aware so a 26-char name commits to
/// 130 bits, not just the default 80.
pub fn keyid_matches_pubkey(keyid: &str, pubkey: &[u8; 32]) -> bool {
    let derived = keyid_from_pubkey(pubkey, keyid.len());
    // Constant-time-ish: lengths are equal by construction; a plain compare is fine
    // here because both sides are public values (no secret leaks via timing).
    derived == keyid
}

/// Default keyid length helper for callers that don't override it.
pub const fn default_keyid_len() -> usize {
    DEFAULT_KEYID_LEN
}
