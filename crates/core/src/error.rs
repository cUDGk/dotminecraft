//! Error types for the core crate. Kept granular so callers (and tests) can assert
//! on the *reason* a record was rejected — rejection reasons are part of the
//! security contract (SPEC §5.2 / §13).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("name does not end with .{0}")]
    BadSuffix(&'static str),

    #[error("name has too many labels")]
    TooManyLabels,

    #[error("keyid length {len} out of range ({min}..={max})")]
    KeyidLen { len: usize, min: usize, max: usize },

    #[error("keyid contains characters outside the base32 charset (a-z2-7)")]
    KeyidCharset,

    #[error("vanity label too long: {0} > 8")]
    VanityTooLong(usize),

    #[error("vanity label contains characters outside the base32 charset (a-z2-7)")]
    VanityCharset,

    #[error("empty label in name")]
    EmptyLabel,
}

/// Why a [`crate::Record`] was rejected during verification. Distinct from
/// [`CoreError`] because every variant here maps to one of the SPEC §5.2 checks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("record exceeds maximum size {0} bytes")]
    TooLarge(usize),

    #[error("record failed to deserialize: {0}")]
    Malformed(String),

    #[error("unsupported record version {0}")]
    UnsupportedVersion(u8),

    #[error("ed25519 signature did not verify")]
    BadSignature,

    #[error("keyid does not match SHA-256(pubkey) prefix")]
    KeyidMismatch,

    #[error("record timestamp {ts} outside allowed skew of now {now} (±{skew}s)")]
    StaleTimestamp { ts: u64, now: u64, skew: u64 },
}
