//! Local ed25519 identity: generation, on-disk persistence, keyid/name derivation.
//! SPEC §8. The signing key is zeroized on drop and is never serialized anywhere
//! except the protected key file.

use crate::error::CoreError;
use crate::name::Name;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use zeroize::Zeroizing;

/// An owned ed25519 keypair. The secret half lives inside `SigningKey`, which
/// zeroizes itself on drop (ed25519-dalek `zeroize` feature).
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh random identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstruct from 32 raw secret-key bytes (e.g. read from the key file).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// The 32-byte verifying (public) key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Borrow the signing key for record signing. Stays in-crate use; never logged.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Secret-key bytes wrapped so they zeroize when the caller drops them. Used only
    /// by the persistence layer just before writing the protected file.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// This identity's address at the given keyid length, with an optional vanity label.
    pub fn name(&self, vanity: &str, keyid_len: usize) -> Result<Name, CoreError> {
        Name::from_pubkey(&self.public_bytes(), vanity, keyid_len)
    }
}
