//! Vanity keyid grinding, SPEC §4.3 mode (B). Brute-force ed25519 keygen until the
//! derived keyid starts with a wanted prefix — same idea as `.onion` vanity addresses.
//!
//! Multithreaded across all cores; progress goes to stderr; an `abort` flag (wired to
//! Ctrl-C by the caller) stops every worker promptly.

use anyhow::{bail, Result};
use mc_tunnel_core::name::keyid_from_pubkey;
use mc_tunnel_core::{Identity, MAX_KEYID_LEN};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

/// Validate a requested vanity prefix against the keyid charset and length.
fn validate(prefix: &str, keyid_len: usize) -> Result<()> {
    if prefix.is_empty() {
        bail!("--vanity-prefix must not be empty");
    }
    if !prefix.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')) {
        bail!("--vanity-prefix must use only the base32 charset a-z2-7 (no 0 1 8 9 o l)");
    }
    if prefix.len() > keyid_len {
        bail!(
            "--vanity-prefix ({} chars) is longer than keyid_len ({keyid_len})",
            prefix.len()
        );
    }
    if prefix.len() > MAX_KEYID_LEN {
        bail!("--vanity-prefix too long");
    }
    Ok(())
}

/// Grind until an identity whose keyid starts with `prefix` is found, or `abort` is set.
/// Returns `Ok(None)` if aborted. Runs synchronously — call via `spawn_blocking`.
pub fn grind(prefix: &str, keyid_len: usize, abort: Arc<AtomicBool>) -> Result<Option<Identity>> {
    validate(prefix, keyid_len)?;
    if prefix.len() >= 7 {
        eprintln!(
            "Note: a {}-char prefix can take a long time (base32 ~ 32^{}).",
            prefix.len(),
            prefix.len()
        );
    }

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let attempts = Arc::new(AtomicU64::new(0));
    let plen = prefix.len();
    let (tx, rx) = mpsc::channel::<[u8; 32]>();

    eprintln!("Grinding for keyid prefix \"{prefix}\" on {threads} threads (Ctrl-C to stop)...");
    let start = Instant::now();

    std::thread::scope(|scope| {
        // Workers.
        for _ in 0..threads {
            let abort = abort.clone();
            let attempts = attempts.clone();
            let tx = tx.clone();
            let prefix = prefix.to_string();
            scope.spawn(move || {
                // Batch the abort/counter checks so the hot loop stays tight.
                loop {
                    if abort.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut local = 0u64;
                    for _ in 0..4096 {
                        let id = Identity::generate();
                        local += 1;
                        if keyid_from_pubkey(&id.public_bytes(), plen) == prefix {
                            attempts.fetch_add(local, Ordering::Relaxed);
                            abort.store(true, Ordering::Relaxed); // tell everyone to stop
                            let _ = tx.send(*id.secret_bytes());
                            return;
                        }
                    }
                    attempts.fetch_add(local, Ordering::Relaxed);
                }
            });
        }
        drop(tx); // so rx disconnects once all workers exit

        // Reporter: print rate until a result arrives or everyone aborts.
        let mut found: Option<[u8; 32]> = None;
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(secret) => {
                    found = Some(secret);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if abort.load(Ordering::Relaxed) {
                        break; // aborted by Ctrl-C
                    }
                    let n = attempts.load(Ordering::Relaxed);
                    let secs = start.elapsed().as_secs_f64().max(0.001);
                    eprintln!(
                        "  {n} tried, {:.0}/s, {:.0}s elapsed",
                        n as f64 / secs,
                        secs
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        match found {
            Some(secret) => {
                let n = attempts.load(Ordering::Relaxed);
                eprintln!(
                    "Found after {n} attempts in {:.1}s.",
                    start.elapsed().as_secs_f64()
                );
                Ok(Some(Identity::from_secret_bytes(&secret)))
            }
            None => Ok(None),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_charset() {
        let abort = Arc::new(AtomicBool::new(false));
        // '0' is not in the base32 charset (digits are 2-7 only). Note o/l ARE valid.
        assert!(grind("b0b", 16, abort).is_err());
    }

    #[test]
    fn rejects_prefix_longer_than_keyid() {
        let abort = Arc::new(AtomicBool::new(false));
        assert!(grind("abcde", 4, abort).is_err());
    }

    #[test]
    fn finds_single_char_prefix() {
        // A 1-char prefix has a 1/32 hit rate, so this resolves near-instantly and
        // exercises the whole worker/reporter path.
        let abort = Arc::new(AtomicBool::new(false));
        let id = grind("a", 16, abort).unwrap().expect("should find quickly");
        let keyid = keyid_from_pubkey(&id.public_bytes(), 16);
        assert!(keyid.starts_with('a'), "got keyid {keyid}");
    }
}
