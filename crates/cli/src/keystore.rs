//! Identity persistence. SPEC §8.
//!
//! Storage priority: (1) the OS keyring (macOS Keychain / Windows Credential Manager /
//! Linux Secret Service) via the `keyring` crate; (2) fallback to `identity.key` holding
//! the 32 raw secret bytes, locked to the owner (Unix 0600; Windows ACL via `icacls`).
//! This module is the single place that touches the secret, so the storage choice stays
//! contained. The keyring entry is keyed by the config dir so several identities (e.g.
//! different `MC_TUNNEL_HOME`s) coexist without clobbering each other.

use anyhow::{bail, Context, Result};
use directories::ProjectDirs;
use mc_tunnel_core::Identity;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_FILE: &str = "identity.key";
const META_FILE: &str = "keyid_len";

/// Resolve the per-user config directory (`~/.config/mc-tunnel` and OS equivalents).
///
/// `MC_TUNNEL_HOME` overrides it — useful for running several identities on one host
/// (and for tests). On Windows the standard path comes from the Known Folder API, which
/// ignores `%APPDATA%`, so this env override is the supported way to relocate it.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("MC_TUNNEL_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let dirs = ProjectDirs::from("", "", "mc-tunnel")
        .context("could not determine a config directory for this OS")?;
    Ok(dirs.config_dir().to_path_buf())
}

pub fn key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(KEY_FILE))
}

fn meta_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(META_FILE))
}

/// OS keyring entry for this config dir. Service is constant; the "user" is the config
/// dir path so distinct homes map to distinct credentials.
fn keyring_entry() -> Result<keyring::Entry> {
    let id = config_dir()?.to_string_lossy().into_owned();
    keyring::Entry::new("mc-tunnel", &id).context("opening OS keyring entry")
}

/// Read the 32 secret bytes from the keyring, or `None` if absent/unavailable/corrupt.
fn keyring_load() -> Option<[u8; 32]> {
    let entry = keyring_entry().ok()?;
    let secret = entry.get_secret().ok()?;
    if secret.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret);
        Some(arr)
    } else {
        None
    }
}

/// True if an identity already exists (keyring or file) so `init` won't clobber it.
pub fn exists() -> Result<bool> {
    Ok(keyring_load().is_some() || key_path()?.exists())
}

/// Persist a freshly generated identity plus its chosen keyid length. Returns a
/// human-readable description of where the secret was stored.
pub fn save(identity: &Identity, keyid_len: usize, force: bool) -> Result<String> {
    if exists()? && !force {
        bail!("identity already exists (use --force to overwrite)");
    }
    let dir = config_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // Secret bytes are zeroized when this buffer drops.
    let secret: Zeroizing<[u8; 32]> = identity.secret_bytes();

    // Prefer the OS keyring; fall back to a locked-down file if no backend is available.
    let location = match keyring_entry().and_then(|e| {
        e.set_secret(secret.as_ref())
            .context("writing secret to OS keyring")
    }) {
        Ok(()) => {
            // One source of truth: drop any stale key file from a previous file-mode save.
            let _ = fs::remove_file(key_path()?);
            "OS keyring".to_string()
        }
        Err(e) => {
            tracing::warn!(error = %e, "OS keyring unavailable; using a key file instead");
            let path = key_path()?;
            write_owner_only(&path, secret.as_ref())?;
            path.display().to_string()
        }
    };

    fs::write(meta_path()?, keyid_len.to_string()).context("writing keyid_len meta")?;
    Ok(location)
}

/// Load the identity (keyring first, then file). Errors clearly if `init` hasn't run.
pub fn load() -> Result<Identity> {
    if let Some(mut arr) = keyring_load() {
        let id = Identity::from_secret_bytes(&arr);
        arr.iter_mut().for_each(|b| *b = 0); // scrub the temporary copy
        return Ok(id);
    }

    let path = key_path()?;
    if !path.exists() {
        bail!(
            "no identity found (keyring empty and no key file at {}) — run `mc-tunnel init` first",
            path.display()
        );
    }
    let bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(fs::read(&path).with_context(|| format!("reading {}", path.display()))?);
    if bytes.len() != 32 {
        bail!(
            "key file {} is corrupt: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let id = Identity::from_secret_bytes(&arr);
    arr.iter_mut().for_each(|b| *b = 0); // scrub the temporary copy
    Ok(id)
}

/// Delete this profile's identity from wherever it lives (keyring and/or file) plus its
/// meta. Returns what was removed. SPEC §8 key management.
pub fn wipe() -> Result<String> {
    let mut removed = Vec::new();
    if let Ok(entry) = keyring_entry() {
        if entry.delete_credential().is_ok() {
            removed.push("OS keyring");
        }
    }
    let kp = key_path()?;
    if kp.exists() {
        fs::remove_file(&kp).with_context(|| format!("removing {}", kp.display()))?;
        removed.push("key file");
    }
    let _ = fs::remove_file(meta_path()?);
    Ok(if removed.is_empty() {
        "nothing to remove".to_string()
    } else {
        removed.join(" + ")
    })
}

/// The keyid length chosen at `init` time (defaults to 16 if the meta is missing).
pub fn load_keyid_len() -> Result<usize> {
    let path = meta_path()?;
    match fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse::<usize>()
            .with_context(|| format!("parsing keyid_len from {}", path.display())),
        Err(_) => Ok(mc_tunnel_core::DEFAULT_KEYID_LEN),
    }
}

/// Write `bytes` to `path` readable only by the owner from the moment it exists. Used for
/// the key file and the agent control token (SPEC §8).
///
/// Unix: create with mode 0600 *atomically* so there is no window where the file is
/// world/group-readable (a create-then-chmod sequence has such a race).
#[cfg(unix)]
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {} (0600)", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Windows: the key file lives under the per-user profile dir (already user-scoped by the
/// default ACL); we then strip inheritance and grant only the current user via `icacls`.
/// Calling the Win32 ACL APIs directly would need `unsafe` (forbidden), so `icacls` is the
/// path. **Fail closed**: if hardening doesn't succeed we delete the file and error rather
/// than leave a possibly-readable secret on disk (the OS keyring is the preferred store).
#[cfg(windows)]
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::process::Command;
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    let user = std::env::var("USERNAME").unwrap_or_default();
    let p = path.to_string_lossy().to_string();
    // `.output()` (not `.status()`) so icacls' chatter doesn't leak onto our console.
    let hardened = !user.is_empty()
        && Command::new("icacls")
            .args([&p, "/inheritance:r", "/grant:r", &format!("{user}:F")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    if hardened {
        Ok(())
    } else {
        let _ = fs::remove_file(path);
        bail!(
            "could not restrict permissions on {} via icacls; refusing to store the key as a \
             possibly-readable file (use the OS keyring instead)",
            path.display()
        );
    }
}
