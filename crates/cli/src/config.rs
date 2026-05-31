//! Config file handling. SPEC §7.2. CLI flags override file values (handled by callers).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub network: NetworkCfg,
    pub publish: PublishCfg,
    pub connect: ConnectCfg,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    /// Bootstrap multiaddrs (each ending in `/p2p/<PeerId>`).
    pub bootstrap: Vec<String>,
    /// Relays to reserve a circuit slot on (defaults to `bootstrap` if empty).
    pub relays: Vec<String>,
    /// Piggyback on the public IPFS DHT (SPEC §5.3 — off by default).
    pub use_ipfs_dht: bool,
    /// LAN mDNS discovery (on by default; turn off to force the WAN/bootstrap path).
    pub mdns: bool,
    pub keyid_len: usize,
}

impl Default for NetworkCfg {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            relays: Vec::new(),
            use_ipfs_dht: false,
            mdns: true,
            keyid_len: mc_tunnel_core::DEFAULT_KEYID_LEN,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct PublishCfg {
    pub target: String,
    pub vanity: String,
    pub max_conns: usize,
    /// Max new inbound tunnels accepted per second (anti-amplification, SPEC §9.7).
    pub max_conn_rate: u32,
}

impl Default for PublishCfg {
    fn default() -> Self {
        Self {
            target: "127.0.0.1:25565".into(),
            vanity: String::new(),
            max_conns: 32,
            max_conn_rate: 16,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ConnectCfg {
    pub listen: String,
}

impl Default for ConnectCfg {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:25566".into(),
        }
    }
}

impl Config {
    /// Load config from the standard path, or return defaults if it doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn path() -> Result<PathBuf> {
        Ok(crate::keystore::config_dir()?.join("config.toml"))
    }
}
