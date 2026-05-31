//! mc-tunnel daemon / CLI. SPEC §7.
//!
//! `init` / `name` are local key operations; `publish` / `connect` / `doctor` run the
//! networked daemon. CLI flags override config-file values (SPEC §7.2).

mod agent;
mod config;
mod grind;
mod keystore;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use config::Config;
use mc_tunnel_core::{Identity, DEFAULT_KEYID_LEN, MAX_KEYID_LEN, MIN_KEYID_LEN};

/// Self-certifying tunnel for Minecraft Java servers.
#[derive(Parser)]
#[command(name = "mc-tunnel", version, about, long_about = None)]
struct Cli {
    /// Emit machine-readable JSON to stdout where applicable.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new ed25519 identity and show its keyid.
    Init(InitArgs),
    /// Print this identity's xxxx.minecraft address.
    Name(NameArgs),
    /// Publish a local MC server under your name (runs until Ctrl-C).
    Publish(PublishArgs),
    /// Connect to a name and open a local port (runs until Ctrl-C).
    Connect(ConnectArgs),
    /// Diagnose connectivity (listen addrs, NAT status, peers).
    Doctor,
    /// Run a public relay + bootstrap node for others to use (runs until Ctrl-C).
    Relay(RelayArgs),
    /// Delete this profile's identity (from the OS keyring and/or key file).
    Forget,
    /// Run the local control agent the Fabric MOD talks to (runs until Ctrl-C).
    Agent(AgentArgs),
}

#[derive(Args)]
struct AgentArgs {
    /// localhost control port (0 = random; the port + token are written to control.json).
    #[arg(long, default_value_t = 0)]
    control_port: u16,
}

#[derive(Args)]
struct RelayArgs {
    /// Port to listen on for both TCP and QUIC.
    #[arg(long, default_value_t = 4001)]
    port: u16,
    /// Also answer mDNS on the LAN (off by default for a public node).
    #[arg(long)]
    mdns: bool,
}

#[derive(Args)]
struct InitArgs {
    /// keyid length in base32 chars (more = more bits). SPEC §4.2.
    #[arg(long, default_value_t = DEFAULT_KEYID_LEN)]
    keyid_len: usize,
    /// Grind for a keyid starting with this prefix, mode (B) (not yet implemented — M5).
    #[arg(long)]
    vanity_prefix: Option<String>,
    /// Overwrite an existing identity.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct NameArgs {
    /// Optional vanity label (mode A, SPEC §4.3).
    #[arg(long, default_value = "")]
    vanity: String,
    /// Override the keyid length for display.
    #[arg(long)]
    keyid_len: Option<usize>,
}

#[derive(Args)]
struct PublishArgs {
    /// Local MC server to expose (overrides config).
    #[arg(long)]
    target: Option<String>,
    /// Vanity label, mode A (overrides config).
    #[arg(long)]
    vanity: Option<String>,
    /// Max simultaneous tunnels (overrides config).
    #[arg(long)]
    max_conns: Option<usize>,
}

#[derive(Args)]
struct ConnectArgs {
    /// The xxxx.minecraft address to connect to.
    name: String,
    /// Local address to listen on (overrides config).
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Human output -> stderr, structured logs gated by RUST_LOG (SPEC §7.3).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => cmd_init(args, cli.json).await,
        Command::Name(args) => cmd_name(args, cli.json),
        Command::Publish(args) => cmd_publish(args).await,
        Command::Connect(args) => cmd_connect(args).await,
        Command::Doctor => cmd_doctor(cli.json).await,
        Command::Relay(args) => cmd_relay(args).await,
        Command::Forget => {
            let what = keystore::wipe()?;
            eprintln!("Removed identity ({what}).");
            Ok(())
        }
        Command::Agent(args) => cmd_agent(args).await,
    }
}

fn check_keyid_len(len: usize) -> Result<()> {
    anyhow::ensure!(
        (MIN_KEYID_LEN..=MAX_KEYID_LEN).contains(&len),
        "keyid_len must be in {MIN_KEYID_LEN}..={MAX_KEYID_LEN}, got {len}"
    );
    Ok(())
}

async fn cmd_init(args: InitArgs, json: bool) -> Result<()> {
    check_keyid_len(args.keyid_len)?;
    if keystore::exists()? && !args.force {
        anyhow::bail!("an identity already exists for this profile (use --force to overwrite)");
    }

    let id = match args.vanity_prefix {
        Some(prefix) => {
            // Mode (B): grind on all cores until the keyid starts with `prefix`.
            // A Ctrl-C watcher flips `abort`, which every grind worker polls.
            use std::sync::atomic::AtomicBool;
            use std::sync::Arc;
            let abort = Arc::new(AtomicBool::new(false));
            {
                let abort = abort.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    abort.store(true, std::sync::atomic::Ordering::SeqCst);
                });
            }
            let keyid_len = args.keyid_len;
            let found =
                tokio::task::spawn_blocking(move || grind::grind(&prefix, keyid_len, abort))
                    .await
                    .context("grinding task panicked")??;
            match found {
                Some(id) => id,
                None => anyhow::bail!("vanity grinding aborted"),
            }
        }
        None => Identity::generate(),
    };

    let location = keystore::save(&id, args.keyid_len, args.force)?;
    let name = id.name("", args.keyid_len).context("deriving name")?;

    if json {
        println!(
            r#"{{"keyid":"{}","keyid_len":{},"name":"{}","key_storage":"{}"}}"#,
            name.keyid,
            args.keyid_len,
            name,
            location.replace('\\', "\\\\")
        );
    } else {
        eprintln!("Generated new identity.");
        eprintln!("  key stored in : {location}");
        eprintln!("  keyid         : {}", name.keyid);
        eprintln!("  address       : {name}");
        eprintln!("\nKeep the key file secret — it *is* your identity.");
    }
    Ok(())
}

fn cmd_name(args: NameArgs, json: bool) -> Result<()> {
    let id = keystore::load()?;
    let keyid_len = match args.keyid_len {
        Some(n) => {
            check_keyid_len(n)?;
            n
        }
        None => keystore::load_keyid_len()?,
    };
    let name = id
        .name(&args.vanity, keyid_len)
        .context("deriving name (check --vanity charset and --keyid-len)")?;

    if json {
        println!(
            r#"{{"keyid":"{}","keyid_len":{},"vanity":"{}","name":"{}"}}"#,
            name.keyid, keyid_len, name.vanity, name
        );
    } else {
        println!("{name}");
    }
    Ok(())
}

fn net_opts<'a>(cfg: &'a Config, reserve: bool, relay_server: bool) -> tunnel::NetOpts<'a> {
    tunnel::NetOpts {
        bootstrap: &cfg.network.bootstrap,
        relays: &cfg.network.relays,
        use_ipfs_dht: cfg.network.use_ipfs_dht,
        enable_mdns: cfg.network.mdns,
        reserve,
        relay_server,
    }
}

async fn cmd_publish(args: PublishArgs) -> Result<()> {
    let cfg = Config::load()?;
    let id = keystore::load()?;
    let keyid_len = keystore::load_keyid_len()?;

    let target = args.target.unwrap_or_else(|| cfg.publish.target.clone());
    let vanity = args.vanity.unwrap_or_else(|| cfg.publish.vanity.clone());
    let max_conns = args.max_conns.unwrap_or(cfg.publish.max_conns);
    let max_conn_rate = cfg.publish.max_conn_rate;
    let net_cfg = tunnel::net_config(net_opts(&cfg, true, false))?;

    tunnel::publish(
        id,
        net_cfg,
        keyid_len,
        target,
        vanity,
        max_conns,
        max_conn_rate,
    )
    .await
}

async fn cmd_connect(args: ConnectArgs) -> Result<()> {
    let cfg = Config::load()?;
    let id = keystore::load()?;
    let secret = *id.secret_bytes();
    let listen = args.listen.unwrap_or_else(|| cfg.connect.listen.clone());
    let net_cfg = tunnel::net_config(net_opts(&cfg, false, false))?;

    tunnel::connect(secret, net_cfg, args.name, listen).await
}

async fn cmd_doctor(json: bool) -> Result<()> {
    let cfg = Config::load()?;
    let id = keystore::load()?;
    let secret = *id.secret_bytes();
    let net_cfg = tunnel::net_config(net_opts(&cfg, false, false))?;

    tunnel::doctor(secret, net_cfg, json).await
}

async fn cmd_relay(args: RelayArgs) -> Result<()> {
    let id = keystore::load()?;
    tunnel::relay(id, args.port, args.mdns).await
}

async fn cmd_agent(args: AgentArgs) -> Result<()> {
    let cfg = Config::load()?;
    let id = keystore::load()?;
    let secret = *id.secret_bytes();
    let net_cfg = tunnel::net_config(net_opts(&cfg, false, false))?;
    agent::run(secret, net_cfg, args.control_port).await
}
