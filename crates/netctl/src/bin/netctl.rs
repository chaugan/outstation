use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use netctl::{
    cleanup_all, delete_iface, iface_exists, iface_owner, list_with_prefix, nic_assessment,
    parse_mac, set_mac, Protection, Topology, DEFAULT_STATE_DIR,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "netctl", about = "outstation bridge/TAP management")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a Linux bridge (name must match ^pcr[a-z0-9_]{0,8}$),
    /// mark it as owned by RUN_ID and bring it up.
    CreateBridge {
        name: String,
        #[arg(long, default_value_t = 0)]
        run_id: u64,
    },
    /// Create a persistent TAP, optionally set its MAC, enslave to a bridge, and bring it up.
    AddTap {
        name: String,
        #[arg(long)]
        bridge: String,
        #[arg(long)]
        mac: Option<String>,
        #[arg(long, default_value_t = 0)]
        run_id: u64,
    },
    /// Set the MAC of an existing interface.
    SetMac { iface: String, mac: String },
    /// Delete an outstation-managed interface (must carry an
    /// `outstation:<run>` marker unless --force).
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Undo everything outstation left behind (interfaces, iptables
    /// rules, sysctls, offloads, aliases) using the state journal.
    Cleanup {
        #[arg(long, default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Show whether NIC may be enslaved/aliased and why not.
    CheckNic { nic: String },
    /// List interfaces whose name starts with PREFIX.
    ListPrefix { prefix: String },
    /// End-to-end sanity check: create a bridge + N taps, show state, tear down.
    Demo {
        #[arg(long, default_value = "pcrtest_br")]
        bridge: String,
        #[arg(long, default_value_t = 2)]
        taps: usize,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::CreateBridge { name, run_id } => {
            let mut t = Topology::new(&name, run_id)?;
            t.create_bridge()?;
            t.leak();
            println!("bridge {name} up");
        }
        Cmd::AddTap {
            name,
            bridge,
            mac,
            run_id,
        } => {
            if !iface_exists(&bridge)? {
                bail!("bridge {bridge} does not exist");
            }
            let mut t = Topology::new(&bridge, run_id)?;
            let mac = mac.as_deref().map(parse_mac).transpose()?;
            t.add_tap(&name, mac)?;
            t.leak();
            println!("tap {name} attached to {bridge}");
        }
        Cmd::SetMac { iface, mac } => {
            let m = parse_mac(&mac)?;
            set_mac(&iface, m)?;
            println!("set mac of {iface} to {mac}");
        }
        Cmd::Delete { name, force } => {
            if !force && iface_owner(&name).is_none() {
                bail!(
                    "{name} carries no outstation ownership marker; use --force to delete anyway"
                );
            }
            delete_iface(&name)?;
            println!("deleted {name}");
        }
        Cmd::Cleanup { state_dir } => {
            let r = cleanup_all(&state_dir)?;
            println!("{r:#?}");
            if !r.is_clean() {
                bail!("cleanup finished with {} error(s)", r.errors.len());
            }
        }
        Cmd::CheckNic { nic } => {
            let a = nic_assessment(&nic, &Protection::default());
            if a.is_clear() {
                println!("{nic}: ok");
            } else {
                for r in a.fatal {
                    println!("{nic}: refused: {r}");
                }
                for r in a.protected {
                    println!("{nic}: protected (needs force): {r}");
                }
            }
        }
        Cmd::ListPrefix { prefix } => {
            for n in list_with_prefix(&prefix)? {
                println!("{n}");
            }
        }
        Cmd::Demo { bridge, taps } => {
            let mut t = Topology::new(&bridge, 0)?;
            t.create_bridge()?;
            let mut inject_sides = Vec::new();
            for i in 0..taps {
                let mac = [0x02, 0x00, 0x00, 0x00, 0x00, (i as u8) + 1];
                let inject = t.add_port(format!("pcrtest_p{i}"), Some(mac))?;
                inject_sides.push(inject);
            }
            println!("-- state --");
            let out = std::process::Command::new("ip")
                .args(["-br", "link", "show"])
                .output()?;
            print!("{}", String::from_utf8_lossy(&out.stdout));
            println!("inject sides: {inject_sides:?}");
            println!("-- tearing down --");
            t.teardown()?;
            println!("ok");
        }
    }
    Ok(())
}
