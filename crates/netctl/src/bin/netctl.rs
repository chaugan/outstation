use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use netctl::{delete_iface, iface_exists, list_with_prefix, parse_mac, set_mac, Topology};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "netctl", about = "pcapreplay bridge/TAP management")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a Linux bridge and bring it up.
    CreateBridge {
        name: String,
    },
    /// Create a persistent TAP, optionally set its MAC, enslave to a bridge, and bring it up.
    AddTap {
        name: String,
        #[arg(long)]
        bridge: String,
        #[arg(long)]
        mac: Option<String>,
    },
    /// Set the MAC of an existing interface.
    SetMac {
        iface: String,
        mac: String,
    },
    /// Delete an interface.
    Delete {
        name: String,
    },
    /// List interfaces whose name starts with PREFIX.
    ListPrefix {
        prefix: String,
    },
    /// End-to-end sanity check: create a bridge + N taps, show state, tear down.
    Demo {
        #[arg(long, default_value = "prtest_br0")]
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
        Cmd::CreateBridge { name } => {
            let mut t = Topology::new(&name);
            t.create_bridge()?;
            t.leak();
            println!("bridge {name} up");
        }
        Cmd::AddTap { name, bridge, mac } => {
            if !iface_exists(&bridge)? {
                bail!("bridge {bridge} does not exist");
            }
            let mut t = Topology::new(&bridge);
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
        Cmd::Delete { name } => {
            delete_iface(&name)?;
            println!("deleted {name}");
        }
        Cmd::ListPrefix { prefix } => {
            for n in list_with_prefix(&prefix)? {
                println!("{n}");
            }
        }
        Cmd::Demo { bridge, taps } => {
            let mut t = Topology::new(&bridge);
            t.create_bridge()?;
            let mut inject_sides = Vec::new();
            for i in 0..taps {
                let mac = [0x02, 0x00, 0x00, 0x00, 0x00, (i as u8) + 1];
                let inject = t.add_port(format!("prtest_p{i}"), Some(mac))?;
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
