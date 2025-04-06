use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use log::{debug, info, warn};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "firewall.yaml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct FirewallConfig {
    #[serde(default = "default_policy_drop")]
    default_policy: DefaultPolicy,
    rules: Rules,
}

#[derive(Debug, Deserialize)]
enum DefaultPolicy {
    #[serde(rename = "ACCEPT")]
    Accept,
    #[serde(rename = "DROP")]
    Drop,
}

fn default_policy_drop() -> DefaultPolicy {
    DefaultPolicy::Drop
}

#[derive(Debug, Deserialize)]
struct Rules {
    tcp: TcpRules,
    udp: UdpRules,
}

#[derive(Debug, Deserialize)]
struct TcpRules {
    #[serde(default)]
    block: Vec<u16>,
    #[serde(default)]
    allow: Vec<u16>,
    #[serde(default)]
    allow_http_only: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct UdpRules {
    #[serde(default)]
    block: Vec<u16>,
    #[serde(default)]
    allow: Vec<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // Load the eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-rs"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load the firewall configuration
    info!("Loading configuration from {}", opt.config.display());
    let config_str = fs::read_to_string(&opt.config).context("Failed to read config file")?;
    let config: FirewallConfig =
        serde_yaml::from_str(&config_str).context("Failed to parse config file")?;

    // Attach the XDP program
    let program: &mut Xdp = ebpf.program_mut("xdp_rs").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Get all maps first
    let maps: Vec<_> = ebpf.maps_mut().collect();

    // Now process each map
    let mut default_policy_map = None;
    let mut tcp_rules_map = None;
    let mut udp_rules_map = None;

    for (name, map) in maps {
        match name {
            "DEFAULT_POLICY" => {
                default_policy_map = Some(HashMap::<_, u32, u8>::try_from(map)?);
            }
            "TCP_RULES" => {
                tcp_rules_map = Some(HashMap::<_, u16, u8>::try_from(map)?);
            }
            "UDP_RULES" => {
                udp_rules_map = Some(HashMap::<_, u16, u8>::try_from(map)?);
            }
            _ => {}
        }
    }

    // Unwrap the maps
    let mut default_policy_map = default_policy_map.unwrap();
    let mut tcp_rules_map = tcp_rules_map.unwrap();
    let mut udp_rules_map = udp_rules_map.unwrap();

    // Now you can use the maps
    match config.default_policy {
        DefaultPolicy::Accept => {
            _ = default_policy_map.insert(0, 1, 0);
            info!("Default policy set to ACCEPT");
        }
        DefaultPolicy::Drop => {
            _ = default_policy_map.insert(0, 0, 0);
            info!("Default policy set to DROP");
        }
    }

    // Configure TCP rules
    for port in &config.rules.tcp.block {
        _ = tcp_rules_map.insert(*port, 0, 0); // 0 = BLOCK
        info!("Added rule: BLOCK TCP port {}", port);
    }

    for port in &config.rules.tcp.allow {
        _ = tcp_rules_map.insert(*port, 1, 0); // 1 = ALLOW
        info!("Added rule: ALLOW TCP port {}", port);
    }

    for port in &config.rules.tcp.allow_http_only {
        _ = tcp_rules_map.insert(*port, 2, 0); // 2 = ALLOW_HTTP_ONLY
        info!("Added rule: ALLOW_HTTP_ONLY TCP port {}", port);
    }

    // Configure UDP rules
    for port in &config.rules.udp.block {
        _ = udp_rules_map.insert(*port, 0, 0); // 0 = BLOCK
        info!("Added rule: BLOCK UDP port {}", port);
    }

    for port in &config.rules.udp.allow {
        _ = udp_rules_map.insert(*port, 1, 0); // 1 = ALLOW
        info!("Added rule: ALLOW UDP port {}", port);
    }

    // Wait for Ctrl-C
    info!(
        "Firewall loaded with {} TCP rules and {} UDP rules",
        config.rules.tcp.block.len()
            + config.rules.tcp.allow.len()
            + config.rules.tcp.allow_http_only.len(),
        config.rules.udp.block.len() + config.rules.udp.allow.len()
    );
    info!("Waiting for Ctrl-C...");
    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
