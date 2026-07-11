//! Configuration structs and parsing from TOML.

use std::{net::*, time::Duration};

use anyhow::{anyhow, bail, Result};
use ip_network::Ipv4Network;
use serde::{Deserialize, Serialize};

use crate::tuning::{apply_auto_tune, Tuning};
use crate::xor::XorCipher;

// Enums

/// Role of the suitspoof instance (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Client,
    Server,
}

/// Protocols for suitspoof uplink and downlink connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    Udp,
    Tcp,
    Icmp,
    Quic,
    Proto58,
    Ipip,
    Gre,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiObfuscation {
    pub enabled: bool,
    pub packet_padding: bool,
    pub ttl_jitter: bool,
    pub fake_tls_header: bool,
    pub random_dscp: bool,
}

impl Default for DpiObfuscation {
    fn default() -> Self {
        Self {
            enabled: true,
            packet_padding: false,
            ttl_jitter: false,
            fake_tls_header: false,
            random_dscp: false,
        }
    }
}

/// Mux/FEC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuxFec {
    pub enabled: bool,
    pub group_size: u32,
}

impl MuxFec {
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.group_size > 0
    }
}

impl Default for MuxFec {
    fn default() -> Self {
        Self {
            enabled: true,
            group_size: 10,
        }
    }
}

// Config

/// Full configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Client or server role.
    pub role: Role,

    /// Log level (`trace`, `debug`, `info`, `warn`, `error`).
    pub log_level: String,

    /// Local address to bind to.
    pub listen_addr: SocketAddr,

    /// Remote peer address (client-side only).
    pub peer_addr: SocketAddr,

    /// Real IP address of the peer.
    pub peer_real_ip: Ipv4Addr,

    /// Spoofed IP address of the peer.
    pub peer_spoofed_ip: Ipv4Addr,

    /// Name of the TUN device.
    pub tun_name: String,

    /// MTU of the TUN device.
    pub tun_mtu: u16,

    /// IP address of the TUN device.
    pub tun_ip: Ipv4Addr,

    /// Peer IP address of the TUN device.
    pub tun_peer_ip: Ipv4Addr,

    /// CIDR of the TUN network.
    pub tun_cidr: u8,

    /// Netmask of the TUN device.
    #[serde(skip)]
    pub tun_netmask: Ipv4Addr,

    /// DNS servers for the TUN device.
    pub dns_servers: Vec<Ipv4Addr>,

    /// Uplink tunnel protocol.
    pub uplink_protocol: TunnelProtocol,

    /// Downlink tunnel protocol.
    pub downlink_protocol: TunnelProtocol,

    /// Data port.
    pub data_port: u16,

    /// Shuffle data port.
    pub data_port_shuffle: bool,

    /// Range of data ports to shuffle.
    pub data_port_range: (u16, u16),

    /// XOR key for encryption.
    pub xor_key: String,

    /// DPI obfuscation settings.
    #[serde(default)]
    pub dpi_obfuscation: DpiObfuscation,

    /// Path to TLS certificate.
    pub tls_cert_path: String,

    /// Path to TLS key.
    pub tls_key_path: String,

    /// Path to TLS CA certificate.
    pub tls_ca_cert_path: String,

    /// Allowed peer IPs (server-side only).
    pub allowed_peers: Vec<Ipv4Addr>,

    /// Tunnel idle timeout in seconds.
    pub tunnel_idle_timeout_secs: u64,

    /// Handshake timeout in seconds.
    pub handshake_timeout_secs: u64,

    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,

    /// Channel capacity.
    pub channel_capacity: usize,

    /// IO channel capacity.
    pub io_channel_capacity: usize,

    /// Number of runtime threads.
    pub runtime_threads: usize,

    /// ICMP ID.
    pub icmp_id: u16,

    /// Random ICMP ID.
    pub random_icmp_id: bool,

    /// Enable multiplexing.
    #[serde(default)]
    pub enable_multiplex: bool,

    /// Multiplex flush interval in milliseconds.
    #[serde(default)]
    pub multiplex_flush_ms: u64,

    /// Multiplex maximum payload size.
    #[serde(default)]
    pub multiplex_max_payload: u16,

    /// Enable FEC.
    #[serde(default)]
    pub enable_fec: bool,

    /// FEC group size.
    #[serde(default)]
    pub fec_group_size: u32,

    /// Tuning settings.
    #[serde(default)]
    pub tuning: Option<Tuning>,

    /// Check mode (client-side only).
    #[serde(default)]
    pub check_mode: bool,

    /// Path to check IPs file (client-side only).
    #[serde(default)]
    pub check_ips_path: String,

    /// Path to check output file (client-side only).
    #[serde(default)]
    pub check_output_path: String,

    /// Check timeout in seconds (client-side only).
    #[serde(default)]
    pub check_timeout: Duration,

    /// Number of check workers (client-side only).
    #[serde(default)]
    pub check_workers: usize,

    /// Number of tunnels to open (client-side only).
    #[serde(default)]
    pub tunnel_count: usize,

    /// List of TCP/UDP ports to forward (client-side only).
    #[serde(default)]
    pub forward_ports: Vec<String>,

    /// Actual MTU being used (after clamping).
    #[serde(skip)]
    pub mtu: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::Client,
            log_level: "info".to_string(),
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
            peer_real_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_spoofed_ip: Ipv4Addr::new(10, 0, 0, 2),
            tun_name: "tun0".to_string(),
            tun_mtu: 1500,
            tun_ip: Ipv4Addr::new(10, 0, 0, 3),
            tun_peer_ip: Ipv4Addr::new(10, 0, 0, 4),
            tun_cidr: 24,
            tun_netmask: Ipv4Addr::new(0, 0, 0, 0),
            dns_servers: vec![],
            uplink_protocol: TunnelProtocol::Udp,
            downlink_protocol: TunnelProtocol::Udp,
            data_port: 12345,
            data_port_shuffle: false,
            data_port_range: (0, 0),
            xor_key: "".to_string(),
            dpi_obfuscation: DpiObfuscation::default(),
            tls_cert_path: "".to_string(),
            tls_key_path: "".to_string(),
            tls_ca_cert_path: "".to_string(),
            allowed_peers: Vec::new(),
            tunnel_idle_timeout_secs: 300,
            handshake_timeout_secs: 10,
            heartbeat_interval_secs: 10,
            channel_capacity: 100,
            io_channel_capacity: 100,
            runtime_threads: 0,
            icmp_id: 0,
            random_icmp_id: false,
            enable_multiplex: false,
            multiplex_flush_ms: 0,
            multiplex_max_payload: 0,
            enable_fec: false,
            fec_group_size: 0,
            tuning: Some(Tuning::default()),
            check_mode: false,
            check_ips_path: "".to_string(),
            check_output_path: "".to_string(),
            check_timeout: Duration::from_secs(0),
            check_workers: 0,
            tunnel_count: 1,
            forward_ports: Vec::new(),
            mtu: 1500,
        }
    }
}

impl Config {
    /// Minimum suitspoof MTU: IP header (20) + UDP header (8) + XOR key (1) + tunnel packet header (20)
    pub const MIN_MTU: u16 = 20 + 8 + 1 + 20;

    pub fn xor_cipher(&self) -> Option<XorCipher> {
        if self.xor_key.is_empty() {
            return None;
        }
        Some(XorCipher::new(&self.xor_key))
    }

    pub fn dpi_obfuscation(&self) -> DpiObfuscation {
        if !self.dpi_obfuscation.enabled {
            return DpiObfuscation {
                enabled: false,
                ..Default::default()
            };
        }
        self.dpi_obfuscation.clone()
    }

    pub fn mux_fec_config(&self) -> MuxFec {
        if !self.enable_fec {
            return MuxFec {
                enabled: false,
                ..Default::default()
            };
        }
        MuxFec {
            enabled: true,
            group_size: self.fec_group_size,
        }
    }

    pub fn build_data_port_pool(&self) -> Result<Option<Vec<u16>>> {
        if !self.data_port_shuffle {
            return Ok(None);
        }

        if self.data_port_range.0 == 0 || self.data_port_range.1 == 0 {
            bail!("data_port_range must be set when data_port_shuffle is enabled");
        }

        if self.data_port_range.0 > self.data_port_range.1 {
            bail!("data_port_range.0 must be <= data_port_range.1");
        }

        if self.data_port == 0 {
            bail!("data_port must be set when data_port_shuffle is enabled");
        }

        let mut ports: Vec<u16> = (self.data_port_range.0..=self.data_port_range.1).collect();
        ports.retain(|&p| p != self.data_port);

        if ports.is_empty() {
            bail!("data_port_range does not contain any ports other than data_port");
        }

        Ok(Some(ports))
    }

    pub fn shuffle_port_range(&self) -> (u16, u16) {
        if self.data_port_shuffle {
            self.data_port_range
        } else {
            (0, 0)
        }
    }

    pub fn pick_spoofed_ip(&self) -> Ipv4Addr {
        if self.role == Role::Server {
            self.peer_spoofed_ip
        } else {
            self.tun_ip
        }
    }

    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        if self.allowed_peers.is_empty() {
            return true;
        }
        self.allowed_peers.contains(ip)
    }

    pub fn effective_forward_ports(&self) -> Vec<(IpProtocol, u16)> {
        let mut ports = Vec::new();

        for port_str in &self.forward_ports {
            let parts: Vec<&str> = port_str.split('/').collect();
            if parts.len() != 2 {
                log::warn!("invalid forward_port format: {}", port_str);
                continue;
            }

            let protocol = match parts[0].to_lowercase().as_str() {
                "tcp" => IpProtocol::Tcp,
                "udp" => IpProtocol::Udp,
                _ => {
                    log::warn!("unknown protocol for forward_port: {}", parts[0]);
                    continue;
                }
            };

            let port: u16 = match parts[1].parse() {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("invalid port for forward_port {}: {}", parts[1], e);
                    continue;
                }
            };

            ports.push((protocol, port));
        }

        ports
    }

    pub fn get_random_icmp_id(&self) -> u16 {
        if self.random_icmp_id {
            use rand::Rng;
            rand::thread_rng().gen_range(0..65535)
        } else {
            self.icmp_id
        }
    }

    pub async fn resolve_peer_addr(&mut self) -> Result<()> {
        if self.peer_addr.ip().is_unspecified() {
            log::info!("resolving peer_addr: {}", self.peer_addr.ip());
            let ips = tokio::net::lookup_host(self.peer_addr.to_string())
                .await?
                .collect::<Vec<_>>();

            if ips.is_empty() {
                bail!("could not resolve peer_addr: {}", self.peer_addr);
            }

            self.peer_addr = ips[0];
            log::info!("resolved peer_addr: {}", self.peer_addr);
        }

        Ok(())
    }

    pub fn build_config_string(&self) -> String {
        format!(
            "
            Role: {}
            Log Level: {}
            Listen Addr: {}
            Peer Addr: {}
            Peer Real IP: {}
            Peer Spoofed IP: {}
            TUN Name: {}
            TUN MTU: {}
            TUN IP: {}
            TUN Peer IP: {}
            TUN CIDR: {}
            DNS Servers: {:?}
            Uplink Protocol: {:?}
            Downlink Protocol: {:?}
            Data Port: {}
            Data Port Shuffle: {}
            Data Port Range: {:?}
            XOR Key: {}
            DPI Obfuscation Enabled: {}
            DPI Packet Padding: {}
            DPI TTL Jitter: {}
            DPI Fake TLS Header: {}
            DPI Random DSCP: {}
            TLS Cert Path: {}
            TLS Key Path: {}
            TLS CA Cert Path: {}
            Allowed Peers: {:?}
            Tunnel Idle Timeout (secs): {}
            Handshake Timeout (secs): {}
            Heartbeat Interval (secs): {}
            Channel Capacity: {}
            IO Channel Capacity: {}
            Runtime Threads: {}
            ICMP ID: {}
            Random ICMP ID: {}
            Enable Multiplex: {}
            Multiplex Flush MS: {}
            Multiplex Max Payload: {}
            Enable FEC: {}
            FEC Group Size: {}
            Tuning Enabled: {}
            Auto IO Threads: {}
            Auto Runtime Threads: {}
            Auto Channel Capacity: {}
            Auto Multiplex Flush MS: {}
            Auto Multiplex Max Payload: {}
            Auto FEC Group Size: {}
            Auto Heartbeat Interval Secs: {}
            Auto Tunnel Idle Timeout Secs: {}
            Check Mode: {}
            Check IPs Path: {}
            Check Output Path: {}
            Check Timeout: {:?}
            Check Workers: {}
            Tunnel Count: {}
            Forward Ports: {:?}
            Actual MTU: {}
            ",
            self.role,
            self.log_level,
            self.listen_addr,
            self.peer_addr,
            self.peer_real_ip,
            self.peer_spoofed_ip,
            self.tun_name,
            self.tun_mtu,
            self.tun_ip,
            self.tun_peer_ip,
            self.tun_cidr,
            self.dns_servers,
            self.uplink_protocol,
            self.downlink_protocol,
            self.data_port,
            self.data_port_shuffle,
            self.data_port_range,
            if self.xor_key.is_empty() {
                "None"
            } else {
                "[REDACTED]"
            },
            self.dpi_obfuscation.enabled,
            self.dpi_obfuscation.packet_padding,
            self.dpi_obfuscation.ttl_jitter,
            self.dpi_obfuscation.fake_tls_header,
            self.dpi_obfuscation.random_dscp,
            self.tls_cert_path,
            self.tls_key_path,
            self.tls_ca_cert_path,
            self.allowed_peers,
            self.tunnel_idle_timeout_secs,
            self.handshake_timeout_secs,
            self.heartbeat_interval_secs,
            self.channel_capacity,
            self.io_channel_capacity,
            self.runtime_threads,
            self.icmp_id,
            self.random_icmp_id,
            self.enable_multiplex,
            self.multiplex_flush_ms,
            self.multiplex_max_payload,
            self.enable_fec,
            self.fec_group_size,
            self.tuning.as_ref().map_or(false, |t| t.enabled),
            self.tuning.as_ref().map_or(false, |t| t.auto_io_threads),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_runtime_threads),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_channel_capacity),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_multiplex_flush_ms),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_multiplex_max_payload),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_fec_group_size),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_heartbeat_interval_secs),
            self.tuning
                .as_ref()
                .map_or(false, |t| t.auto_tunnel_idle_timeout_secs),
            self.check_mode,
            self.check_ips_path,
            self.check_output_path,
            self.check_timeout,
            self.check_workers,
            self.tunnel_count,
            self.forward_ports,
            self.mtu,
        )
    }

    pub async fn from_file(path: &str) -> Result<Self> {
        let file_content = tokio::fs::read_to_string(path).await?;
        let mut cfg: Config = toml::from_str(&file_content)?;

        if let Some(summary) = apply_auto_tune(&mut cfg) {
            for line in summary.lines() {
                log::info!("{}", line);
            }
        }

        cfg.tun_netmask = Ipv4Network::new(cfg.tun_ip, cfg.tun_cidr)
            .map_err(|e| anyhow!("invalid tun_ip/tun_cidr: {}", e))?
            .netmask();

        cfg.mtu = if cfg.tun_mtu == 0 {
            1500
        } else {
            cfg.tun_mtu.max(Config::MIN_MTU)
        };

        cfg.check_integrity().await?;
        Ok(cfg)
    }

    async fn check_integrity(&self) -> Result<()> {
        if self.role == Role::Client && self.tun_mtu < Config::MIN_MTU {
            bail!(
                "tun_mtu ({}) must be at least {} (IP header + UDP header + XOR key + tunnel packet header)",
                self.tun_mtu,
                Config::MIN_MTU
            );
        }

        if self.tunnel_idle_timeout_secs < self.handshake_timeout_secs {
            bail!(
                "tunnel_idle_timeout_secs ({}) must be >= handshake_timeout_secs ({})",
                self.tunnel_idle_timeout_secs,
                self.handshake_timeout_secs
            );
        }

        if self.peer_real_ip.is_multicast()
            || self.peer_real_ip.is_broadcast()
            || self.peer_real_ip.is_unspecified()
        {
            bail!(
                "peer_real_ip ({}) must be a valid unicast IP address",
                self.peer_real_ip
            );
        }

        if self.peer_spoofed_ip.is_multicast()
            || self.peer_spoofed_ip.is_broadcast()
            || self.peer_spoofed_ip.is_unspecified()
        {
            bail!(
                "peer_spoofed_ip ({}) must be a valid unicast IP address",
                self.peer_spoofed_ip
            );
        }

        if self.tun_ip.is_multicast() || self.tun_ip.is_broadcast() || self.tun_ip.is_unspecified()
        {
            bail!("tun_ip ({}) must be a valid unicast IP address", self.tun_ip);
        }

        if self.tun_peer_ip.is_multicast()
            || self.tun_peer_ip.is_broadcast()
            || self.tun_peer_ip.is_unspecified()
        {
            bail!(
                "tun_peer_ip ({}) must be a valid unicast IP address",
                self.tun_peer_ip
            );
        }

        let network = Ipv4Network::new(self.tun_ip, self.tun_cidr)
            .map_err(|e| anyhow!("invalid tun_ip/tun_cidr: {}", e))?;

        if !network.contains(self.tun_peer_ip) {
            bail!(
                "tun_peer_ip ({}) is not in tun_ip network ({})",
                self.tun_peer_ip,
                network
            );
        }

        // Ensure that the given log level is a valid simplelog level.
        // If not, it will cause suitspoof to crash at startup.
        match self.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => bail!("invalid log_level: {}", self.log_level),
        }

        // Ensure that `quic` is only used when both uplink and downlink protocols are set to `quic`.
        // If only one is `quic`, it will cause errors at startup of suitspoof.
        let use_quic = self.uplink_protocol == TunnelProtocol::Quic
            || self.downlink_protocol == TunnelProtocol::Quic;

        if use_quic
            && (self.uplink_protocol != TunnelProtocol::Quic
                || self.downlink_protocol != TunnelProtocol::Quic)
        {
            bail!("quic requires both uplink_protocol and downlink_protocol = quic");
        }

        if use_quic && self.mux_fec_config().is_enabled() {
            log::warn!("mux/fec is ignored when using quic transport");
        }

        if self.uplink_protocol == TunnelProtocol::Tcp && self.mux_fec_config().is_enabled() {
            log::warn!("mux/fec is ignored when using tcp transport");
        }

        if use_quic && self.data_port_shuffle {
            bail!("data_port_shuffle is not supported with quic transport");
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    Tcp,
    Udp,
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::Tcp
    }
}
