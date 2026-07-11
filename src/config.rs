use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::{bail, Result};
use rand::prelude::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::raw_socket::{XorCipher, DpiObfuscation};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum TunnelProtocol {
    Udp,
    Icmp,
    Tcp,
    Quic,
    Proto58, // IPIP
    Gre,     // Protocol 47
    UdpXor,
    IcmpXor,
    TcpXor,
    Proto58Xor,
    GreXor,
}

impl TunnelProtocol {
    pub fn has_xor(&self) -> bool {
        use TunnelProtocol::*;
        matches!(self, UdpXor | IcmpXor | TcpXor | Proto58Xor | GreXor)
    }

    pub fn unwrap_xor(&self) -> Self {
        use TunnelProtocol::*;
        match self {
            UdpXor => Udp,
            IcmpXor => Icmp,
            TcpXor => Tcp,
            Proto58Xor => Proto58,
            GreXor => Gre,
            _ => *self,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum PerformanceMode {
    Throughput,
    Latency,
    Balanced,
}

#[derive(Clone, Debug)]
pub struct MuxFecConfig {
    pub enable_multiplex:      bool,
    pub multiplex_flush_ms:    u64,
    pub multiplex_max_payload: usize,
    pub enable_fec:            bool,
    pub fec_group_size:        usize,
}

impl MuxFecConfig {
    pub fn is_enabled(&self) -> bool {
        self.enable_multiplex || self.enable_fec
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub role:             Role,
    // The "physical" real IP address of this node.
    pub real_ip:          Ipv4Addr,
    // The "physical" real IP address of the peer node.
    pub peer_real_ip:     Ipv4Addr,
    // The "virtual" spoofed IP address of this node, placed in outgoing packets.
    pub spoofed_ip:       Ipv4Addr,
    // A pool of virtual spoofed IP addresses for this node, for rotation.
    // If empty, `spoofed_ip` is always used.
    pub spoofed_ip_pool:  Vec<Ipv4Addr>,
    // The "virtual" spoofed IP address of the peer node (expected in incoming packets).
    pub peer_spoofed_ip:  Ipv4Addr,
    // Uplink transport protocol for packets originating from this node.
    pub uplink_protocol:  TunnelProtocol,
    // Downlink transport protocol for packets destined to this node.
    pub downlink_protocol: TunnelProtocol,
    // The data port to listen on and send to.
    pub data_port:        u16,
    // If true, randomly choose data port from shuffle_port_min to shuffle_port_max for each packet (UDP/TCP only).
    pub shuffle_data_port: bool,
    // Minimum port number for shuffle_data_port.
    pub shuffle_port_min: u16,
    // Maximum port number for shuffle_data_port.
    pub shuffle_port_max: u16,

    // Use this ID for ICMP echo requests/replies.
    pub icmp_id:       u16,
    // If true, randomly choose ICMP ID for each packet.
    pub random_icmp_id: bool,

    // If true, enable UDP multiplexing (multiple logical packets per UDP frame).
    pub enable_multiplex: bool,
    // Flush multiplexed packets after this many milliseconds.
    pub multiplex_flush_ms: u64,
    // Max payload size for multiplexed frames.
    pub multiplex_max_payload: usize,

    // If true, enable XOR FEC on UDP multiplexed packets.
    pub enable_fec:     bool,
    // Number of data packets per FEC group. One parity packet is generated per group.
    pub fec_group_size: usize,

    // QUIC config.
    pub quic_server_name:      Option<String>,
    pub quic_cert:             Option<String>,
    pub quic_key:              Option<String>,
    pub quic_alpn:             Option<String>,
    pub quic_idle_timeout_ms:  u64,
    pub quic_max_data:         u64,
    pub quic_max_stream_data:  u64,
    pub quic_max_streams_bidi: u64,

    // Performance tuning.
    pub perf_mode: PerformanceMode,
    // Auto-tune performance parameters based on system resources.
    pub auto_tune: bool,

    // Whitelist of allowed physical peer IP addresses (in addition to `peer_real_ip`).
    pub allowed_peers: Vec<Ipv4Addr>,

    // Number of independent tunnels to maintain.
    pub tunnel_count: u8,
    // Pre-shared key for packet authentication (hex string).
    pub pre_shared_key: String,

    // Max capacity for internal MPSC channels.
    pub io_channel_capacity: usize,
    pub channel_capacity:    usize,

    // Log level (trace, debug, info, warn, error).
    pub log_level: String,

    // Raw socket config.
    pub interface: Option<String>,

    // TUN config.
    pub tun_name:    String,
    pub tun_ip:      Ipv4Addr,
    pub tun_peer_ip: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,

    // Max payload size for a tunnel packet (bytes).
    pub mtu:     usize,
    // MTU for the TUN interface (clamped to `mtu`).
    pub tun_mtu: usize,

    // Port forwarding.
    // Client-side port filter (TCP/UDP).
    pub forward_ports: Vec<u16>,
    // Old single port.
    pub forward_port:  u16,

    // XOR obfuscation.
    // If true, enable XOR stream encryption on all wire frames.
    pub enable_xor: bool,
    // Key string for XOR encryption. If empty, pre_shared_key is used.
    pub xor_key:    String,

    // DPI obfuscation.
    // If true, add random padding bytes to each wire frame to prevent length-based fingerprinting.
    // Receiver automatically strips padding.
    pub packet_padding: bool,
    // Max random padding bytes per frame (1-255, default 64).
    pub packet_padding_max: u8,
    // If true, randomly jitter IPv4 TTL from common OS values {64, 128, 255} to prevent pattern detection.
    pub ttl_jitter:     bool,
    // If true, prefix TCP payloads with a fake TLS Application Data record header.
    pub fake_tls_header: bool,
    // If true, set a random acceptable DSCP value in IPv4 ToS field.
    pub random_dscp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role:                      Role::Client,
            real_ip:                   Ipv4Addr::UNSPECIFIED,
            peer_real_ip:              Ipv4Addr::UNSPECIFIED,
            spoofed_ip:                Ipv4Addr::UNSPECIFIED,
            spoofed_ip_pool:           Vec::new(),
            peer_spoofed_ip:           Ipv4Addr::UNSPECIFIED,
            uplink_protocol:           TunnelProtocol::Udp,
            downlink_protocol:         TunnelProtocol::Udp,
            data_port:                 0,
            shuffle_data_port:         false,
            shuffle_port_min:          0,
            shuffle_port_max:          0,
            icmp_id:                   0,
            random_icmp_id:            false,
            enable_multiplex:          false,
            multiplex_flush_ms:        0,
            multiplex_max_payload:     0,
            enable_fec:                false,
            fec_group_size:            0,
            quic_server_name:          None,
            quic_cert:                 None,
            quic_key:                  None,
            quic_alpn:                 None,
            quic_idle_timeout_ms:      0,
            quic_max_data:             0,
            quic_max_stream_data:      0,
            quic_max_streams_bidi:     0,
            perf_mode:                 PerformanceMode::Balanced,
            auto_tune:                 false,
            allowed_peers:             Vec::new(),
            tunnel_count:              0,
            pre_shared_key:            String::new(),
            io_channel_capacity:       0,
            channel_capacity:          0,
            log_level:                 String::new(),
            interface:                 None,
            tun_name:                  String::new(),
            tun_ip:                    Ipv4Addr::UNSPECIFIED,
            tun_peer_ip:               Ipv4Addr::UNSPECIFIED,
            tun_netmask:               Ipv4Addr::UNSPECIFIED,
            mtu:                       0,
            tun_mtu:                   0,
            forward_ports:             Vec::new(),
            forward_port:              0,
            enable_xor:                false,
            xor_key:                   String::new(),
            packet_padding:            false,
            packet_padding_max:        0,
            ttl_jitter:                false,
            fake_tls_header:           false,
            random_dscp:               false,
        }
    }
}
