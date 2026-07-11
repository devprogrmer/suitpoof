//! Runtime auto-tuning of suitspoof parameters.

use std::time::Duration;

use serde::Deserialize;

use crate::config::Config;

/// Automatically tune configuration parameters at runtime based on system
/// characteristics and whether DPI obfuscation is enabled.
#[derive(Debug, Clone, Deserialize)]
pub struct Tuning {
    pub enabled: bool,
    pub auto_io_threads: bool,
    pub auto_runtime_threads: bool,
    pub auto_channel_capacity: bool,
    pub auto_multiplex_flush_ms: bool,
    pub auto_multiplex_max_payload: bool,
    pub auto_fec_group_size: bool,
    pub auto_heartbeat_interval_secs: bool,
    pub auto_tunnel_idle_timeout_secs: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_io_threads: true,
            auto_runtime_threads: true,
            auto_channel_capacity: true,
            auto_multiplex_flush_ms: true,
            auto_multiplex_max_payload: true,
            auto_fec_group_size: true,
            auto_heartbeat_interval_secs: true,
            auto_tunnel_idle_timeout_secs: true,
        }
    }
}

#[derive(Debug)]
pub enum AutoTuneReason {
    DpiEnabled,
    DpiEnabledSuit,
    InitialSetup,
}

#[derive(Debug)]
pub struct TuningSummary(Vec<String>);

impl TuningSummary {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, line: String) {
        self.0.push(line);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn lines(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }
}

pub fn apply_auto_tune(cfg: &mut Config) -> Option<TuningSummary> {
    if !cfg.tuning.as_ref().map_or(false, |t| t.enabled) {
        return None;
    }

    let mut summary = TuningSummary::new();
    let tuning = cfg.tuning.as_ref().unwrap();
    let mut reason = AutoTuneReason::InitialSetup;

    if cfg.dpi_obfuscation {
        reason = AutoTuneReason::DpiEnabled;

        let uplink = cfg.uplink_protocol.as_str().to_ascii_lowercase();
        let downlink = cfg.downlink_protocol.as_str().to_ascii_lowercase();

        if uplink.contains("suit") || downlink.contains("suit") {
            reason = AutoTuneReason::DpiEnabledSuit;
        }
    }

    match reason {
        AutoTuneReason::DpiEnabled => {
            if tuning.auto_io_threads {
                cfg.io_channel_capacity = 256;
                summary.add("io_channel_capacity = 256 (DPI enabled)".to_string());
            }
            if tuning.auto_heartbeat_interval_secs {
                cfg.heartbeat_interval_secs = 2;
                summary.add("heartbeat_interval_secs = 2 (DPI enabled)".to_string());
            }
            if tuning.auto_tunnel_idle_timeout_secs {
                cfg.tunnel_idle_timeout_secs = 10;
                summary.add("tunnel_idle_timeout_secs = 10 (DPI enabled)".to_string());
            }
        }
        AutoTuneReason::DpiEnabledSuit => {
            if tuning.auto_io_threads {
                cfg.io_channel_capacity = 512;
                summary.add("io_channel_capacity = 512 (DPI enabled, suit-specific)".to_string());
            }
            if tuning.auto_heartbeat_interval_secs {
                cfg.heartbeat_interval_secs = 1;
                summary.add("heartbeat_interval_secs = 1 (DPI enabled, suit-specific)".to_string());
            }
            if tuning.auto_tunnel_idle_timeout_secs {
                cfg.tunnel_idle_timeout_secs = 5;
                summary.add("tunnel_idle_timeout_secs = 5 (DPI enabled, suit-specific)".to_string());
            }
        }
        AutoTuneReason::InitialSetup => {}
    }

    if summary.is_empty() {
        None
    } else {
        Some(summary)
    }
}

pub fn effective_runtime_threads(cfg: &Config) -> usize {
    if cfg.tuning.as_ref().map_or(false, |t| !t.auto_runtime_threads) {
        return cfg.runtime_threads;
    }

    std::cmp::max(1, num_cpus::get_physical() / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Role, TunnelProtocol};
    use std::net::Ipv4Addr;

    fn default_config() -> Config {
        Config {
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
            dns_servers: vec![],
            uplink_protocol: TunnelProtocol::Udp,
            downlink_protocol: TunnelProtocol::Udp,
            data_port: 12345,
            data_port_shuffle: false,
            data_port_range: (0, 0),
            xor_key: "".to_string(),
            dpi_obfuscation: false,
            tls_cert_path: "".to_string(),
            tls_key_path: "".to_string(),
            tls_ca_cert_path: "".to_string(),
            allowed_peers: vec![],
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
        }
    }

    #[test]
    fn test_apply_auto_tune_initial_setup() {
        let mut cfg = default_config();
        cfg.dpi_obfuscation = false;
        let summary = apply_auto_tune(&mut cfg);
        assert!(summary.is_none());
    }

    #[test]
    fn test_apply_auto_tune_dpi_enabled() {
        let mut cfg = default_config();
        cfg.dpi_obfuscation = true;
        let summary = apply_auto_tune(&mut cfg).unwrap();
        assert!(!summary.is_empty());
        assert_eq!(cfg.io_channel_capacity, 256);
        assert_eq!(cfg.heartbeat_interval_secs, 2);
        assert_eq!(cfg.tunnel_idle_timeout_secs, 10);
    }

    #[test]
    fn test_effective_runtime_threads_auto_tuned() {
        let mut cfg = default_config();
        cfg.tuning = Some(Tuning {
            auto_runtime_threads: true,
            ..Tuning::default()
        });
        assert!(effective_runtime_threads(&cfg) > 0);
    }

    #[test]
    fn test_effective_runtime_threads_manual() {
        let mut cfg = default_config();
        cfg.tuning = Some(Tuning {
            auto_runtime_threads: false,
            ..Tuning::default()
        });
        cfg.runtime_threads = 8;
        assert_eq!(effective_runtime_threads(&cfg), 8);
    }
}
