use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Raw transport mode used by suitspoof.
/// NOTE:
/// - In most deployments we use UDP socket as carrier for reliability + compatibility.
/// - Raw IP/ICMP crafting usually requires CAP_NET_RAW/root and is platform-sensitive.
/// This module provides a safe UDP fallback plus optional raw-socket constructor.
#[derive(Debug, Clone)]
pub struct RawSocketConfig {
    pub bind_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub recv_buf_size: usize,
    pub send_buf_size: usize,
}

impl Default for RawSocketConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            peer_addr: SocketAddr::from(([127, 0, 0, 1], 4000)),
            recv_buf_size: 4 * 1024 * 1024,
            send_buf_size: 4 * 1024 * 1024,
        }
    }
}

/// Runtime raw transport wrapper (UDP carrier).
pub struct RawTransport {
    sock: UdpSocket,
    peer: SocketAddr,
}

impl RawTransport {
    /// Create transport using UDP socket (recommended path).
    pub async fn bind(cfg: &RawSocketConfig) -> Result<Self> {
        let std_sock = std::net::UdpSocket::bind(cfg.bind_addr)
            .with_context(|| format!("bind udp failed on {}", cfg.bind_addr))?;
        std_sock
            .set_nonblocking(true)
            .context("set_nonblocking failed")?;
        std_sock
            .set_recv_buffer_size(cfg.recv_buf_size)
            .context("set recv buffer size failed")?;
        std_sock
            .set_send_buffer_size(cfg.send_buf_size)
            .context("set send buffer size failed")?;

        let sock = UdpSocket::from_std(std_sock).context("tokio UdpSocket::from_std failed")?;

        debug!(
            "raw transport udp bound {} -> peer {}",
            sock.local_addr().unwrap_or(cfg.bind_addr),
            cfg.peer_addr
        );

        Ok(Self {
            sock,
            peer: cfg.peer_addr,
        })
    }

    /// Send one datagram/frame to configured peer.
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let n = self
            .sock
            .send_to(data, self.peer)
            .await
            .with_context(|| format!("udp send_to {} failed", self.peer))?;
        Ok(n)
    }

    /// Receive one datagram/frame from any peer.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, from) = self.sock.recv_from(buf).await.context("udp recv_from failed")?;
        Ok((n, from))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.sock.local_addr().context("udp local_addr failed")
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

/// Optional: construct a platform raw socket (IPv4/ICMP) for advanced use-cases.
/// Not used by default data-path; provided for future spoof/craft extensions.
///
/// Requires elevated privileges (root/CAP_NET_RAW).
pub fn try_create_icmp_raw_socket() -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("create raw icmp socket failed (need CAP_NET_RAW/root?)")?;

    // common safe defaults
    sock.set_nonblocking(true)
        .context("set_nonblocking on raw socket failed")?;

    #[cfg(target_os = "linux")]
    {
        // Hint kernel to include IP header? Usually false for ICMP raw on Linux unless crafting full IP packets.
        // Keep untouched unless full packet crafting is enabled.
    }

    Ok(sock)
}

/// Minimal IPv4 header builder (if ever needed for crafted packets).
/// Returns header bytes without payload checksum for transport segment.
pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    total_len: u16,
    identification: u16,
    ttl: u8,
) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = (4 << 4) | 5; // version=4, ihl=5
    h[1] = 0; // dscp/ecn
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[4..6].copy_from_slice(&identification.to_be_bytes());
    h[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/frag
    h[8] = ttl;
    h[9] = proto;
    h[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());

    let csum = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

/// Standard Internet checksum (RFC 1071).
pub fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0usize;

    while i + 1 < data.len() {
        let w = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(w);
        i += 2;
    }

    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Helper to parse IPv4 from generic IpAddr.
pub fn as_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Validate raw environment quickly.
pub fn raw_env_check() {
    #[cfg(unix)]
    {
        if nix::unistd::Uid::effective().is_root() {
            debug!("raw_socket: running as root");
        } else {
            warn!("raw_socket: not running as root (raw mode may fail, udp fallback is fine)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_nonzero() {
        let h = build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            60,
            0x1234,
            64,
        );
        // checksum field exists
        let c = u16::from_be_bytes([h[10], h[11]]);
        assert_ne!(c, 0);
    }

    #[test]
    fn as_ipv4_works() {
        assert!(as_ipv4(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_some());
        assert!(as_ipv4("::1".parse::<IpAddr>().unwrap()).is_none());
    }
}
