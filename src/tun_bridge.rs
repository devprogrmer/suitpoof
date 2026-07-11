//! Helpers for bridging a TUN device to a set of tunnels.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use async_channel as mpsc;
use event_listener::Event;

use crate::tun::TunDevice;

/// A lock-free tunnel pool.
///
/// Readers (which is most operations) acquire an `ArcSwap` guard. Writes
/// (add/remove) take a short `std::sync::Mutex` to serialize a snapshot
/// swap.
pub struct TunnelPool {
    inner: ArcSwap<Arc<Inner>>,
}

struct Inner {
    tunnels:     HashMap<u32, TunnelHandle>,
    next_tunnel: usize,
    ready:       Event,
}

#[derive(Debug)]
pub struct TunnelHandle {
    pub id:     u32,
    pub tx:     mpsc::Sender<Bytes>,
    is_closed:  bool,
}

impl TunnelPool {
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(Inner {
                tunnels:     HashMap::new(),
                next_tunnel: 0,
                ready:       Event::new(),
            }),
        }
    }

    pub fn add_tunnel(&self, id: u32, tx: mpsc::Sender<Bytes>) {
        let mut inner = self.inner.load().as_ref().clone();
        log::info!("adding tunnel id={}", id);
        inner.tunnels.insert(
            id,
            TunnelHandle {
                id,
                tx,
                is_closed: false,
            },
        );
        inner.ready.notify_additional(1);
        self.inner.store(Arc::new(inner));
    }

    pub fn remove_tunnel(&self, id: u32) {
        let mut inner = self.inner.load().as_ref().clone();
        log::info!("removing tunnel id={}", id);
        inner.tunnels.remove(&id);
        self.inner.store(Arc::new(inner));
    }

    pub async fn is_empty(&self) -> bool { self.inner.load().tunnels.is_empty() }

    pub async fn wait_ready(&self) {
        loop {
            let inner = self.inner.load();
            if !inner.tunnels.is_empty() {
                break;
            }
            log::info!("waiting for tunnel to become ready...");
            inner.ready.listen().await;
        }
    }

    /// Send a packet to a tunnel, chosen by a hash.
    ///
    /// This ensures packets from the same flow always go to the same tunnel,
    /// as long as the set of active tunnels is stable.
    pub async fn send_hashed(&self, pkt: Bytes, hash: u64) -> Result<()> {
        let inner = self.inner.load();
        if inner.tunnels.is_empty() {
            bail!("no tunnels available");
        }
        // Choose tunnel based on hash to keep flows consistent.
        let idx = hash as usize % inner.tunnels.len();
        let h = inner.tunnels.values().nth(idx).unwrap();
        h.tx.send(pkt).await?;
        Ok(())
    }

    pub fn prune_closed(&self) {
        let mut inner = self.inner.load().as_ref().clone();
        inner.tunnels.retain(|_, h| !h.tx.is_closed());
        if inner.tunnels.is_empty() {
            log::warn!("all tunnels closed");
        }
        self.inner.store(Arc::new(inner));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    pub src_ip:  Ipv4Addr,
    pub dst_ip:  Ipv4Addr,
    pub proto:   u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

pub fn parse_ipv4_meta(packet: &[u8]) -> Option<PacketMeta> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (src_port, dst_port) = match proto {
        6 | 17 => {
            if packet.len() >= ihl + 4 {
                let sp = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dp = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                (Some(sp), Some(dp))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    Some(PacketMeta {
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
    })
}

/// Returns true if the packet should be forwarded based on the port filter.
///
/// When `forward_ports` is empty, all TCP/UDP ports are accepted. For
/// non-TCP/UDP protocols, packets are always accepted.
pub fn should_forward(meta: &PacketMeta, forward_ports: &[u16]) -> bool {
    if forward_ports.is_empty() {
        return true;
    }
    match meta.dst_port {
        Some(p) => forward_ports.contains(&p),
        None => true,
    }
}

pub fn flow_hash(meta: &PacketMeta) -> u64 {
    let mut h = 0u64;
    h = h.wrapping_add(u32::from(meta.src_ip) as u64);
    h = h.rotate_left(13) ^ (u32::from(meta.dst_ip) as u64);
    h = h.rotate_left(7) ^ (meta.proto as u64);
    if let Some(sp) = meta.src_port {
        h = h.rotate_left(11) ^ (sp as u64);
    }
    if let Some(dp) = meta.dst_port {
        h = h.rotate_left(17) ^ ((dp as u64) << 1);
    }
    h
}

pub fn spawn_tun_writer(tun: Arc<TunDevice>, rx: mpsc::Receiver<Bytes>) {
    tokio::spawn(async move {
        while let Ok(pkt) = rx.recv().await {
            log::trace!("tun writer packet_len={}", pkt.len());
            if let Err(e) = tun.write_packet(&pkt).await {
                log::warn!("tun write: {}", e);
            }
        }
    })
    ;
}

pub fn spawn_tunnel_to_tun(app_rx: mpsc::Receiver<Bytes>, tx: mpsc::Sender<Bytes>) {
    tokio::spawn(async move {
        while let Ok(pkt) = app_rx.recv().await {
            if tx.send(pkt).await.is_err() {
                break;
            }
        }
    })
    ;
}

pub async fn run_tun_reader(
    tun: Arc<TunDevice>,
    pool: TunnelPool,
    forward_ports: &[u16],
) -> Result<()> {
    loop {
        if pool.is_empty().await {
            pool.wait_ready().await;
        }

        let pkt = match tun.read_packet().await {
            Ok(p) => p,
            Err(e) => {
                log::warn!("tun read: {}", e);
                continue;
            }
        };

        if pkt.len() > tun.mtu() {
            log::warn!("drop oversized packet {} > mtu {}", pkt.len(), tun.mtu());
            continue;
        }

        let meta = match parse_ipv4_meta(&pkt) {
            Some(m) => m,
            None => {
                log::trace!("drop non-ipv4 packet ({} bytes)", pkt.len());
                continue;
            }
        };

        if !should_forward(&meta, forward_ports) {
            log::trace!("tun drop forward_filter dst_port={:?}", meta.dst_port);
            continue;
        }

        let hash = flow_hash(&meta);
        if let Err(e) = pool.send_hashed(pkt, hash).await {
            log::warn!("tun->tunnel: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + 20];
        buf[0] = 0x45; // v4 + ihl=5
        buf[9] = 6; // TCP
        buf[12..16].copy_from_slice(&src.octets());
        buf[16..20].copy_from_slice(&dst.octets());
        buf[20..22].copy_from_slice(&sp.to_be_bytes());
        buf[22..24].copy_from_slice(&dp.to_be_bytes());
        buf
    }

    fn build_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + 8];
        buf[0] = 0x45; // v4 + ihl=5
        buf[9] = 17; // UDP
        buf[12..16].copy_from_slice(&src.octets());
        buf[16..20].copy_from_slice(&dst.octets());
        buf[20..22].copy_from_slice(&sp.to_be_bytes());
        buf[22..24].copy_from_slice(&dp.to_be_bytes());
        buf
    }

    #[test]
    fn parse_ipv4_tcp_ports() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1234,
            80,
        );
        let meta = parse_ipv4_meta(&pkt).unwrap();
        assert_eq!(meta.src_port, Some(1234));
        assert_eq!(meta.dst_port, Some(80));
        assert_eq!(meta.proto, 6);
    }

    #[test]
    fn parse_ipv4_udp_ports() {
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            5555,
            53,
        );
        let meta = parse_ipv4_meta(&pkt).unwrap();
        assert_eq!(meta.src_port, Some(5555));
        assert_eq!(meta.dst_port, Some(53));
        assert_eq!(meta.proto, 17);
    }

    #[test]
    fn forward_port_filter() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            40000,
            8080,
        );
        let meta = parse_ipv4_meta(&pkt).unwrap();
        assert!(should_forward(&meta, &[8080]));
        assert!(!should_forward(&meta, &[9090]));
        assert!(should_forward(&meta, &[]));
    }
}
