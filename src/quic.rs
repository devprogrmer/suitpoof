use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// QUIC runtime config used by suitspoof transport layer.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub bind_addr: SocketAddr,
    pub peer_addr: Option<SocketAddr>,
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4443".parse().expect("valid socket"),
            peer_addr: None,
            server_name: "localhost".to_string(),
            alpn: vec![b"suitspoof/1".to_vec()],
            cert_der: Vec::new(),
            key_der: Vec::new(),
            idle_timeout_ms: 30_000,
            keep_alive_interval_ms: 5_000,
        }
    }
}

fn build_transport(cfg: &QuicConfig) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();

    let idle = std::time::Duration::from_millis(cfg.idle_timeout_ms);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle).unwrap_or_else(|_| {
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).expect("idle timeout")
        }),
    ));

    transport.keep_alive_interval(Some(std::time::Duration::from_millis(
        cfg.keep_alive_interval_ms,
    )));

    Arc::new(transport)
}

fn build_server_config(cfg: &QuicConfig) -> Result<ServerConfig> {
    let cert: CertificateDer<'static> = CertificateDer::from(cfg.cert_der.clone());
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cfg.key_der.clone()));

    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
        .context("failed to build quic server config with certificate/key")?;

    server_config.transport = build_transport(cfg);
    Ok(server_config)
}

fn build_client_config(cfg: &QuicConfig) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(cfg.cert_der.clone()))
        .context("failed to add server certificate to client root store")?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    crypto.alpn_protocols = cfg.alpn.clone();

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("failed to convert rustls client config to quinn config")?,
    ));

    client_config.transport_config(build_transport(cfg));
    Ok(client_config)
}

/// Lightweight QUIC connection wrapper.
pub struct QuicConnection {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl QuicConnection {
    pub async fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len() as u32;
        self.send
            .write_u32(len)
            .await
            .context("quic write frame length failed")?;
        self.send
            .write_all(payload)
            .await
            .context("quic write frame payload failed")?;
        self.send.flush().await.context("quic flush failed")?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<Bytes> {
        let len = self
            .recv
            .read_u32()
            .await
            .context("quic read frame length failed")?;
        let mut buf = vec![0u8; len as usize];
        self.recv
            .read_exact(&mut buf)
            .await
            .context("quic read frame payload failed")?;
        Ok(Bytes::from(buf))
    }

    pub async fn close(mut self) -> Result<()> {
        self.send.finish().context("quic finish send stream failed")?;
        Ok(())
    }
}

/// Run QUIC server: accept one bi-directional stream and return connection.
pub async fn accept_quic(cfg: &QuicConfig) -> Result<QuicConnection> {
    let server_config = build_server_config(cfg)?;
    let endpoint = Endpoint::server(server_config, cfg.bind_addr)
        .context("failed to start quic server endpoint")?;

    info!("quic server listening on {}", cfg.bind_addr);

    let incoming = endpoint
        .accept()
        .await
        .context("quic endpoint closed before accept")?;
    let new_conn = incoming.await.context("quic incoming handshake failed")?;

    info!(
        "quic server accepted connection from {}",
        new_conn.remote_address()
    );

    let (send, recv) = new_conn
        .accept_bi()
        .await
        .context("quic accept_bi failed")?;

    Ok(QuicConnection { send, recv })
}

/// Run QUIC client: connect and open one bi-directional stream.
pub async fn connect_quic(cfg: &QuicConfig) -> Result<QuicConnection> {
    let peer = cfg.peer_addr.context("quic peer_addr is required for client")?;

    let mut endpoint =
        Endpoint::client(cfg.bind_addr).context("failed to create quic client endpoint")?;
    endpoint.set_default_client_config(build_client_config(cfg)?);

    let server_name = ServerName::try_from(cfg.server_name.clone())
        .context("invalid quic server_name for TLS")?;

    let conn = endpoint
        .connect(peer, server_name.as_ref())
        .context("quic connect() failed")?
        .await
        .context("quic handshake failed")?;

    info!("quic client connected to {}", peer);

    let (send, recv) = conn
        .open_bi()
        .await
        .context("quic open_bi stream failed")?;

    Ok(QuicConnection { send, recv })
}

/// Generate a self-signed cert/key pair (DER) for quick bootstrap/testing.
pub fn generate_self_signed(server_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec![server_name.to_string()])
        .context("failed to generate self-signed cert")?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    Ok((cert_der, key_der))
}

/// Simple ping helper over QUIC framed stream.
pub async fn quic_ping(conn: &mut QuicConnection) -> Result<()> {
    conn.send_frame(b"ping").await?;
    let got = conn.recv_frame().await?;
    if got.as_ref() != b"pong" {
        warn!("unexpected quic ping reply: {:?}", got);
    } else {
        debug!("quic ping ok");
    }
    Ok(())
}
