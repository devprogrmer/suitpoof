//! Configuration structs for the suitspoof server and client.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::Certificate;
use serde::Deserialize;
use tokio_rustls::rustls::sign::{self, SigningKey};
use tokio_rustls::rustls::PrivateKey;

use crate::mux_fec::MuxFecConfig;
use crate::tuning::Tuning;
use crate::xor::XorCipher;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Udp,
    Icmp,
    Tcp,
    Proto58,
    Ipip,
    Gre,
    Quic,
}

impl FromStr for TunnelProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            "tcp" => Ok(Self::Tcp),
            "proto58" => Ok(Self::Proto58),
            "ipip" => Ok(Self::Ipip),
            "gre" => Ok(Self::Gre),
            "quic" => Ok(Self::Quic),
            _ => bail!("unknown protocol '{}'", s),
        }
    }
}

impl TunnelProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Proto58 => "proto58",
            Self::Ipip => "ipip",
            Self::Gre => "gre",
            Self::Quic => "quic",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub role: Role,
    pub log_level: String,

    pub listen_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub peer_real_ip: Ipv4Addr,
    pub peer_spoofed_ip: Ipv4Addr,
    pub tun_name: String,
    pub tun_mtu: u16,
    pub tun_ip: Ipv4Addr,
    pub tun_peer_ip: Ipv4Addr,
    pub tun_cidr: u8,
    pub dns_servers: Vec<Ipv4Addr>,

    pub uplink_protocol: TunnelProtocol,
    pub downlink_protocol: TunnelProtocol,
    pub data_port: u16,
    pub data_port_shuffle: bool,
    pub data_port_range: (u16, u16),

    pub xor_key: String,
    pub dpi_obfuscation: bool,

    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_ca_cert_path: String,

    pub allowed_peers: Vec<Ipv4Addr>,

    pub tunnel_idle_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub channel_capacity: usize,
    pub io_channel_capacity: usize,
    pub runtime_threads: usize,
    pub icmp_id: u16,
    pub random_icmp_id: bool,

    pub enable_multiplex: bool,
    pub multiplex_flush_ms: u64,
    pub multiplex_max_payload: usize,
    pub enable_fec: bool,
    pub fec_group_size: u8,

    pub tuning: Option<Tuning>,

    pub check_mode: bool,
    pub check_ips_path: String,
    pub check_output_path: String,
    pub check_timeout: Duration,
    pub check_workers: usize,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read config file {}", path))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| format!("parse config file {}", path))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn is_client(&self) -> bool {
        self.role == Role::Client
    }

    pub fn tun_socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.tun_ip, 0)
    }

    pub fn tun_peer_socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.tun_peer_ip, 0)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tun_mtu < 576 || self.tun_mtu > 9000 {
            bail!("tun_mtu must be between 576 and 9000");
        }
        if self.tun_cidr == 0 || self.tun_cidr > 32 {
            bail!("tun_cidr must be between 1 and 32");
        }
        if self.data_port == 0 {
            bail!("data_port must be non-zero");
        }
        if self.data_port_range.0 == 0 || self.data_port_range.1 == 0 {
            bail!("data_port_range must be non-zero");
        }
        if self.data_port_shuffle {
            if self.data_port_range.0 >= self.data_port_range.1 {
                bail!("data_port_range start must be less than end");
            }
            if self.data_port_range.1 - self.data_port_range.0 < 100 {
                log::warn!(
                    "data_port_range is small; consider a range of at least 100 ports for better shuffling"
                );
            }
        }
        if self.tunnel_idle_timeout_secs < 10 {
            bail!("tunnel_idle_timeout_secs must be at least 10");
        }
        if self.handshake_timeout_secs < 5 {
            bail!("handshake_timeout_secs must be at least 5");
        }
        if self.heartbeat_interval_secs < 1 {
            bail!("heartbeat_interval_secs must be at least 1");
        }
        if self.channel_capacity < 1 {
            bail!("channel_capacity must be at least 1");
        }
        if self.io_channel_capacity < 1 {
            bail!("io_channel_capacity must be at least 1");
        }
        if self.runtime_threads == 0 {
            bail!("runtime_threads must be non-zero");
        }

        if self.uplink_protocol == TunnelProtocol::Quic
            || self.downlink_protocol == TunnelProtocol::Quic
        {
            if self.enable_multiplex || self.enable_fec {
                log::warn!("mux-fec is not used with QUIC transports");
            }
        }

        if self.enable_multiplex || self.enable_fec {
            self.mux_fec_config().validate()?;
        }

        self.validate_xor_key()?;

        if self.check_mode {
            if self.check_ips_path.is_empty() {
                bail!("check_ips_path must be set in check_mode");
            }
            if self.check_output_path.is_empty() {
                bail!("check_output_path must be set in check_mode");
            }
            if self.check_timeout < Duration::from_secs(1) {
                bail!("check_timeout must be at least 1 second");
            }
            if self.check_workers == 0 {
                bail!("check_workers must be non-zero");
            }
        }

        Ok(())
    }

    pub fn xor_cipher(&self) -> Option<XorCipher> {
        if self.xor_key.is_empty() {
            return None;
        }
        Some(XorCipher::new(&self.xor_key))
    }

    fn validate_xor_key(&self) -> Result<()> {
        if !self.xor_key.is_empty() && self.xor_key.len() < 16 {
            bail!("xor_key must be at least 16 bytes (characters)");
        }
        Ok(())
    }

    pub fn mux_fec_config(&self) -> MuxFecConfig {
        MuxFecConfig {
            enable_multiplex: self.enable_multiplex,
            multiplex_flush_ms: self.multiplex_flush_ms,
            multiplex_max_payload: self.multiplex_max_payload,
            enable_fec: self.enable_fec,
            fec_group_size: self.fec_group_size,
        }
    }

    pub fn build_tls_client_config(&self) -> Result<tokio_rustls::rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&self.tls_ca_cert_path)? {
            roots.add(&cert)?;
        }
        let client_cert = load_certs(&self.tls_cert_path)?;
        let client_key = load_private_key(&self.tls_key_path)?;
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_cert, client_key)?;
        Ok(config)
    }

    pub fn build_tls_server_config(&self) -> Result<tokio_rustls::rustls::ServerConfig> {
        let certs = load_certs(&self.tls_cert_path)?;
        let key = load_private_key(&self.tls_key_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&self.tls_ca_cert_path)? {
            roots.add(&cert)?;
        }
        let client_auth = AllowAnyAuthenticatedClient::new(roots);
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
            .map_err(|e| anyhow!("build_tls_server_config: {}", e))?;
        Ok(config)
    }

    pub fn pick_icmp_id(&self) -> u16 {
        if self.random_icmp_id {
            rand::random()
        } else {
            self.icmp_id
        }
    }

    pub fn shuffle_port_range(&self) -> std::ops::Range<u16> {
        self.data_port_range.0..self.data_port_range.1
    }

    pub fn build_data_port_pool(&self) -> Result<Option<Arc<Vec<u16>>>> {
        if !self.data_port_shuffle {
            return Ok(None);
        }
        let ports = shuffle_ports(self.data_port_range.0, self.data_port_range.1)?;
        Ok(Some(Arc::new(ports)))
    }
}

pub fn pick_data_port(default_port: u16, pool: &Option<Arc<Vec<u16>>>) -> u16 {
    if let Some(p) = pool {
        let idx = rand::random::<usize>() % p.len();
        p[idx]
    } else {
        default_port
    }
}

pub fn shuffle_ports(min: u16, max: u16) -> Result<Vec<u16>> {
    let count = max - min;
    if count == 0 {
        bail!("port range is empty");
    }
    let mut ports: Vec<u16> = (min..max).collect();
    for i in (1..ports.len()).rev() {
        let j = rand::random::<usize>() % (i + 1);
        ports.swap(i, j);
    }
    Ok(ports)
}

fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let cert_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey> {
    let key_bytes = std::fs::read(path)?;
    Ok(PrivateKey(key_bytes))
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct License {
    pub name: String,
    pub expiry: u64,
    pub max_tunnels: u32,
    pub key_bytes: Vec<u8>,
}

impl License {
    pub fn new(name: String, expiry: u64, max_tunnels: u32, key_bytes: Vec<u8>) -> Self {
        Self {
            name,
            expiry,
            max_tunnels,
            key_bytes,
        }
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let lic: Self = serde_json::from_str(&content)?;
        Ok(lic)
    }

    pub fn decode(b64_key: &str, password: &str) -> Result<Self> {
        let key_bytes = base64::decode(b64_key)?;
        let decrypted = Self::decrypt_with_password(&key_bytes, password)?;
        let lic: Self = serde_json::from_slice(&decrypted)?;
        Ok(lic)
    }

    pub fn encrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher};

        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)?;
        let key = hash.hash.as_ref().context("no hash")?.as_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(b"suitspoof-non");
        let encrypted_data = cipher.encrypt(nonce, data)?;

        let mut output = salt.as_str().as_bytes().to_vec();
        output.extend_from_slice(b":");
        output.extend_from_slice(&encrypted_data);

        Ok(output)
    }

    pub fn decrypt_with_password(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};

        let parts: Vec<&[u8]> = encrypted_data.splitn(2, |&b| b == b':').collect();
        if parts.len() != 2 {
            bail!("invalid encrypted data format");
        }
        let salt_bytes = parts[0];
        let encrypted_payload = parts[1];

        let salt_str = std::str::from_utf8(salt_bytes)?;
        let salt = SaltString::from_str(salt_str)?;

        let argon2 = Argon2::default();
        let expected_hash = argon2.hash_password(password.as_bytes(), &salt)?;

        let key = expected_hash.hash.as_ref().context("no hash")?.as_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(b"suitspoof-non");
        let decrypted_data = cipher.decrypt(nonce, encrypted_payload.as_ref())?;
        Ok(decrypted_data)
    }

    pub async fn read_key_pem(path: &str) -> Result<Vec<u8>> {
        let key_pem = tokio::fs::read_to_string(path).await?;
        let key_bytes =
            tokio_rustls::rustls::sign::any_ecdsa_type(&PrivateKey(key_pem.as_bytes().to_vec()))
                .map_err(|_| anyhow!("invalid key file"))?;
        Ok(key_bytes.public_key().to_vec())
    }

    pub async fn sign(key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = sign::any_ecdsa_type(key).map_err(|_| anyhow!("invalid key file"))?;
        let signature = signing_key.sign(data)?;
        Ok(signature.as_ref().to_vec())
    }

    pub async fn verify_signature(
        _key_bytes: &[u8],
        _signature: &[u8],
        _data: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    pub fn to_jwt_token(&self, secret: &[u8]) -> Result<String> {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let token = encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret),
        )?;
        Ok(token)
    }

    pub fn from_jwt_token(token: &str, secret: &[u8]) -> Result<Self> {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let token_data = decode::<Self>(
            token,
            &DecodingKey::from_secret(secret),
            &validation,
        )?;
        Ok(token_data.claims)
    }
}

#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}
