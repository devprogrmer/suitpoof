//! XOR-style framing helper.
//! [ nonce : 12 bytes ][ ciphertext : N bytes ]
//!
//! The previous implementation used SHA-256 CTR which hashes 32 bytes per
//! block -- roughly one SHA-256 call per 32 bytes of plaintext. ChaCha20 is a
//! purpose-built stream cipher that processes 64 bytes per block and
//! auto-vectorises to AVX2/NEON, achieving substantially better throughput
//! with lower CPU cost.
//!
//! # Wire layout
//!
//! [ nonce : 12 bytes ][ ciphertext : N bytes ]

use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;

/// 32-byte static key (placeholder). Replace with your key-management later.
const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

type ChaCha20 = chacha20::ChaCha20;

/// Encrypt payload -> [nonce(12) | ciphertext(N)]
pub fn seal_xor(payload: &[u8]) -> Bytes {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut out = BytesMut::with_capacity(12 + payload.len());
    out.put_slice(&nonce);

    let mut ct = payload.to_vec();
    let mut cipher = ChaCha20::new(&KEY.into(), &nonce.into());
    cipher.apply_keystream(&mut ct);
    out.put_slice(&ct);

    out.freeze()
}

/// Decrypt frame [nonce(12) | ciphertext(N)] -> plaintext
pub fn open_xor(frame: &[u8]) -> Result<Bytes> {
    if frame.len() < 12 {
        bail!("xor frame too short: {}", frame.len());
    }

    let (nonce, ct) = frame.split_at(12);
    let mut pt = ct.to_vec();

    let mut cipher = ChaCha20::new(&KEY.into(), nonce.into());
    cipher.apply_keystream(&mut pt);

    Ok(Bytes::from(pt))
}
