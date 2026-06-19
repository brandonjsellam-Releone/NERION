//! polarseek-crypto (Rust) — PQ signature primitive for the hot-path SuiteID
//! contract, mirroring the TypeScript reference (crypto/src).
//!
//! STATUS: compiles + type-checks here (`cargo build`, `cargo test --no-run`).
//! The build sandbox blocks EXECUTING freshly-built binaries, so `cargo test`
//! was not RUN in this environment — run it on a normal machine to execute the
//! assertions. Keygen is deterministic (FIPS 204 KeyGen_internal from a 32-byte
//! seed), so no OS RNG is needed here. The conformance suite (../conformance) is
//! the cross-implementation contract this crate must ultimately satisfy.
//!
//! Build note (windows-gnu): a transitive dep (`getrandom`) links a Windows
//! import lib, which needs `dlltool`. The rustup gnu toolchain bundles one under
//! `…/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/`; put that dir on
//! PATH if the build can't find `dlltool.exe`.

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{B32, Keypair, MlDsa87, Signature, SigningKey};
use ml_kem::kem::TryDecapsulate;
use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};
use sha3::{Digest, Sha3_256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha384;

type HmacSha384 = Hmac<Sha384>;

/// SuiteID identifiers mirroring crypto/src/suites.ts (active subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteId {
    /// General / CNSA-transition tier.
    Ps1,
    /// Regulated CNSA 2.0 Cat-5 tier.
    Ps5,
}

impl SuiteId {
    pub fn as_str(&self) -> &'static str {
        match self {
            SuiteId::Ps1 => "PS-1",
            SuiteId::Ps5 => "PS-5",
        }
    }
    /// General-purpose signature scheme for the active suites.
    pub fn signature_alg(&self) -> &'static str {
        "ML-DSA-87"
    }
}

/// SHA3-256 digest — the receipt/commitment hash used across PolarSeek.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// An ML-DSA-87 (FIPS 204) signing key.
pub struct MlDsaKeypair {
    sk: SigningKey<MlDsa87>,
}

impl MlDsaKeypair {
    /// Deterministic keygen from a 32-byte seed (FIPS 204 KeyGen_internal).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            sk: SigningKey::<MlDsa87>::from_seed(&B32::from(seed)),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature<MlDsa87> {
        self.sk.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature<MlDsa87>) -> bool {
        self.sk.verifying_key().verify(msg, sig).is_ok()
    }
}

/// ML-KEM-1024 (FIPS 203) deterministic encapsulate/decapsulate round-trip.
/// Uses FIPS deterministic keygen (64-byte d‖z seed) and deterministic
/// encapsulation (32-byte m), so no OS RNG is needed. Returns true iff both
/// sides derive the same shared secret.
pub fn mlkem1024_roundtrip_ok(seed: [u8; 64], m: [u8; 32]) -> bool {
    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(seed));
    let ek = dk.encapsulation_key();
    let (ct, ss_send) = ek.encapsulate_deterministic(&KemB32::from(m));
    let ss_recv = dk.try_decapsulate(&ct).expect("decapsulate");
    ss_send == ss_recv
}

/// HMAC-SHA-384 — the Plane-1 PermitToken MAC (matches crypto/src/symmetric.ts).
pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> [u8; 48] {
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    out
}

/// Constant-time HMAC-SHA-384 verification.
pub fn hmac_sha384_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

/// AES-256-GCM seal (transport AEAD). Output is ciphertext || 16-byte tag.
pub fn aes256gcm_seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .expect("AES-256-GCM encryption")
}

/// AES-256-GCM open; returns None on tag/AAD mismatch (never panics on bad input).
pub fn aes256gcm_open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key).expect("32-byte key");
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_digest_is_32_bytes() {
        assert_eq!(sha3_256(b"polarseek").len(), 32);
    }

    #[test]
    fn suite_ids_match_contract() {
        assert_eq!(SuiteId::Ps5.as_str(), "PS-5");
        assert_eq!(SuiteId::Ps5.signature_alg(), "ML-DSA-87");
    }

    #[test]
    fn ml_dsa_sign_verify_roundtrip() {
        let kp = MlDsaKeypair::from_seed([7u8; 32]);
        let msg = b"action: transfer 5 USDC to vendor-acme";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn ml_dsa_rejects_tampered_message() {
        let kp = MlDsaKeypair::from_seed([9u8; 32]);
        let sig = kp.sign(b"original action");
        assert!(!kp.verify(b"tampered action", &sig));
    }

    #[test]
    fn keygen_is_deterministic() {
        let a = MlDsaKeypair::from_seed([3u8; 32]);
        let b = MlDsaKeypair::from_seed([3u8; 32]);
        let msg = b"determinism";
        // Same seed -> same key -> a signature from one verifies under the other.
        assert!(b.verify(msg, &a.sign(msg)));
    }

    #[test]
    fn ml_kem_1024_encaps_decaps_roundtrip() {
        assert!(mlkem1024_roundtrip_ok([1u8; 64], [3u8; 32]));
    }

    #[test]
    fn hmac_sha384_roundtrip_and_tamper() {
        let key = [1u8; 32];
        let msg = b"PolarSeek-Permit-v1";
        let tag = hmac_sha384(&key, msg);
        assert_eq!(tag.len(), 48);
        assert!(hmac_sha384_verify(&key, msg, &tag));
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!hmac_sha384_verify(&key, msg, &bad));
        assert!(!hmac_sha384_verify(&[2u8; 32], msg, &tag));
    }

    #[test]
    fn aes256gcm_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let pt = b"hot-path payload";
        let aad = b"suite=PS-5";
        let ct = aes256gcm_seal(&key, &nonce, pt, aad);
        assert_eq!(aes256gcm_open(&key, &nonce, &ct, aad).as_deref(), Some(&pt[..]));
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert!(aes256gcm_open(&key, &nonce, &bad, aad).is_none());
        assert!(aes256gcm_open(&key, &nonce, &ct, b"suite=PS-1").is_none());
    }
}
