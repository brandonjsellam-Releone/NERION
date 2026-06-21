// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

//! polarseek-crypto (Rust) — PQ signature primitive for the hot-path SuiteID
//! contract, mirroring the TypeScript reference (crypto/src).
//!
//! STATUS: builds AND `cargo test` PASSES here — 9 tests, including
//! `ts_kat_vectors_reproduce`, which loads ../conformance/vectors/ps-kat.json and
//! confirms this crate byte-matches the TypeScript reference for SHA3-256,
//! HMAC-SHA-384, AES-256-GCM, and the ML-DSA-87 *public key* (FIPS 204 keygen
//! from a 32-byte seed). The secret key is intentionally not cross-checked: this
//! crate stores it in seed form, @noble in expanded form. Keygen is deterministic
//! (FIPS 204 KeyGen_internal), so no OS RNG is needed. ../conformance is the
//! cross-implementation contract this crate satisfies.
//!
//! Build note (windows-gnu): a transitive dep (`getrandom`) links a Windows
//! import lib, which needs `dlltool`. The rustup gnu toolchain bundles one under
//! `…/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained/`; put that dir on
//! PATH if the build can't find `dlltool.exe`.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{B32, Keypair, MlDsa87, Signature, SigningKey};
use ml_kem::kem::TryDecapsulate;
use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};
use sha2::Sha384;
use sha3::{Digest, Sha3_256};

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

/// SHAKE256 extendable-output function — mirrors the TS reference
/// (`crypto/src/symmetric.ts` `SHA3_SHAKE256.xof`, i.e. @noble's
/// `shake256(message, { dkLen })`). Returns exactly `out_len` bytes.
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    use shake::{ExtendableOutput, Shake256, Update, XofReader};
    let mut x = Shake256::default();
    x.update(data);
    let mut reader = x.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
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

    /// FIPS 204 encoded public-key bytes (ρ‖t1) — for cross-implementation KATs.
    /// NOTE: there is deliberately no secret-key accessor here. This crate stores
    /// the signing key in *seed* form (32-byte ξ; see `as_seed`/`to_seed`), while
    /// `@noble` emits the expanded 4896-byte FIPS secret key — two correct but
    /// representationally different encodings of the same key, so they are NOT
    /// byte-comparable. The public key is canonical and must match across impls.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.sk.verifying_key().encode().to_vec()
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
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
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
        assert_eq!(
            aes256gcm_open(&key, &nonce, &ct, aad).as_deref(),
            Some(&pt[..])
        );
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert!(aes256gcm_open(&key, &nonce, &bad, aad).is_none());
        assert!(aes256gcm_open(&key, &nonce, &ct, b"suite=PS-1").is_none());
    }

    /// Cross-implementation Known-Answer Tests: this Rust hot-path must reproduce
    /// the byte-exact vectors the TS reference froze in
    /// `../conformance/vectors/ps-kat.json` (generated by `npm run kat`).
    /// SHA3-256 / HMAC-SHA-384 / AES-256-GCM are universal standards and are
    /// guaranteed to match; the ML-DSA-87 keygen-from-seed digests additionally
    /// assert that this crate's FIPS-204 public-key encoding agrees with @noble
    /// byte for byte.
    #[test]
    fn ts_kat_vectors_reproduce() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/vectors/ps-kat.json"
        );
        let raw =
            std::fs::read_to_string(path).expect("read ps-kat.json (run `npm run kat` first)");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse KAT json");
        assert_eq!(v["version"].as_str(), Some("PS-KAT-1"));

        for it in v["hash"]["sha3_256"].as_array().unwrap() {
            let msg = it["msgUtf8"].as_str().unwrap();
            assert_eq!(
                hex::encode(sha3_256(msg.as_bytes())),
                it["digestHex"].as_str().unwrap(),
                "SHA3-256 mismatch"
            );
        }

        for it in v["mac"]["hmac_sha384"].as_array().unwrap() {
            let key = hex::decode(it["keyHex"].as_str().unwrap()).unwrap();
            let msg = it["msgUtf8"].as_str().unwrap();
            assert_eq!(
                hex::encode(hmac_sha384(&key, msg.as_bytes())),
                it["tagHex"].as_str().unwrap(),
                "HMAC-SHA-384 mismatch"
            );
        }

        for it in v["aead"]["aes_256_gcm"].as_array().unwrap() {
            let key: [u8; 32] = hex::decode(it["keyHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let nonce: [u8; 12] = hex::decode(it["nonceHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let aad = hex::decode(it["aadHex"].as_str().unwrap()).unwrap();
            let pt = hex::decode(it["ptHex"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(aes256gcm_seal(&key, &nonce, &pt, &aad)),
                it["ctHex"].as_str().unwrap(),
                "AES-256-GCM ciphertext mismatch"
            );
        }

        // ML-DSA-87: assert this crate derives the SAME public key from the same
        // 32-byte seed as @noble (canonical FIPS 204 pk encoding). The secret key
        // is intentionally NOT cross-checked — this crate stores it in seed form,
        // @noble in expanded form: different representations of the same key.
        let mldsa = &v["sig"]["ML-DSA-87"];
        let seed: [u8; 32] = hex::decode(mldsa["seedHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let pk = MlDsaKeypair::from_seed(seed).public_key_bytes();
        assert_eq!(
            pk.len() as u64,
            mldsa["publicKeyLen"].as_u64().unwrap(),
            "ML-DSA pk length"
        );
        assert_eq!(
            hex::encode(sha3_256(&pk)),
            mldsa["publicKeySha3"].as_str().unwrap(),
            "ML-DSA public-key encoding disagrees with the TS/@noble vector"
        );
    }
}
