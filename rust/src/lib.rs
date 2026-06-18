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
use sha3::{Digest, Sha3_256};

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
}
