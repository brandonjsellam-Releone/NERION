// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

//! governance_roundtrip.rs — Nerion criterion.rs benchmark suite.
//!
//! Measures the end-to-end latency of the Nerion PQ governance hot-path:
//!   ML-KEM-1024 encap/decap  →  ML-DSA-87 sign/verify  →  HMAC-SHA-384  →  AES-256-GCM
//!
//! These benchmarks are for planning and capacity-sizing purposes ONLY.
//! Numbers produced here are measured on the machine that ran them.
//! Do NOT cite them in procurement documents without specifying exact hardware,
//! Rust toolchain version, and criterion configuration.
//!
//! Run:
//!   cd rust && cargo bench --bench governance_roundtrip
//!
//! HTML reports land at: target/criterion/report/index.html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use polarseek_crypto::{
    MlDsaKeypair, aes256gcm_open, aes256gcm_seal, hmac_sha384, hmac_sha384_verify,
    mlkem1024_roundtrip_ok, sha3_256,
};

// ---------------------------------------------------------------------------
// Fixed test inputs — deterministic, no OS RNG in benchmarks.
// ---------------------------------------------------------------------------

/// 64-byte ML-KEM-1024 keygen seed (d‖z).
const KEM_SEED: [u8; 64] = [0x42u8; 64];

/// 32-byte ML-KEM-1024 encapsulation randomness (m).
const KEM_M: [u8; 32] = [0x37u8; 32];

/// ML-DSA-87 signing key seed.
const DSA_SEED: [u8; 32] = [0x1au8; 32];

/// Representative governance action payload — matches the Nerion permit format.
const GOVERNANCE_MSG: &[u8] =
    b"nerion:permit:v1 action=transfer amount=5000 target=vendor-acme suite=PS-5";

/// 256-byte plaintext block for symmetric benchmarks.
const PT_256: [u8; 256] = [0x5cu8; 256];

/// AES-256-GCM key and nonce.
const AES_KEY: [u8; 32] = [0xdeu8; 32];
const AES_NONCE: [u8; 12] = [0xadu8; 12];
const AES_AAD: &[u8] = b"suite=PS-5;intent=transfer";

/// HMAC key (256-bit).
const HMAC_KEY: [u8; 32] = [0xbeu8; 32];

// ---------------------------------------------------------------------------
// ML-KEM-1024 benchmarks
// ---------------------------------------------------------------------------

/// Benchmark ML-KEM-1024 encapsulation (key agreement sender side).
/// Uses the deterministic (non-randomized) API so results are reproducible.
fn bench_ml_kem_1024_encap(c: &mut Criterion) {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};

    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(KEM_SEED));
    let ek = dk.encapsulation_key();

    c.bench_function("ml_kem_1024_encap", |b| {
        b.iter(|| {
            let (ct, ss) = ek.encapsulate_deterministic(&KemB32::from(black_box(KEM_M)));
            black_box((ct, ss))
        })
    });
}

/// Benchmark ML-KEM-1024 decapsulation (key agreement receiver side).
fn bench_ml_kem_1024_decap(c: &mut Criterion) {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};

    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(KEM_SEED));
    let ek = dk.encapsulation_key();
    let (ct, _ss_send) = ek.encapsulate_deterministic(&KemB32::from(KEM_M));

    c.bench_function("ml_kem_1024_decap", |b| {
        b.iter(|| {
            let ss = dk.decapsulate(black_box(&ct)).expect("decapsulate");
            black_box(ss)
        })
    });
}

// ---------------------------------------------------------------------------
// ML-DSA-87 benchmarks
// ---------------------------------------------------------------------------

/// Benchmark ML-DSA-87 signing.
fn bench_ml_dsa_87_sign(c: &mut Criterion) {
    let kp = MlDsaKeypair::from_seed(DSA_SEED);

    c.bench_function("ml_dsa_87_sign", |b| {
        b.iter(|| {
            let sig = kp.sign(black_box(GOVERNANCE_MSG));
            black_box(sig)
        })
    });
}

/// Benchmark ML-DSA-87 verification.
fn bench_ml_dsa_87_verify(c: &mut Criterion) {
    let kp = MlDsaKeypair::from_seed(DSA_SEED);
    let sig = kp.sign(GOVERNANCE_MSG);

    c.bench_function("ml_dsa_87_verify", |b| {
        b.iter(|| {
            let ok = kp.verify(black_box(GOVERNANCE_MSG), black_box(&sig));
            black_box(ok)
        })
    });
}

// ---------------------------------------------------------------------------
// HMAC-SHA-384 benchmark
// ---------------------------------------------------------------------------

/// Benchmark HMAC-SHA-384 over 256 bytes (PermitToken MAC hot-path).
fn bench_hmac_sha384(c: &mut Criterion) {
    c.bench_function("hmac_sha384_256b", |b| {
        b.iter(|| {
            let tag = hmac_sha384(black_box(&HMAC_KEY), black_box(&PT_256));
            black_box(tag)
        })
    });
}

// ---------------------------------------------------------------------------
// AES-256-GCM benchmark
// ---------------------------------------------------------------------------

/// Benchmark AES-256-GCM encryption of a 256-byte plaintext.
fn bench_aes_256_gcm_encrypt(c: &mut Criterion) {
    c.bench_function("aes_256_gcm_encrypt_256b", |b| {
        b.iter(|| {
            let ct = aes256gcm_seal(
                black_box(&AES_KEY),
                black_box(&AES_NONCE),
                black_box(&PT_256),
                black_box(AES_AAD),
            );
            black_box(ct)
        })
    });
}

// ---------------------------------------------------------------------------
// Governance round-trip composite benchmark
// ---------------------------------------------------------------------------

/// Benchmark a synthetic governance round-trip that chains the key Nerion
/// hot-path primitives in sequence:
///
///   1. ML-KEM-1024 encap (session key establishment, sender)
///   2. ML-DSA-87 sign     (permit intention commitment)
///   3. SHA3-256            (receipt hash / intent commitment)
///   4. ML-DSA-87 verify   (quorum seat receipt verification)
///   5. HMAC-SHA-384       (PermitToken MAC check)
///   6. AES-256-GCM seal   (transport encryption of the decided payload)
///
/// This is NOT an integration test — it is a latency estimate for the
/// combined operation under criterion's statistical harness. The ordering
/// mirrors the critical path defined in the Nerion protocol spec (permit_create
/// → decide() → receipt_verify) as of 2026.
///
/// IMPORTANT: This does not exercise real Nerion session management or
/// quorum logic. It benchmarks the underlying cryptographic primitives in
/// the same order they appear on the hot path.
fn bench_governance_roundtrip(c: &mut Criterion) {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};

    // Pre-generate long-lived keypairs outside the timed section.
    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(KEM_SEED));
    let ek = dk.encapsulation_key();
    let dsa_kp = MlDsaKeypair::from_seed(DSA_SEED);

    c.bench_function("governance_roundtrip", |b| {
        b.iter(|| {
            // Step 1: session key establishment (sender encap).
            let (ct, ss_send) =
                ek.encapsulate_deterministic(&KemB32::from(black_box(KEM_M)));

            // Step 2: permit intention commitment — sign the governance message.
            let sig = dsa_kp.sign(black_box(GOVERNANCE_MSG));

            // Step 3: SHA3-256 receipt hash over the ciphertext.
            let receipt_hash = sha3_256(black_box(ct.as_ref()));

            // Step 4: verify the signature (quorum seat receipt).
            let verified = dsa_kp.verify(black_box(GOVERNANCE_MSG), black_box(&sig));

            // Step 5: HMAC-SHA-384 PermitToken MAC (session-key-derived tag).
            // Derive a 32-byte HMAC key from the first 32 bytes of the shared secret.
            let ss_bytes: &[u8] = ss_send.as_ref();
            let hmac_key: [u8; 32] = ss_bytes[..32].try_into().expect("ss >= 32 bytes");
            let permit_tag = hmac_sha384(black_box(&hmac_key), black_box(GOVERNANCE_MSG));

            // Step 6: AES-256-GCM seal the decided payload.
            // Reuse the first 32 bytes of shared secret as transport key.
            let aes_key: [u8; 32] = hmac_key;
            let ct_payload = aes256gcm_seal(
                black_box(&aes_key),
                black_box(&AES_NONCE),
                black_box(GOVERNANCE_MSG),
                black_box(&receipt_hash),
            );

            // Step 7: receiver decaps to confirm shared secret agreement.
            let ss_recv = dk.decapsulate(black_box(&ct)).expect("decapsulate");

            black_box((verified, permit_tag, ct_payload, ss_recv, receipt_hash))
        })
    });
}

// ---------------------------------------------------------------------------
// Throughput scaling: vary payload sizes for AES-GCM + HMAC
// ---------------------------------------------------------------------------

/// Benchmark AES-256-GCM across several payload sizes to characterise
/// throughput scaling (relevant for bulk permit-receipt batches).
fn bench_aes_gcm_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_payload_scaling");
    for size in [64usize, 256, 1024, 4096] {
        let pt = vec![0x5cu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &pt, |b, pt| {
            b.iter(|| {
                let ct = aes256gcm_seal(
                    black_box(&AES_KEY),
                    black_box(&AES_NONCE),
                    black_box(pt),
                    black_box(AES_AAD),
                );
                black_box(ct)
            })
        });
    }
    group.finish();
}

/// Benchmark HMAC-SHA-384 across payload sizes matching the AES-GCM scaling above.
fn bench_hmac_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha384_payload_scaling");
    for size in [64usize, 256, 1024, 4096] {
        let msg = vec![0x5cu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &msg, |b, msg| {
            b.iter(|| {
                let tag = hmac_sha384(black_box(&HMAC_KEY), black_box(msg));
                black_box(tag)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// criterion_group / criterion_main wiring
// ---------------------------------------------------------------------------

criterion_group!(
    kem_benches,
    bench_ml_kem_1024_encap,
    bench_ml_kem_1024_decap,
);

criterion_group!(
    dsa_benches,
    bench_ml_dsa_87_sign,
    bench_ml_dsa_87_verify,
);

criterion_group!(
    symmetric_benches,
    bench_hmac_sha384,
    bench_aes_256_gcm_encrypt,
);

criterion_group!(
    roundtrip_benches,
    bench_governance_roundtrip,
);

criterion_group!(
    scaling_benches,
    bench_aes_gcm_scaling,
    bench_hmac_scaling,
);

criterion_main!(
    kem_benches,
    dsa_benches,
    symmetric_benches,
    roundtrip_benches,
    scaling_benches,
);
