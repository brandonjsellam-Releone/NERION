// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

//! crypto_ops.rs — Nerion criterion.rs micro-benchmark suite.
//!
//! Individual primitive benchmarks that isolate each cryptographic operation
//! for capacity planning, regression detection, and comparative analysis
//! against NIST pqc-project reference numbers.
//!
//! These benchmarks complement the composite governance_roundtrip suite.
//! They are for planning purposes; do NOT cite raw numbers in procurement
//! documents without specifying hardware, toolchain, and run conditions.
//!
//! Run:
//!   cd rust && cargo bench --bench crypto_ops
//!
//! HTML reports: target/criterion/report/index.html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use polarseek_crypto::{
    MlDsaKeypair, aes256gcm_open, aes256gcm_seal, hmac_sha384, hmac_sha384_verify,
    mlkem1024_roundtrip_ok, sha3_256, shake256,
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const KEM_SEED: [u8; 64] = [0x11u8; 64];
const KEM_M: [u8; 32] = [0x22u8; 32];
const DSA_SEED: [u8; 32] = [0x33u8; 32];

const AES_KEY: [u8; 32] = [0x44u8; 32];
const AES_NONCE: [u8; 12] = [0x55u8; 12];
const AES_AAD: &[u8] = b"nerion:aad:v1";

const HMAC_KEY: [u8; 32] = [0x66u8; 32];

// ---------------------------------------------------------------------------
// SHA3-256 microbenchmarks
// ---------------------------------------------------------------------------

/// SHA3-256 over varying message sizes.
fn bench_sha3_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256");
    for size in [32usize, 64, 128, 256, 1024] {
        let msg = vec![0xabu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &msg, |b, msg| {
            b.iter(|| {
                let digest = sha3_256(black_box(msg));
                black_box(digest)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// SHAKE-256 microbenchmarks (used in Nerion key-derivation paths)
// ---------------------------------------------------------------------------

/// SHAKE-256 XOF over varying input/output sizes.
fn bench_shake256(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256");
    // (input_size, output_len) pairs representative of Nerion KDF uses.
    for (in_size, out_len) in [(32usize, 32usize), (64, 48), (128, 64)] {
        let input = vec![0xcdu8; in_size];
        let label = format!("in={}_out={}", in_size, out_len);
        group.bench_function(&label, |b| {
            b.iter(|| {
                let out = shake256(black_box(&input), black_box(out_len));
                black_box(out)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// HMAC-SHA-384 microbenchmarks
// ---------------------------------------------------------------------------

/// HMAC-SHA-384 over multiple payload sizes; includes tag + verify pass.
fn bench_hmac_sha384_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha384");

    // Tag generation
    for size in [32usize, 64, 128, 256, 512, 1024] {
        let msg = vec![0xefu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("tag_gen", size),
            &msg,
            |b, msg| {
                b.iter(|| {
                    let tag = hmac_sha384(black_box(&HMAC_KEY), black_box(msg));
                    black_box(tag)
                })
            },
        );
    }

    // Tag verification (constant-time)
    let msg_256 = vec![0xefu8; 256];
    let tag_256 = hmac_sha384(&HMAC_KEY, &msg_256);
    group.bench_function("tag_verify_256b", |b| {
        b.iter(|| {
            let ok = hmac_sha384_verify(
                black_box(&HMAC_KEY),
                black_box(&msg_256),
                black_box(&tag_256),
            );
            black_box(ok)
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// AES-256-GCM microbenchmarks
// ---------------------------------------------------------------------------

/// AES-256-GCM seal + open across payload sizes.
fn bench_aes256gcm_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_256_gcm");

    for size in [32usize, 64, 128, 256, 512, 1024, 4096] {
        let pt = vec![0x12u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Seal (encrypt + tag)
        group.bench_with_input(
            BenchmarkId::new("seal", size),
            &pt,
            |b, pt| {
                b.iter(|| {
                    let ct = aes256gcm_seal(
                        black_box(&AES_KEY),
                        black_box(&AES_NONCE),
                        black_box(pt),
                        black_box(AES_AAD),
                    );
                    black_box(ct)
                })
            },
        );

        // Open (decrypt + verify tag)
        let ct = aes256gcm_seal(&AES_KEY, &AES_NONCE, &pt, AES_AAD);
        group.bench_with_input(
            BenchmarkId::new("open", size),
            &ct,
            |b, ct| {
                b.iter(|| {
                    let pt = aes256gcm_open(
                        black_box(&AES_KEY),
                        black_box(&AES_NONCE),
                        black_box(ct),
                        black_box(AES_AAD),
                    );
                    black_box(pt)
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-KEM-1024 microbenchmarks
// ---------------------------------------------------------------------------

/// ML-KEM-1024 keygen, encap, and decap as isolated operations.
fn bench_ml_kem_1024_ops(c: &mut Criterion) {
    use ml_kem::kem::TryDecapsulate;
    use ml_kem::{B32 as KemB32, DecapsulationKey, MlKem1024, Seed};

    let mut group = c.benchmark_group("ml_kem_1024");

    // Keygen from seed (deterministic — measures FIPS 203 KeyGen_internal + Expand)
    group.bench_function("keygen_from_seed", |b| {
        b.iter(|| {
            let dk =
                DecapsulationKey::<MlKem1024>::from_seed(Seed::from(black_box(KEM_SEED)));
            black_box(dk)
        })
    });

    // Encapsulation (sender)
    let dk = DecapsulationKey::<MlKem1024>::from_seed(Seed::from(KEM_SEED));
    let ek = dk.encapsulation_key();
    group.bench_function("encap", |b| {
        b.iter(|| {
            let (ct, ss) = ek.encapsulate_deterministic(&KemB32::from(black_box(KEM_M)));
            black_box((ct, ss))
        })
    });

    // Decapsulation (receiver)
    let (ct, _) = ek.encapsulate_deterministic(&KemB32::from(KEM_M));
    group.bench_function("decap", |b| {
        b.iter(|| {
            let ss = dk.try_decapsulate(black_box(&ct)).expect("decap");
            black_box(ss)
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-DSA-87 microbenchmarks
// ---------------------------------------------------------------------------

/// ML-DSA-87 keygen, sign, and verify as isolated operations.
fn bench_ml_dsa_87_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_87");

    // Keygen from seed
    group.bench_function("keygen_from_seed", |b| {
        b.iter(|| {
            let kp = MlDsaKeypair::from_seed(black_box(DSA_SEED));
            black_box(kp.public_key_bytes())
        })
    });

    let kp = MlDsaKeypair::from_seed(DSA_SEED);

    // Sign — short message (governance permit)
    let msg_short = b"nerion:permit:v1 action=transfer amount=5000 target=vendor-acme";
    group.bench_function("sign_short", |b| {
        b.iter(|| {
            let sig = kp.sign(black_box(msg_short));
            black_box(sig)
        })
    });

    // Sign — longer message (e.g., full permit JSON ~512 bytes)
    let msg_long = vec![0x7eu8; 512];
    group.bench_function("sign_512b", |b| {
        b.iter(|| {
            let sig = kp.sign(black_box(&msg_long));
            black_box(sig)
        })
    });

    // Verify — short message
    let sig_short = kp.sign(msg_short);
    group.bench_function("verify_short", |b| {
        b.iter(|| {
            let ok = kp.verify(black_box(msg_short), black_box(&sig_short));
            black_box(ok)
        })
    });

    // Verify — longer message
    let sig_long = kp.sign(&msg_long);
    group.bench_function("verify_512b", |b| {
        b.iter(|| {
            let ok = kp.verify(black_box(&msg_long), black_box(&sig_long));
            black_box(ok)
        })
    });

    // Public key serialization (used in receipt inclusion proofs)
    group.bench_function("public_key_bytes", |b| {
        b.iter(|| {
            let pk = kp.public_key_bytes();
            black_box(pk)
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-KEM-1024 full round-trip (convenience wrapper benchmarked separately)
// ---------------------------------------------------------------------------

/// Benchmark the convenience `mlkem1024_roundtrip_ok` helper — measures the
/// combined encap + decap + equality check in one allocation-free call.
fn bench_ml_kem_roundtrip_helper(c: &mut Criterion) {
    c.bench_function("mlkem1024_roundtrip_ok", |b| {
        b.iter(|| {
            let ok = mlkem1024_roundtrip_ok(black_box(KEM_SEED), black_box(KEM_M));
            black_box(ok)
        })
    });
}

// ---------------------------------------------------------------------------
// Key-derivation chain: SHA3-256 → HMAC-SHA-384 (PermitToken derivation path)
// ---------------------------------------------------------------------------

/// Benchmark the two-step derivation used to produce a PermitToken MAC key
/// from a base secret:  SHA3-256(secret) → HMAC-SHA-384(derived_key, context)
fn bench_permit_token_derivation(c: &mut Criterion) {
    let base_secret = [0x99u8; 48];
    let context = b"nerion:permit-token:v1:context";
    c.bench_function("permit_token_derivation", |b| {
        b.iter(|| {
            let derived_key = sha3_256(black_box(&base_secret));
            let token = hmac_sha384(black_box(&derived_key), black_box(context));
            black_box(token)
        })
    });
}

// ---------------------------------------------------------------------------
// criterion_group / criterion_main wiring
// ---------------------------------------------------------------------------

criterion_group!(hash_benches, bench_sha3_256, bench_shake256);

criterion_group!(mac_benches, bench_hmac_sha384_ops);

criterion_group!(aead_benches, bench_aes256gcm_ops);

criterion_group!(
    pqc_benches,
    bench_ml_kem_1024_ops,
    bench_ml_dsa_87_ops,
    bench_ml_kem_roundtrip_helper,
);

criterion_group!(kdf_benches, bench_permit_token_derivation);

criterion_main!(hash_benches, mac_benches, aead_benches, pqc_benches, kdf_benches);
