// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

//! manual_bench.rs — dependency-free micro-benchmark for the Nerion PQ hot-path.
//!
//! This harness uses only `std::time::Instant` and the `polarseek-crypto` crate
//! itself — NO criterion, NO plotters, NO windows-sys. It therefore runs on the
//! windows-gnu dev toolchain where the criterion HTML-report dependency chain
//! cannot link (see lib.rs build note re: dlltool).
//!
//! Numbers are a rough single-machine baseline (median of N iterations after a
//! warm-up). They are NOT statistically rigorous like criterion and MUST NOT be
//! cited in procurement documents. For authoritative numbers, run
//! `cargo bench --bench governance_roundtrip` on a Linux CI runner.
//!
//! Run: cargo run --release --example manual_bench

use std::time::Instant;

use polarseek_crypto::{
    MlDsaKeypair, aes256gcm_seal, hmac_sha384, mlkem1024_roundtrip_ok, sha3_256,
};

const DSA_SEED: [u8; 32] = [0x1a; 32];
const KEM_SEED: [u8; 64] = [0x42; 64];
const KEM_M: [u8; 32] = [0x37; 32];
const AES_KEY: [u8; 32] = [0xde; 32];
const AES_NONCE: [u8; 12] = [0xad; 12];
const HMAC_KEY: [u8; 32] = [0xbe; 32];
const MSG: &[u8] = b"nerion:permit:v1 action=transfer amount=5000 target=vendor-acme suite=PS-5";

/// Time a closure `iters` times after `warm` warm-up runs; return median ns/op.
fn bench<F: FnMut()>(name: &str, warm: u32, iters: u32, mut f: F) {
    for _ in 0..warm {
        f();
    }
    let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let min = samples[0];
    let p95 = samples[(samples.len() as f64 * 0.95) as usize];
    println!(
        "{:<28} median={:>10.2} us   min={:>10.2} us   p95={:>10.2} us   (n={})",
        name,
        median as f64 / 1000.0,
        min as f64 / 1000.0,
        p95 as f64 / 1000.0,
        iters
    );
}

fn main() {
    println!("Nerion PQ hot-path — dependency-free manual baseline");
    println!("{}", "-".repeat(96));

    let dsa = MlDsaKeypair::from_seed(DSA_SEED);
    let sig = dsa.sign(MSG);

    bench("ml_dsa_87_sign", 20, 200, || {
        let _ = dsa.sign(MSG);
    });
    bench("ml_dsa_87_verify", 20, 200, || {
        let _ = dsa.verify(MSG, &sig);
    });
    bench("ml_kem_1024_roundtrip", 20, 200, || {
        let _ = mlkem1024_roundtrip_ok(KEM_SEED, KEM_M);
    });
    bench("hmac_sha384_75b", 50, 2000, || {
        let _ = hmac_sha384(&HMAC_KEY, MSG);
    });
    bench("sha3_256_75b", 50, 2000, || {
        let _ = sha3_256(MSG);
    });
    bench("aes_256_gcm_seal_75b", 50, 2000, || {
        let _ = aes256gcm_seal(&AES_KEY, &AES_NONCE, MSG, b"suite=PS-5");
    });

    // Composite: sign + sha3 + verify + hmac + aes (the decide() critical path,
    // minus session establishment which is one-time per session).
    bench("decide_path_composite", 20, 200, || {
        let s = dsa.sign(MSG);
        let h = sha3_256(MSG);
        let _ = dsa.verify(MSG, &s);
        let _ = hmac_sha384(&HMAC_KEY, MSG);
        let _ = aes256gcm_seal(&AES_KEY, &AES_NONCE, MSG, &h);
    });

    println!("{}", "-".repeat(96));
    println!("NOTE: rough single-machine baseline; not criterion-grade. Do not cite in procurement.");
}
