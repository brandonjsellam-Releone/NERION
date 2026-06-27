// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0
//
// Fuzz target: ML-KEM-1024 deterministic keygen+encap+decap over arbitrary seed
// material must NEVER panic (FIPS 203 — no input from this path should crash the
// primitive). The boolean result (shared-secret agreement) is not asserted; only
// the absence of panics/aborts is being fuzzed.
#![no_main]
use libfuzzer_sys::fuzz_target;
use polarseek_crypto::mlkem1024_roundtrip_ok;

fuzz_target!(|data: &[u8]| {
    // 64-byte keygen seed (d‖z) + 32-byte encap randomness (m).
    if data.len() < 96 {
        return;
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&data[0..64]);
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[64..96]);
    let _ = mlkem1024_roundtrip_ok(seed, m);
});
