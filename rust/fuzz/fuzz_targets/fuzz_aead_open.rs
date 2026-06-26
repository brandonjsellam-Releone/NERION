// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0
//
// Fuzz target: AES-256-GCM open must NEVER panic on adversarial input — it must
// return None on any tag/length/AAD mismatch (FIPS 203/SP 800-38D fail-closed
// AEAD discipline). libFuzzer flags any panic/abort.
#![no_main]
use libfuzzer_sys::fuzz_target;
use polarseek_crypto::aes256gcm_open;

fuzz_target!(|data: &[u8]| {
    // Need 32-byte key + 12-byte nonce; remainder is the (adversarial) ciphertext.
    if data.len() < 44 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[32..44]);
    let ct = &data[44..];
    // Must return Option, never panic. We don't assert on the value — any
    // structurally-invalid ciphertext is expected to yield None.
    let _ = aes256gcm_open(&key, &nonce, ct, b"nerion-fuzz-aad");
});
