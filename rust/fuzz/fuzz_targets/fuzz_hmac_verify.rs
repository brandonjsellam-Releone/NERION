// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0
//
// Fuzz target: HMAC-SHA-384 verification must NEVER panic on adversarial input —
// it returns false on any mismatch (constant-time compare inside @noble/RustCrypto).
#![no_main]
use libfuzzer_sys::fuzz_target;
use polarseek_crypto::hmac_sha384_verify;

fuzz_target!(|data: &[u8]| {
    // 32-byte key + 48-byte tag (SHA-384 output) + remainder = message.
    if data.len() < 80 {
        return;
    }
    let key = &data[0..32];
    let tag = &data[32..80];
    let msg = &data[80..];
    // Must return bool, never panic; an arbitrary tag should almost always be false.
    let _ = hmac_sha384_verify(key, msg, tag);
});
