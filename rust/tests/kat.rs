// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-implementation Known-Answer Tests (integration).
//!
//! This is the CI keystone (backlog A1): the Rust hot-path MUST reproduce, byte
//! for byte, the deterministic vectors the TypeScript reference froze in
//! `../conformance/vectors/ps-kat.json` (regenerated with `npm run kat`). The
//! committed JSON is the single source of truth — these tests read it and FAIL
//! on any drift, so a Rust-side regression (or an accidental vector edit) turns
//! `gate-rust` red.
//!
//! Primitives reproduced here: SHA3-256, SHAKE256 (outLen 16/32/64),
//! HMAC-SHA-384, and AES-256-GCM seal. (The ML-DSA-87 public-key vector is
//! additionally cross-checked by the in-crate unit test `ts_kat_vectors_reproduce`.)

use polarseek_crypto::{aes256gcm_seal, hmac_sha384, sha3_256, shake256};

/// Load and parse the committed KAT vectors. Path is resolved relative to the
/// crate manifest so the test is independent of the working directory.
fn load_kat() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/vectors/ps-kat.json"
    );
    let raw = std::fs::read_to_string(path)
        .expect("read ps-kat.json (run `npm run kat` first to (re)generate it)");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse ps-kat.json");
    assert_eq!(
        v["version"].as_str(),
        Some("PS-KAT-1"),
        "unexpected KAT vector version"
    );
    v
}

#[test]
fn sha3_256_vectors_reproduce() {
    let v = load_kat();
    let cases = v["hash"]["sha3_256"]
        .as_array()
        .expect("hash.sha3_256 array");
    assert!(!cases.is_empty(), "no SHA3-256 vectors");
    for it in cases {
        let msg = it["msgUtf8"].as_str().unwrap();
        assert_eq!(
            hex::encode(sha3_256(msg.as_bytes())),
            it["digestHex"].as_str().unwrap(),
            "SHA3-256 mismatch for msg {msg:?}"
        );
    }
}

#[test]
fn shake256_vectors_reproduce() {
    let v = load_kat();
    let cases = v["hash"]["shake256"]
        .as_array()
        .expect("hash.shake256 array");
    assert!(!cases.is_empty(), "no SHAKE256 vectors");
    for it in cases {
        let msg = it["msgUtf8"].as_str().unwrap();
        let out_len = it["outLen"].as_u64().unwrap() as usize;
        let out = shake256(msg.as_bytes(), out_len);
        assert_eq!(out.len(), out_len, "SHAKE256 wrong output length");
        assert_eq!(
            hex::encode(&out),
            it["outHex"].as_str().unwrap(),
            "SHAKE256 mismatch for msg {msg:?} outLen {out_len}"
        );
    }
}

#[test]
fn hmac_sha384_vectors_reproduce() {
    let v = load_kat();
    let cases = v["mac"]["hmac_sha384"]
        .as_array()
        .expect("mac.hmac_sha384 array");
    assert!(!cases.is_empty(), "no HMAC-SHA-384 vectors");
    for it in cases {
        let key = hex::decode(it["keyHex"].as_str().unwrap()).unwrap();
        let msg = it["msgUtf8"].as_str().unwrap();
        assert_eq!(
            hex::encode(hmac_sha384(&key, msg.as_bytes())),
            it["tagHex"].as_str().unwrap(),
            "HMAC-SHA-384 mismatch for msg {msg:?}"
        );
    }
}

#[test]
fn aes_256_gcm_vectors_reproduce() {
    let v = load_kat();
    let cases = v["aead"]["aes_256_gcm"]
        .as_array()
        .expect("aead.aes_256_gcm array");
    assert!(!cases.is_empty(), "no AES-256-GCM vectors");
    for it in cases {
        let key: [u8; 32] = hex::decode(it["keyHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("32-byte key");
        let nonce: [u8; 12] = hex::decode(it["nonceHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("12-byte nonce");
        let aad = hex::decode(it["aadHex"].as_str().unwrap()).unwrap();
        let pt = hex::decode(it["ptHex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(aes256gcm_seal(&key, &nonce, &pt, &aad)),
            it["ctHex"].as_str().unwrap(),
            "AES-256-GCM ciphertext (ct||tag) mismatch"
        );
    }
}
