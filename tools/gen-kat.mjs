#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Generate PolarSeek's frozen Known-Answer Test (KAT) vectors.
 *
 * These pin the *deterministic* outputs of the suite's primitives to exact bytes
 * so that (a) a future code change that silently alters an encoding is caught,
 * and (b) the Rust hot-path crate (and any other implementation) has a concrete,
 * auditor-rerunnable contract to reproduce. Only deterministic operations are
 * pinned to bytes; randomized ones (signing, hybrid-KEM encapsulation) are left
 * to the property checks in conformance/test/kat.test.ts.
 *
 * Prereq: `npm run build`.  Usage: `npm run kat`  (writes conformance/vectors/ps-kat.json).
 */
import { writeFileSync, mkdirSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  SHA3_SHAKE256,
  HMAC_SHA384,
  AES_256_GCM,
  encodeCanonical,
  getSigner,
  SIG_IDS,
} from '../dist/crypto/src/index.js'

const enc = (s) => new TextEncoder().encode(s)
/** Deterministic byte pattern of a given length (no RNG — KATs must be fixed). */
const pattern = (len, a = 1, b = 0) => Uint8Array.from({ length: len }, (_, i) => (i * a + b) & 0xff)
const hx = bytesToHex

const MESSAGES = ['', 'PolarSeek KAT — govern the verb, never the eye', 'post-quantum all the way down']

const hash = {
  sha3_256: MESSAGES.map((m) => ({ msgUtf8: m, digestHex: hx(SHA3_SHAKE256.digest(enc(m))) })),
  shake256: [16, 32, 64].map((outLen) => ({
    msgUtf8: MESSAGES[1],
    outLen,
    outHex: hx(SHA3_SHAKE256.xof(enc(MESSAGES[1]), outLen)),
  })),
}

const mac = {
  hmac_sha384: [
    { keyHex: hx(pattern(32, 1)), msgUtf8: MESSAGES[1] },
    { keyHex: hx(pattern(48, 3, 7)), msgUtf8: MESSAGES[2] },
  ].map((v) => ({ ...v, tagHex: hx(HMAC_SHA384.compute(Uint8Array.from(Buffer.from(v.keyHex, 'hex')), enc(v.msgUtf8))) })),
}

const aeadKey = pattern(32, 5, 1)
const aeadNonce = pattern(12, 2, 9)
const aeadAad = enc('PS-AAD')
const aeadPt = enc('settle:acct://treasury/ops amount<threshold')
const aead = {
  aes_256_gcm: [
    {
      keyHex: hx(aeadKey),
      nonceHex: hx(aeadNonce),
      aadHex: hx(aeadAad),
      ptHex: hx(aeadPt),
      ctHex: hx(AES_256_GCM.seal(aeadKey, aeadNonce, aeadPt, aeadAad)),
    },
  ],
}

/** Pin keygen-from-seed by digesting the (large) keys — deterministic, compact. */
function sigVector(sigId, seedLen) {
  const seed = pattern(seedLen, 1, 0)
  const kp = getSigner(sigId).keygen(seed)
  return {
    seedHex: hx(seed),
    publicKeyLen: kp.publicKey.length,
    secretKeyLen: kp.secretKey.length,
    publicKeySha3: hx(SHA3_SHAKE256.digest(kp.publicKey)),
    secretKeySha3: hx(SHA3_SHAKE256.digest(kp.secretKey)),
  }
}

const sig = {
  [SIG_IDS.ML_DSA_87]: sigVector(SIG_IDS.ML_DSA_87, 32),
  [SIG_IDS.SLH_DSA_SHAKE_256F]: sigVector(SIG_IDS.SLH_DSA_SHAKE_256F, 96),
}

/** dCBOR is a TS-side determinism contract (canonical, sorted-key encoding). */
const CBOR_VALUES = [
  { label: 'sorted-keys', value: { z: 1, a: 2, m: 3 } },
  { label: 'nested', value: { effect: 'allow', tier: 2, obligations: ['receipt', 'log'], n: 0 } },
  { label: 'ints', value: [0, 1, 23, 24, 255, 256, 65535, 65536] },
]
const cbor = CBOR_VALUES.map((c) => ({ label: c.label, value: c.value, hex: hx(encodeCanonical(c.value)) }))

const vectors = {
  version: 'PS-KAT-1',
  note:
    'Frozen Known-Answer Tests for PolarSeek deterministic primitives. Regenerate with `npm run kat`. ' +
    'Per-vector cross-implementation coverage: SHA3-256 and HMAC-SHA384 are reproduced by TS, Rust AND ' +
    'Python (3 languages); SHAKE256 by TS and Python; AES-256-GCM and the ML-DSA-87 *public key* by TS ' +
    'and Rust; SLH-DSA-SHAKE-256f keygen and the dCBOR encodings by TS only. Randomized ops are ' +
    'property-checked, ' +
    'not byte-pinned.',
  hash,
  mac,
  aead,
  sig,
  cbor,
}

const path = new URL('../conformance/vectors/ps-kat.json', import.meta.url)
mkdirSync(new URL('../conformance/vectors/', import.meta.url), { recursive: true })
writeFileSync(path, JSON.stringify(vectors, null, 2) + '\n')
console.log('wrote KAT vectors ->', path.pathname)
console.log(
  `sha3:${hash.sha3_256.length} shake:${hash.shake256.length} hmac:${mac.hmac_sha384.length} ` +
    `aead:${aead.aes_256_gcm.length} sig:${Object.keys(sig).length} cbor:${cbor.length}`,
)
