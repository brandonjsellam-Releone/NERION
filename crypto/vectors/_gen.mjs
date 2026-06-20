// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

// Regenerates crypto/vectors/deterministic-kat.json.
// Run: node crypto/vectors/_gen.mjs   (kept in-repo so vectors are reproducible)
import { writeFileSync } from 'node:fs'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { slh_dsa_shake_256f } from '@noble/post-quantum/slh-dsa.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

const seed = (byte, len) => new Uint8Array(len).fill(byte)
const h = (b) => bytesToHex(sha256(b))
const hex = (b) => bytesToHex(b)

// --- ML-KEM-1024 (deterministic keygen + deterministic encapsulation) ---
const mlkemSeed = seed(0x11, 64)
const mlkemCoins = seed(0x22, 32)
const kk = ml_kem1024.keygen(mlkemSeed)
const enc = ml_kem1024.encapsulate(kk.publicKey, mlkemCoins)
const dec = ml_kem1024.decapsulate(enc.cipherText, kk.secretKey)

// --- X25519 (deterministic ECDH) ---
const xSkA = seed(0x33, 32)
const xSkB = seed(0x44, 32)
const xPkA = x25519.getPublicKey(xSkA)
const xPkB = x25519.getPublicKey(xSkB)
const xShared = x25519.getSharedSecret(xSkA, xPkB)
const xSharedRev = x25519.getSharedSecret(xSkB, xPkA)

// --- ML-DSA-87 (deterministic keygen) ---
const mldsaSeed = seed(0x55, 32)
const dk = ml_dsa87.keygen(mldsaSeed)

// --- SLH-DSA-SHAKE-256f (deterministic keygen) ---
const slhSeed = seed(0x66, 96)
const sk = slh_dsa_shake_256f.keygen(slhSeed)

const vectors = {
  _note:
    'Deterministic regression vectors generated from fixed seeds via @noble/post-quantum. ' +
    'These pin reproducible behavior; wiring official NIST ACVP KAT vectors is tracked in STATUS.md.',
  _generator: 'crypto/vectors/_gen.mjs',
  ml_kem_1024: {
    keygenSeedHex: hex(mlkemSeed),
    encapsCoinsHex: hex(mlkemCoins),
    publicKeyLen: kk.publicKey.length,
    secretKeyLen: kk.secretKey.length,
    publicKeySha256: h(kk.publicKey),
    secretKeySha256: h(kk.secretKey),
    cipherTextLen: enc.cipherText.length,
    cipherTextSha256: h(enc.cipherText),
    sharedSecretHex: hex(enc.sharedSecret),
    decapsMatches: hex(dec) === hex(enc.sharedSecret),
  },
  x25519: {
    skAHex: hex(xSkA),
    skBHex: hex(xSkB),
    pkAHex: hex(xPkA),
    pkBHex: hex(xPkB),
    sharedHex: hex(xShared),
    sharedSymmetric: hex(xShared) === hex(xSharedRev),
  },
  ml_dsa_87: {
    keygenSeedHex: hex(mldsaSeed),
    publicKeyLen: dk.publicKey.length,
    publicKeySha256: h(dk.publicKey),
  },
  slh_dsa_shake_256f: {
    keygenSeedHex: hex(slhSeed),
    publicKeyLen: sk.publicKey.length,
    publicKeySha256: h(sk.publicKey),
  },
}

const out = new URL('./deterministic-kat.json', import.meta.url)
writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n')
console.log('wrote', out.pathname)
console.log('ml-kem decaps matches:', vectors.ml_kem_1024.decapsMatches)
console.log('x25519 symmetric:', vectors.x25519.sharedSymmetric)
