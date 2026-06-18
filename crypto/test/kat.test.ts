import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { slh_dsa_shake_256f } from '@noble/post-quantum/slh-dsa.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

/**
 * Known-Answer Tests against committed deterministic regression vectors.
 * We re-derive every value from its seed and assert byte-equality with the
 * pinned vector, catching any drift in the underlying PQC library or our use
 * of it. (Wiring official NIST ACVP vectors is tracked in docs/STATUS.md.)
 */

interface Vectors {
  ml_kem_1024: {
    keygenSeedHex: string
    encapsCoinsHex: string
    publicKeySha256: string
    cipherTextSha256: string
    sharedSecretHex: string
    decapsMatches: boolean
  }
  x25519: { skAHex: string; skBHex: string; pkAHex: string; pkBHex: string; sharedHex: string }
  ml_dsa_87: { keygenSeedHex: string; publicKeySha256: string }
  slh_dsa_shake_256f: { keygenSeedHex: string; publicKeySha256: string }
}

const v: Vectors = JSON.parse(
  readFileSync(new URL('../vectors/deterministic-kat.json', import.meta.url), 'utf8'),
)
const h = (b: Uint8Array): string => bytesToHex(sha256(b))

describe('ML-KEM-1024 KAT', () => {
  const seed = hexToBytes(v.ml_kem_1024.keygenSeedHex)
  const coins = hexToBytes(v.ml_kem_1024.encapsCoinsHex)
  const kp = ml_kem1024.keygen(seed)
  const enc = ml_kem1024.encapsulate(kp.publicKey, coins)

  it('reproduces the public key from its seed', () => {
    expect(h(kp.publicKey)).toBe(v.ml_kem_1024.publicKeySha256)
  })
  it('reproduces ciphertext and shared secret from fixed coins', () => {
    expect(h(enc.cipherText)).toBe(v.ml_kem_1024.cipherTextSha256)
    expect(bytesToHex(enc.sharedSecret)).toBe(v.ml_kem_1024.sharedSecretHex)
  })
  it('decapsulation recovers the encapsulated shared secret', () => {
    const ss = ml_kem1024.decapsulate(enc.cipherText, kp.secretKey)
    expect(bytesToHex(ss)).toBe(v.ml_kem_1024.sharedSecretHex)
  })
})

describe('X25519 KAT', () => {
  const skA = hexToBytes(v.x25519.skAHex)
  const skB = hexToBytes(v.x25519.skBHex)
  it('reproduces public keys and a symmetric shared secret', () => {
    const pkA = x25519.getPublicKey(skA)
    const pkB = x25519.getPublicKey(skB)
    expect(bytesToHex(pkA)).toBe(v.x25519.pkAHex)
    expect(bytesToHex(pkB)).toBe(v.x25519.pkBHex)
    expect(bytesToHex(x25519.getSharedSecret(skA, pkB))).toBe(v.x25519.sharedHex)
    expect(bytesToHex(x25519.getSharedSecret(skB, pkA))).toBe(v.x25519.sharedHex)
  })
})

describe('ML-DSA-87 KAT', () => {
  it('reproduces the public key from its seed', () => {
    const kp = ml_dsa87.keygen(hexToBytes(v.ml_dsa_87.keygenSeedHex))
    expect(h(kp.publicKey)).toBe(v.ml_dsa_87.publicKeySha256)
  })
})

describe('SLH-DSA-SHAKE-256f KAT', () => {
  it('reproduces the public key from its seed', () => {
    const kp = slh_dsa_shake_256f.keygen(hexToBytes(v.slh_dsa_shake_256f.keygenSeedHex))
    expect(h(kp.publicKey)).toBe(v.slh_dsa_shake_256f.publicKeySha256)
  })
})
