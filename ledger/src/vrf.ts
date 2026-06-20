// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, ciphersuite 0x03) — the consensus VRF
 * for PolarSeek's private, verifiable, grind-resistant leader sortition (ADR-0004).
 *
 * ⚠️ CLASSICAL, NOT POST-QUANTUM. This VRF rests on the edwards25519 discrete-log
 * assumption (~128-bit CLASSICAL security). It is DELIBERATE and load-bearing: a
 * VRF break lets a (future quantum) adversary PREDICT or grind future leaders — a
 * LIVENESS / FAIRNESS degradation — but does NOT let them forge blocks,
 * attestations, or finality, which remain ML-DSA-87 (FIPS 204, post-quantum). The
 * PQ SAFETY boundary is unchanged; only leader UNPREDICTABILITY is classical. No
 * standardized post-quantum VRF exists yet; this is the pragmatic hybrid (see
 * docs/adr/ADR-0004). The GROUP (edwards25519) and HASH (SHA-512) are audited
 * @noble primitives; the ECVRF WIRING here is unaudited — see docs/STATUS.md.
 *
 * TAI ("try-and-increment") is chosen for the consensus path because its
 * encode_to_curve needs no hash-to-curve map / DST / salt — lowest exactness risk
 * for matching the published RFC 9381 test vectors.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import type { Bytes } from '../../crypto/src/index.js'

export class VrfError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'VrfError'
  }
}

const P = ed25519.Point
const B = P.BASE
const L = P.Fn.ORDER // group order ℓ
const COF = 8n
const SUITE = 0x03 // ECVRF-EDWARDS25519-SHA512-TAI
const PROOF_LEN = 80 // Gamma(32) || c(16) || s(32)

const mod = (n: bigint): bigint => ((n % L) + L) % L

/** OS2IP, little-endian (the ed25519 ciphersuite encoding, RFC 8032). */
function os2ipLE(bytes: Bytes): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number)
  return n
}

/** I2OSP, little-endian, fixed length. */
function i2ospLE(value: bigint, len: number): Bytes {
  const out = new Uint8Array(len)
  let n = value
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

const oneByte = (b: number): Bytes => Uint8Array.of(b)

interface Secret {
  x: bigint // clamped scalar
  trunc: Bytes // upper half of SHA-512(seed), for nonce generation
  Ystr: Bytes // public key (point) string
  Y: InstanceType<typeof P>
}

/** Derive the VRF scalar + public key from a 32-byte seed (RFC 8032 clamping). */
function deriveSecret(seed: Bytes): Secret {
  if (seed.length !== 32) throw new VrfError('VRF seed must be 32 bytes')
  const h = sha512(seed)
  const a = h.slice(0, 32)
  a[0] = (a[0] as number) & 248
  a[31] = ((a[31] as number) & 127) | 64
  const x = mod(os2ipLE(a))
  const Y = B.multiply(x)
  return { x, trunc: h.slice(32, 64), Ystr: Y.toBytes(), Y }
}

/** The 32-byte ed25519 public key for a VRF seed (hex elsewhere). */
export function vrfPublicKey(seed: Bytes): Bytes {
  return deriveSecret(seed).Ystr
}

/**
 * ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1): hash (suite || 0x01
 * || PK || alpha || ctr || 0x00), take the first 32 bytes as a candidate point,
 * increment ctr until it decodes; clear the cofactor.
 */
function encodeToCurveTai(Ystr: Bytes, alpha: Bytes): InstanceType<typeof P> {
  for (let ctr = 0; ctr <= 255; ctr++) {
    const hashInput = concatBytes(
      oneByte(SUITE),
      oneByte(0x01),
      Ystr,
      alpha,
      oneByte(ctr),
      oneByte(0x00),
    )
    const candidate = sha512(hashInput).slice(0, 32)
    try {
      return P.fromBytes(candidate).clearCofactor()
    } catch {
      // not a valid point encoding — try the next counter
    }
  }
  throw new VrfError('encode_to_curve: no valid point in 256 tries')
}

/** ECVRF_challenge_generation (RFC 9381 §5.4.3): c = LE16(SHA-512(0x03||0x02||pts||0x00)). */
function challenge(points: Bytes[]): bigint {
  const str = concatBytes(oneByte(SUITE), oneByte(0x02), ...points, oneByte(0x00))
  return os2ipLE(sha512(str).slice(0, 16))
}

export interface VrfOutput {
  /** The 80-byte proof π = Gamma(32) || c(16) || s(32). */
  readonly proof: Bytes
  /** The 64-byte VRF output β = SHA-512(0x03||0x03||(8·Gamma)||0x00). */
  readonly beta: Bytes
}

function proofToHash(Gamma: InstanceType<typeof P>): Bytes {
  return sha512(
    concatBytes(oneByte(SUITE), oneByte(0x03), Gamma.multiply(COF).toBytes(), oneByte(0x00)),
  )
}

/** ECVRF_prove (RFC 9381 §5.1). Deterministic in (seed, alpha). */
export function prove(seed: Bytes, alpha: Bytes): VrfOutput {
  const { x, trunc, Ystr } = deriveSecret(seed)
  const H = encodeToCurveTai(Ystr, alpha)
  const Hstr = H.toBytes()
  const Gamma = H.multiply(x)
  const k = mod(os2ipLE(sha512(concatBytes(trunc, Hstr)))) // nonce (RFC 8032 variant)
  const c = challenge([
    Ystr,
    Hstr,
    Gamma.toBytes(),
    B.multiply(k).toBytes(),
    H.multiply(k).toBytes(),
  ])
  const s = mod(k + c * x)
  const proof = concatBytes(Gamma.toBytes(), i2ospLE(c, 16), i2ospLE(s, 32))
  return { proof, beta: proofToHash(Gamma) }
}

/**
 * ECVRF_verify (RFC 9381 §5.3). Returns β on success or null on ANY failure
 * (never throws — it sits behind a stateless consensus verifier).
 */
export function verify(publicKey: Bytes, alpha: Bytes, proof: Bytes): Bytes | null {
  try {
    if (proof.length !== PROOF_LEN) return null
    const Y = P.fromBytes(publicKey)
    const Gamma = P.fromBytes(proof.slice(0, 32))
    const c = os2ipLE(proof.slice(32, 48))
    const s = os2ipLE(proof.slice(48, 80))
    if (s >= L) return null
    const H = encodeToCurveTai(publicKey, alpha)
    const negC = mod(L - c)
    // U = s·B − c·Y ; V = s·H − c·Gamma  (variable-time on public values)
    const U = B.multiplyUnsafe(s).add(Y.multiplyUnsafe(negC))
    const V = H.multiplyUnsafe(s).add(Gamma.multiplyUnsafe(negC))
    const cPrime = challenge([publicKey, H.toBytes(), Gamma.toBytes(), U.toBytes(), V.toBytes()])
    if (cPrime !== c) return null
    return proofToHash(Gamma)
  } catch {
    return null
  }
}
