/**
 * Zero-knowledge range proof: prove a committed amount is BELOW a public
 * threshold WITHOUT revealing the amount. Built on the audited ristretto255
 * prime-order group (@noble/curves). Construction = Pedersen commitments +
 * bit-decomposition + Chaum–Pedersen OR-proofs (Fiat–Shamir), all standard.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STATUS: UNAUDITED REFERENCE. The GROUP and HASH are audited; the PROTOCOL │
 * │ composition here has NOT had external cryptographic review. Do not rely   │
 * │ on it for production privacy until audited. Tracked in docs/STATUS.md.    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Proves diff = (threshold - 1 - amount) ∈ [0, 2^n), hence 0 ≤ amount < threshold
 * for non-negative integer amount/threshold < 2^n.
 */

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js'
import { shake256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { randomBytes, type Bytes } from '../../crypto/src/index.js'

const Point = ristretto255.Point
type Pt = InstanceType<typeof Point>
const L: bigint = Point.Fn.ORDER
const G: Pt = Point.BASE
// Second generator with unknown discrete log w.r.t. G (nothing-up-my-sleeve).
const H: Pt = ristretto255_hasher.hashToCurve(utf8ToBytes('PolarSeek/disclosure/generator-H/v1'))

export class RangeProofError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'RangeProofError'
  }
}

const mod = (x: bigint): bigint => ((x % L) + L) % L
const mul = (P: Pt, s: bigint): Pt => {
  const k = mod(s)
  return k === 0n ? Point.ZERO : P.multiply(k)
}
const neg = (P: Pt): Pt => mul(P, L - 1n)
const sub = (P: Pt, Q: Pt): Pt => P.add(neg(Q))
const scalarFromBytes = (b: Bytes): bigint => mod(BigInt('0x' + bytesToHex(b)))
const randScalar = (): bigint => scalarFromBytes(randomBytes(64))

function modpow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n
  let b = mod(base)
  let e = exp
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m
    e >>= 1n
    b = (b * b) % m
  }
  return r
}
const inv = (a: bigint): bigint => modpow(a, L - 2n, L)

/** Pedersen commitment C = G^v · H^r. */
export function commit(value: bigint, r: bigint): Pt {
  return mul(G, value).add(mul(H, r))
}

interface BitProof {
  t0: Pt
  t1: Pt
  c0: bigint
  c1: bigint
  s0: bigint
  s1: bigint
}
export interface RangeProof {
  readonly commitments: Pt[]
  readonly bits: BitProof[]
  readonly n: number
}

function challenge(ci: Pt, p0: Pt, p1: Pt, t0: Pt, t1: Pt, idx: number): bigint {
  const tag = utf8ToBytes(`PolarSeek/disclosure/bit/${idx}`)
  return scalarFromBytes(
    shake256(
      concatBytes(tag, ci.toBytes(), p0.toBytes(), p1.toBytes(), t0.toBytes(), t1.toBytes()),
      {
        dkLen: 64,
      },
    ),
  )
}

// CDS OR-proof that Ci commits to bit b∈{0,1}: dlog_H(P_b) known, where
// P0 = Ci, P1 = Ci - G. Real branch = b; the other is simulated.
function proveBit(ci: Pt, b: number, ri: bigint, idx: number): BitProof {
  const P0 = ci
  const P1 = sub(ci, G)
  const real = b
  const kReal = randScalar()
  const tReal = mul(H, kReal)
  const sFake = randScalar()
  const cFake = randScalar()
  const Pfake = real === 0 ? P1 : P0
  const tFake = mul(H, sFake).add(neg(mul(Pfake, cFake)))

  const t0 = real === 0 ? tReal : tFake
  const t1 = real === 0 ? tFake : tReal
  const c = challenge(ci, P0, P1, t0, t1, idx)
  const cReal = mod(c - cFake)
  const sReal = mod(kReal + cReal * ri)

  return real === 0
    ? { t0, t1, c0: cReal, c1: cFake, s0: sReal, s1: sFake }
    : { t0, t1, c0: cFake, c1: cReal, s0: sFake, s1: sReal }
}

function verifyBit(ci: Pt, bp: BitProof, idx: number): boolean {
  const P0 = ci
  const P1 = sub(ci, G)
  const c = challenge(ci, P0, P1, bp.t0, bp.t1, idx)
  if (mod(bp.c0 + bp.c1) !== c) return false
  const lhs0 = mul(H, bp.s0)
  const rhs0 = bp.t0.add(mul(P0, bp.c0))
  const lhs1 = mul(H, bp.s1)
  const rhs1 = bp.t1.add(mul(P1, bp.c1))
  return lhs0.equals(rhs0) && lhs1.equals(rhs1)
}

/**
 * Prove the value committed in C = commit(amount, r) is < threshold.
 * Throws RangeProofError if amount is not actually < threshold (honest prover).
 */
export function proveBelow(amount: bigint, r: bigint, threshold: bigint, n = 32): RangeProof {
  const diff = threshold - 1n - amount
  if (diff < 0n || diff >= 1n << BigInt(n)) {
    throw new RangeProofError('amount is not < threshold within the supported range')
  }
  // Choose bit randomness so that Σ r_i·2^i ≡ -r (mod L); then ∏ Ci^{2^i} = C_diff.
  const r_i: bigint[] = []
  let partial = 0n
  for (let i = 0; i < n - 1; i++) {
    const ri = randScalar()
    r_i.push(ri)
    partial = mod(partial + ri * (1n << BigInt(i)))
  }
  const target = mod(-r)
  const lastWeight = 1n << BigInt(n - 1)
  r_i.push(mod((target - partial) * inv(lastWeight)))

  const commitments: Pt[] = []
  const bits: BitProof[] = []
  for (let i = 0; i < n; i++) {
    const b = Number((diff >> BigInt(i)) & 1n)
    const ci = commit(BigInt(b), r_i[i]!)
    commitments.push(ci)
    bits.push(proveBit(ci, b, r_i[i]!, i))
  }
  return { commitments, bits, n }
}

/** Verify a proof that `commitment` (= G^amount·H^r) hides an amount < threshold. */
export function verifyBelow(commitment: Pt, threshold: bigint, proof: RangeProof): boolean {
  if (proof.commitments.length !== proof.n || proof.bits.length !== proof.n) return false
  // C_diff = G^{threshold-1} - C_amt  (a commitment to threshold-1-amount).
  const cDiff = sub(mul(G, threshold - 1n), commitment)
  // Bit commitments must combine to C_diff.
  let combined = Point.ZERO
  for (let i = 0; i < proof.n; i++) {
    combined = combined.add(mul(proof.commitments[i]!, 1n << BigInt(i)))
  }
  if (!combined.equals(cDiff)) return false
  // Each commitment must hide a real bit.
  for (let i = 0; i < proof.n; i++) {
    if (!verifyBit(proof.commitments[i]!, proof.bits[i]!, i)) return false
  }
  return true
}

export { randScalar as randomScalar }
