// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Zero-knowledge range proof: prove a committed amount is BELOW a public
 * threshold WITHOUT revealing the amount. Built on the audited ristretto255
 * prime-order group (@noble/curves). Pedersen commitments + bit-decomposition
 * + Chaum–Pedersen OR-proofs (Fiat–Shamir).
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STATUS: UNAUDITED REFERENCE. The GROUP and HASH are audited; the PROTOCOL │
 * │ composition has NOT had external cryptographic review. Do not rely on it  │
 * │ for production privacy until audited. Tracked in docs/STATUS.md.          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SOUNDNESS (post multi-model council review, 2026-06-18): we prove BOTH
 *   amount ∈ [0, 2^n)   AND   diff = (threshold-1-amount) ∈ [0, 2^n)
 * which over the integers gives 0 ≤ amount < threshold (for threshold ≤ 2^n).
 * Proving only `diff` (an earlier version) was unsound: an adversary could
 * commit to an out-of-range / mod-L value and pass. Both range proofs are now
 * required, and the Fiat–Shamir challenge binds the FULL statement (n,
 * threshold, the amount commitment, and every bit commitment) — closing the
 * weak-Fiat–Shamir ("Frozen Heart") class the council flagged.
 */

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js'
import { shake256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { randomBytes, type Bytes } from '../../crypto/src/index.js'

const Point = ristretto255.Point
export type Pt = InstanceType<typeof Point>
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

/**
 * Homomorphic shift by a PUBLIC value: `C + G^delta = commit(v+delta, r)`. Used to
 * prove `aggregate + amount` bounds from a commitment to `amount` alone, where the
 * running `aggregate` is a public (externally signed) scalar.
 */
export function shiftCommitment(c: Pt, delta: bigint): Pt {
  return c.add(mul(G, delta))
}

interface BitProof {
  t0: Pt
  t1: Pt
  c0: bigint
  c1: bigint
  s0: bigint
  s1: bigint
}
interface SubProof {
  commitments: Pt[]
  bits: BitProof[]
}
export interface RangeProof {
  readonly n: number
  /** Proof that the committed amount ∈ [0, 2^n). */
  readonly amount: SubProof
  /** Proof that diff = threshold-1-amount ∈ [0, 2^n). */
  readonly diff: SubProof
}

/** Full-statement Fiat–Shamir binding (strong FS). */
function statementHash(threshold: bigint, n: number, cAmt: Pt, amountC: Pt[], diffC: Pt[]): Bytes {
  const tag = utf8ToBytes(`PolarSeek/disclosure/stmt/v2|n=${n}|thr=${threshold}`)
  const parts = [
    tag,
    cAmt.toBytes(),
    ...amountC.map((p) => p.toBytes()),
    ...diffC.map((p) => p.toBytes()),
  ]
  return shake256(concatBytes(...parts), { dkLen: 64 })
}

function challenge(stmt: Bytes, tag: string, ci: Pt, p0: Pt, p1: Pt, t0: Pt, t1: Pt): bigint {
  return scalarFromBytes(
    shake256(
      concatBytes(
        utf8ToBytes(tag),
        stmt,
        ci.toBytes(),
        p0.toBytes(),
        p1.toBytes(),
        t0.toBytes(),
        t1.toBytes(),
      ),
      {
        dkLen: 64,
      },
    ),
  )
}

// CDS OR-proof that Ci commits to bit b∈{0,1}: dlog_H(P_b) known, P0=Ci, P1=Ci-G.
function proveBit(ci: Pt, b: number, ri: bigint, stmt: Bytes, tag: string): BitProof {
  const P0 = ci
  const P1 = sub(ci, G)
  const kReal = randScalar()
  const tReal = mul(H, kReal)
  const sFake = randScalar()
  const cFake = randScalar()
  const Pfake = b === 0 ? P1 : P0
  const tFake = mul(H, sFake).add(neg(mul(Pfake, cFake)))
  const t0 = b === 0 ? tReal : tFake
  const t1 = b === 0 ? tFake : tReal
  const c = challenge(stmt, tag, ci, P0, P1, t0, t1)
  const cReal = mod(c - cFake)
  const sReal = mod(kReal + cReal * ri)
  return b === 0
    ? { t0, t1, c0: cReal, c1: cFake, s0: sReal, s1: sFake }
    : { t0, t1, c0: cFake, c1: cReal, s0: sFake, s1: sReal }
}

function verifyBit(ci: Pt, bp: BitProof, stmt: Bytes, tag: string): boolean {
  const P0 = ci
  const P1 = sub(ci, G)
  const c = challenge(stmt, tag, ci, P0, P1, bp.t0, bp.t1)
  if (mod(bp.c0 + bp.c1) !== c) return false
  return (
    mul(H, bp.s0).equals(bp.t0.add(mul(P0, bp.c0))) &&
    mul(H, bp.s1).equals(bp.t1.add(mul(P1, bp.c1)))
  )
}

// Build bit commitments for `value` whose randomness sums (weighted) to `rand`,
// so that Σ Ci·2^i == commit(value, rand).
function buildBits(
  value: bigint,
  rand: bigint,
  n: number,
): { bits: number[]; r: bigint[]; commitments: Pt[] } {
  const r: bigint[] = []
  let partial = 0n
  for (let i = 0; i < n - 1; i++) {
    const ri = randScalar()
    r.push(ri)
    partial = mod(partial + ri * (1n << BigInt(i)))
  }
  r.push(mod((mod(rand) - partial) * inv(1n << BigInt(n - 1))))
  const bits: number[] = []
  const commitments: Pt[] = []
  for (let i = 0; i < n; i++) {
    const b = Number((value >> BigInt(i)) & 1n)
    bits.push(b)
    commitments.push(commit(BigInt(b), r[i]!))
  }
  return { bits, r, commitments }
}

function proveSub(
  built: { bits: number[]; r: bigint[]; commitments: Pt[] },
  stmt: Bytes,
  prefix: string,
): SubProof {
  const bits = built.commitments.map((ci, i) =>
    proveBit(ci, built.bits[i]!, built.r[i]!, stmt, `PolarSeek/disclosure/bit/${prefix}/${i}`),
  )
  return { commitments: built.commitments, bits }
}

function verifySub(target: Pt, sub: SubProof, n: number, stmt: Bytes, prefix: string): boolean {
  if (sub.commitments.length !== n || sub.bits.length !== n) return false
  let combined = Point.ZERO
  for (let i = 0; i < n; i++) combined = combined.add(mul(sub.commitments[i]!, 1n << BigInt(i)))
  if (!combined.equals(target)) return false
  for (let i = 0; i < n; i++) {
    if (
      !verifyBit(sub.commitments[i]!, sub.bits[i]!, stmt, `PolarSeek/disclosure/bit/${prefix}/${i}`)
    ) {
      return false
    }
  }
  return true
}

/**
 * Prove the value committed in commit(amount, r) satisfies 0 ≤ amount < threshold.
 * Throws RangeProofError if the inputs are out of the supported range.
 */
export function proveBelow(amount: bigint, r: bigint, threshold: bigint, n = 32): RangeProof {
  const bound = 1n << BigInt(n)
  if (amount < 0n || amount >= bound) throw new RangeProofError('amount must be in [0, 2^n)')
  if (threshold < 1n || threshold > bound)
    throw new RangeProofError('threshold must be in (0, 2^n]')
  const diff = threshold - 1n - amount
  if (diff < 0n) throw new RangeProofError('amount is not < threshold')

  const builtAmount = buildBits(amount, mod(r), n)
  const builtDiff = buildBits(diff, mod(-r), n)
  const cAmt = commit(amount, r)
  const stmt = statementHash(threshold, n, cAmt, builtAmount.commitments, builtDiff.commitments)
  return {
    n,
    amount: proveSub(builtAmount, stmt, 'amount'),
    diff: proveSub(builtDiff, stmt, 'diff'),
  }
}

/**
 * Verify a proof that `commitment` (= commit(amount, r)) hides 0 ≤ amount < threshold.
 *
 * `n` is the VERIFIER's expected bit-length (a protocol constant, default 32) —
 * it is NOT taken from the proof. A proof whose `n` differs is rejected, and `n`
 * is hard-capped at **251** so that 2^(n+1) ≤ L. Both `amount` and
 * `diff = threshold-1-amount` are proven in [0, 2^n); soundness requires their
 * value ranges not to alias across the group order L.
 *   - ZKRANGE-001: a large `proof.n` with 2^n ≥ L would wrap a false claim around L
 *     (closed by capping n and by `proof.n === n`).
 *   - ZKRANGE-002 (off-by-one, found by the Team Apex multi-model code audit
 *     2026-06-21): at n=252, a negative `diff` wraps to L-|diff| ∈ [0, 2^n) — since
 *     L = 2^252 + d with d ≈ 2^124.7 — so a huge `amount` (≈2^124) falsely proves
 *     `< threshold`. The n ≤ 251 cap (2^(n+1) ≤ L) closes it.
 */
export function verifyBelow(commitment: Pt, threshold: bigint, proof: RangeProof, n = 32): boolean {
  if (!Number.isInteger(n) || n < 1 || n > 251) return false
  if (proof.n !== n) return false
  const bound = 1n << BigInt(n)
  if (threshold < 1n || threshold > bound) return false
  const cDiff = sub(mul(G, threshold - 1n), commitment)
  const stmt = statementHash(
    threshold,
    n,
    commitment,
    proof.amount.commitments,
    proof.diff.commitments,
  )
  // amount ∈ [0,2^n) bound to C_amt, and diff ∈ [0,2^n) bound to C_diff.
  if (!verifySub(commitment, proof.amount, n, stmt, 'amount')) return false
  if (!verifySub(cDiff, proof.diff, n, stmt, 'diff')) return false
  return true
}

export { randScalar as randomScalar }
