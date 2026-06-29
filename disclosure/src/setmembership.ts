// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Zero-knowledge SET-MEMBERSHIP proof: prove a Pedersen-committed value is a member of a PUBLIC set
 * WITHOUT revealing WHICH element it is (Team Apex R&D council 2026-06-28). This is the deferred
 * disclosure clause `policyproof.ts` flagged — "prove the action-type / counterparty is in the
 * governed allow-set, reveal nothing else" — the categorical privacy move a central governor cannot
 * make: an auditor learns "the action was one the policy permits" without learning which.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STATUS: UNAUDITED REFERENCE. The GROUP and HASH are audited; this PROTOCOL │
 * │ (a 1-of-k Chaum–Pedersen OR-proof) has NOT had external review. Soundness  │
 * │ is CLASSICAL (discrete-log over ristretto255), proven in the ROM, NOT      │
 * │ post-quantum. Do not rely on it for production privacy until audited.      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CONSTRUCTION. Reuses the EXACT same audited group + generators G,H as `zkrange` (Pedersen
 * `C = v·G + r·H`). To prove `v ∈ {s_0,…,s_{k-1}}` define `P_j = C − s_j·G`. If `v = s_t` then
 * `P_t = r·H`, so the prover knows `dlog_H(P_t) = r`; for `j ≠ t` it does not. The proof is a
 * 1-of-k OR of "I know dlog_H(P_j)" — a direct generalization of `zkrange`'s 1-of-2 bit OR-proof,
 * compiled non-interactively with a SHAKE256 Fiat–Shamir challenge that binds the full statement
 * (domain, C, the whole set, and all per-branch commitments). The prover simulates the k−1 false
 * branches (pick response+challenge, back-compute the commitment) and runs one real Schnorr branch;
 * the challenge shares must sum to the FS challenge, which forces ≥1 real branch (special-soundness)
 * while hiding which (HVZK). Compact form: the proof is just the k challenge shares + k responses.
 */

import { shake256 } from '@noble/hashes/sha3.js'
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { G, H, L, mul, sub, scalarFromBytes, commit, randomScalar, type Pt } from './zkrange.js'
import type { Bytes } from '../../crypto/src/index.js'

const DOMAIN = 'Nerion/disclosure/set-membership/v1'

/** Bound the public set size before the O(k) point work (decode-side DoS on the verifier). Honest
 *  allow-lists (action-type / counterparty sets) are small; reject larger sets fail-closed. */
const MAX_SET_SIZE = 1024

const mod = (x: bigint): bigint => ((x % L) + L) % L

export class SetMembershipError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'SetMembershipError'
  }
}

/** A 1-of-k OR-proof that a commitment hides a member of a public set (compact CDS form). */
export interface MembershipProof {
  /** Per-branch challenge shares (length k); must sum to the Fiat–Shamir challenge. */
  readonly c: readonly bigint[]
  /** Per-branch Schnorr responses (length k). */
  readonly s: readonly bigint[]
}

/** Canonical 32-byte big-endian encoding of a scalar (reduced mod L) for the transcript. */
function scalarTo32(x: bigint): Bytes {
  const out = new Uint8Array(32)
  let v = mod(x)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** Fiat–Shamir challenge binding the FULL statement: domain, k, C, the whole set, and every t_j. */
function challenge(commitment: Pt, set: readonly bigint[], ts: readonly Pt[]): bigint {
  const parts: Bytes[] = [
    utf8ToBytes(`${DOMAIN}|k=${set.length}`),
    commitment.toBytes(),
    ...set.map(scalarTo32),
    ...ts.map((t) => t.toBytes()),
  ]
  return scalarFromBytes(shake256(concatBytes(...parts), { dkLen: 64 }))
}

/**
 * Prove the value committed in `commit(value, r)` is a member of `set`, revealing nothing about
 * which element. Throws if `value` is not in `set` (a prover cannot prove a false statement) or the
 * set is empty / too large.
 */
export function proveMembership(value: bigint, r: bigint, set: readonly bigint[]): MembershipProof {
  if (set.length === 0) throw new SetMembershipError('set must be non-empty')
  if (set.length > MAX_SET_SIZE)
    throw new SetMembershipError(`set exceeds MAX_SET_SIZE (${MAX_SET_SIZE})`)
  const v = mod(value)
  const t = set.findIndex((s) => mod(s) === v)
  if (t < 0) throw new SetMembershipError('value is not a member of the set')

  const commitment = commit(value, r)
  const k = set.length
  const P: Pt[] = set.map((s) => sub(commitment, mul(G, s)))
  const c: bigint[] = new Array<bigint>(k)
  const s: bigint[] = new Array<bigint>(k)
  const ts: Pt[] = new Array<Pt>(k)

  // Simulate every FALSE branch: pick (response, challenge) and back-compute the commitment t_j so
  // the verify equation s_j·H = t_j + c_j·P_j holds by construction.
  let sumFake = 0n
  for (let j = 0; j < k; j++) {
    if (j === t) continue
    c[j] = randomScalar()
    s[j] = randomScalar()
    ts[j] = sub(mul(H, s[j]!), mul(P[j]!, c[j]!))
    sumFake = mod(sumFake + c[j]!)
  }
  // Real branch: a genuine Schnorr commitment over base H.
  const kReal = randomScalar()
  ts[t] = mul(H, kReal)

  const chal = challenge(commitment, set, ts)
  c[t] = mod(chal - sumFake) // challenge shares must sum to the FS challenge
  s[t] = mod(kReal + c[t]! * r) // close the real branch with the witness r

  return { c, s }
}

/**
 * Verify a set-membership proof against a commitment and a PUBLIC set. Fail-closed: a length
 * mismatch, an oversized set, or a Fiat–Shamir mismatch all return false. Never throws.
 */
export function verifyMembership(
  commitment: Pt,
  set: readonly bigint[],
  proof: MembershipProof,
): boolean {
  try {
    const k = set.length
    if (k === 0 || k > MAX_SET_SIZE) return false
    if (proof.c.length !== k || proof.s.length !== k) return false
    const ts: Pt[] = new Array<Pt>(k)
    let sumC = 0n
    for (let j = 0; j < k; j++) {
      const Pj = sub(commitment, mul(G, set[j]!))
      // t_j = s_j·H − c_j·P_j  (so the per-branch Schnorr equation holds by construction).
      ts[j] = sub(mul(H, proof.s[j]!), mul(Pj, proof.c[j]!))
      sumC = mod(sumC + proof.c[j]!)
    }
    // Soundness gate: the challenge shares must sum to the FS challenge over the recomputed t_j.
    return sumC === challenge(commitment, set, ts)
  } catch {
    return false
  }
}
