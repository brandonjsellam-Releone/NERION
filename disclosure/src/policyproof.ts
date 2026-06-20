// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Policy-Satisfaction Proof (PSP) — prove an action satisfied the kernel's NUMERIC
 * policy bounds WITHOUT revealing the amount.
 *
 * The privacy-preserving compliance proof: an auditor learns "the decided amount
 * was within the per-action ceiling (and the running aggregate stayed under the
 * cap)" — but NEVER the amount itself. This is the categorical move a central-
 * visibility governor cannot make: the verdict is checkable without seeing the
 * payload.
 *
 * This is the CONSERVATIVE, SOUND subset of the ZK-PSR design (ADR-0006). It
 * composes ONLY the existing audited-group range proof (`zkrange`). The ZK
 * SET-MEMBERSHIP clauses (action-type / counterparty) are DEFERRED: they need a
 * new k-way Chaum-Pedersen OR-proof that is not yet built or reviewed, and the
 * unsalted selective-disclosure fallback is deliberately NOT used here (it is
 * brute-forceable over small enumerable domains — flagged by the design audit).
 *
 * UNAUDITED REFERENCE — DO NOT RELY ON FOR PRODUCTION PRIVACY. The group
 * (ristretto255) + hash (SHAKE256) are audited; this PROTOCOL composition is not,
 * and inherits zkrange's unaudited status. No privacy claim until external ZK audit
 * + FTO review.
 *
 * POST-QUANTUM PROFILE (corrected by the multi-model crypto council — the common
 * mistake runs the OTHER way): the hidden amount's CONFIDENTIALITY is
 * INFORMATION-THEORETIC. Pedersen commitments are PERFECTLY hiding, so NO adversary
 * — including a future quantum one — can recover the amount from a logged proof.
 * There is NO harvest-now-decrypt-later risk to the hidden amount. What rests on a
 * CLASSICAL assumption is the proof's SOUNDNESS / binding (discrete-log over
 * ristretto255): a quantum adversary could FORGE a satisfaction proof for an
 * out-of-bound amount. So: receipt-envelope integrity is PQ (ML-DSA-87); the ZK
 * proof's INTEGRITY is classical; the amount's SECRECY is unconditional.
 *
 * NUANCE (Team Apex / DeepSeek, 2026-06-20): the COMMITMENT's hiding is unconditional, but
 * the non-interactive proof's ZERO-KNOWLEDGE is established in the classical random-oracle
 * model and is NOT yet analyzed in the QROM. Treat "the proof itself reveals nothing about
 * the amount to a QUANTUM verifier" as UNPROVEN (not guaranteed) pending QROM analysis.
 *
 * LINKAGE CONTRACT (soundness prerequisite, per the design audit's strongest
 * finding): this proves a property of the COMMITTED amount. End-to-end soundness
 * requires the ISSUER to commit the SAME amount the kernel decided on and bind the
 * commitment into the signed receipt body (a v:2 receipt's `commitments.psr`, via
 * `policyProofDigest`). Until that wiring exists a proof attests "some committed
 * amount is within bounds," not "the decided amount is" — callers MUST supply the
 * decided amount.
 */

import {
  commit,
  shiftCommitment,
  proveBelow,
  verifyBelow,
  randomScalar,
  type Pt,
  type RangeProof,
} from './zkrange.js'
import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

/** Public policy bounds the amount must satisfy (drawn from the capability/policy). */
export interface PolicyBounds {
  /** amount <= perActionCeiling. Required. */
  readonly perActionCeiling: bigint
  /** Running total already observed (a public, externally signed scalar). */
  readonly aggregate?: bigint
  /** observedAggregate + amount <= aggregateCap. Requires `aggregate`. */
  readonly aggregateCap?: bigint
  /** Verifier-fixed bit width (protocol constant; default 32). */
  readonly n?: number
}

export interface PolicySatisfactionProof {
  readonly n: number
  /** Proof that amount <= perActionCeiling, over C_amount. */
  readonly ceiling: RangeProof
  /** Proof that aggregate + amount <= aggregateCap, over C_sum — null when uncapped. */
  readonly aggregate: RangeProof | null
}

export interface AmountCommitment {
  readonly commitment: Pt
  readonly opening: bigint
}

/** Commit to a decided amount; keep the opening to prove satisfaction. */
export function commitAmount(amount: bigint): AmountCommitment {
  const opening = randomScalar()
  return { commitment: commit(amount, opening), opening }
}

/**
 * Prove the committed `amount` satisfies the policy bounds, revealing nothing about
 * the amount. Reuses the audited-group dual range proof: amount < ceiling+1, and
 * (when an aggregate cap is set) amount+aggregate < cap+1 over the homomorphic sum
 * commitment. zkrange throws if the amount is out of [0, 2^n) or not below a bound,
 * so a prover cannot prove a false statement.
 */
export function provePolicySatisfaction(
  amount: bigint,
  opening: bigint,
  bounds: PolicyBounds,
): PolicySatisfactionProof {
  const n = bounds.n ?? 32
  const ceiling = proveBelow(amount, opening, bounds.perActionCeiling + 1n, n)
  let aggregate: RangeProof | null = null
  if (bounds.aggregate !== undefined && bounds.aggregateCap !== undefined) {
    // C_sum = C_amount + G^aggregate = commit(amount+aggregate, opening).
    aggregate = proveBelow(amount + bounds.aggregate, opening, bounds.aggregateCap + 1n, n)
  }
  return { n, ceiling, aggregate }
}

/**
 * Verify a Policy-Satisfaction Proof against a commitment and the PUBLIC bounds.
 * `bounds.aggregate` MUST be the trusted (externally signed) running total — the
 * verifier reconstructs C_sum from it. Fail-closed: any missing/invalid sub-proof,
 * an `n` mismatch, a capped policy with no aggregate proof, or a stray aggregate
 * proof under an uncapped policy all return false.
 */
export function verifyPolicySatisfaction(
  commitment: Pt,
  bounds: PolicyBounds,
  proof: PolicySatisfactionProof,
): boolean {
  const n = bounds.n ?? 32
  if (proof.n !== n) return false
  // A policy that sets an aggregate cap MUST supply the (trusted, signed) aggregate;
  // otherwise the cap check below would be silently skipped. Fail closed on that
  // misconfiguration rather than accepting a ceiling-only proof against a capped policy.
  if (bounds.aggregateCap !== undefined && bounds.aggregate === undefined) return false
  if (!verifyBelow(commitment, bounds.perActionCeiling + 1n, proof.ceiling, n)) return false

  const capped = bounds.aggregate !== undefined && bounds.aggregateCap !== undefined
  if (capped) {
    if (proof.aggregate === null) return false
    const cSum = shiftCommitment(commitment, bounds.aggregate as bigint)
    if (!verifyBelow(cSum, (bounds.aggregateCap as bigint) + 1n, proof.aggregate, n)) return false
  } else if (proof.aggregate !== null) {
    return false // an aggregate proof with no cap is rejected, fail-closed
  }
  return true
}

function serializeRangeProof(p: RangeProof): unknown {
  const sub = (s: RangeProof['amount']): unknown => ({
    commitments: s.commitments.map((c) => bytesToHex(c.toBytes())),
    bits: s.bits.map((b) => ({
      t0: bytesToHex(b.t0.toBytes()),
      t1: bytesToHex(b.t1.toBytes()),
      c0: b.c0.toString(16),
      c1: b.c1.toString(16),
      s0: b.s0.toString(16),
      s1: b.s1.toString(16),
    })),
  })
  return { n: p.n, amount: sub(p.amount), diff: sub(p.diff) }
}

/**
 * The binding digest that ties this proof to a specific policy and commitment — the
 * value a v:2 receipt carries in `commitments.psr`, so the proof is transitively
 * ML-DSA-87-signed and transparency-log-anchored by the receipt body. Binds the
 * policy identity (`policyBinding`, e.g. the kernel `evaluatorVersion`) so a proof
 * issued under policy P cannot be presented as satisfying P'.
 */
export function policyProofDigest(
  commitment: Pt,
  proof: PolicySatisfactionProof,
  policyBinding: string,
): string {
  const serialized = encodeCanonical([
    'polarseek-psp-v1',
    policyBinding,
    bytesToHex(commitment.toBytes()),
    proof.n,
    serializeRangeProof(proof.ceiling),
    proof.aggregate ? serializeRangeProof(proof.aggregate) : 'none',
  ])
  return bytesToHex(SHA3_SHAKE256.digest(serialized))
}
