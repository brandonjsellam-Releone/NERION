// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * M-of-N quorum approval, revocation registry, and the local kill switch.
 *
 * Each approval is an independent PQ signature (ML-DSA-87) over the canonical
 * proposal. Enactment counts DISTINCT valid member signatures and requires at
 * least `threshold`. This is an independent-signature quorum — NOT single-key
 * threshold-MPC crypto (which would need a threshold signature scheme; tracked
 * as future work). No single member can veto.
 */

import {
  DOMAIN_TAGS,
  encodeCanonical,
  signerFor,
  SHA3_SHAKE256,
  type KeyPair,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { Approval, EnactmentResult, Proposal, Quorum } from './types.js'

const GOV_CONTEXT = DOMAIN_TAGS.GOVERNANCE_PROPOSAL

/**
 * Stable identity of a quorum CONFIGURATION = SHA3 over its sorted members +
 * threshold. Bound into every approval signature so a signature gathered under
 * one committee cannot be re-counted under a DIFFERENT committee that merely
 * lists the same operator — cross-quorum / set-substitution consent transfer
 * (GOV-QUORUM-001, Team Apex 2026-06-21). This mirrors the validator-set binding
 * ADR-0005 added to receipts/quorum.ts; governance previously carried only the
 * k>0 fail-closed back-port, not the set-binding.
 */
function quorumId(quorum: Quorum): string {
  const sortedMembers = [...quorum.members].sort()
  const h = SHA3_SHAKE256.digest(
    encodeCanonical([GOV_CONTEXT, 'quorum', sortedMembers, quorum.threshold]),
  )
  // Full-length (no truncation): quorumId is the SECURITY binding that isolates one committee's
  // consent from another's, so a 96-bit truncation invited a ~2^48 cross-quorum collision
  // (GOV-QID-001, Team Apex 2026-06-21). The short proposal id is fine; this binding must not be.
  return bytesToHex(h)
}

function proposalBytes(p: Proposal, qid: string, suite: string): Bytes {
  return encodeCanonical([
    GOV_CONTEXT,
    p.id,
    p.kind,
    p.target,
    p.payload,
    p.notBefore,
    p.notAfter,
    p.nonce,
    qid,
    // Bind the signature suite (GOV-SUITE-001, Team Apex 2026-06-21): without it an approval is
    // not tied to the algorithm it was made under (cross-suite/downgrade confusion, the CAP-001
    // class). Changing the approval's `suite` now changes the signed bytes and fails verification.
    suite,
  ])
}

/** Deterministic proposal id from its content (excluding the id itself). */
export function proposalId(p: Omit<Proposal, 'id'>): string {
  const h = SHA3_SHAKE256.digest(
    encodeCanonical([GOV_CONTEXT, p.kind, p.target, p.payload, p.notBefore, p.notAfter, p.nonce]),
  )
  return bytesToHex(h).slice(0, 24)
}

export function approve(p: Proposal, suite: string, member: KeyPair, quorum: Quorum): Approval {
  const sig = signerFor(suite).sign(proposalBytes(p, quorumId(quorum), suite), member.secretKey)
  return { proposalId: p.id, signer: bytesToHex(member.publicKey), suite, sig }
}

export function verifyApproval(p: Proposal, a: Approval, quorum: Quorum): boolean {
  if (a.proposalId !== p.id) return false
  try {
    return signerFor(a.suite).verify(
      a.sig,
      proposalBytes(p, quorumId(quorum), a.suite),
      hexToBytes(a.signer),
    )
  } catch {
    return false
  }
}

/**
 * Count distinct valid member approvals; enact iff >= threshold and in-window.
 *
 * STATELESS — ANTI-REPLAY IS THE CALLER'S RESPONSIBILITY (GOV-REPLAY-001, AAC council review:
 * DeepSeek + Grok seats converged). `enact` is a PURE predicate: given the same in-window proposal
 * and a valid approval set it returns `enacted:true` EVERY time it is called. The proposal's `nonce`
 * is bound into each signature (so it cannot be mutated without invalidating the approvals) but
 * nothing HERE consumes it as a one-time token. A caller that EXECUTES a proposal's side effect
 * (rotate / config change / payout / any non-idempotent action) MUST record enacted proposal
 * ids/nonces in a durable seen-set — the ledger/translog is the natural home — and refuse a second
 * enactment of the same id; otherwise one quorum decision can be replayed within its validity window
 * (and, by re-presentation of the same signed approvals, across windows). `RevocationRegistry` below
 * is replay-SAFE only incidentally: re-adding an already-revoked target to a Set is idempotent. Do
 * NOT generalize that safety to a non-idempotent enactment.
 */
export function enact(
  p: Proposal,
  approvals: readonly Approval[],
  quorum: Quorum,
  now: number,
): EnactmentResult {
  const reasons: string[] = []
  // Fail-closed on a non-finite clock: a NaN/Infinity `now` makes BOTH window comparisons false,
  // silently skipping the validity-window gate so an out-of-window proposal would enact
  // (GOV-TIME-001 — the KERNEL-TIME-001 / ATTEST-TIME-001 class, missed in governance). `now` is
  // the caller's clock; governance reads no clock of its own.
  if (!Number.isSafeInteger(now)) {
    reasons.push('enactment clock is non-finite or unsafe')
  } else if (
    !Number.isSafeInteger(p.notBefore) ||
    !Number.isSafeInteger(p.notAfter) ||
    p.notAfter < p.notBefore
  ) {
    // GOV-WINDOW-001 (Team Apex sweep): the window bounds are author-supplied. A non-finite
    // notAfter (NaN/Infinity) makes `now > p.notAfter` false, silently disabling expiry — so a
    // time-boxed proposal would never expire. Fail closed on a malformed/inverted window, same
    // discipline as the clock guard above.
    reasons.push('proposal validity window is malformed (non-finite or inverted bounds)')
  } else if (now < p.notBefore || now > p.notAfter) {
    reasons.push('proposal is outside its validity window')
  }
  // Fail-closed on a non-positive threshold: threshold=0 would otherwise enact a
  // proposal with ZERO approvals (`0 < 0` is false). Surfaced by the re-audit.
  if (!Number.isInteger(quorum.threshold) || quorum.threshold < 1) {
    reasons.push('quorum threshold must be a positive integer')
  }

  const members = new Set(quorum.members)
  const distinctValid = new Set<string>()
  // GOV-QUORUM-CENSOR-001 (AAC cycle-2, 2026-07-03): the earlier DOS-VERIFY-001 cap marked a member
  // "attempted" — spending its single ML-DSA-87 verify budget — on the FIRST approval seen for that
  // signer, BEFORE checking the signature. Since the roster is public, an attacker could prepend ONE
  // garbage-sig approval per member and thereby suppress every genuine vote: a unanimous approval set
  // returned enacted:false (an order-dependent censorship of an emergency revoke/rotate/kill quorum).
  // Fix: bound the expensive verifies by a DECODE-SIDE cap on the approval list (matching
  // receipts/quorum.ts) and skip only members already COUNTED (`distinctValid`), never members merely
  // tried — so a member's genuine approval is still verified after an earlier garbage one. Total
  // verifies ≤ maxApprovals (linear, attacker-bounded); the censorship is removed. Honest inputs
  // (one approval per member) are counted exactly as before.
  const threshold =
    Number.isInteger(quorum.threshold) && quorum.threshold >= 1 ? quorum.threshold : Infinity
  // GOV-QUORUM-FLOOD-001 (AAC cycle-6 self-verify): bound the expensive ML-DSA-87 verifies (DoS)
  // WITHOUT rejecting the whole list. An earlier version wholesale-rejected when approvals.length
  // exceeded a cap — but governance approvals may be assembled by an adversarial aggregator/gossip
  // (unlike a receipt's builder-controlled attestations), so padding a GENUINE quorum's list past the
  // cap would force enacted:false — flooding-censorship of an emergency revoke/rotate/kill quorum, the
  // same harm GOV-QUORUM-CENSOR-001 exists to prevent, in another guise. Non-members and already-
  // counted members are skipped CHEAPLY (no verify), so junk padding never consumes the verify budget
  // and a genuine quorum still enacts regardless of how much junk is appended; only the expensive
  // verifies are bounded.
  const maxVerifies = Math.max(quorum.members.length * 4, 256)
  let verifies = 0
  for (const a of approvals) {
    if (distinctValid.size >= threshold) break // quorum already reached — no need to verify more
    if (!members.has(a.signer)) continue // non-member — cheap, consumes no verify budget
    if (distinctValid.has(a.signer)) continue // already counted — cheap, consumes no verify budget
    if (verifies >= maxVerifies) break // bound the expensive verifies (DoS); do NOT reject the list
    verifies++
    if (verifyApproval(p, a, quorum)) distinctValid.add(a.signer)
  }
  const n = distinctValid.size
  if (n < quorum.threshold) reasons.push(`need ${quorum.threshold} approvals, have ${n}`)
  return { enacted: reasons.length === 0, validApprovals: n, reasons }
}

/** In-memory revocation registry driven by enacted `revoke` proposals. */
export class RevocationRegistry {
  private readonly revoked = new Set<string>()

  enactRevocation(
    p: Proposal,
    approvals: readonly Approval[],
    quorum: Quorum,
    now: number,
  ): EnactmentResult {
    if (p.kind !== 'revoke') {
      return { enacted: false, validApprovals: 0, reasons: ['proposal is not a revocation'] }
    }
    const r = enact(p, approvals, quorum, now)
    if (r.enacted) this.revoked.add(p.target)
    return r
  }

  isRevoked(target: string): boolean {
    return this.revoked.has(target)
  }

  /**
   * The enacted revoked capability ids. Pass to admission as the explicit `revoked`
   * input (`node.admit({ ..., revoked: registry.revokedIds() })`) so a capability
   * whose chain contains any of these is denied — wiring quorum revocation into the
   * stateless kernel's enforcement path (REVOKE-ENFORCE-001, Team Apex 2026-06-21).
   */
  revokedIds(): string[] {
    return [...this.revoked]
  }
}

/**
 * Customer-held LOCAL kill switch — a sovereign override that denies everything
 * regardless of quorum. Complements (does not replace) threshold global
 * revocation.
 */
export class LocalKillSwitch {
  private killed = false
  engage(): void {
    this.killed = true
  }
  release(): void {
    this.killed = false
  }
  get engaged(): boolean {
    return this.killed
  }
}
