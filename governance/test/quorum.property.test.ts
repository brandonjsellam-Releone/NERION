// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import { approve, enact, proposalId } from '../src/index.js'
import type { Proposal, Quorum, Approval } from '../src/index.js'

/**
 * Property-based correspondence between the **machine-checked** TLA+ consensus model
 * (`docs/formal/NerionConsensus.tla`, invariant `QuorumIntegrity`) and the REAL
 * M-of-N governance quorum in `governance/src/quorum.ts`. The formal model proves
 * "a finalized decision always carries a ≥threshold quorum" abstractly over a finite
 * state space (and the formal README notes the governance quorum is modelled there
 * only as the stake-finality analogue); here we assert the SAME integrity property on
 * the actual `enact()` code over a randomized space of member sets, thresholds,
 * validity windows, and adversarial approvals — closing the model-is-not-the-code gap.
 *
 * The named single-shot cases (GOV-QUORUM-001 cross-quorum non-transfer, duplicate
 * counting, non-member/invalid rejection, the window/threshold fail-closed guards)
 * live in `quorum.test.ts`; this fuzzes the same surfaces together to catch any
 * combination that lets `enact()` return `enacted` without a genuine quorum.
 */

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
// ML-DSA-87 keygen is expensive; generate a fixed pool once and reuse across runs.
const POOL: KeyPair[] = Array.from({ length: 5 }, () => s.keygen())
const POOL_HEX = POOL.map((k) => bytesToHex(k.publicKey))

const mkProposal = (nonce: string, notBefore: number, notAfter: number): Proposal => {
  const body = { kind: 'param' as const, target: 't', payload: 'v', notBefore, notAfter, nonce }
  return { id: proposalId(body), ...body }
}

// An approval plus the GROUND-TRUTH of whether it is a valid approval BY A MEMBER for
// THIS proposal+quorum — computed at construction (no extra PQ verifies), so the test's
// expectation is independent of the code under test.
function buildApproval(
  kind: 'valid' | 'tampered' | 'wrongquorum' | 'wrongproposal',
  idx: number,
  p: Proposal,
  quorum: Quorum,
  memberHex: readonly string[],
): { a: Approval; valid: boolean } {
  const kp = POOL[idx]!
  const isMember = memberHex.includes(POOL_HEX[idx]!)
  switch (kind) {
    case 'valid':
      return { a: approve(p, suite, kp, quorum), valid: isMember }
    case 'tampered': {
      const a = approve(p, suite, kp, quorum)
      const sig = Uint8Array.from(a.sig)
      sig[0]! ^= 0x01 // corrupt one byte ⇒ signature no longer verifies
      return { a: { ...a, sig }, valid: false }
    }
    case 'wrongquorum': {
      // Same members, different threshold ⇒ different quorumId ⇒ signature is bound to a
      // DIFFERENT committee and must not count here (GOV-QUORUM-001).
      const q2: Quorum = { members: quorum.members, threshold: quorum.threshold + 1 }
      return { a: approve(p, suite, kp, q2), valid: false }
    }
    case 'wrongproposal': {
      const p2 = mkProposal(p.nonce + 'x', p.notBefore, p.notAfter)
      return { a: approve(p2, suite, kp, quorum), valid: false }
    }
  }
}

describe('QuorumIntegrity — property-based (mirrors the machine-checked TLA+ model on real enact())', () => {
  it('enact() approves iff in-window, threshold≥1, and ≥threshold DISTINCT valid member sigs — never over-counts', () => {
    const idxArb = fc.integer({ min: 0, max: 4 })
    const instrArb = fc.record({
      idx: idxArb,
      kind: fc.constantFrom('valid', 'tampered', 'wrongquorum', 'wrongproposal' as const),
    })
    fc.assert(
      fc.property(
        fc.subarray([0, 1, 2, 3, 4], { minLength: 1 }), // member indices (non-empty)
        fc.integer({ min: 0, max: 6 }), // threshold (incl. 0 = invalid, and > member count)
        fc.integer({ min: 0, max: 1000 }), // notBefore
        fc.integer({ min: 0, max: 1000 }), // window duration ⇒ notAfter = nb + dur (well-formed)
        fc.integer({ min: -100, max: 2000 }), // now (inside or outside the window)
        fc.array(instrArb, { maxLength: 8 }),
        (memberIdx, threshold, nb, dur, now, instrs) => {
          const memberHex = memberIdx.map((i) => POOL_HEX[i]!)
          const na = nb + dur
          const quorum: Quorum = { members: memberHex, threshold }
          const p = mkProposal('n0', nb, na)

          const built = instrs.map((it) => buildApproval(it.kind, it.idx, p, quorum, memberHex))
          const approvals = built.map((b) => b.a)

          // Ground truth: distinct MEMBER signers carrying a genuinely valid approval.
          const distinctValid = new Set(built.filter((b) => b.valid).map((b) => b.a.signer))
          const full = distinctValid.size
          const thrOk = Number.isInteger(threshold) && threshold >= 1
          const inWindow = now >= nb && now <= na
          const expectedEnacted = thrOk && inWindow && full >= threshold

          const r = enact(p, approvals, quorum, now)

          // QuorumIntegrity: the verdict matches the genuine quorum exactly.
          expect(r.enacted).toBe(expectedEnacted)
          // Never over-counts: no double-counting a member, no non-member, no invalid sig.
          expect(r.validApprovals).toBeGreaterThanOrEqual(0)
          expect(r.validApprovals).toBeLessThanOrEqual(full)
          // When it enacts, the count genuinely meets threshold.
          if (expectedEnacted) expect(r.validApprovals).toBeGreaterThanOrEqual(threshold)
          // Censorship guard (GOV-QUORUM-CENSOR-001): below threshold there is NO early-exit, so
          // every genuine valid member approval must be counted — a garbage-sig approval seen first
          // for a member can NOT suppress that member's genuine one. Undercount here == censorship.
          if (thrOk && inWindow && full < threshold) expect(r.validApprovals).toBe(full)
        },
      ),
      { numRuns: 60 },
    )
  })
})
