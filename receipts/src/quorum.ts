// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Decentralized k-of-n quorum receipts — no single host can mint a valid receipt.
 *
 * A quorum receipt wraps an ordinary `ReceiptBody` with a BINDING to the exact
 * validator set + threshold + epoch it was issued under, then collects k
 * INDEPENDENT ML-DSA-87 signatures over that bound body. Verification recomputes
 * the set id from the verifier's own trusted (finalized) `ValidatorSet` and
 * rejects any receipt whose committed set id does not match — so a verifier
 * cannot be fed a permissive or attacker-substituted validator set at
 * verification time (the load-bearing multi-model council finding).
 *
 * This is an INDEPENDENT-signature quorum (a decentralized multi-attestation) —
 * NOT single-key threshold-MPC / FROST. A real threshold signature would need a
 * threshold scheme AND would be classical (not post-quantum). Forgery resistance
 * here reduces to ML-DSA-87 (FIPS 204) EUF-CMA: no party holding fewer than k
 * distinct member keys can produce k distinct member signatures over the bound
 * body. **Safety is fully post-quantum**; liveness depends on k validators being
 * available — an availability property of any quorum, not a crypto assumption.
 *
 * Mirrors `governance/quorum.ts` `enact()` (distinct-member counting, fail-closed)
 * and adds the set-binding `receipts/receipt.ts` receipts lack by design.
 */

import {
  encodeCanonical,
  signerFor,
  SHA3_SHAKE256,
  type KeyPair,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { ReceiptBody } from './receipt.js'
import type { ValidatorSet } from '../../ledger/src/index.js'

const QUORUM_CONTEXT = 'polarseek-quorum-receipt-v1'

/** One validator's independent ML-DSA-87 attestation over the bound body. */
export interface QuorumAttestation {
  /** hex validator public key — the consensus identity that is counted. */
  readonly validator: string
  readonly suite: string
  readonly sig: Bytes
}

/** Binds a receipt to the exact set / threshold / epoch / suite its signers attested. */
export interface QuorumBinding {
  /** Hash of the canonical (sorted [pubkey, stake] list, k, epoch). */
  readonly setId: string
  readonly k: number
  readonly epoch: number
  readonly suite: string
}

export interface QuorumReceiptBody {
  readonly receipt: ReceiptBody
  readonly quorum: QuorumBinding
}

export interface QuorumReceipt {
  readonly body: QuorumReceiptBody
  readonly attestations: readonly QuorumAttestation[]
}

export interface QuorumVerdict {
  readonly ok: boolean
  readonly distinctValid: number
  /** Count threshold `k` (number) for the count variant, or stake threshold (bigint) for the stake variant. */
  readonly threshold: number | bigint
  readonly reasons: string[]
}

/**
 * Deterministic id of (validator set, threshold, epoch). Sorting by pubkey makes
 * it order-independent; stake is included so a reweighted set is a DIFFERENT set.
 * Any change to membership, stake, k, or epoch changes the id — which is exactly
 * what lets a verifier detect a substituted set.
 */
export function quorumSetId(set: ValidatorSet, k: number, epoch: number): string {
  const sorted = set.validators
    .map((v) => [v.pubkey, v.stake] as const)
    .slice()
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  return bytesToHex(SHA3_SHAKE256.digest(encodeCanonical([QUORUM_CONTEXT, sorted, k, epoch])))
}

/**
 * Collect k-of-n independent ML-DSA-87 attestations over a receipt bound to the
 * given set / threshold / epoch. Each signer signs the SAME canonical bound body.
 */
export function buildQuorumReceipt(
  receipt: ReceiptBody,
  set: ValidatorSet,
  k: number,
  epoch: number,
  signers: readonly KeyPair[],
  suite: string,
): QuorumReceipt {
  const body: QuorumReceiptBody = {
    receipt,
    quorum: { setId: quorumSetId(set, k, epoch), k, epoch, suite },
  }
  // Domain-separated signing message (Team Apex audit 2026-06-21): the QUORUM_CONTEXT
  // tag is at the TOP LEVEL of the signed bytes, not only inside setId — so a validator's
  // ML-DSA-87 signature over a quorum body can never be confused with (or harvested from)
  // any other message shape that reuses the same key.
  const msg = encodeCanonical([QUORUM_CONTEXT, body])
  const signer = signerFor(suite)
  const attestations = signers.map((s) => ({
    validator: bytesToHex(s.publicKey),
    suite,
    sig: signer.sign(msg, s.secretKey),
  }))
  return { body, attestations }
}

function countDistinctValid(
  receipt: QuorumReceipt,
  isMember: (v: string) => boolean,
  onValid: (v: string) => void,
): void {
  const q = receipt.body.quorum
  // Must match buildQuorumReceipt's domain-separated message exactly.
  const msg = encodeCanonical([QUORUM_CONTEXT, receipt.body])
  const seen = new Set<string>()
  for (const a of receipt.attestations) {
    if (a.suite !== q.suite) continue // bind to the quorum's committed suite
    if (!isMember(a.validator) || seen.has(a.validator)) continue
    // GOV-QUORUM-CENSOR-001 (AAC cycle-2, 2026-07-03): count a member on its FIRST VALID attestation
    // and skip only members already counted (`seen`) — NOT members merely tried. The earlier
    // DOS-VERIFY-001 cap marked a member "attempted" before verifying, so a garbage-sig attestation
    // seen first burned that member's single verify budget and suppressed its genuine one (an
    // order-dependent censorship). Total verifies stay bounded by the callers' decode-side
    // `maxAttestations` cap (fail-closed above), so this is O(attestations) WITHOUT the censorship.
    let valid = false
    try {
      valid = signerFor(a.suite).verify(a.sig, msg, hexToBytes(a.validator))
    } catch {
      valid = false
    }
    if (valid) {
      seen.add(a.validator)
      onValid(a.validator)
    }
  }
}

/**
 * Verify a quorum receipt against the verifier's OWN trusted (finalized)
 * `ValidatorSet` + threshold + epoch. Fail-closed. The committed `setId` must
 * equal the id recomputed from the trusted set — this rejects a permissive or
 * attacker-substituted set at verification time. Then count DISTINCT valid member
 * attestations (a duplicated signer cannot inflate the count) and require >= k.
 * Pure: no clock, no module state, byte-stable on re-verification.
 */
export function verifyQuorumReceipt(
  receipt: QuorumReceipt,
  set: ValidatorSet,
  k: number,
  epoch: number,
): QuorumVerdict {
  const reasons: string[] = []
  // Fail-closed on a non-positive threshold: k=0 would otherwise accept a receipt
  // with ZERO signatures (`0 < 0` is false). Surfaced by the adversarial re-audit.
  if (!Number.isInteger(k) || k < 1) reasons.push('threshold k must be a positive integer')
  const q = receipt.body.quorum
  if (q.k !== k) reasons.push(`committed threshold ${q.k} != expected ${k}`)
  if (q.epoch !== epoch) reasons.push(`committed epoch ${q.epoch} != expected ${epoch}`)
  if (q.setId !== quorumSetId(set, k, epoch)) {
    reasons.push(
      'committed validator-set id does not match the trusted set (substitution rejected)',
    )
  }

  const members = new Set(set.validators.map((v) => v.pubkey))
  let distinct = 0
  // F11 (Team Apex max sweep 2026-06-28): bound the attacker-supplied attestations array on this
  // exported verifier before iterating it. At most |members| can ever count, so an array far
  // larger than the set is junk that only burns O(A) iteration. Reject past 4× the set size,
  // fail-closed, and SKIP the loop (do not push a reason and still iterate).
  const maxAttestations = Math.max(set.validators.length * 4, 256)
  if (receipt.attestations.length > maxAttestations) {
    reasons.push(
      `attestation count ${receipt.attestations.length} exceeds bound ${maxAttestations}`,
    )
  } else {
    countDistinctValid(
      receipt,
      (v) => members.has(v),
      () => {
        distinct += 1
      },
    )
  }
  if (distinct < k) reasons.push(`only ${distinct} distinct valid attestation(s); need ${k}`)
  return { ok: reasons.length === 0, distinctValid: distinct, threshold: k, reasons }
}

/**
 * Stake-weighted variant: require the DISTINCT valid signers to control at least
 * `stakeThreshold` of the set's stake (reusing the ledger's stake weights),
 * instead of a flat count. Same binding + fail-closed discipline; binds against
 * the receipt's COMMITTED k so a reweighted set is still rejected.
 */
export function verifyQuorumReceiptByStake(
  receipt: QuorumReceipt,
  set: ValidatorSet,
  stakeThreshold: bigint,
  epoch: number,
): QuorumVerdict {
  const reasons: string[] = []
  // Fail-closed on a non-positive stake threshold (the k=0 analogue) and on a
  // malformed set carrying negative stake (defensive — the set is verifier-supplied).
  if (typeof stakeThreshold !== 'bigint' || stakeThreshold <= 0n) {
    reasons.push('stake threshold must be a positive bigint')
  }
  if (set.validators.some((v) => typeof v.stake !== 'bigint' || v.stake < 0n)) {
    reasons.push('validator set has a non-bigint or negative stake (malformed)')
  }
  const q = receipt.body.quorum
  if (q.epoch !== epoch) reasons.push(`committed epoch ${q.epoch} != expected ${epoch}`)
  if (q.setId !== quorumSetId(set, q.k, epoch)) {
    reasons.push(
      'committed validator-set id does not match the trusted set (substitution rejected)',
    )
  }
  const stakeOf = new Map(set.validators.map((v) => [v.pubkey, v.stake]))
  // LEDGER-PRECISION-003 (Team Apex sweep): accumulate + compare stake as BigInt. Validator
  // stakes are unbounded PoS weights; a float `stake += ...` past 2^53 can round a sub-threshold
  // subset UP across the threshold and accept it (parity with chain.ts/leader.ts BigInt finality).
  let stake = 0n
  let counted = 0
  // F11 (Team Apex max sweep 2026-06-28): bound the attacker-supplied attestations array before
  // iterating (at most |members| can ever count); reject past 4× the set size and skip the loop.
  const maxAttestations = Math.max(set.validators.length * 4, 256)
  if (receipt.attestations.length > maxAttestations) {
    reasons.push(
      `attestation count ${receipt.attestations.length} exceeds bound ${maxAttestations}`,
    )
  } else {
    countDistinctValid(
      receipt,
      (v) => stakeOf.has(v),
      (v) => {
        const s = stakeOf.get(v)
        stake += typeof s === 'bigint' && s >= 0n ? s : 0n
        counted += 1
      },
    )
  }
  if (stake < stakeThreshold)
    reasons.push(`distinct valid stake ${stake} < required ${stakeThreshold}`)
  return { ok: reasons.length === 0, distinctValid: counted, threshold: stakeThreshold, reasons }
}
