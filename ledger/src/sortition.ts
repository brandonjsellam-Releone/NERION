// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifiable, stake-weighted leader selection.
 *
 * The leader for (prevHash, round) is a deterministic function of a hash seed,
 * mapped onto the cumulative-stake interval — so anyone with the validator set
 * can recompute and verify who was eligible to propose.
 *
 * NOTE: this is a DETERMINISTIC verifiable selection, not a private VRF. A
 * proper ECVRF / PQ-VRF (hiding the leader until reveal) is future work; flagged
 * in docs/STATUS.md.
 */

import { DOMAIN_TAGS, encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ValidatorSet } from './types.js'

/**
 * The single canonical round for a height (grind-resistance, LEDGER-002): the
 * leader is fixed by the parent hash, so a proposer cannot choose `round` to
 * make itself leader. (A view-change / timeout liveness fallback for an offline
 * leader is future work — see docs/STATUS.md.)
 */
export function canonicalRound(_height: number): number {
  return 0
}

/**
 * A validator's stake as a SAFE non-negative bigint. A non-bigint (e.g. a `number` from an untrusted
 * decode of a verifier-supplied set) or a negative value yields 0n, so stake arithmetic never throws a
 * `bigint + number` TypeError (council R5 review, ADR-0027). Malformed sets are still REJECTED —
 * fail-closed — by `isWellFormedStakeSet`; this helper only keeps the running total safe meanwhile.
 */
export function safeStake(stake: unknown): bigint {
  return typeof stake === 'bigint' && stake >= 0n ? stake : 0n
}

/**
 * Fail-closed malformed-set predicate: every validator's stake must be a NON-NEGATIVE BIGINT and
 * all pubkeys must be DISTINCT. The uniqueness check (Team Apex max sweep 2026-06-28, F-C) closes
 * an inconsistent-dedup gap: the finality NUMERATOR dedups (counted/attempted + first-wins
 * `stakeIndex`), but `totalStake` (denominator) and `selectLeader`/`vrfLeaderEligible` walk EVERY
 * entry — so a duplicated pubkey double-counts in the denominator and inflates its leader-draw
 * interval. Rejecting non-unique sets fail-closed (same posture as negative stake) keeps the
 * numerator, denominator, and leader draw on one dedup discipline.
 */
export function isWellFormedStakeSet(set: ValidatorSet): boolean {
  if (!set.validators.every((v) => typeof v.stake === 'bigint' && v.stake >= 0n)) return false
  return new Set(set.validators.map((v) => v.pubkey)).size === set.validators.length
}

export function totalStake(set: ValidatorSet): bigint {
  // Exact for unbounded PoS weights (ADR-0027): stake is bigint. A non-bigint / negative (malformed)
  // stake contributes 0; callers that must reject a malformed set call isWellFormedStakeSet.
  return set.validators.reduce((a, v) => a + safeStake(v.stake), 0n)
}

/** @deprecated stake is bigint, so `totalStake` is already exact; retained as an alias. */
export function totalStakeBig(set: ValidatorSet): bigint {
  return totalStake(set)
}

export function stakeOf(set: ValidatorSet, pubkey: string): bigint {
  return safeStake(set.validators.find((v) => v.pubkey === pubkey)?.stake)
}

/**
 * O(1) pubkey→stake index built ONCE per verify call, so a hot loop over attacker-supplied
 * attestations/votes does not pay an O(V) `stakeOf` linear scan per entry (F6/F7 decode-side
 * DoS, Team Apex max sweep 2026-06-28: the exported light-client verifiers ran O(A·V) string
 * compares on uncapped peer input). First occurrence wins, matching `stakeOf`'s `find` so a
 * (malformed) set with duplicate pubkeys behaves identically; malformed/negative stake → 0n.
 */
export function stakeIndex(set: ValidatorSet): Map<string, bigint> {
  const m = new Map<string, bigint>()
  for (const v of set.validators) if (!m.has(v.pubkey)) m.set(v.pubkey, safeStake(v.stake))
  return m
}

/**
 * Stable identity of a validator-set CONFIGURATION = SHAKE256 over its sorted members
 * (pubkey + stake + VRF key) and reconfiguration epoch (ADR-0020/B5, Team Apex max sweep
 * 2026-06-28). Bound into every signed attestation/timeout message so a signature gathered
 * under set S(epoch e) cannot be re-counted under a DIFFERENT set S'(epoch e+1) — the
 * cross-epoch consent-transfer / set-substitution TOCTOU the consensus path previously left
 * open (receipts/quorum.ts already had the analogous `quorumSetId`). Sorting by pubkey makes
 * it order-independent; stake + epoch make a reweighted or re-epoched set a DIFFERENT id.
 */
export function consensusSetId(set: ValidatorSet): string {
  const sorted = set.validators
    .map((v) => [v.pubkey, v.stake, v.vrfPubkey ?? null] as const)
    .slice()
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  return bytesToHex(
    SHA3_SHAKE256.digest(
      encodeCanonical([DOMAIN_TAGS.NATIVE_CONSENSUS_SET, sorted, set.epoch ?? 0]),
    ),
  )
}

/** Deterministic stake-weighted leader for a (prevHash, round). */
export function selectLeader(set: ValidatorSet, prevHash: string, round: number): string {
  const total = totalStake(set)
  if (total <= 0n) throw new Error('validator set has no stake')
  const seed = SHA3_SHAKE256.digest(encodeCanonical([DOMAIN_TAGS.SORTITION, prevHash, round]))
  // Exact BigInt cumulative walk: both the modulo base (total) and the running `acc` are bigint, so
  // leader selection stays exact for unbounded PoS stake weights (LEDGER-PRECISION-001/-004/-005).
  const x = BigInt('0x' + bytesToHex(seed)) % total
  // Sort by pubkey so the cumulative interval is order-independent.
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0n
  for (const v of sorted) {
    acc += safeStake(v.stake)
    if (x < acc) return v.pubkey
  }
  return sorted[sorted.length - 1]!.pubkey
}
