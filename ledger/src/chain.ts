// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure-PoS ledger with stake-finality and PQ light-client verification.
 *
 * A block is proposed by the sortition leader, then attested (ML-DSA-signed) by
 * validators. It FINALIZES when attesting stake reaches the finality fraction
 * (default 2/3) of total stake. A light client verifies a finalized block from
 * the block + attestations + validator set alone — no full-state replay.
 */

import {
  encodeCanonical,
  SHA3_SHAKE256,
  signerFor,
  type Bytes,
  type KeyPair,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { selectLeader, stakeOf, totalStake, canonicalRound } from './sortition.js'
import { prove as vrfProve, verify as vrfVerify } from './vrf.js'
import { vrfAlpha, vrfLeaderEligible, verifyViewChangeCert } from './leader.js'
import type {
  Attestation,
  Block,
  BlockHeader,
  FinalizedBlock,
  LightClientVerdict,
  ValidatorSet,
  ViewChangeCert,
} from './types.js'

export const GENESIS_PREV = '00'.repeat(32)

export class LedgerError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'LedgerError'
  }
}

function headerBytes(h: BlockHeader): Bytes {
  return encodeCanonical([
    'polarseek-block-v1',
    h.height,
    h.prevHash,
    h.round,
    h.proposer,
    h.payloadRoot,
    h.timestamp,
    h.vrfOutput ?? '',
  ])
}

export function blockHash(h: BlockHeader): string {
  return bytesToHex(SHA3_SHAKE256.digest(headerBytes(h)))
}

/**
 * Message the PROPOSER signs: binds the cipher suite + block identity, so a valid
 * signature cannot be replayed under a relabeled `suite` (cross-suite confusion —
 * PS-1 and PS-5 share ML-DSA-87). Distinct domain tag from the hash preimage.
 */
function blockSignMessage(suite: string, hash: string): Bytes {
  return encodeCanonical(['polarseek-block-sig-v1', suite, hash])
}

/**
 * Message a VALIDATOR attests: binds the cipher suite + block HEIGHT + block
 * identity. Exported so the equivocation verifier recovers the exact same
 * preimage (no drift). Height is bound so an "equivocation" can be required to be
 * a SAME-height double-sign — an honest validator's distinct attestations across
 * different heights must not be slashable (LEDGER-EQUIV-001, Team Apex 2026-06-21).
 */
export function attestMessage(suite: string, height: number, hash: string): Bytes {
  return encodeCanonical(['polarseek-attest-v1', suite, height, hash])
}

export class Ledger {
  private readonly chain: FinalizedBlock[] = []

  constructor(
    private readonly set: ValidatorSet,
    private readonly suite: string,
    private readonly finalityNum = 2,
    private readonly finalityDen = 3,
  ) {}

  height(): number {
    return this.chain.length
  }
  headHash(): string {
    const h = this.chain[this.chain.length - 1]
    return h ? h.hash : GENESIS_PREV
  }

  /** The sortition leader propose a block anchoring `payloadRoot`. */
  propose(payloadRoot: string, round: number, timestamp: number, proposer: KeyPair): Block {
    const proposerHex = bytesToHex(proposer.publicKey)
    if (selectLeader(this.set, this.headHash(), round) !== proposerHex) {
      throw new LedgerError('proposer is not the sortition leader for this round')
    }
    const header: BlockHeader = {
      height: this.height(),
      prevHash: this.headHash(),
      round,
      proposer: proposerHex,
      payloadRoot,
      timestamp,
    }
    const sig = signerFor(this.suite).sign(
      blockSignMessage(this.suite, blockHash(header)),
      proposer.secretKey,
    )
    return { header, proposerSig: sig, suite: this.suite }
  }

  /**
   * VRF-mode proposal (ADR-0004): the proposer must be VRF-eligible for the draw.
   * `vrfSecret` is the proposer's CLASSICAL ed25519 VRF seed — separate from its
   * ML-DSA consensus key. `viewChangeCert` is required when `round > 0`.
   */
  proposeVrf(
    payloadRoot: string,
    round: number,
    timestamp: number,
    proposer: KeyPair,
    vrfSecret: Bytes,
    viewChangeCert?: ViewChangeCert,
  ): Block {
    const proposerHex = bytesToHex(proposer.publicKey)
    const prevHash = this.headHash()
    // A round must be a non-negative integer: the cert requirement is gated on
    // `round > 0`, so a NEGATIVE round would skip the view-change cert while still
    // seeding a distinct VRF draw — a sub-1/3 grind (LEDGER-VRF-001).
    if (!Number.isSafeInteger(round) || round < 0) {
      throw new LedgerError('round must be a non-negative integer')
    }
    const { beta, proof } = vrfProve(vrfSecret, vrfAlpha(prevHash, round))
    if (!vrfLeaderEligible(this.set, proposerHex, beta)) {
      throw new LedgerError('proposer is not VRF-eligible for this round')
    }
    if (
      round > 0 &&
      !verifyViewChangeCert(
        this.set,
        this.suite,
        this.height(),
        prevHash,
        round - 1,
        viewChangeCert,
        this.finalityNum,
        this.finalityDen,
      )
    ) {
      throw new LedgerError('round > 0 requires a valid 2/3 view-change certificate')
    }
    const header: BlockHeader = {
      height: this.height(),
      prevHash,
      round,
      proposer: proposerHex,
      payloadRoot,
      timestamp,
      vrfOutput: bytesToHex(beta),
    }
    const sig = signerFor(this.suite).sign(
      blockSignMessage(this.suite, blockHash(header)),
      proposer.secretKey,
    )
    const block: Block = { header, proposerSig: sig, suite: this.suite, vrfProof: proof }
    return viewChangeCert ? { ...block, viewChangeCert } : block
  }

  /** A validator attests (signs) a block hash. */
  attest(block: Block, validator: KeyPair): Attestation {
    const h = blockHash(block.header)
    const height = block.header.height
    const sig = signerFor(this.suite).sign(
      attestMessage(this.suite, height, h),
      validator.secretKey,
    )
    return {
      blockHash: h,
      height,
      validator: bytesToHex(validator.publicKey),
      suite: this.suite,
      sig,
    }
  }

  /** Validate a block + attestations and, if it reaches finality, append it. */
  submit(block: Block, attestations: readonly Attestation[]): FinalizedBlock {
    const v = this.appraise(block, attestations, this.headHash())
    if (!v.ok) throw new LedgerError(v.reasons.join('; '))
    const fb: FinalizedBlock = {
      block,
      hash: blockHash(block.header),
      attestations: [...attestations],
      attestingStake: v.attestingStake,
      finalized: v.finalized,
    }
    if (!fb.finalized) throw new LedgerError('block did not reach stake finality')
    this.chain.push(fb)
    return fb
  }

  private appraise(
    block: Block,
    attestations: readonly Attestation[],
    expectedPrev: string,
  ): LightClientVerdict {
    return verifyFinalized(
      block,
      attestations,
      this.set,
      expectedPrev,
      this.finalityNum,
      this.finalityDen,
      {
        expectedHeight: this.height(),
        expectedSuite: this.suite,
      },
    )
  }
}

export interface VerifyOpts {
  /** If set, the block must extend to exactly this height (LEDGER-005). */
  readonly expectedHeight?: number
  /** If set, block + attestations must use this suite (LEDGER-003/004). */
  readonly expectedSuite?: string
}

// A failed signer resolution (e.g. an attacker-declared bogus suite) must NEVER
// throw out of the verifier (LEDGER-003) — it is a failed verification.
function safeVerify(suite: string, sig: Bytes, msg: Bytes, pub: Bytes): boolean {
  try {
    return signerFor(suite).verify(sig, msg, pub)
  } catch {
    return false
  }
}

/**
 * Verify an attestation's signature (binds suite + height + block hash). Used by
 * the gossip ingress filter so ONLY attestations the safety verifier would count
 * are pooled — otherwise a zero-stake gossiper floods garbage-signed attestations
 * that occupy each (blockHash, validator) slot first and censor finalization
 * (GOSSIP-CENSOR-001, Team Apex 2026-06-21).
 */
export function verifyAttestationSig(att: Attestation): boolean {
  return safeVerify(
    att.suite,
    att.sig,
    attestMessage(att.suite, att.height, att.blockHash),
    hexToBytesLocal(att.validator),
  )
}

/**
 * Stateless PQ light-client verification of a (claimed) finalized block:
 * correct sortition leader, valid proposer signature, valid distinct
 * attestations, and attesting stake >= finality fraction of total stake.
 *
 * `opts.expectedHeight`/`opts.expectedSuite` pin the block to its chain position
 * and to the ledger's suite. Leader eligibility is dual-mode, FIXED by the
 * validator set: VRF (ADR-0004 — private, grind-resistant, view-change liveness;
 * when every validator carries a VRF key) or the deprecated deterministic
 * sortition. A set in one mode rejects the other's blocks (no downgrade).
 * Equivocation slashing is deferred (LEDGER-006); the view-change round-skip
 * caveat is LEDGER-007. See docs/adr/ADR-0004 and docs/STATUS.md.
 */
export function verifyFinalized(
  block: Block,
  attestations: readonly Attestation[],
  set: ValidatorSet,
  expectedPrev: string,
  finalityNum = 2,
  finalityDen = 3,
  opts: VerifyOpts = {},
): LightClientVerdict {
  const reasons: string[] = []
  const total = totalStake(set)
  const h = blockHash(block.header)

  if (opts.expectedSuite !== undefined && block.suite !== opts.expectedSuite) {
    reasons.push('block suite is not the ledger suite')
  }
  if (opts.expectedHeight !== undefined && block.header.height !== opts.expectedHeight) {
    reasons.push('block height does not match the chain position')
  }
  if (block.header.prevHash !== expectedPrev)
    reasons.push('prevHash does not extend the expected head')
  // A block's round must be a non-negative integer. Without this the VRF branch's
  // view-change-cert requirement (gated on `round > 0`) is skipped for round <= 0,
  // letting a sub-1/3 proposer GRIND negative round values through vrfAlpha until
  // VRF-eligible and publish a cert-less block (LEDGER-VRF-001, Team Apex 2026-06-21).
  if (!Number.isSafeInteger(block.header.round) || block.header.round < 0) {
    reasons.push('block round must be a non-negative integer')
  }
  // Leader eligibility. The MODE is fixed by the VALIDATOR SET, never per block: a
  // set whose validators all carry a VRF key is VRF-mode (ADR-0004), and a
  // proof-less legacy block is rejected as a DOWNGRADE — so the predictable
  // deterministic leader can never bypass VRF. A set with no VRF keys is legacy
  // (deprecated). total<=0 fails closed first (selectLeader is undefined on it).
  const vrfSet = set.validators.length > 0 && set.validators.every((v) => v.vrfPubkey !== undefined)
  if (total <= 0) {
    reasons.push('validator set has no stake')
  } else if (vrfSet) {
    if (block.vrfProof === undefined) {
      reasons.push('legacy block rejected: this validator set is VRF-mode (no downgrade)')
    } else {
      // round > 0 requires a ≥2/3 view-change cert for the PREVIOUS round (liveness
      // without grind by a <1/3 adversary). LIMITATION (LEDGER-007): only round r-1
      // is proven, not a chain from round 0, so a ≥2/3 coalition can skip to an
      // arbitrary round to re-draw the VRF leader among themselves — a fairness
      // weakening exploitable only by the quorum that already controls liveness;
      // safety is unaffected (each block still needs its own 2/3 attestations). A
      // cert chain (each cert referencing the prior) is the rigorous future fix.
      if (
        block.header.round > 0 &&
        !verifyViewChangeCert(
          set,
          block.suite,
          block.header.height,
          expectedPrev,
          block.header.round - 1,
          block.viewChangeCert,
          finalityNum,
          finalityDen,
        )
      ) {
        reasons.push('round > 0 without a valid 2/3 view-change certificate')
      }
      const proposerV = set.validators.find((v) => v.pubkey === block.header.proposer)
      if (proposerV === undefined || proposerV.vrfPubkey === undefined) {
        reasons.push('proposer is not a validator with a VRF key')
      } else {
        const beta = vrfVerify(
          hexToBytesLocal(proposerV.vrfPubkey),
          vrfAlpha(expectedPrev, block.header.round),
          block.vrfProof,
        )
        if (beta === null) reasons.push('VRF proof is invalid')
        else if (bytesToHex(beta) !== (block.header.vrfOutput ?? '').toLowerCase())
          reasons.push('vrfOutput does not match the VRF proof')
        else if (!vrfLeaderEligible(set, block.header.proposer, beta))
          reasons.push('proposer is not VRF-eligible for this round')
      }
    }
  } else if (block.vrfProof !== undefined) {
    reasons.push('VRF block rejected: this validator set has no VRF keys')
  } else {
    if (block.header.round !== canonicalRound(block.header.height)) {
      reasons.push('non-canonical round (grind-resistance, LEDGER-002)')
    }
    if (selectLeader(set, expectedPrev, block.header.round) !== block.header.proposer) {
      reasons.push('proposer is not the sortition leader')
    }
  }
  if (
    !safeVerify(
      block.suite,
      block.proposerSig,
      blockSignMessage(block.suite, h),
      hexToBytesLocal(block.header.proposer),
    )
  ) {
    reasons.push('proposer signature is invalid')
  }

  const counted = new Set<string>()
  let attestingStake = 0
  for (const a of attestations) {
    if (a.blockHash !== h) continue
    // The attestation must be for THIS block's height (it is bound into the signed
    // message); a height mismatch is not a valid attestation for this block.
    if (a.height !== block.header.height) continue
    // Count only attestations under the block's OWN declared suite. Together with the
    // suite-bound proposer signature this closes cross-suite confusion even when a
    // standalone light client omits opts.expectedSuite (council/audit hardening).
    if (a.suite !== block.suite) continue
    if (counted.has(a.validator)) continue
    if (opts.expectedSuite !== undefined && a.suite !== opts.expectedSuite) continue
    const stake = stakeOf(set, a.validator)
    if (stake <= 0) continue
    if (
      !safeVerify(
        a.suite,
        a.sig,
        attestMessage(a.suite, block.header.height, h),
        hexToBytesLocal(a.validator),
      )
    ) {
      continue
    }
    counted.add(a.validator)
    attestingStake += stake
  }

  // BigInt comparison (LEDGER-PRECISION-001, Team Apex 2026-06-21): `attestingStake * finalityDen`
  // can exceed 2^53 even when total <= 2^53, silently corrupting the finality threshold under
  // IEEE-754. Cross-multiply in bigint so the >=2/3-stake check is exact.
  const finalized =
    total > 0 && BigInt(attestingStake) * BigInt(finalityDen) >= BigInt(finalityNum) * BigInt(total)
  if (!finalized)
    reasons.push(
      `attesting stake ${attestingStake}/${total} below finality ${finalityNum}/${finalityDen}`,
    )
  return { ok: reasons.length === 0, finalized, attestingStake, totalStake: total, reasons }
}

function hexToBytesLocal(hex: string): Bytes {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
