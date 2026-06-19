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
import type {
  Attestation,
  Block,
  BlockHeader,
  FinalizedBlock,
  LightClientVerdict,
  ValidatorSet,
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
  ])
}

export function blockHash(h: BlockHeader): string {
  return bytesToHex(SHA3_SHAKE256.digest(headerBytes(h)))
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
    const sig = signerFor(this.suite).sign(headerBytes(header), proposer.secretKey)
    return { header, proposerSig: sig, suite: this.suite }
  }

  /** A validator attests (signs) a block hash. */
  attest(block: Block, validator: KeyPair): Attestation {
    const h = blockHash(block.header)
    const sig = signerFor(this.suite).sign(
      encodeCanonical(['polarseek-attest-v1', h]),
      validator.secretKey,
    )
    return { blockHash: h, validator: bytesToHex(validator.publicKey), suite: this.suite, sig }
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
 * Stateless PQ light-client verification of a (claimed) finalized block:
 * correct sortition leader, valid proposer signature, valid distinct
 * attestations, and attesting stake >= finality fraction of total stake.
 *
 * `opts.expectedHeight`/`opts.expectedSuite` pin the block to its chain position
 * and to the ledger's suite. NOTE (LEDGER-001/002): full BFT finality safety and
 * grind-resistant leader selection require the planned VRF sortition + slashing /
 * equivocation tracking; the current deterministic public sortition is a
 * single-trusted-set demo (a proposer can grind `round`). See docs/STATUS.md.
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
  if (block.header.round !== canonicalRound(block.header.height)) {
    reasons.push('non-canonical round (grind-resistance, LEDGER-002)')
  }
  // Zero total stake (e.g. after slashing) finalizes nothing — and selectLeader
  // is undefined on an empty set, so guard before calling it (fail closed).
  if (total <= 0) {
    reasons.push('validator set has no stake')
  } else if (selectLeader(set, expectedPrev, block.header.round) !== block.header.proposer) {
    reasons.push('proposer is not the sortition leader')
  }
  if (
    !safeVerify(
      block.suite,
      block.proposerSig,
      headerBytes(block.header),
      hexToBytesLocal(block.header.proposer),
    )
  ) {
    reasons.push('proposer signature is invalid')
  }

  const counted = new Set<string>()
  let attestingStake = 0
  for (const a of attestations) {
    if (a.blockHash !== h) continue
    if (counted.has(a.validator)) continue
    if (opts.expectedSuite !== undefined && a.suite !== opts.expectedSuite) continue
    const stake = stakeOf(set, a.validator)
    if (stake <= 0) continue
    if (
      !safeVerify(
        a.suite,
        a.sig,
        encodeCanonical(['polarseek-attest-v1', h]),
        hexToBytesLocal(a.validator),
      )
    ) {
      continue
    }
    counted.add(a.validator)
    attestingStake += stake
  }

  const finalized = total > 0 && attestingStake * finalityDen >= finalityNum * total
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
