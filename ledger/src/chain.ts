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
import { selectLeader, stakeOf, totalStake } from './sortition.js'
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
    )
  }
}

/**
 * Stateless PQ light-client verification of a (claimed) finalized block:
 * correct sortition leader, valid proposer signature, valid distinct
 * attestations, and attesting stake >= finality fraction of total stake.
 */
export function verifyFinalized(
  block: Block,
  attestations: readonly Attestation[],
  set: ValidatorSet,
  expectedPrev: string,
  finalityNum = 2,
  finalityDen = 3,
): LightClientVerdict {
  const reasons: string[] = []
  const total = totalStake(set)
  const h = blockHash(block.header)

  if (block.header.prevHash !== expectedPrev)
    reasons.push('prevHash does not extend the expected head')
  if (selectLeader(set, expectedPrev, block.header.round) !== block.header.proposer) {
    reasons.push('proposer is not the sortition leader')
  }
  if (
    !signerFor(block.suite).verify(
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
    const stake = stakeOf(set, a.validator)
    if (stake <= 0) continue
    if (
      !signerFor(a.suite).verify(
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

  const finalized = attestingStake * finalityDen >= finalityNum * total
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
