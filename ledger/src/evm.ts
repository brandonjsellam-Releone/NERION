// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * EVM / QRL-Zond interchain encoder — packages a {@link PortableFinalityProof} into the 0x-hex shape
 * a relayer submits to an on-chain verifier (e.g. `contracts/NerionFinalityVerifier.sol` on QRL
 * Zond's QRVM). See docs/research/interchain-qrl-zond.md.
 *
 * The interop substrate is that **Nerion and QRL Zond both sign with ML-DSA-87 (FIPS-204)** — the
 * same scheme QRVM/Hyperion verifies natively — so no signature translation is needed: the contract
 * verifies Nerion's existing attestations directly. This module is pure packaging (bytes → 0x-hex);
 * it performs no cryptography and changes nothing about how Nerion signs. The destination contract
 * MUST independently recompute `setId` and each attestation message from the validator set + header
 * for soundness — the values emitted here are the relayer's convenience copy, not a trust input.
 */

import { blockHash } from './chain.js'
import { attestMessage } from './chain.js'
import { consensusSetId } from './sortition.js'
import type { PortableFinalityProof } from './portable.js'
import type { ValidatorSet } from './types.js'
import { bytesToHex } from '@noble/hashes/utils.js'

const hex0x = (h: string): string => (h.startsWith('0x') ? h : `0x${h}`)

/** A validator as the on-chain verifier expects it (stake as decimal string for uint256). */
export interface EvmValidator {
  readonly pubkey: string // 0x-hex ML-DSA-87 public key
  readonly stake: string // decimal string (uint256)
  readonly vrfPubkey: string | null
}

/** One attestation for the contract: validator + the exact signed message + the ML-DSA-87 signature. */
export interface EvmAttestation {
  readonly validator: string // 0x-hex pubkey
  readonly message: string // 0x-hex of the dCBOR message Nerion signed (relayer convenience)
  readonly sig: string // 0x-hex ML-DSA-87 signature
}

/** Calldata-ready view of a portable finality proof for an EVM/QRVM verifier. */
export interface EvmFinalityInput {
  readonly tag: string
  readonly suite: string
  readonly height: number
  readonly blockHash: string // 0x-hex
  readonly setId: string // 0x-hex (consensusSetId of the trusted set)
  readonly epoch: number
  readonly finalityNum: number
  readonly finalityDen: number
  readonly validators: readonly EvmValidator[]
  readonly attestations: readonly EvmAttestation[]
}

/**
 * Encode a portable finality proof + the consumer's trusted validator set into the 0x-hex input an
 * EVM/QRVM verifier consumes. Only the attestations that are actually for this block (matching hash
 * + height) are included. Pure, deterministic, no crypto.
 */
export function finalityProofToEvmInput(
  proof: PortableFinalityProof,
  trustedSet: ValidatorSet,
): EvmFinalityInput {
  const h = blockHash(proof.block.header)
  const setId = consensusSetId(trustedSet)
  const height = proof.block.header.height
  const attestations: EvmAttestation[] = proof.attestations
    .filter((a) => a.blockHash === h && a.height === height)
    .map((a) => ({
      validator: hex0x(a.validator),
      message: hex0x(bytesToHex(attestMessage(a.suite, a.height, a.blockHash, setId))),
      sig: hex0x(bytesToHex(a.sig)),
    }))
  return {
    tag: 'polarseek-attest-v2',
    suite: proof.block.suite,
    height,
    blockHash: hex0x(h),
    setId: hex0x(setId),
    epoch: trustedSet.epoch ?? 0,
    finalityNum: proof.finalityNum,
    finalityDen: proof.finalityDen,
    validators: trustedSet.validators.map((v) => ({
      pubkey: hex0x(v.pubkey),
      stake: v.stake.toString(),
      vrfPubkey: v.vrfPubkey !== undefined ? hex0x(v.vrfPubkey) : null,
    })),
    attestations,
  }
}
