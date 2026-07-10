// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * NATIVE-profile relayer/inspection packer (option-A reference; retained for the dCBOR/SHAKE256
 * consensus view, NOT the on-chain contract target) — packages a {@link PortableFinalityProof} into
 * a 0x-hex shape for offline inspection or a native-scheme relayer. See
 * docs/research/interchain-qrl-zond.md.
 *
 * PARITY-002 (AAC council review, 2026-07-11) — WRONG-TARGET WARNING, corrected: this module's
 * docstring previously named `contracts/NerionFinalityVerifier.sol` as its destination. It does
 * NOT match that contract: `consensusSetId`/`attestMessage` (used here, via chain.ts/sortition.ts)
 * are SHAKE256-over-dCBOR under the NATIVE domain tags, while the contract independently
 * recomputes `evmSetId`/`evmMessage` via keccak256 folds and verifies against THAT recomputed
 * digest. A native ML-DSA-87 signature can never verify against a keccak-recomputed message, so
 * calldata built here would be rejected by every attestation (fail-closed — a liveness bug, not a
 * soundness gap: `ledger/src/evmprofile.ts`'s own `verifyEvmFinality` would likewise reject this
 * module's output). This `EvmFinalityInput.tag` field is also the NATIVE `ATTESTATION` domain tag
 * (`polarseek-attest-v2`), not the EVM profile's, and this shape carries no `chainId`/`verifier`
 * destination-binding fields at all, which the contract requires.
 *
 * The BYTE-COMPATIBLE encoder for `contracts/NerionFinalityVerifier.sol` is
 * `ledger/src/evmprofile.ts` (`signEvmAttestation` / `evmSetId` / `evmAttestMessage` /
 * `verifyEvmFinality` — the tested TS reference the contract recomputes and must match
 * byte-for-byte). Use that module, not this one, to build calldata for the Solidity contract.
 *
 * This module performs no cryptography and changes nothing about how Nerion signs; it remains
 * useful for inspecting/relaying a NATIVE finality proof in 0x-hex form to a non-EVM consumer.
 */

import { blockHash } from './chain.js'
import { attestMessage } from './chain.js'
import { consensusSetId } from './sortition.js'
import type { PortableFinalityProof } from './portable.js'
import type { ValidatorSet } from './types.js'
import { DOMAIN_TAGS } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

const hex0x = (h: string): string => (h.startsWith('0x') ? h : `0x${h}`)

/** A validator in 0x-hex form (stake as decimal string). NOT the contract's calldata shape — see
 *  the module docstring; use evmprofile.ts's EvmTarget-bound types for the Solidity contract. */
export interface EvmValidator {
  readonly pubkey: string // 0x-hex ML-DSA-87 public key
  readonly stake: string // decimal string
  readonly vrfPubkey: string | null
}

/** One NATIVE-profile attestation in 0x-hex form: validator + the exact dCBOR/SHAKE256 message +
 *  the ML-DSA-87 signature. NOT verifiable by NerionFinalityVerifier.sol — see the module docstring. */
export interface EvmAttestation {
  readonly validator: string // 0x-hex pubkey
  readonly message: string // 0x-hex of the NATIVE dCBOR message Nerion signed (relayer convenience)
  readonly sig: string // 0x-hex ML-DSA-87 signature
}

/** 0x-hex view of a portable finality proof under the NATIVE (dCBOR/SHAKE256) domain — a relayer/
 *  inspection convenience shape, NOT the Solidity contract's calldata (see the module docstring:
 *  use evmprofile.ts for that). */
export interface EvmFinalityInput {
  readonly tag: string
  readonly suite: string
  readonly height: number
  readonly blockHash: string // 0x-hex
  readonly setId: string // 0x-hex (NATIVE consensusSetId of the trusted set)
  readonly epoch: number
  readonly finalityNum: number
  readonly finalityDen: number
  readonly validators: readonly EvmValidator[]
  readonly attestations: readonly EvmAttestation[]
}

/**
 * Encode a portable finality proof + the consumer's trusted validator set into a 0x-hex view under
 * the NATIVE (dCBOR/SHAKE256) domain — NOT calldata for NerionFinalityVerifier.sol (see the module
 * docstring; use evmprofile.ts for that). Only the attestations that are actually for this block
 * (matching hash + height) are included. Pure, deterministic, no crypto.
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
    tag: DOMAIN_TAGS.ATTESTATION,
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
