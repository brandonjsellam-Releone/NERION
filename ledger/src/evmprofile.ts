// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * EVM-native attestation profile (interchain option B — docs/research/interchain-qrl-zond.md).
 *
 * Nerion's NATIVE consensus message is dCBOR + SHAKE256, which an EVM cannot reproduce cheaply (no
 * SHAKE precompile). This profile defines a **keccak256-only**, fixed-layout commitment a
 * Solidity/Hyperion contract recomputes ON-CHAIN — so the destination verifier reconstructs the
 * signed message ITSELF (no trusted relayer message) and verifies the validator's ML-DSA-87
 * signature over it via the QRVM precompile. Validators co-sign this profile alongside consensus
 * when interchain export is wanted (OPT-IN); this module is the primitive + the TS reference
 * verifier the contract must match byte-for-byte. Purely additive — it does NOT change Nerion's
 * native consensus signing.
 *
 * Encoding (reproducible as Solidity `keccak256(abi.encodePacked(...))`):
 *   evmSetId   = fold over pubkey-SORTED members:
 *                  h0 = keccak256(SET_TAG)
 *                  h  = keccak256(h ‖ keccak256(pubkey) ‖ uint256(stake) ‖ keccak256(vrfPubkey|""))
 *                  evmSetId = keccak256(h ‖ uint256(epoch))
 *   evmMessage = keccak256( keccak256(ATT_TAG) ‖ keccak256(suite) ‖ uint256(height)
 *                           ‖ blockHash(32) ‖ evmSetId(32) )
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js'
import { signerFor, type Bytes, type KeyPair } from '../../crypto/src/index.js'
import type { ValidatorSet } from './types.js'

const SET_TAG = utf8ToBytes('Nerion/evm-consensus-set/v1')
const ATT_TAG = utf8ToBytes('Nerion/evm-attest/v1')
const EMPTY_KECCAK = keccak_256(new Uint8Array(0))

/** 32-byte big-endian encoding of a non-negative integer (Solidity uint256). */
function u256(x: bigint | number): Bytes {
  let v = typeof x === 'bigint' ? x : BigInt(x)
  if (v < 0n) throw new Error('u256: negative')
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** keccak256 EVM-reproducible validator-set id (running fold over pubkey-sorted members). */
export function evmSetId(set: ValidatorSet): Bytes {
  const sorted = set.validators
    .slice()
    .sort((a, b) => (a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0))
  let h = keccak_256(SET_TAG)
  for (const v of sorted) {
    const stake = typeof v.stake === 'bigint' && v.stake > 0n ? v.stake : 0n
    const vrfH = v.vrfPubkey !== undefined ? keccak_256(hexToBytes(v.vrfPubkey)) : EMPTY_KECCAK
    h = keccak_256(concatBytes(h, keccak_256(hexToBytes(v.pubkey)), u256(stake), vrfH))
  }
  return keccak_256(concatBytes(h, u256(set.epoch ?? 0)))
}

/** keccak256 EVM-reproducible attestation message a validator signs (32 bytes). */
export function evmAttestMessage(
  suite: string,
  height: number,
  blockHashHex: string,
  setId: Bytes,
): Bytes {
  return keccak_256(
    concatBytes(
      keccak_256(ATT_TAG),
      keccak_256(utf8ToBytes(suite)),
      u256(height),
      hexToBytes(blockHashHex),
      setId,
    ),
  )
}

/** A validator's ML-DSA-87 signature over the EVM-profile attestation message. */
export interface EvmSignedAttestation {
  readonly validator: string // hex ML-DSA-87 public key
  readonly evmSig: Bytes
}

/** Co-sign the EVM-profile attestation for a block (the validator runs this for interchain export). */
export function signEvmAttestation(
  keypair: KeyPair,
  set: ValidatorSet,
  suite: string,
  height: number,
  blockHashHex: string,
): EvmSignedAttestation {
  const msg = evmAttestMessage(suite, height, blockHashHex, evmSetId(set))
  return {
    validator: bytesToHex(keypair.publicKey),
    evmSig: signerFor(suite).sign(msg, keypair.secretKey),
  }
}

export interface EvmFinalityVerdict {
  readonly finalized: boolean
  readonly attestingStake: bigint
  readonly totalStake: bigint
}

/**
 * TS reference of `NerionFinalityVerifier.verifyFinality` — the on-chain contract must match this
 * byte-for-byte. Recomputes the setId + message from the trusted set (NOT trusted from a relayer),
 * verifies each ML-DSA-87 signature over the recomputed message, dedups distinct members, and
 * finalizes iff a >finalityNum/finalityDen stake quorum signed. Fail-closed.
 */
export function verifyEvmFinality(
  set: ValidatorSet,
  atts: readonly EvmSignedAttestation[],
  suite: string,
  height: number,
  blockHashHex: string,
  finalityNum = 2,
  finalityDen = 3,
): EvmFinalityVerdict {
  const total = set.validators.reduce(
    (a, v) => a + (typeof v.stake === 'bigint' && v.stake > 0n ? v.stake : 0n),
    0n,
  )
  if (
    !Number.isInteger(finalityNum) ||
    !Number.isInteger(finalityDen) ||
    finalityNum < 1 ||
    finalityDen < 1 ||
    finalityNum > finalityDen ||
    total <= 0n
  ) {
    return { finalized: false, attestingStake: 0n, totalStake: total }
  }
  const msg = evmAttestMessage(suite, height, blockHashHex, evmSetId(set))
  const stakeOf = new Map(
    set.validators.map((v) => [
      v.pubkey,
      typeof v.stake === 'bigint' && v.stake > 0n ? v.stake : 0n,
    ]),
  )
  const verifier = signerFor(suite)
  const seen = new Set<string>()
  let attesting = 0n
  for (const a of atts) {
    if (seen.has(a.validator)) continue // dedup distinct validators
    const s = stakeOf.get(a.validator) ?? 0n
    if (s <= 0n) continue // non-member / zero stake
    let ok = false
    try {
      ok = verifier.verify(a.evmSig, msg, hexToBytes(a.validator))
    } catch {
      ok = false
    }
    if (!ok) continue
    seen.add(a.validator)
    attesting += s
  }
  return {
    finalized: attesting * BigInt(finalityDen) >= BigInt(finalityNum) * total,
    attestingStake: attesting,
    totalStake: total,
  }
}
