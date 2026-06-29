// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Portable post-quantum finality proof — the cross-chain interoperability primitive from
 * docs/research/pq-pos-interop-convergence.md §3.
 *
 * A self-contained, transportable attestation that "Nerion finalized THIS block under THIS
 * validator-set / epoch", verifiable OFFLINE by a bridge or another chain through the stateless
 * light-client verifier (`verifyFinalized`). It is the post-quantum alternative to the trusted-
 * multisig bridges the interoperability literature shows lost ~$1B (Wormhole + Ronin): the trust
 * root here is a >2/3 ML-DSA-87 STAKE QUORUM over a transparency-logged block, not a custodial
 * committee. The consumer supplies its OWN trusted `ValidatorSet`; the proof carries only the
 * already-public block + attestations, so it discloses nothing the chain did not already publish.
 *
 * ADDITIVE: this is a thin, presentational packaging over the audited verify path — it performs no
 * new cryptography and changes nothing about how Nerion signs or finalizes.
 */

import { verifyFinalized } from './chain.js'
import type { Attestation, Block, LightClientVerdict, ValidatorSet } from './types.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

/** A self-contained finality proof a non-Nerion verifier can consume. */
export interface PortableFinalityProof {
  readonly block: Block
  readonly attestations: readonly Attestation[]
  /** The prevHash the block must extend — the verifier's expected head at this height. */
  readonly expectedPrev: string
  readonly finalityNum: number
  readonly finalityDen: number
  /** The reconfiguration epoch the attestations were made under; must match the verifier's set. */
  readonly epoch?: number
}

/** Bundle a finalized block + its attestations into a portable proof (no crypto; just packaging). */
export function exportFinalityProof(
  block: Block,
  attestations: readonly Attestation[],
  expectedPrev: string,
  opts: { finalityNum?: number; finalityDen?: number; epoch?: number } = {},
): PortableFinalityProof {
  return {
    block,
    attestations,
    expectedPrev,
    finalityNum: opts.finalityNum ?? 2,
    finalityDen: opts.finalityDen ?? 3,
    ...(opts.epoch !== undefined ? { epoch: opts.epoch } : {}),
  }
}

/**
 * Verify a portable finality proof against the consumer's OWN trusted `ValidatorSet`. Fail-closed.
 * Delegates to the hardened stateless `verifyFinalized` (input caps, O(1) stake index, setId/epoch
 * binding). `expect` optionally pins the suite and chain height the consumer requires.
 */
export function verifyPortableFinality(
  proof: PortableFinalityProof,
  trustedSet: ValidatorSet,
  expect: { expectedSuite?: string; expectedHeight?: number } = {},
): LightClientVerdict {
  // Epoch must match the verifier's trusted set when both are explicit: an attestation made under
  // epoch e is not finality under a set the verifier holds for a different epoch (defense in depth
  // over the consensusSetId binding already inside verifyFinalized).
  if (
    proof.epoch !== undefined &&
    trustedSet.epoch !== undefined &&
    proof.epoch !== trustedSet.epoch
  ) {
    return {
      ok: false,
      finalized: false,
      attestingStake: 0n,
      totalStake: 0n,
      reasons: [`epoch mismatch: proof ${proof.epoch} vs trusted set ${trustedSet.epoch}`],
    }
  }
  return verifyFinalized(
    proof.block,
    proof.attestations,
    trustedSet,
    proof.expectedPrev,
    proof.finalityNum,
    proof.finalityDen,
    expect,
  )
}

// ─── Stable serialization (JSON; Uint8Array ⇄ {"$b": hex}) ───────────────────────────────────────
// The proof's only non-JSON-native values are byte strings (signatures, VRF proof). Encode them as
// {"$b": hex} so the artifact is a plain, portable JSON string any consumer can parse.

const replacer = (_k: string, v: unknown): unknown =>
  v instanceof Uint8Array ? { $b: bytesToHex(v) } : v

const isByteTag = (v: unknown): v is { readonly $b: string } =>
  typeof v === 'object' && v !== null && typeof (v as { $b?: unknown }).$b === 'string'

const reviver = (_k: string, v: unknown): unknown => (isByteTag(v) ? hexToBytes(v.$b) : v)

/** Serialize a portable finality proof to a transportable JSON string (bytes → hex). */
export function serializeFinalityProof(proof: PortableFinalityProof): string {
  return JSON.stringify(proof, replacer)
}

/** Parse a portable finality proof from its JSON string (hex → bytes). */
export function deserializeFinalityProof(json: string): PortableFinalityProof {
  return JSON.parse(json, reviver) as PortableFinalityProof
}
