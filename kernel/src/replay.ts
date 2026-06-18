/**
 * ReplayBundle — byte-identical re-derivation of a decision and its receipt.
 *
 * A ReplayBundle captures the kernel's complete explicit input as canonical
 * CBOR plus the pinned evaluator version. Replaying it on any conforming kernel
 * reproduces the exact decision and the exact receipt hash. This is what makes
 * "replayable" mean *byte-identical*, not merely "similar".
 */

import { encodeCanonical, decodeCbor, SHA3_SHAKE256, type Bytes } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { decide } from './kernel.js'
import { evaluatorVersion } from './policy.js'
import type { Decision, KernelInput } from './types.js'

export interface ReplayBundle {
  /** Canonical CBOR of the complete KernelInput. */
  readonly inputBytes: Bytes
  /** Pinned evaluator version at capture time (cross-checked on replay). */
  readonly evaluatorVersion: string
}

export interface ReplayResult {
  readonly decision: Decision
  readonly inputHash: string
  /** Commitment over {evaluatorVersion, inputHash, decision} — the receipt core. */
  readonly receiptHash: string
}

export function buildReplayBundle(input: KernelInput): ReplayBundle {
  return { inputBytes: encodeCanonical(input), evaluatorVersion: evaluatorVersion(input.policy) }
}

export function replay(bundle: ReplayBundle): ReplayResult {
  const input = decodeCbor(bundle.inputBytes) as KernelInput
  const decision = decide(input)
  const inputHash = bytesToHex(SHA3_SHAKE256.digest(bundle.inputBytes))
  const receiptHash = bytesToHex(
    SHA3_SHAKE256.digest(encodeCanonical([decision.evaluatorVersion, inputHash, decision])),
  )
  return { decision, inputHash, receiptHash }
}
