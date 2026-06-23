// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * ReplayBundle — byte-identical re-derivation of a decision and its receipt.
 *
 * A ReplayBundle captures the kernel's complete explicit input as canonical
 * CBOR plus the pinned evaluator version. Replaying it on any conforming kernel
 * reproduces the exact decision and the exact receipt hash. This is what makes
 * "replayable" mean *byte-identical*, not merely "similar".
 */

import {
  encodeCanonical,
  decodeCanonical,
  SHA3_SHAKE256,
  type Bytes,
} from '../../crypto/src/index.js'
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
  const inputHash = bytesToHex(SHA3_SHAKE256.digest(bundle.inputBytes))
  // REPLAY-CANON-001 (R7): inputHash is taken over the RAW inputBytes, but decide() runs on the
  // DECODED value. A NON-canonical encoding — notably a duplicate-key map, which CBOR decoders resolve
  // first-vs-last differently — would let ONE decision carry many distinct receipt hashes, or split
  // replay across decoders. Decode STRICTLY and fail closed: a bundle whose inputBytes are not the
  // canonical encoding of their value is tampered or non-conforming.
  let decision: Decision
  try {
    const input = decodeCanonical(bundle.inputBytes) as KernelInput
    decision = decide(input)
    // Enforce the pinned evaluator version: a bundle whose recorded version does not match the
    // re-derived one is tampered or drifted — fail closed (PS-KERNEL-01).
    if (decision.evaluatorVersion !== bundle.evaluatorVersion) {
      decision = {
        effect: 'deny',
        tier: 3,
        reasons: ['replay evaluator-version mismatch (bundle tampered or policy drift)'],
        obligations: [],
        evaluatorVersion: decision.evaluatorVersion,
      }
    }
  } catch {
    decision = {
      effect: 'deny',
      tier: 3,
      reasons: ['replay bundle inputBytes are not canonical CBOR (REPLAY-CANON-001)'],
      obligations: [],
      evaluatorVersion: '',
    }
  }
  const receiptHash = bytesToHex(
    SHA3_SHAKE256.digest(encodeCanonical([decision.evaluatorVersion, inputHash, decision])),
  )
  return { decision, inputHash, receiptHash }
}
