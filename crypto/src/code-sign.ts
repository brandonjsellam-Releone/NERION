// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CNSA 2.0 code/firmware-signing: one-time-key hash-based signatures (LMS /
 * single-tree XMSS, NIST SP 800-208). Deliberately SEPARATE from `sign.ts` (the
 * stateless SignatureScheme registry) — a one-time-key HBS scheme cannot implement
 * `sign(message, secretKey)`: it has no exportable secret (SP 800-208 §8.1 forbids
 * private-key export) and each signature mutates durable one-time-key state. Routing
 * it through `signerFor()` / the seed-sealing custody path would be the catastrophic
 * clone bug (two restored seeds = two divergent OTS state machines = index reuse =
 * total forgery). So this is its own interface + catalog, resolved via the keystore
 * `HbsKeyProvider`, never via `signerFor`.
 *
 * CNSA 2.0 approves ONLY single-tree LMS/XMSS for code signing and EXCLUDES the
 * multi-tree variants HSS / XMSSᴹᵀ — enforced by {@link assertSingleTree}.
 *
 * NOT IMPLEMENTED: `@noble` ships no LMS/XMSS, and SP 800-208 §8.1 validates these
 * ONLY inside a FIPS 140-3 L3+ hardware module (no software validation). The raw
 * primitive is adapter-provided (keystore `HbsSignEngine`); `getCodeSigner` throws
 * `NotImplementedError` with a CONNECT pointer, exactly like FN-DSA-1024 today.
 */

import { NotImplementedError, PolicyError } from './errors.js'
import type { Bytes } from './types.js'

export type HbsHash = 'SHA-256' | 'SHA-256/192' | 'SHAKE256/256' | 'SHAKE256/192'

export interface HbsParams {
  readonly family: 'LMS' | 'XMSS'
  /** CNSA 2.0 forbids multi-tree (HSS / XMSSᴹᵀ); single-tree only. */
  readonly multiTree: boolean
  readonly hash: HbsHash
  /** Single-tree height H → 2^H one-time signatures for the key's lifetime. */
  readonly height: number
  readonly winternitz?: number
}

export interface CodeSigner {
  readonly id: string
  readonly params: HbsParams
  /** The LMS/XMSS tree root (public key). */
  readonly publicKey: Bytes
  /** One-time-key: consumes exactly one OTS leaf; the index advance is durable BEFORE
   * the signature returns. No `secretKey` arg — the secret never leaves the module. */
  sign(message: Bytes): Promise<Bytes>
  /** Stateless and safe to run anywhere: root + signature + message only. */
  verify(signature: Bytes, message: Bytes): boolean
  /** Remaining one-time keys before exhaustion. */
  remaining(): number
}

export const CODE_SIG_IDS = {
  LMS_SHA256_M24: 'LMS-SHA256-M24',
  XMSS_SHA2_192: 'XMSS-SHA2-192',
} as const

export type CodeSigId = (typeof CODE_SIG_IDS)[keyof typeof CODE_SIG_IDS]

const MULTI_TREE_ID = /HSS|XMSSMT|_MT_|MT-/i

/**
 * Enforce CNSA 2.0's single-tree-only rule. Throws {@link PolicyError}
 * (`E_MULTI_TREE_FORBIDDEN`) for any multi-tree (HSS / XMSSᴹᵀ) parameter set —
 * checked both on the explicit flag AND on a defensive id match, since a misreported
 * `multiTree:false` on a multi-tree key id must still be refused.
 */
export function assertSingleTree(params: HbsParams, id = ''): void {
  if (params.multiTree || MULTI_TREE_ID.test(id) || MULTI_TREE_ID.test(params.family)) {
    throw new PolicyError(
      'E_MULTI_TREE_FORBIDDEN',
      `${params.family} multi-tree (HSS/XMSS^MT) is EXCLUDED by CNSA 2.0 for code/firmware signing; single-tree LMS/XMSS only`,
    )
  }
}

/**
 * Resolve a code-signer by id. Throws {@link NotImplementedError}: the raw
 * SP 800-208 primitive must be supplied by a vetted FIPS 140-3 L3+ module via the
 * keystore `HbsSignEngine` adapter — it is never home-rolled (a single OTS-index
 * reuse is a silent, total forgery). Multi-tree ids are rejected before that.
 */
export function getCodeSigner(id: string): CodeSigner {
  if (MULTI_TREE_ID.test(id)) {
    throw new PolicyError(
      'E_MULTI_TREE_FORBIDDEN',
      `${id}: HSS/XMSS^MT multi-tree is EXCLUDED by CNSA 2.0; single-tree LMS/XMSS only`,
    )
  }
  throw new NotImplementedError(
    `LMS/XMSS code-signer ${id}`,
    'a FIPS 140-3 L3+ SP 800-208 module wired through the keystore HbsKeyProvider + HbsSignEngine',
  )
}

/** Code-signers usable today (none — the primitive is hardware-module-only). */
export function implementedCodeSigIds(): string[] {
  return []
}
