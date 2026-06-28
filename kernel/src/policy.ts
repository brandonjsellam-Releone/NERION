// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Deterministic risk-tiering and the pinned evaluator version.
 *
 * Tiering is a pure function of the explicit intent and policy — no clock, no
 * lookup, no randomness. The evaluator version is a hash binding the kernel
 * release to the exact policy, so a receipt records precisely what evaluated it.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ActionIntent, RiskTier } from '../../capabilities/src/index.js'
import type { Policy } from './types.js'

/** Bump on any change to the decision logic; bound into the evaluator version. */
export const KERNEL_VERSION = 'polarseek-kernel/0.1.0'

/**
 * SEGMENT-prefix action match (PS-KERNEL-03): `entry` matches `type` iff they are
 * equal OR `type` is a dotted-namespace child of `entry` (`export.mass` matches
 * `export.mass.full`, but `data.read` does not match a crafted `data.readX`).
 *
 * This is the SINGLE matcher shared by `tierOf` and the deny/transform RESTRICTION
 * lists, so a marked verb family covers its dotted children identically (the
 * exact-vs-prefix asymmetry F1/F2, Team Apex max sweep 2026-06-28: previously
 * `tierOf` was prefix while `denyActions`/`transformActions` were exact `includes`,
 * so a dotted child inherited the parent's TIER but escaped its deny/transform
 * obligation toward the more-permissive effect).
 *
 * ROLE NOTE — this is for RESTRICTION lists, where a child must INHERIT the parent's
 * restriction (deny/transform flows DOWN the namespace). Capability GRANT matching
 * (`capabilities/src/grant.ts` `authorizesIntent`) deliberately stays EXACT: a grant
 * for `x` must NEVER auto-authorize `x.child`. The two semantics are opposite by
 * design — do not unify them.
 */
export function actionMatches(type: string, entry: string): boolean {
  const boundary = entry.endsWith('.') ? entry : entry + '.'
  return type === entry || type.startsWith(boundary)
}

/** True iff `type` is matched by any entry of a restriction list (deny/transform). */
export function actionInList(type: string, list: readonly string[]): boolean {
  return list.some((entry) => actionMatches(type, entry))
}

/**
 * A well-formed action-type identifier: one or more dot-separated NON-EMPTY segments of
 * `[A-Za-z0-9_-]` (ASCII only — no whitespace, no leading/trailing/double dots, no Unicode
 * confusables/NFD), max 256 chars. `intent.type` drives `tierOf`, the deny/transform matchers,
 * exact grant authorization, AND the `actionHash` permit binding — three different rules over the
 * same raw string. Without a shared canonicality gate a non-canonical sibling (trailing space,
 * empty segment, NFD variant) can keep its TIER via the prefix rule yet DODGE the exact
 * deny/transform leaf, and the same logical verb can alias across grant/policy/permit (Team Apex
 * max sweep 2026-06-28, intent-type-canonicality F-C/F-D). The kernel rejects a non-canonical type
 * fail-closed so every downstream consumer only ever sees a canonical identifier; restricting to
 * ASCII sidesteps NFC/NFD normalization entirely.
 */
const ACTION_TYPE_RE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/
export function isCanonicalActionType(type: unknown): boolean {
  return typeof type === 'string' && type.length <= 256 && ACTION_TYPE_RE.test(type)
}

/**
 * Deterministic tier of an intent: first matching prefix wins, else default.
 *
 * Matching is SEGMENT-wise, not substring (PS-KERNEL-03) via {@link actionMatches}.
 */
export function tierOf(intent: ActionIntent, policy: Policy): RiskTier {
  for (const rule of policy.tierRules) {
    if (actionMatches(intent.type, rule.prefix)) return rule.tier
  }
  return policy.defaultTier
}

/**
 * Pinned evaluator identity = hash over the kernel version + the canonical
 * policy. Two parties on the same kernel + policy compute the same id, and any
 * policy change is visible in every receipt.
 */
export function evaluatorVersion(policy: Policy): string {
  const id = SHA3_SHAKE256.digest(encodeCanonical([KERNEL_VERSION, policy]))
  return `${KERNEL_VERSION}+${bytesToHex(id).slice(0, 16)}`
}

/** A sensible default policy for the demo / tests (finance-flavored). */
export const DEFAULT_POLICY: Policy = {
  version: '0.1.0',
  tierRules: [
    { prefix: 'data.read', tier: 0 },
    { prefix: 'draft.', tier: 0 },
    { prefix: 'message.send', tier: 1 },
    { prefix: 'data.create', tier: 1 },
    { prefix: 'payment.', tier: 2 },
    { prefix: 'key.', tier: 2 },
    { prefix: 'data.delete', tier: 2 },
    { prefix: 'infra.deploy', tier: 2 },
    { prefix: 'actuation.physical', tier: 3 },
    { prefix: 'export.mass', tier: 3 },
    { prefix: 'model.weights', tier: 3 },
  ],
  denyActions: [],
  transformActions: [],
  defaultTier: 3,
}
