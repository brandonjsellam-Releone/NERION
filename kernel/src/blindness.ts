// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-PARAMS-BLINDNESS — make "govern the verb, never the eye" a STRUCTURAL fact.
 *
 * `ActionIntent.params` is the receipt-bound payload (hashed into receipts for the
 * audit trail) that the admission kernel must NEVER read: it is the perception
 * channel the design-around (ADR-0007) deliberately keeps out of the decision.
 * Historically that invariant was substantiated only by a finite negative-oracle
 * vector set. This module lifts it to two strictly stronger guarantees:
 *
 *   (a) STRUCTURAL — `ParamsBlind<I>` / `GovernedIntent` is the projection of an
 *       intent with `params` omitted; `governedView()` produces it. The kernel's
 *       decision body (`decideWithAuthorizer`) is typed over this projection, so
 *       reading `intent.params` inside the decision is a COMPILE error.
 *   (b) EMPIRICAL — an unbounded property test
 *       (kernel/test/params-blindness.property.test.ts) asserts `decide()` is
 *       byte-identical under arbitrary, adversarial `params`.
 *
 * This adds NO behaviour, NO wire/KAT change, and no cross-decision state — it is a
 * type plus a pure projection that strengthen (never weaken) the verb-only invariant.
 */

import type { ActionIntent } from '../../capabilities/src/index.js'

/**
 * The structural projection of an intent that OMITS the perception payload `params`.
 * Typing a decision surface as `ParamsBlind<ActionIntent>` makes "cannot read params"
 * a compile-time fact rather than a tested convention.
 */
export type ParamsBlind<I> = Omit<I, 'params'>

/** The perception-free view of an action intent: every governed field, never `params`. */
export type GovernedIntent = ParamsBlind<ActionIntent>

/**
 * Project an action intent onto its governed view, dropping `params`. Pure and total;
 * does not mutate the input. The admission decision is a function of THIS projection
 * only: `governedView(a)` deep-equals `governedView(b)` ⇒ `decide` returns the same
 * Decision for a and b (proven empirically in the property test).
 *
 * The governed fields are enumerated EXPLICITLY (an allowlist), so a future field added
 * to `ActionIntent` is excluded from the view by default; the compile-time witness in the
 * test then forces a conscious decision about whether that field is governed or perception.
 */
export function governedView(intent: ActionIntent): GovernedIntent {
  const { type, resource, counterparty, amount } = intent
  // Conditional spreads, not `x: undefined`, because tsconfig sets
  // exactOptionalPropertyTypes (mirrors the kernel's own EvalContext construction).
  return {
    type,
    resource,
    ...(counterparty !== undefined ? { counterparty } : {}),
    ...(amount !== undefined ? { amount } : {}),
  }
}
