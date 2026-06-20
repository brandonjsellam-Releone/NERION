<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — ZK range-proof code audit (2026-06-21)

**Subject:** `disclosure/zkrange.ts` — the bespoke Pedersen / ristretto255 range proof (bit‑decomposition +
Chaum‑Pedersen OR‑proofs + strong Fiat‑Shamir + dual‑range). This is the dominant audit‑risk component and the
target of the planned external ROS / Trail of Bits ZK audit.

**Panel (independent model lineages):** DeepSeek · Grok · Hermes · Gemini · OpenAI (ChatGPT) · Claude Opus 4.8
(lead / adjudicator). Each received the *actual source* and was asked to find a concrete way to make
`verifyBelow` accept a **false** statement.

**Outcome: a real soundness bug was found and fixed *before* external audit.**

## Finding — ZKRANGE‑002 (off‑by‑one wraparound) — HIGH severity, latent

The verifier capped the range bit‑length at `n ≤ 252` under the (incorrect) invariant "2ⁿ < L." But
ristretto255's group order is `L = 2²⁵² + d` with `d ≈ 2¹²⁴·⁷`. At **n = 252** a malicious prover can:

1. commit to a huge `amount ≈ 2¹²⁴` (still `< 2²⁵²`, so the *amount* sub‑proof passes); then
2. `diff = threshold − 1 − amount` is negative and wraps to `L − |diff| ∈ [0, 2ⁿ)`
   (e.g. `amount = d + threshold` ⇒ `diff mod L = 2²⁵² − 1`), so the *diff* sub‑proof **also** passes ⇒
3. `verifyBelow` accepts a **false** `amount < threshold`.

The correct invariant is `2^(n+1) ≤ L` ⟹ **n ≤ 251**.

- **Production impact: none.** The default and every in‑repo use is `n = 32` (≪ 251). The hole was latent at
  the maximum `n` only.
- **Fix:** verifier cap `n ≤ 252` → **`n ≤ 251`**; docstring corrected; regression test added (a valid n=252
  proof of a *true* statement is now rejected; n=251 still verifies). Gate green at **298 tests / 21‑of‑21**.

## Adjudication — why a panel, not a vote

The panel **split**: DeepSeek flagged ZKRANGE‑002; **Grok and Hermes both cleared the code as "sound even at
n=252"** — Hermes with an explicit sign error (it claimed the wrap value is always `> 2ⁿ`; it is not). Gemini
verified the primitives but not the dual‑range step; the OpenAI seat returned empty. The lead re‑derived the
`L = 2²⁵² + d` arithmetic and confirmed the dissent was correct.

**Lesson: the value of a multi‑model panel is in *verifying the minority report*, not averaging the majority.**
A simple majority vote here would have shipped the bug.

## Residual (unchanged, honest)

Soundness remains **classical** (discrete‑log); zero‑knowledge is proven in the classical ROM, not the QROM.
The construction is still **UNAUDITED** — this internal multi‑model review *accelerates* but does **not**
replace the external ROS / ToB audit. Top forward upgrade: migrate the commitment layer to a post‑quantum
commitment scheme (see [../STATUS.md](../STATUS.md)).
