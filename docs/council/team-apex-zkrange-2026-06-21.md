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

## Follow-up — `policyproof.ts` (policy-satisfaction composition), same campaign

The panel (DeepSeek · Grok · Hermes; Gemini 503, OpenAI empty) then audited the policy-satisfaction layer
that *composes* the range proof.

**Central worry, adjudicated SAFE.** All three asked: *does `proveBelow` bind the threshold, or could a proof
for a large threshold verify against a small one?* It **binds it** — `zkrange` folds `threshold` into both the
Fiat-Shamir `statementHash` **and** the verifier-recomputed `cDiff`, and the existing test "rejects a proof
checked against the wrong threshold" confirms it. **No cross-bounds soundness break.**

**Two hardenings applied (panel-recommended, MEDIUM/LOW):**
1. `policyProofDigest` now binds the **explicit numeric bounds** (ceiling / cap / aggregate / n), not just the
   `policyBinding` string — so the v:2 receipt anchor is self-describing and a proof cannot be re-anchored as
   satisfying different bounds that share a policyBinding (+ a test asserting the digest changes when bounds do).
2. `proveBelow` now enforces the same **n ≤ 251** cap as the verifier (fail-fast; closes the prove/verify
   spec divergence the panel flagged).

Neither is a break (the proof is threshold-bound), but both are genuine audit-trail + consistency hardening.
Gate green at 298 tests / 21-of-21.

## Follow-up — `receipts/quorum.ts` (k-of-n quorum receipts), same campaign

Panel: DeepSeek · Grok · Hermes (all delivered; Gemini 503, OpenAI empty).

**One real hardening applied; two over-reaches adjudicated SAFE.**

- **Applied (unanimous): explicit top-level domain separation.** The signed message was
  `canonical({receipt, quorum})` with `QUORUM_CONTEXT` only *inside* `setId`. DeepSeek framed a
  cross-protocol signature-confusion path (harvest a validator's ML-DSA signature from another protocol
  that reuses the key and reproduces the body shape, then replay it as a quorum attestation). **Not
  currently exploitable** in Nerion — no other protocol signs that 2-field shape — but it is textbook
  best practice and exactly what an external auditor flags. Fix: the signed message is now
  `canonical([QUORUM_CONTEXT, body])` on **both** build and verify.
- **Adjudicated SAFE — Hermes "stake-path `q.k` divergence":** claimed an attacker could choose `q.k` to
  make a `setId` validate for a high-stake subset. **False** — `q.k` and `q.setId` are both inside the
  signed body, so neither can change without valid signatures; the committed `q.k` is signature-bound.
- **Adjudicated SAFE — Hermes "replay across receipts":** the full `ReceiptBody` (decision hashes +
  timestamp) is in the signed message, so genuine distinct decisions never share signatures.

Acknowledged (unchanged, already-documented trust model): safety reduces to ML-DSA-87 EUF-CMA **assuming
k distinct, non-colluding member keys**; the verifier must supply its own finalized trusted set. Both are
stated in the module docstring and [ASSURANCE.md](../ASSURANCE.md). Gate green at 298 tests / 21-of-21.

## Follow-up — `disclosure/commitbind.ts` (v:2 commitment binding) — **CB-001, the headline find**

Panel: DeepSeek · Grok · Hermes — **unanimous, concrete, and correct** (DeepSeek "DO-NOT-SHIP,"
Grok "Critical flaw," Hermes "broken for its stated privacy goals").

**CB-001 — the public binding digest leaked the amount via brute-force.** `boundIntentDigest` hashed the
FULL intent *including the plaintext `amount`* into a digest that is a PUBLIC, "externally-recomputable"
receipt field. The Pedersen commitment is perfectly hiding and the random opening is NOT in the pre-image
— but the amount **is**. So anyone holding the receipt (digest + commitment + the rest of the intent)
recovers the amount by enumerating candidates, recomputing the digest, and matching. Amounts are
low-entropy, so this is O(amount-space) hashes — trivial. The commitment's information-theoretic hiding is
**nullified** by the public hash pre-image. This is the exact "unsalted selective-disclosure brute-force
over small enumerable domains" class the project already flags in `policyproof.ts` — re-introduced here.

**Severity, honestly scoped.** commitbind is a reference PRIMITIVE **not yet wired into the signed receipt
body** (per its own docstring), so no production receipt carries this digest yet — **caught before it
shipped.** It must be fixed before wiring; it would have been a serious privacy regression if wired.

**Adjudication (verified, not rubber-stamped).** The attack reproduces directly from the code — amount in
the pre-image + public digest + enumerable domain. True positive, independently derived at the lead seat
*before* the fan-out, then confirmed 3-for-3. The encoding itself is sound (dCBOR + canonical ristretto255,
no malleability — DeepSeek).

**Fix applied (all three converge).** Omit the amount from the digest pre-image. The amount is already
bound CRYPTOGRAPHICALLY by the commitment and checked against `intent.amount` in the opening-holder's
`verifyBoundAmount`; the public digest now binds only the amount-free intent skeleton + the commitment
point. This *also* closes a second gap the panel raised — a privacy verifier previously could not recompute
the digest at all (it needed the amount); now it can, from the skeleton. Regression test asserts two intents
differing only in amount produce the SAME digest, while a different non-secret field still changes it.

**Acknowledged (unchanged trust model).** Against a binder malicious *at admission* (binds commitment-to-Z
under intent-amount-Y), only `verifyBoundAmount` (opening-holder) or the quorum/attestation layer defends —
documented, by design.

## Follow-up — enforcement boundary: `kernel/kernel.ts` + `planes/permit.ts` + `receipts/receipt.ts`

Panel: DeepSeek · Grok · Hermes. The last big security-critical surface — "a denied action never executes."

**Positive result — `decide()` validated fail-closed.** All three found NO fail-open: default-deny,
denylist-before-resolve ordering is safe, the `catch` returns a tier-3 deny, and `ev` defaults to
`+uncomputed` so an un-canonicalizable policy still denies. No input yields allow/transform without positive
capability authorization. The enforcement core holds.

**RCPT-001 (real, deployment-relevant) — the logged receipt leaks the amount.** `commitments.intent =
SHA3(canonical(full intent))` (receipt.ts) and the receipt body IS the public transparency-log leaf. The
intent includes the plaintext `amount`, so a log observer who knows the rest of the intent brute-forces the
amount — the **CB-001 attack, but in the v:1 receipt that is actually logged.** SPLIT verdict, adjudicated:
DeepSeek + Grok confirmed it; **Hermes wrongly cleared it citing SHA3 preimage-resistance** — the same error
class as the ZKRANGE-002 false-clearers (preimage-resistance does NOT stop a brute-force over a low-entropy,
known-structure preimage). The project already knows this class (`selective.ts`, `policyproof.ts`), but the
receipt's intent-hash re-introduced it. **Scope:** amount-privacy *in the log* is the v:2 receipt's job
(salted/PSP path, not yet wired); the proper fix is a salted/hiding intent commitment = a schema change
(ADR). **Action taken now:** corrected the ASSURANCE "amount confidentiality" claim to state plainly that the
v:1 intent-hash leaks low-entropy amounts — NOT silently left as an overclaim; salted v:2 commitment roadmapped.

**PERMIT-001 (real, architectural) — symmetric-key cross-audience forgery.** The PermitToken is an HMAC under
a per-session symmetric `sessionKey` shared issuer+resource (node.ts). The `audience` is MAC-bound, but a
key-holding (malicious) resource can re-MAC a permit for a *different* audience. Exploitable only if the
session key spans multiple mutually-distrusting resources, but the design does not enforce per-audience keys.
**Fix (panel converges):** derive per-(session,audience) keys via HKDF and distribute only the derived key, or
use asymmetric issuer signatures (trades the Plane-1 hot-path HMAC speed). Documented in ASSURANCE; the
architectural fix is an ADR.

**Fixed now — the permit binds the decision `effect`.** The permit previously carried tier + actionHash but
NOT the kernel's effect (allow vs transform); `verifyPermitForAction` now MAC-binds `effect` and a resource
can pin `expectedEffect`, so a transform cannot be presented/honored as a plain allow. (Transform is
"allowed-but-flagged" today — this future-proofs it before transform becomes a real action-modification.)
+ regression test.

## Residual (unchanged, honest)

Soundness remains **classical** (discrete‑log); zero‑knowledge is proven in the classical ROM, not the QROM.
The construction is still **UNAUDITED** — this internal multi‑model review *accelerates* but does **not**
replace the external ROS / ToB audit. Top forward upgrade: migrate the commitment layer to a post‑quantum
commitment scheme (see [../STATUS.md](../STATUS.md)).
