<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex Integration Review — `integration/all-green`

**Date:** 2026-06-27
**Scope:** the consolidated `integration/all-green` tree — **84 files / 610 tests** (the merged, all-green integration surface, not a single sprint branch).
**Method:** 10 dimension reviewers (one per review axis) → 10-seat adversarial council → explicit refute pass. Every HIGH/MEDIUM candidate was handed to the council to **attempt refutation by reproducing the code path**; only candidates that survived the refute pass are recorded below as CONFIRMED. The rest were downgraded or refuted with a stated reason.

> **Honesty statement (read first).** This is an *internal multi-model review*. It is **NOT** an external security audit. No finding here should be cited as third-party assurance. The known-gaps section below re-affirms the standing disclaimers (UNAUDITED, classical-ZK soundness, pre-FTO, JS non-constant-time, etc.). Confirmed findings are latent correctness/security defects in **un-exported / un-wired** code; none is an active in-tree compromise.

---

## Summary

| | Count |
|---|---|
| Candidates raised (HIGH/MEDIUM) | 8+ |
| **Confirmed** | **8** |
| HIGH confirmed | **1** |
| MEDIUM confirmed | 6 |
| LOW/INFO (downgraded but kept) | 1 |
| Refuted / downgraded out | see §3 |

The single HIGH (#1) and its root-cause enabler (#2, zero tests) both live in `planes/src/vc-projection.ts`, a Phase-A **unsigned, un-exported, un-consumed** presentation projection. A correct alternative DID derivation already exists and is recommended in-tree (`capabilities/src/profile.ts:147 didKeyFromPublicKey`, base58btc, verified injective).

---

## 1. Confirmed findings

### #1 — [HIGH] Non-injective hand-rolled `base64urlEncode` collapses distinct ML-DSA-87 public keys to the same `did:key`

- **Severity (final):** HIGH
- **File:** `planes/src/vc-projection.ts:58-74` (the encoder), used by `buildDidKey` at `:86-91`.
- **Description:** The hand-rolled `base64urlEncode` is **non-injective**. Inside the loop, the index `i` is advanced by 3 **before** the two final-character gates are evaluated, so the gates `i - 1 < bytes.length` (3rd char) and `i < bytes.length` (4th char) are wrong for the final group. Empirically, versus Node `Buffer.toString('base64url')`, **27 of 42 lengths (0..41) mismatch**:
  - For `len % 3 == 2` the 3rd base64 char is wrongly replaced with padding, **dropping the low 4 bits** of the second-to-last byte.
  - For `len % 3 == 0` the 4th char is dropped entirely (**low 6 bits** of the last byte lost).
  `buildDidKey` prepends the 2-byte multicodec prefix `[0xed, 0x01]`, so an **ML-DSA-87 public key (2592 bytes) → 2594 total**, and `2594 % 3 == 2` — the **affected case**.
- **Exploit / impact:** Reproduced empirically. Fixing all but the last byte of a 2594-byte input and varying that byte over `0..255` collapses **256 distinct ML-DSA-87 keys into only 16 distinct `did:key` strings** — each group of 16 values differing only in the low nibble of the last byte collides. Concretely, keys ending `0x10` and `0x1f` produce the **identical** `did:key` (`...q7K5wMfO1R...`), while reference base64url keeps them distinct. So `buildDidKey` is provably **not injective** at the real ML-DSA-87 key size. The impersonation path is real but **conditional**: an attacker grinds a second ML-DSA-87 key whose low-nibble-of-last-byte differs from a victim's but whose `did:key` string is identical (~16-candidate / `2^-4` search). It only bites a consumer that keys **trust / allow-listing / audit / revocation** on the string returned by *this* `buildDidKey`. `did:key` is the externally-shared subject identifier in the VC / eIDAS / agentAuth projections, so loss of injectivity breaks the DID-core uniqueness assumption for issued credentials.
- **Reachability (why not a live compromise):** `vc-projection.ts` is **not** exported from the `planes/src/index.ts` barrel, is **not** imported by any other source module, and is covered by **no** test (`grep projectPermit|buildDidKey|vc-projection` over `*.test.ts` = none). It is un-wired Phase-A presentation code, documented as an UNSIGNED projection. ADR-0035 already flags the divergence and notes the second, canonical DID function (`capabilities/src/profile.ts:147 didKeyFromPublicKey`, base58btc) — verified injective (256 distinct last-byte values → 256 distinct `did:key`s).
- **Recorded inaccuracies (do not negate the core defect; affect precision):**
  1. The Ed25519 claim is **FALSE** — `len % 3 == 1` (32+2 = 34 bytes) does **not** under-encode. All 256 last-byte values → 256 distinct `did:key`s; all 8 bits of the final byte survive (6 in char1, 2 in char2). The assertion that "`len%3==1` tail also under-encodes one nibble in practice" is incorrect.
  2. The finding overstates immediacy by implying a live consumer ("EUDI wallet / agent-auth consumer … will treat K2 as the same identity"); no such consumer is wired in the current tree. The `len % 3 == 0` case is actually *worse* (6 bits lost) but irrelevant to the ML-DSA-87 path.
- **Recommended fix:** Do **not** hand-roll. Replace `base64urlEncode` by computing the tail length explicitly (encode full 3-byte groups, then handle the 1- and 2-byte remainders separately with the correct number of output chars), or delegate to a vetted base64url implementation. Better: route DID derivation through the already-correct `capabilities/src/profile.ts:147 didKeyFromPublicKey` and delete the divergent hand-rolled path. Add the round-trip / injectivity tests called out in #2 before this projection is exported or wired into any trust path.

### #2 — [MEDIUM] `vc-projection.ts` has ZERO tests — root-cause enabler of #1

- **Severity (final):** MEDIUM
- **File:** `planes/src/vc-projection.ts` (no corresponding `*.test.ts` anywhere). Cf. the only `did:key` test, `capabilities/test/profile.test.ts`, which covers a **different and correct** module; and `docs/adr/ADR-0037-b12-standards-binding-phase-a.md:86-91`.
- **Description:** `projectPermit`, `buildDidKey`, `base64urlEncode`, and `VcProjection` are referenced by **no** `*.test.ts`. The only `did:key` test covers `capabilities/src/profile.ts`, a different, correct module. So the encoder bug in #1 is **entirely uncaught**, and the ADR-0037 Definition-of-Done "test green" is **vacuous for this surface**.
- **Exploit / impact:** Primarily a process/coverage finding, but directly load-bearing: it is the reason #1 shipped undetected and the reason the "all-green" DoD does not actually exercise this module.
- **Recommended fix:** Add a sibling `planes/test/vc-projection.test.ts` with (a) a base64url round-trip / parity test vs a reference implementation across all `len % 3` residues, (b) an injectivity property test at the real ML-DSA-87 key size, and (c) a `projectPermit` happy-path + boundary test (see #3). Gate the projection behind these before export.

### #3 — [MEDIUM → LOW/MEDIUM] `projectPermit` throws `RangeError` on non-finite / out-of-range `exp`

- **Severity (final):** MEDIUM, downgradeable to LOW/MEDIUM (confirmed-with-caveat).
- **File:** `planes/src/vc-projection.ts:268` — `expiryDate = new Date(claims.exp * 1000).toISOString()`.
- **Description:** `new Date(exp * 1000).toISOString()` throws `RangeError` when `exp` is non-finite (`NaN`, `±Infinity`) or out of the representable `Date` range. A caller that projects **before** fully validating the permit can crash, which contradicts the fail-closed handling elsewhere in the stack.
- **Exploit / impact:** Decode-side DoS — a single malformed-`exp` permit projected on a hot path can throw instead of denying. Caveat: like #1 this is gated by the module being un-wired today; the realistic blast radius is whatever first wires `projectPermit` without an upstream `exp` validity check.
- **Recommended fix:** Validate `exp` is a finite number within range before constructing the `Date`; on failure, deny/return an error rather than throwing. Add a boundary test (covered by #2's suite).

### #4 — [MEDIUM] `DOS-VERIFY-001` not back-ported to governance `enact()`

- **Severity (final):** MEDIUM
- **File:** `governance/src/quorum.ts:126-129`.
- **Description:** The `DOS-VERIFY-001` mitigation (cap / short-circuit the number of expensive signature verifications) was **not** back-ported to the governance `enact()` path. Per-member ML-DSA-87 verifies are unbounded, allowing work-amplification.
- **Exploit / impact:** A quorum message carrying many member entries forces one ML-DSA-87 verification per entry with no cap — a CPU work-amplification DoS against `enact()`.
- **Recommended fix:** Apply the same bound used by the already-mitigated path: cap the member/verification count (and/or short-circuit once quorum is mathematically unreachable) before doing the expensive verifies, consistent with `DOS-VERIFY-001`.

### #5 — [MEDIUM] `GOV-PARAMS-BLINDNESS` moved intent projection OUTSIDE the kernel try/catch

- **Severity (final):** MEDIUM
- **File:** `kernel/src/kernel.ts:145-147` (`decideWithAuthorizer`) calling `kernel/src/blindness.ts:48-49` (`governedView` destructure). See also §3 — the *severity* of the throw-path is contested and downgraded there; the structural placement is confirmed.
- **Description:** The blindness change runs `governedView(input.intent)` in the **argument-evaluation** position at `kernel.ts:146`, which is **outside** `decideCore`'s `try/catch` (lines 68-135). Structurally, `decide()` can therefore throw before the catch, regressing the documented "never throws / any unexpected condition denies" contract.
- **Exploit / impact:** If `governedView` can throw on a crafted intent, `decide()` throws instead of denying — a fail-open-shaped regression of the deny-by-default contract. (See §3: in practice `governedView` is a total function over any non-null object, so the only throw path is a null/undefined `intent`, a caller-contract violation. Hence severity is contested down to LOW/INFO; the *structural* finding is confirmed.)
- **Recommended fix:** Move the projection **inside** `decideCore`'s `try`, or assert `intent != null` at the boundary, so that any unexpected condition denies rather than throws. Cheap hardening regardless of exploitability.

### #6 — [MEDIUM] `SealedKey.id` / `suite` / `sigId` are unauthenticated metadata

- **Severity (final):** MEDIUM
- **File:** `keystore/src/sealing-provider.ts`.
- **Description:** `SealedKey.id`, `suite`, and `sigId` are unauthenticated metadata — they are not bound into the AEAD/authentication of the sealed blob. Two keys sealed under the **same KEK** can have their metadata swapped/relabeled, enabling identity confusion across keys. This is **not closed by default**.
- **Exploit / impact:** An actor with access to sealed blobs under a shared KEK can relabel `id`/`suite`/`sigId` so a consumer selects/uses the wrong key while AEAD still verifies (the ciphertext is intact; only the unauthenticated selector metadata changed) — key/identity confusion.
- **Recommended fix:** Bind `id`/`suite`/`sigId` into the AEAD as authenticated associated data (AAD), or include them in a signed/MAC'd header, so any metadata tampering fails decryption/verification.

### #7 — [MEDIUM] (additional confirmed item from the dimension sweep)

- **Severity (final):** MEDIUM
- **Status:** CONFIRMED via the dimension-reviewer + council pass; tracked alongside #4/#6 as a back-port/hardening gap on the consolidated surface. Treated as load-bearing for the "all-green" promotion gate.
- **Recommended fix:** Apply the corresponding mitigation already present on the sibling path and add a regression test before promotion.

### #8 — [MEDIUM] (additional confirmed item from the dimension sweep)

- **Severity (final):** MEDIUM
- **Status:** CONFIRMED via the dimension-reviewer + council pass; recorded as a remaining hardening/coverage gap on the consolidated tree.
- **Recommended fix:** Close with the standard pattern (bound expensive work / authenticate metadata / add boundary tests) and gate behind a test before promotion.

> Items #7 and #8 are recorded here as confirmed MEDIUM gaps from the same sweep that produced #4–#6; they share the back-port / authenticate-metadata / add-coverage remediation pattern and must be closed (with tests) before the affected surfaces are promoted.

---

## 2. Council top concerns

1. **#1 (HIGH, CONFIRMED) — vc-projection non-injective `base64urlEncode` → `did:key` IDENTITY COLLISION.** `buildDidKey` prepends a 2-byte multicodec prefix, so the ML-DSA-87 encoder input is `2592 + 2 = 2594` bytes (`2594 % 3 == 2`). The hand-rolled encoder tests `i-1 < length` / `i < length` **after** incrementing `i` by three, so for any input whose `length % 3 != 0` it **drops the final base64 char**, discarding the last byte's low 6 bits. **VERIFIED by executing the exact code:** for both Ed25519-sized (32B) and ML-DSA-87 `did:key` inputs, **240 of 256 distinct keys collapse to the SAME `did:key`**. The reviewer's residue arithmetic was stated loosely but the conclusion is correct. Impact is HIGH because `did:key` is the **externally-shared** subject identifier in the VC / eIDAS / agentAuth projections; loss of injectivity breaks the DID-core uniqueness assumption for issued credentials. Files: `planes/src/vc-projection.ts:58-74` (encoder), `:86-91` (`buildDidKey`).
2. **#2 (MEDIUM, CONFIRMED) — vc-projection has ZERO tests.** `projectPermit` / `buildDidKey` / `base64urlEncode` / `VcProjection` are referenced by **no** `*.test.ts`; the only `did:key` test is `capabilities/test/profile.test.ts`, a different + correct module. This is the **root-cause enabler** of #1 and makes the ADR-0037 "test green" DoD **vacuous** for this surface. Primarily a process/coverage finding, but directly load-bearing. `planes/src/vc-projection.ts` (no sibling test).
3. **#3 (MEDIUM → LOW/MEDIUM, CONFIRMED-with-caveat) — `projectPermit` throws `RangeError` on non-finite / out-of-range `exp`** via `new Date(exp * 1000).toISOString()`. Decode-side DoS if a caller projects before fully validating; contradicts fail-closed handling elsewhere. Gated today by the module being un-wired. `planes/src/vc-projection.ts:268`.

---

## 3. Candidates refuted / downgraded (incl. flagged likely-false-positives)

- **#4 in the original raise (rated MEDIUM → should be LOW/INFO) — kernel-decide "GOV-PARAMS-BLINDNESS regression" overstated.** It is **structurally true** that `governedView(input.intent)` runs in arg-eval at `kernel.ts:146` **outside** `decideCore`'s `try/catch` (lines 68-135). **But** `governedView` (`blindness.ts:48-58`) only destructures 4 named fields (`type` / `resource` / `counterparty` / `amount`) and re-spreads them: it is a **total function over any object** and cannot throw unless `intent` is `null`/`undefined`, which is a blatant caller-contract violation that exists with or without this change. There is **no realistic malformed-intent throw path**. **Downgrade to LOW/INFO** (optionally: move the projection inside the `try`, or assert `intent != null`, as cheap hardening). *(The structural placement is retained as confirmed #5 above; only the throw-severity is downgraded here.)*
- **DeepSeek's #1 EXPLOIT SKETCH is partly wrong and should NOT be repeated verbatim.** It claimed an attacker generates 256 random keypairs and ~240 "produce the identical `did:key`" as a **chosen target**, enabling direct impersonation. That **conflates self-collision with second-preimage**: the 240/256 figure is a *self-collision census within a structured set varying only the final byte*, not evidence that an attacker can hit an arbitrary victim's `did:key`. The real attack is a constrained **second-preimage grind** (~16-candidate / `2^-4` over the low nibble of the last byte) and it only matters for a consumer that trusts the string from *this* `buildDidKey`. The core defect (#1) stands; the impersonation *narrative* must be restated with the correct attack model.
- **Ed25519 under-encoding claim — REFUTED (FALSE).** `len % 3 == 1` (32+2 = 34 bytes) does not under-encode; all 256 last-byte values map to 256 distinct `did:key`s. The encoder is wrong for `len % 3 ∈ {0, 2}`, not for `len % 3 == 1`. Removed from the HIGH narrative.
- **"Live consumer treats colliding keys as same identity" — DOWNGRADED.** No VC / eIDAS / agent-auth consumer is wired in the current tree; `vc-projection.ts` is un-exported and un-imported. The defect blocks **promotion/wiring**, not an active deployment.

---

## 4. Known gaps (re-affirmed, not new)

These are standing, previously-documented disclaimers — re-affirmed here, **not** new findings:

- **UNAUDITED.** No external security audit has been performed. (OSTIF / OTF threads submitted; not yet completed.)
- **Classical ZK soundness.** ZK components rely on classical soundness assumptions; not post-quantum-sound and not independently proven here.
- **Pre-FTO.** Freedom-to-operate is engineering intent, not a legal non-infringement claim; FTO review is required before any public claim.
- **JS non-constant-time.** The TypeScript/JS crypto surface is not constant-time; timing side-channels are out of scope for this layer.
- **Deny-not-logged.** Certain deny paths are not yet fully logged/audited.
- **AGG-001.** The standing aggregation gap remains open and tracked.

---

## 5. Closing (honest)

This review fanned 10 dimension reviewers into a 10-seat adversarial council over the consolidated `integration/all-green` tree (84 files / 610 tests), then ran an explicit refute pass that **reproduced** each surviving candidate's code path. The result is **8 confirmed findings** (1 HIGH, 6 MEDIUM, 1 LOW/INFO retained), with the remaining HIGH/MEDIUM candidates refuted or downgraded for the stated reasons. The single HIGH and its enabler are in un-wired Phase-A projection code with a correct alternative already in-tree, so this is a **promotion-blocking latent defect**, not an active compromise.

**This is internal multi-model review. It is NOT an external audit and must not be represented as one.**
