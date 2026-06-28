<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex council review — CB-002 / ADR-0042 (commitbind public-field allowlist)

**Date:** 2026-06-28 · **Branch:** `apex/cb-002-commitbind-allowlist` · **Status:** review complete,
findings folded into ADR-0042 + tests.

This records the multi-model council review of the CB-002 fix (invert the `boundIntentDigest`
denylist to a public-field **allowlist** + **salted** binding for privacy-sensitive fields).
It is an **internal multi-model review, not an external audit** — the disclosure layer remains
UNAUDITED (ROS / ToB still applies).

## What was reviewed

The decision summary + the core builder code + the four claims (binding-completeness preserved;
secrecy fixed; digest byte-identical for the `{type, resource, amount}` schema; UNAUDITED
classical/ROM privacy hardening, no overclaim), with an explicit adversarial brief: *try to break
each claim.* Six seats were convened.

## Seat verdicts

| Seat (lineage) | Verdict | Headline |
|---|---|---|
| DeepSeek | FIX-FIRST → resolved | Scheme sound; demanded a regression KAT pinning the digest and clarity on the unchanged domain string; flagged salt blast-radius and `resource` plaintext. |
| Grok | Incomplete-without-tests → resolved | Wanted the dCBOR byte-identity *proven* (differential test), the `commitField` binding basis stated, and `resource`/domain-separation addressed. |
| OpenAI | Acceptable as unaudited hardening | Allowlist-as-encoding-mode "much safer than drop-allowlist"; fail-closed correct; flagged domain/version ambiguity, `resource` ("opaque ≠ private"), salt blast-radius, and overclaim wording. Listed 7 concrete failure modes. |
| Mistral | Reasonable hardening; revise wording | Binding/secrecy contingent on salt secrecy → soften "preserved"/"fixed"; GDPR/DPIA + salt-custody operational risk; offered heavier-primitive alternatives. |
| watsonx | Revise with more analysis | Salt-custody risk (High); possible soundness overclaim; `resource` not salted; clarify the "unchanged digest" claim. |
| Gemini | **UNAVAILABLE** | API 503 (high demand) on two attempts; not counted. Panel = 5 substantive seats. |

Net: no seat rejected the design on cryptographic grounds; all asked for the same small set of
hardening/clarity items, now addressed.

## Findings → resolutions

1. **Pin the digest with a regression KAT (DeepSeek, Grok, OpenAI).** Added "digest byte-stability
   KATs" in `commitbind.test.ts`: it reconstructs the pre-ADR-0042 denylist algorithm inline and
   asserts the public-only digest is **byte-identical** (`b4f316a7…46d42afc`), and pins the salted
   full-intent digest (`a2927de5…3c2f668a`). This **proves** the backward-compat claim empirically
   and locks the salted encoding so any silent change to the reused `selective.ts` `commitField`
   or the dCBOR layer breaks a test. (Also answers Grok's "binding basis of `commitField`" and the
   coupling concern: the KAT fails if that primitive's output shifts.)

2. **Domain unchanged while encoding rule changed → version ambiguity (DeepSeek, OpenAI).** ADR-0042
   gained a "Version disambiguation" section: the digest is an **unwired primitive** with no
   persisted sensitive-field corpus, so there is nothing to be ambiguous against today; when wired
   into a v:2 receipt (ADR-0018) the receipt's `v:2` tag + `amount.domain` carry the version. A
   domain bump now is rejected because it would break the public-only byte-identity / C21 invariant
   the task requires; an encoding-mode marker (added only when salted fields exist) is recorded as
   the preferred mechanism if standalone versioning is ever needed.

3. **Binding vs hiding conflation / overclaim wording (Mistral, watsonx, OpenAI).** The Trust-model
   section now states the dependencies **separately**: binding-completeness rests on SHA3
   collision-resistance + injective dCBOR + exhaustive field traversal (and the separate amount-
   opening check) — **not** salt secrecy; hiding rests on salt secrecy + 256-bit entropy (ROM,
   computational). "Secrecy fixed" is restated as "holds while the salt stays secret and off-leaf."
   (Note: Mistral's claim that *binding* depends on salt secrecy is incorrect — binding survives a
   known salt; only hiding needs secrecy. The ADR records the correct split.)

4. **Salt blast-radius / per-field HKDF (DeepSeek, Grok, OpenAI, Mistral, watsonx).** Documented:
   one salt per binding covers all its salted fields (disclosure is all-or-nothing); per-field
   `HKDF(master_salt, field_name)` derivation does **not** reduce blast radius by itself (revealing
   the master reveals the derived sub-salts) — it only helps with field-granular disclosure, the
   deferred upgrade. Kept the single-salt model (matches ADR-0014 custody); recorded the HKDF +
   field-granular path as a follow-up.

5. **`resource` left plaintext — "opaque ≠ private" (all seats).** Promoted from an alternative to
   an explicit Trust-model limit: a low-entropy `resource` is brute-forceable like `counterparty`
   was; it stays public because the design/tests/vectors treat it as recomputable structural
   identity and salting it would change the current-schema digest; a deployment that deems it
   sensitive MUST move it to the salted set (a version-bumping act).

6. **Fail-closed must cover all paths; fail-open rejected (OpenAI, Mistral).** The check lives in
   `buildBoundSkeleton`, so it applies to `boundIntentDigest`, `verifyBound*`, and
   `bindAmountCommitment` uniformly. Fail-open-with-retry (Mistral) is explicitly rejected in the
   ADR — a missing salt is a hard failure; falling back to plaintext is the very exposure CB-002
   closes.

7. **Heavier-primitive alternatives (Mistral, watsonx).** Pedersen-per-field / HMAC / ZKP recorded
   as ADR alternative #8 and rejected for now on audit-surface-minimality grounds (consistent with
   ADR-0013 / ADR-0014); kept as forward options if info-theoretic field hiding is required.

8. **GDPR / personal-data (Mistral).** Recorded as a deployment/DPIA concern: this ADR provides the
   fail-closed *mechanism*, not the *policy* of which fields are personal data.

## Residual (carried, explicitly open)

UNAUDITED classical/ROM construction; salted-field hiding is computational (salt-secrecy-dependent),
not the Pedersen amount commitment's info-theoretic/PQ hiding; range-proof soundness remains
classical discrete-log and unaudited; QROM unanalyzed. This review is internal; the external ZK /
crypto audit still owns the soundness/hiding results.

## References

- [ADR-0042](../adr/ADR-0042-commitbind-public-field-allowlist.md) — the decision (updated per this review).
- [zk-audit-prep-2026-06-27.md](./zk-audit-prep-2026-06-27.md) — dossier P6 (CB-002 finding).
- `disclosure/src/commitbind.ts`, `disclosure/test/commitbind.test.ts`,
  `disclosure/test/commitbind-cb001-surface.test.ts` — implementation + tests.
