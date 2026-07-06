<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0042 — `polarseek-*` → `Nerion/*` domain-tag value migration as a versioned v2→v3 protocol bump (proposed, design-only)

**Status: PROPOSED — DESIGN ONLY, UNIMPLEMENTED.** This ADR records a _decision about the shape and
sequencing_ of renaming the protocol's **domain-separation tag VALUES** (the `polarseek-*` /
`PolarSeek-*` / `PolarSeek/…` strings embedded inside signed / MAC'd / committed messages) to the
`Nerion/*` convention, as the final code-level step of the PolarSeek→Nerion rename. It changes **no**
code, **no** KAT vector, and **no** wire byte in this commit. The number **0042 is provisional**,
pending cross-branch ADR reconciliation (the ADR range 0001–0041 is collision-managed); renumber on
merge if it collides. Date: 2026-07-06. Nothing here is a security, audited, production-ready, FIPS,
or non-infringement claim. UNAUDITED, pre-FTO.

## Context

### The rename is branding-only for prose, but the tags are on the wire

The project was renamed **PolarSeek → Nerion** (2026-06-20), a **branding change** that leaves the
concept and the FTO design-around untouched. Human-facing prose (README, grants, executive summary)
is migrated. The **package identity** is migrated (`package.json` → `nerion`). The **module
plumbing** is migrated: DS-REGISTRY-001 (`crypto/src/domains.ts`) now routes every consumer's tag
through a single central `DOMAIN_TAGS` registry, and that migration is complete and byte-identical.

What remains is the one part of the rename that is **not cosmetic**: the tag **VALUES** themselves.
A domain-separation tag is not a label — it is _bytes hashed into a signature / MAC / commitment_ to
keep one message space from colliding with another. Examples still carrying the old brand (from the
DS-REGISTRY-001 inventory in `crypto/src/domains.ts`):

- `ENVELOPE_SIGNED: 'PolarSeek-Signed-v1'` (ML-DSA-87 signed envelope)
- `PERMIT_MAC: 'PolarSeek-Permit-v1'` (HMAC-SHA-384 hot-path permit)
- `BLOCK_HASH: 'polarseek-block-v1'`, `BLOCK_SIG: 'polarseek-block-sig-v1'`,
  `ATTESTATION: 'polarseek-attest-v2'`, `TIMEOUT: 'polarseek-timeout-v2'` (ledger consensus)
- `GOVERNANCE_PROPOSAL: 'polarseek-gov-v1'`, `QUORUM_RECEIPT: 'polarseek-quorum-receipt-v1'`,
  `STH: 'polarseek-sth-v1'`, `CREDIT_GRANT: 'polarseek-credit-grant-v1'`,
  `CAPABILITY_GRANT: 'polarseek/capability/grant/v2'`, `ATTEST_EVIDENCE: 'polarseek/attest/evidence/v1'`

The surface is genuinely **mixed** today: every tag _added_ since the rename already uses the new
convention (`nerion-receipt-v1`, `Nerion/evm-attest/v1`, `Nerion/permit-caveat/v1`,
`Nerion/disclosure/salted-commit/v1`, `Nerion/evm-consensus-set/v1`, …), while the pre-rename tags
still read `polarseek-*`. This inconsistency is cosmetic-only (domain separation depends on tag
_uniqueness_, which the DS-REGISTRY-001 uniqueness gate already enforces regardless of brand), but it
is a visible seam an auditor will notice.

### Why a find-replace is wrong (the load-bearing fact)

Changing a tag value changes the bytes fed into every signature / MAC / commitment that uses it.
Therefore a blanket `polarseek-*` → `Nerion/*` replacement would:

1. **Rehash every affected signed message**, so **the frozen KAT vectors change** —
   `conformance/vectors/ps-kat.json`, `conformance/vectors/ps-negative.json`, and
   `crypto/vectors/deterministic-kat.json` are frozen precisely so that a wire-format change cannot
   land silently. A find-replace would force-regenerate them, destroying their value as a
   change-detector.
2. **Break interop with any deployed v2 verifier**: a v2 receipt/permit/attestation signed under
   `polarseek-attest-v2` will not verify against a verifier recomputing the message under
   `Nerion/attest/v3`, and vice-versa. Domain separation working _as designed_ guarantees the two
   are mutually unverifiable — which is exactly why this is a **wire-format break**, not a rename.
3. **Emit no version signal**, so a peer cannot tell which tag generation a message belongs to.

So the tag rename is a **protocol version bump (v2 → v3)**, and must be sequenced like one: additive,
versioned, with the frozen v2 vectors preserved byte-for-byte and new v3 vectors added beside them.
This is the same discipline ADR-0018 used for the `amount.domain` (`"u64"` → `"u64/pq"`) discriminator
and ADR-0013/0018 used for the v:1→v:2 receipt body: **never substitute frozen bytes; add a new
versioned domain and gate it.**

## Decision

**Adopt a versioned, additive v2→v3 domain-tag migration, switched at the DS-REGISTRY-001 registry,
with the frozen v2 KATs preserved byte-identical and new v3 KATs added — implementation deferred
until the version-negotiation and vector-regeneration plan below is built and gated.** Concretely:

### (a) The registry is the single switch point

Because DS-REGISTRY-001 already routes every consumer through `DOMAIN_TAGS`, the migration is a
change to **one file's values under a version guard**, not a scattered edit. Introduce a protocol tag
generation:

- Keep the current `DOMAIN_TAGS` map as the **v2 tag set** (`DOMAIN_TAGS_V2`), byte-frozen, the
  source of the existing KATs. No value in it changes, ever.
- Add a **v3 tag set** (`DOMAIN_TAGS_V3`) in which each migrated tag adopts the `Nerion/*` convention
  **and increments its embedded version suffix**, so a v3 tag is unambiguously a _different string_
  from its v2 predecessor (e.g. `polarseek-attest-v2` → `Nerion/consensus/attest/v3`;
  `PolarSeek-Signed-v1` → `Nerion/envelope/signed/v2`; `PolarSeek-Permit-v1` →
  `Nerion/permit/mac/v2`). Tags added since the rename that are _already_ `Nerion/*` keep their value
  and are simply re-homed into the v3 set (no version bump needed — they were never v2).
- A build/deployment selector `PROTOCOL_TAG_GENERATION` (default **v2**, so with the flag unset the
  emitted bytes and KATs are exactly today's) chooses which set consumers resolve.

The DS-REGISTRY-001 **uniqueness gate runs over each generation independently** (no tag collides
_within_ a generation) and additionally asserts **no v3 value equals any v2 value** (the version
increment guarantees this), so a message can never be ambiguous about its generation.

### (b) Version negotiation and no dual-accept

A verifier is configured for exactly one generation (its own), or negotiates the peer's generation
via the existing suite/version-negotiation path (ADR-0029, downgrade-resistant). **Verifiers MUST NOT
"try v2, then try v3"**: dual-accept re-introduces exactly the cross-space confusion domain
separation exists to prevent, and it would let a downgrade attacker present a v2-tagged message to a
v3 deployment. The generation is a _negotiated, bound_ parameter, not a fallback loop. Mixed-fleet
operation is a migration window, not a steady state; the steady state is single-generation.

### (c) Frozen v2 vectors are preserved; v3 vectors are added

- `conformance/vectors/ps-kat.json`, `ps-negative.json`, and `crypto/vectors/deterministic-kat.json`
  stay **byte-identical** — they are the v2 generation's frozen truth and are never regenerated by
  this migration.
- A **new v3 vector set** (e.g. `ps-kat-v3.json` / a `v3:` section) is **added**: the same
  `(message, key, expected signature/MAC/commitment)` fixtures recomputed under the v3 tag set. These
  are additive fixtures, never substitutions.
- A **new conformance check** (next free C-id, assigned at implementation time per the repo's
  conformance bookkeeping — none reserved here) asserts: (1) with the selector at v2, every emitted
  byte and KAT is identical to today; (2) with the selector at v3, messages verify under the v3 tag
  set and **fail** under v2 (proving the generations are cryptographically separated); (3) the
  registry uniqueness gate holds within each generation and across the v2/v3 disjointness.

### (d) SuiteID enum is out of scope and untouched

The frozen `SuiteID` enum in `crypto/src/suites.ts` and the `SUITE_IDS` values (`PS_1`…`PS_5`) are a
**separate** frozen surface (the suiteid-lock test pins them). They are _identifiers of crypto
suites_, not domain-separation tags, and are **not** renamed by this ADR. `PS_5` stays `PS_5`. This
ADR touches only the `DOMAIN_TAGS` values. (Whether the `PS_` suite-id prefix is ever rebranded is a
separate, independently-frozen decision and is explicitly **not** proposed here.)

## Alternatives considered

1. **Find-replace all tags in place, regenerate the KATs — REJECTED.** Silently rewrites frozen
   wire-format vectors (destroying the change-detector), breaks every deployed v2 verifier with no
   version signal, and pretends a wire break is a rename. This is the tempting-but-wrong option the
   ADR exists to forbid.
2. **Leave the tags `polarseek-*` forever — ACCEPTED as the interim, REJECTED as the end-state.**
   Domain separation depends on tag _uniqueness_, not brand, and the DS-REGISTRY-001 gate already
   enforces uniqueness — so the mixed `polarseek-*`/`Nerion/*` surface is **cryptographically fine**
   and carries **zero risk** today. Renaming is a **branding/cosmetic** debt, not a security need. So
   the honest interim is: ship as-is, disclose the mixed naming, and do the v3 bump only when a real
   driver (a breaking release, a fresh audited generation, external interop) justifies paying the
   migration cost. **This ADR does not argue the rename is urgent** — it argues that _when_ it is
   done, it is done as a versioned bump, not a find-replace.
3. **Dual-accept both v2 and v3 tags at verify — REJECTED.** Re-opens cross-generation confusion and
   hands a downgrade attacker a v2/v3 substitution path; defeats the purpose of domain separation.
4. **Big-bang v3 with no v2 support — REJECTED.** Instantly invalidates every existing receipt,
   permit, and attestation and every RFC-6962-anchored transparency-log leaf. The additive,
   selector-gated, negotiated migration is the only interop-safe path.
5. **A single global tag prefix swap (one `PROTOCOL_PREFIX` constant) instead of per-tag values —
   REJECTED.** Some tags are slash-namespaced (`polarseek/capability/grant/v2`) and some are hyphenated
   (`polarseek-block-v1`); a single prefix constant cannot express both canonical shapes, and it would
   couple every message space to one string (a blast-radius and review-granularity regression versus
   the explicit per-tag map DS-REGISTRY-001 already provides).

## Consequences

- **Positive (post-migration).** Retires the last `polarseek-*` naming seam in the code, giving a
  single consistent `Nerion/*` convention across every signed message space, under an explicit,
  negotiated protocol generation. Because it reuses the DS-REGISTRY-001 registry as the switch point
  and the ADR-0018 additive-versioning discipline, it lands with **no frozen-vector regeneration** and
  **no v2 interop break** — v2 and v3 coexist during the migration window and are cryptographically
  separated.
- **Cost / caveats.** A second KAT generation and a new conformance check are new maintenance surface;
  a migration window requires fleet coordination (which generation each verifier speaks) and leans on
  ADR-0029 negotiation being downgrade-resistant. The migration is **only worth doing behind a real
  driver** (breaking release / audited-generation cutover) — doing it for aesthetics alone spends
  audit and interop budget for a cosmetic gain (Alternative 2).
- **Residual, explicit.** This is **design-only and unimplemented**; no primitive, no negotiation
  wire format, and no v3 vector set exists yet. The `SuiteID` freeze is untouched and out of scope.
  Everything remains **UNAUDITED** and pre-FTO. Renaming the tags does **not** change any security
  property — v2 and v3 are equally (un)audited; the migration is a _branding/versioning_ act carried
  out with wire-format discipline, not a security upgrade.

## Honesty / status note

This ADR is a **design-direction record**, not an implementation and not a security result. It
proposes _how_ the `polarseek-*` → `Nerion/*` tag-value rename would be done safely (as an additive,
selector-gated, negotiated v2→v3 generation with the frozen v2 KATs preserved and v3 KATs added) and
explicitly records that the rename is **cosmetic/branding**, carries **no security change**, and is
**not urgent** — the mixed naming is cryptographically sound today under the DS-REGISTRY-001 uniqueness
gate. No production, audited, FIPS, or non-infringement claim is made or implied. The ADR number 0042
is provisional pending cross-branch reconciliation. © TRELYAN.

## References

- `crypto/src/domains.ts` — DS-REGISTRY-001 central `DOMAIN_TAGS` registry (the single switch point);
  `crypto/test/domain-separation.test.ts` — the tag-uniqueness gate.
- The PolarSeek→Nerion rename: branding-only, phased; prose + package identity + DS-REGISTRY-001 module
  migration done; this tag-value bump is the remaining code-level step (deliberately deferred as a
  versioned protocol migration, not a find-replace).
- `conformance/vectors/ps-kat.json`, `conformance/vectors/ps-negative.json`,
  `crypto/vectors/deterministic-kat.json` — the frozen v2 KATs preserved byte-identical.
- `crypto/src/suites.ts` — the frozen `SuiteID` enum + `SUITE_IDS`; out of scope for this ADR
  (pinned separately by the suiteid-lock test).
- ADR-0018 — canonical `u64` amount domain + additive v:2 body; the `amount.domain` (`"u64"` →
  `"u64/pq"`) additive-versioning pattern this migration mirrors for tag generations.
- ADR-0013 — v:2 structural commitment-to-intent binding; the v:1→v:2 additive-versioning precedent.
- ADR-0029 — negotiation / downgrade-resistance; the path a v2/v3 generation is negotiated over.
