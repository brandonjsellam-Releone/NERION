<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0042 — Public-field allowlist + salted binding for the bound intent digest (closes CB-002)

**Status: ACCEPTED — implemented & tested on branch `apex/cb-002-commitbind-allowlist`
(`disclosure/src/commitbind.ts`, `disclosure/test/commitbind.test.ts`,
`disclosure/test/commitbind-cb001-surface.test.ts`); pending human merge to `main`.
Multi-model council review recorded in the "Council review" section below. The
construction is a salted SHA3 commitment in the classical ROM; UNAUDITED like the rest
of the disclosure layer — no formal soundness/hiding claim until external audit.**

Date: 2026-06-28. Direct response to **CB-002** from the ZK-soundness audit-prep dossier
([council/zk-audit-prep-2026-06-27.md](../council/zk-audit-prep-2026-06-27.md), section P6).
Builds on **ADR-0013** (`boundIntentDigest` structural commitment-binding) and **ADR-0014**
(salted/hiding v:1 intent commitment; off-leaf salt custody).

## Context

`boundIntentDigest(intent, commitment)` (`disclosure/src/commitbind.ts`) is a PUBLIC,
externally-recomputable receipt field that point-binds a Pedersen commitment to an intent.
Before this ADR it built its pre-image from a **denylist**:

```ts
// pre-ADR-0042 — denylist (excludes ONLY `amount`)
const skeleton = Object.fromEntries(Object.entries(intent).filter(([k]) => k !== 'amount'))
```

CB-001 (Team Apex audit, 2026-06-21) already removed `amount` from this pre-image: hashing a
low-entropy `amount` in plaintext would let anyone holding the public digest + the rest of the
skeleton brute-force it over its small enumerable domain. The amount is instead bound by the
(perfectly hiding) Pedersen commitment and re-checked in `verifyBoundAmount`.

**CB-002 (audit-prep dossier P6, raised as PRESENT, not hypothetical):** the denylist excludes
*only* `amount`. **Every other `ActionIntent` field is therefore hashed into the public digest
in plaintext** — including:

- **`counterparty`** — typed in `capabilities/src/types.ts:26-27` as an opaque reference
  *"never re-identified across calls"*, i.e. explicitly privacy-sensitive; and
- **arbitrary `params`** (`:30-31`).

If `counterparty` or any `params` value is **low-entropy / enumerable**, it is brute-forceable
from a **single** public digest *exactly as the amount was pre-CB-001*: the commitment is
public, the rest of the skeleton is public, so a holder enumerates the candidate and matches the
SHA3. (The random Pedersen commitment blinds *cross-call linkage* of a repeated counterparty,
but **not** single-receipt *recovery* of an enumerable value — these are different properties.)
This is a **present** exposure of the unaudited disclosure layer, not only a future-schema hazard.

A regression test now locks the excluded-field set
(`disclosure/test/commitbind-cb001-surface.test.ts`) so any change to it is conscious and
reconciled here.

### The design tension (why this needs an ADR, not a unilateral flip)

The dossier's recommendation — *invert the denylist to an allowlist of known-public fields* —
trades one risk for its inverse:

- **Secrecy risk (denylist).** A denylist hashes any *new or sensitive* field in plaintext by
  default → low-entropy fields are brute-forceable (the CB-002 finding).
- **Binding-completeness risk (naïve allowlist).** An allowlist that **drops** a field from the
  pre-image makes that field *invisible* to the digest: a malicious binder could vary the dropped
  field **without changing the digest**, so point-binding no longer covers it. Dropping a
  *legitimately-public* field (e.g. `counterparty`, which a receipt should attest the action
  targeted) silently weakens the receipt's integrity guarantee.

Either error is a real regression. So the partition of `ActionIntent` fields is a design decision
for an ADR + council, recorded here.

## Decision

Invert to an **allowlist**, but make the allowlist govern **encoding mode, not inclusion** — so
**no field is ever dropped** and binding-completeness is fully preserved:

1. **Allowlist of known-public fields — PLAINTEXT.**
   `PUBLIC_INTENT_FIELDS = {`type`, `resource`}`. These are the structural, non-privacy-sensitive
   identity of the action. They are hashed in plaintext: they **bind** and remain **publicly
   recomputable with no secret**.

2. **`amount` — OMITTED entirely (CB-001, unchanged).** Bound cryptographically by the Pedersen
   commitment; re-checked against `intent.amount` in `verifyBoundAmount`.

3. **Every OTHER non-`amount` field — SALTED commitment (the new part).** `counterparty`,
   `params`, **and any future field not in the allowlist** are folded into the pre-image as a
   high-entropy **salted commitment** over `{field, value}`, reusing the audited
   `selective.ts` `commitField(value, salt)` primitive (ADR-0014's salted-commit pattern). The
   field name domain-separates one field's commitment from another's.

```ts
// post-ADR-0042 — allowlist of *plaintext* fields; everything else salted, nothing dropped
for (const [k, v] of Object.entries(intent)) {
  if (k === 'amount') continue                       // CB-001: omitted (Pedersen-bound)
  if (PUBLIC_INTENT_FIELDS.includes(k)) out[k] = v   // plaintext: binding + public
  else {
    if (salt === undefined) throw new CommitBindError(/* fail-closed */)
    out[k] = commitField({ field: k, value: v }, salt) // salted: binding + hiding
  }
}
```

This resolves the tension instead of trading one risk for the other:

- **Secrecy (CB-002 closed).** No non-`amount` field is brute-forceable from the public digest:
  the salted fields are hidden behind a ≥256-bit salt kept off the public artifact. Strictly
  stronger than a drop-allowlist (which only protects the *dropped* fields and exposes everything
  it keeps).
- **Binding-completeness preserved.** Because salting *keeps* the field in the pre-image (vs.
  dropping it), **every** field still affects the digest — a malicious binder cannot vary
  `counterparty`/`params` without changing the digest. The inverse risk is avoided entirely.
- **Fail-closed by default for future fields.** Anything not explicitly allowlisted is salted
  automatically: a new *sensitive* field is protected without action, and a new field that should
  be *public* must be **consciously** added to `PUBLIC_INTENT_FIELDS` — a deliberate,
  council-reviewable act (a field placed there becomes brute-forceable if it is low-entropy).

4. **Fail-closed, never silent plaintext fallback.** If a non-public field is present and **no
   salt** is supplied, the builder **throws** `CommitBindError`. We never fall back to hashing a
   sensitive field in plaintext (that would re-open the CB-001/CB-002 surface).

5. **Salt custody (mirrors ADR-0014's `intentSalt`).** `bindAmountCommitment` mints a fresh
   32-byte CSPRNG salt **iff** the intent carries any non-public field, and returns it on
   `BoundAmount.salt`. The salt is a **disclosure secret**: it must be kept **off** any public
   artifact (signed body / log leaf) and revealed only to authorized verifiers, who pass it back
   to `verifyBoundCommitment` / `verifyBoundAmount` to recompute the digest. An intent confined to
   the public allowlist (+ amount) needs no salt.

### Backward compatibility — digest UNCHANGED for the current schema

For an intent whose fields are confined to the public allowlist plus the omitted `amount` (e.g.
`{type, resource, amount}`), the new pre-image is **byte-identical** to the pre-ADR-0042 one, so
the digest is unchanged. This is the schema used by the existing `commitbind.test.ts`, the
surface-lock test's public-only vectors, and conformance **C21** — all pass unmodified, and no
KAT references `boundIntentDigest`. The digest only changes for intents that actually carry
`counterparty`/`params`, which no existing frozen vector does.

This is **proven empirically**, not just argued: a pinned KAT
(`commitbind.test.ts`, "digest byte-stability KATs") reconstructs the pre-ADR-0042 denylist
algorithm inline and asserts the public-only digest equals it byte-for-byte
(`b4f316a7…46d42afc` for a deterministic `commit(500n, 7n)`), and a second KAT pins the salted
full-intent digest (`a2927de5…3c2f668a`) so any silent change to the reused `selective.ts`
`commitField` primitive or the dCBOR layer breaks a test instead of shifting a protocol digest.

### Version disambiguation — why the domain string is not bumped

The encoding *rule* changed for non-public fields (plaintext → salted commitment) without a bump
of the digest domain (`PolarSeek/disclosure/commit-bind/v2`). The council flagged the resulting
cross-version ambiguity (old vs new code compute different digests for a sensitive-field intent
under the same domain tag). This is acceptable here because `boundIntentDigest` is an **unwired
primitive** (per its docstring; wiring into the signed v:2 receipt body is a follow-up), so there
is **no persisted corpus** of old sensitive-field digests and no KAT pins one — there is nothing
to be ambiguous against. When the digest is wired into a receipt (ADR-0018 v:2), the receipt's
own `v: 2` tag and `amount.domain` field carry the version at the layer that actually persists and
transmits it. **If this digest is ever wired into a versioned artifact without such an outer tag,
the domain string MUST be bumped at that point.** Bumping it now is rejected because it would
change the public-only digest too and break the byte-identity / C21 invariant the task requires.
A lighter alternative (an encoding-mode marker added to the pre-image only when salted fields are
present, preserving public-only byte-identity) is recorded as the preferred mechanism should
standalone versioning become necessary.

### What stays unchanged on purpose

- **The domain string `PolarSeek/disclosure/commit-bind/v2` is NOT touched.** The dossier's
  cross-cutting finding flags the `PolarSeek→Nerion` domain-prefix rename as a protocol-frozen,
  version-bumping change (it feeds every digest) — explicitly out of scope here; this ADR is a
  privacy hardening, not a rename.
- **No conformance check is added/renumbered here.** Wiring a dedicated conformance vector
  (next free id) for the salted path is a follow-up, deliberately deferred to avoid colliding
  with concurrent sprints' conformance-count bookkeeping. Coverage is provided by the vitest
  suite (binding-preserved, fail-closed, salt round-trip, unlinkability, amount still omitted).

## Alternatives considered

1. **Keep the denylist, document the hazard — REJECTED.** Leaves a present, exploitable
   single-receipt recovery of low-entropy `counterparty`/`params`. This is the CB-002 finding.
2. **Naïve allowlist: DROP non-public fields from the pre-image — REJECTED.** Protects the
   dropped fields' secrecy but **weakens binding-completeness**: a malicious binder could vary a
   dropped field silently, and the receipt would no longer attest, e.g., which `counterparty` the
   action targeted. Trades the secrecy risk for the inverse binding risk.
3. **Allowlist + salt the non-public fields (CHOSEN).** Keeps every field in the pre-image
   (full binding-completeness) *and* hides the non-public ones (full secrecy). The only cost is
   that the digest is no longer recomputable by a party lacking the salt — but such a party could
   not safely recompute it before either, without enabling the brute-force this ADR closes. Salt
   custody is the established ADR-0014 model.
4. **Single per-binding salt folded once over the whole skeleton (à la ADR-0014's `intentSalt`)
   — VIABLE, NOT CHOSEN.** Would also hide all non-public fields with full binding. Per-field
   salted commitments were chosen instead because they keep the pre-image's `{key: value}` shape
   (so the public allowlist fields stay byte-identical to the legacy encoding) and lay the
   groundwork for field-granular disclosure. Both use one salt today; see #5.
5. **Per-field DISTINCT salts (field-granular disclosure) — DEFERRED.** A single salt makes
   disclosure all-or-nothing (revealing the salt recomputes every salted field), matching
   ADR-0014's deferred per-field-salt decision. Distinct salts would let an authorized verifier
   disclose `counterparty` without `params`; that is a selective-disclosure ergonomics upgrade,
   orthogonal to CB-002, and can layer on later.
6. **Encrypt the sensitive fields to authorized verifiers — REJECTED.** Heavier key-management /
   confidentiality trust model; the digest only needs a *hiding commitment*, which a salted hash
   provides without new key material (same rationale as ADR-0014).
7. **Move `resource` into the salted set too — NOT NOW.** `resource` is "opaque" and *could* be
   sensitive in some deployments, but the existing design, tests, and KAT-adjacent vectors treat
   it as public-binding, and salting it would change the current-schema digest. If a deployment
   deems `resource` privacy-sensitive, moving it is a conscious, version-bumping change (it alters
   public digests) — recorded here as the place to revisit.
8. **Pedersen-commit (or HMAC) every field instead of salted SHA3 — REJECTED for now.** A Pedersen
   commitment per field would give information-theoretic hiding but is algebraic, heavier, changes
   the digest shape, and expands the audit surface; an HMAC needs a managed key rather than a
   per-binding salt. The salted SHA3 commitment reuses an already-present primitive and keeps the
   audit surface minimal (same de-risking rationale as ADR-0013 / ADR-0014). Recorded as a
   forward option if a deployment needs info-theoretic field hiding.
9. **Fail-OPEN (log a warning, hash plaintext) when the salt is missing — REJECTED.** That is
   exactly the CB-001/CB-002 exposure; a missing salt MUST be a hard failure. Availability of the
   salt is an integration responsibility (mint per-binding; the binder already does so), not a
   reason to weaken the digest. The fail-closed check is enforced in `buildBoundSkeleton`, so it
   applies to **every** path (`boundIntentDigest`, `verifyBound*`, `bindAmountCommitment`), not
   just one entry point.

## Consequences

- **API (additive, backward-compatible).** `boundIntentDigest` / `boundIntentDigestHex` /
  `verifyBoundCommitment` / `verifyBoundAmount` gain a trailing optional `salt?: Bytes` parameter
  (same idiom as `selective.commitField`). `bindAmountCommitment` gains an optional `salt?` and
  returns `BoundAmount.salt?`. New exports: `PUBLIC_INTENT_FIELDS`, `hasSaltedFields`. Existing
  call sites (conformance C21, library callers) that pass no salt and use public-only intents are
  unaffected.
- **Operational obligation (carried from P6's second item).** The salt is a *caller*
  responsibility: integrators MUST mint ≥128-bit (we mint 256-bit) entropy and keep it off the
  signed body / log leaf. When `boundIntentDigest` is wired into a v:2 receipt, the salt rides the
  receipt wrapper off-leaf exactly like `intentSalt` (ADR-0014). This ADR enforces *fail-closed if
  the salt is missing*, but cannot enforce *off-leaf custody* — that remains an integration-point
  audit item.
- **No v:1 / KAT regression.** Current-schema digests are byte-identical; no frozen vector
  references this digest; `npm run gate` is green.
- **Unlinkability.** A fresh per-binding salt means two bindings of the same sensitive intent
  produce different digests — removing a correlation channel, at the cost that the salt must be
  unique per binding (enforced by always minting fresh CSPRNG bytes).
- **Follow-ups (deferred, recorded so they are not lost):** (i) wire the digest + the off-leaf salt
  into the v:2 receipt body (ADR-0018) with the salt carried like `intentSalt`; (ii) per-field
  HKDF sub-salts + field-granular selective disclosure (alt #5 / council blast-radius point);
  (iii) a dedicated conformance vector for the salted path (next free id), deferred here to avoid
  colliding with concurrent sprints' conformance-count bookkeeping; (iv) reconcile the legacy
  `PolarSeek/…` domain prefix at the protocol-wide rename (separate version-bump, dossier
  cross-cutting finding).

## Trust model / limits (honest)

The council pressed on conflating *binding* with *hiding*; they rest on **different** assumptions
and must be stated separately:

- **Binding-completeness rests on SHA3 collision-resistance + canonical encoding + exhaustive
  field traversal — NOT on salt secrecy.** Even an adversary who *knows* the salt cannot vary a
  salted field without changing its `commitField` output (absent a SHA3 collision), so a malicious
  binder still cannot vary `counterparty`/`params` undetected. It is contingent on: (i) SHA3
  collision-resistance; (ii) `encodeCanonical` (dCBOR) being injective and type-distinct
  (`"1"` ≠ `1` ≠ `1.0` — distinct CBOR major types, relied upon); (iii) the builder traversing
  *every* present field (it iterates `Object.entries`, default-salting anything outside the small
  public allowlist, so a future/unknown field is covered, never silently dropped); and (iv) for
  the *amount*, the separate opening check in `verifyBoundAmount` (the public digest deliberately
  does not bind the amount — CB-001 — so `verifyBoundCommitment` is point-binding only, by design).
- **Hiding (secrecy) of the salted fields is computational (ROM) and DOES depend on salt secrecy +
  256-bit entropy** — **not** information-theoretic, and **not** the PQ/info-theoretic hiding of
  the Pedersen amount commitment. If the salt leaks to an unauthorized party, the salted low-entropy
  fields become brute-forceable again. So "secrecy fixed" is precisely "secrecy holds **while the
  salt remains secret and off the public artifact**."
- **Salt blast radius (council).** One per-binding salt covers all of that binding's salted fields,
  so revealing it (the disclosure act) opens them all — disclosure is all-or-nothing. Per-field
  salt *derivation* (`salt_k = HKDF(master_salt, field_name)`) does **not** reduce blast radius on
  its own: revealing the master salt also reveals every derived sub-salt. It only helps **together
  with field-granular disclosure** (revealing sub-salts individually), which is the deferred
  upgrade below; until then the single-salt model matches ADR-0014's accepted custody.
- **`resource` is hashed in PLAINTEXT and is therefore NOT private — "opaque" ≠ "private"
  (council).** A low-entropy `resource` (e.g. a pool id, SKU, service identifier) is brute-forceable
  from the public digest exactly like `counterparty` was. It is in the public allowlist because the
  current design/tests/vectors treat it as the action's recomputable structural identity and
  because salting it would change the current-schema digest. A deployment that deems `resource`
  privacy-sensitive MUST move it to the salted set — a conscious, digest-changing (version-bumping)
  act (see alternative #7).
- **No defense against a malicious binder is added or needed here.** The binder authors the
  intent and the salt and gains nothing by manipulating its own salt. Issuer-honesty at admission
  remains the quorum / attestation model's job (unchanged, per ADR-0013).
- **Personal-data classification is a deployment/DPIA concern, not decided here (council).** Whether
  `counterparty` is "personal data" (and thus which fields must be salted/minimised) depends on the
  deployment; this ADR makes the *mechanism* available and fail-closed, not the policy.
- **This is a privacy hardening, not a soundness change.** It does not touch the range-proof
  soundness (classical / discrete-log, UNAUDITED) or the QROM question. The Pedersen commitment and
  ristretto255 are **classical** discrete-log, not post-quantum.
- **UNAUDITED.** Like the rest of `disclosure/`, this is an internal-review-level construction;
  the external ROS / ToB audit still applies. This ADR records a *design + implementation
  decision*, not a security result.

## Council review

Multi-model Team Apex review of this decision + the implementation is recorded in
[council/cb-002-commitbind-allowlist-2026-06-28.md](../council/cb-002-commitbind-allowlist-2026-06-28.md).
Summary of verdicts and how each material point was resolved is appended to that file and
reflected in the sections above.

## References

- `docs/council/zk-audit-prep-2026-06-27.md` — ZK-soundness audit-prep dossier, P6 (CB-002).
- ADR-0013 — v:2 commitment-to-intent structural binding (`boundIntentDigest`, `verifyBoundAmount`).
- ADR-0014 — Salted / hiding v:1 intent commitment (off-leaf salt custody; salted-commit primitive).
- ADR-0018 — Canonical amount domain + additive v:2 receipt body (where this digest is wired).
- `disclosure/src/commitbind.ts` — `boundIntentDigest`, `PUBLIC_INTENT_FIELDS`, `hasSaltedFields`,
  `bindAmountCommitment` (allowlist + salted binding implemented here).
- `disclosure/src/selective.ts` — `commitField(value, salt?)` salted-commit primitive reused here.
- `disclosure/test/commitbind-cb001-surface.test.ts` — CB-001/CB-002 exposure-surface lock.
- `capabilities/src/types.ts:21-32` — `ActionIntent` (`counterparty` "never re-identified", `params`).
