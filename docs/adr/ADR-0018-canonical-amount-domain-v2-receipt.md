<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0018 — Canonical amount domain + v:2 commitment-binding receipt body (proposed)

**Status: PROPOSED — DESIGN ONLY, UNIMPLEMENTED.** This ADR specifies a design to be
*built and externally audited*; it is **not** a security result and makes **no** claim of
soundness, correctness, or completeness until implemented and reviewed. The cryptographic
parts route to the **external ZK / crypto audit** (ROS / ToB — see `docs/STATUS.md`,
ADR-0006, ADR-0013). Nothing here changes code, behavior, or any frozen KAT vector; it is
the funded grant R&D plan (milestones **M3 / M4**), recorded so the implementation and the
audit have one agreed target.

Date: 2026-06-21. Builds directly on **ADR-0013** (structural commitment-binding, replacing
the heavy ZK equality circuit) and **ADR-0014** (salted/hiding v:1 intent commitment), and
on the linkage contract documented in `disclosure/src/policyproof.ts` /
`disclosure/src/commitbind.ts`.

## Context

Nerion (formerly PolarSeek) represents an action's monetary magnitude — "the amount" — in
**three different numeric domains** that were grown independently and never reconciled. This
is a latent soundness hazard, not just an ergonomics wart, because the amount is the value a
v:2 Policy-Satisfaction Proof (PSP) is supposed to be *about*. The three domains today:

1. **Intent / capability / kernel domain — JS `number`, integer minor units.**
   - `ActionIntent.amount?: number` (`capabilities/src/types.ts`): "Optional integer amount
     (minor units). Integers only — no float nondeterminism."
   - `CapabilityGrant.perActionCeiling: number | null`, `aggregateCap: number | null`
     (same file).
   - `KernelInput.observedAggregate: number` (`kernel/src/types.ts`).
   - The admission predicate (`capabilities/src/grant.ts` `authorizesIntent`) gates on
     `Number.isSafeInteger(intent.amount) && intent.amount >= 0` and likewise for
     `observedAggregate` (PS-CAP-01 / PS-CAP-02), then compares `amount > perActionCeiling`
     and `observedAggregate + amount > aggregateCap` in **JS number arithmetic**.
   - So the *effective* admitted domain is **non-negative safe integers**: `[0, 2^53 − 1]`,
     i.e. `≤ Number.MAX_SAFE_INTEGER`. Anything outside is already rejected fail-closed.

2. **Disclosure / ZK domain — `bigint`, range-limited by the proof width.**
   - `PolicyBounds.perActionCeiling: bigint`, `aggregate?: bigint`, `aggregateCap?: bigint`,
     `n?: number` (`disclosure/src/policyproof.ts`).
   - `commitAmount(amount: bigint)`, `commit(value: bigint, r: bigint)` over ristretto255
     (`disclosure/src/zkrange.ts`).
   - The range proof proves `amount ∈ [0, 2^n)` (default `n = 32`) and the verifier enforces
     a **hard cap `n ≤ 251`** so `2^(n+1) ≤ L` (ZKRANGE-001 / ZKRANGE-002 in `zkrange.ts`),
     where `L` is the ristretto255 scalar-field order ≈ `2^252 + 2^124.7`. Above that, a
     negative `diff` wraps mod `L` and a false claim verifies.

3. **Binding domain — `bigint`, derived from (1).**
   - `commitbind.ts` `intentAmount(intent)` reads `intent.amount` (a `number`), asserts
     `Number.isSafeInteger(a) && a >= 0`, and returns `BigInt(a)`. So the bridge from (1) to
     (2) already exists and already enforces the safe-integer floor/ceiling — but only inside
     the disclosure layer, and only when someone calls it.

**The unresolved tensions:**

- **(T1) Two incompatible *upper* limits.** The kernel admits up to `2^53 − 1`. The default
  ZK width admits up to `2^32 − 1`, and the *maximum* width admits up to `2^251 − 1`. So
  there exist amounts the kernel will admit (`> 2^53`? no — those are rejected; but `2^32 ≤
  amount < 2^53`) that a **default-width** PSP **cannot prove** (proving throws), and
  conversely a wider PSP can prove amounts (`2^53 ≤ a < 2^251`) the **kernel would never
  admit**. The proof's range and the admission gate's range are not the same interval. A
  PSP that "verifies" only certifies `amount < ceiling AND amount ∈ [0, 2^n)` — it does
  **not** certify `amount ≤ MAX_SAFE_INTEGER`, which is the kernel's real domain.

- **(T2) `number` vs `bigint` mismatch is silent at the boundary.** `perActionCeiling` is a
  `number` in the grant but a `bigint` in `PolicyBounds`. Today the conversion is manual and
  ad hoc (the caller writes `BigInt(grant.perActionCeiling!)`). A ceiling near `2^53` round-
  trips fine; nothing enforces that the `bigint` bounds the PSP is given are the *same*
  numbers the kernel compared against. This is the **same class** of "two unlinked amount
  representations" that ADR-0013 closes for the *commitment* — but for the *bounds*.

- **(T3) The committed-amount binding is implemented but not *admitted-against*.** ADR-0013 +
  `commitbind.ts` give us a primitive that binds a Pedersen commitment `C` to an intent
  skeleton and (with the opening) checks `C = commit(intent.amount, r)`. But **the admission
  kernel never calls it.** `kernel/src/kernel.ts` `decide()` returns a `Decision` and reads
  `intent.amount` purely as a `number` through `authorizesIntent`; it never sees `C`, never
  checks `C` opens to the amount it admitted, and the receipt builder (`receipts/src/
  receipt.ts`, `ReceiptBody.v: 1`) has no field to carry `C`. So the malicious-issuer gap
  ("two unlinked amount commitments") is closed *as a library primitive* but **open as a
  protocol**: nothing in the admit→receipt path forces the `C` that ends up in a future v:2
  receipt to be the `C` the kernel checked against the admitted amount.

- **(T4) v:1 `ReceiptBody` is frozen and carries no `C`.** `ReceiptBody` is `v: 1` with a
  fixed `commitments` shape (`intent`, `capability`, `policy`, `inputHash`, `decisionHash`),
  all SHA3 hex strings; ADR-0014's salt rides on the `Receipt` wrapper, off-leaf. The v:1
  body is pinned by signatures, by the transparency-log leaf bytes
  (`receiptLeaf = encodeCanonical(body)`), and by conformance C23 (and adjacent KATs). We
  **must not** mutate it. A v:2 must be **purely additive and version-tagged**.

This ADR reconciles (T1)–(T4): it fixes **one** canonical amount domain end-to-end, adds the
**kernel-admission binding check** that ties the admitted amount to `C`, and specifies an
**additive v:2 `ReceiptBody`** that carries `C` and the PSP binding without touching v:1.

## Decision

### (a) ONE canonical amount type/domain end-to-end: `u64` minor units, range-gated

Adopt a single canonical amount domain for the *whole* protocol:

> **Amount ∈ `[0, 2^64 − 1]`, non-negative integers, in minor currency units, carried as an
> opaque decimal string `amount_str` on the wire / in canonical encodings, and materialized
> as `bigint` everywhere arithmetic or commitment happens.**

Rationale and how it resolves the tensions:

- **Why `u64`, not "JS `number` ≤ 2^53" and not "arbitrary `2^n` bigint".** `2^53 − 1`
  (`Number.MAX_SAFE_INTEGER`) is an artifact of JS `number`, not a domain we *want* — it
  cannot represent, e.g., 10^16 minor units (large-notional or low-denomination currencies),
  and it leaks the reference language into the protocol spec. Unbounded bigint, at the other
  extreme, collides with the ZK width cap (`n ≤ 251`) and offers no natural serialization or
  interop target. **`u64`** is the smallest *principled, language-neutral* domain that (i)
  comfortably exceeds every realistic minor-unit amount, (ii) maps to a single, ubiquitous
  fixed-width integer type in Rust / Go / C and to `bigint` in TS, and (iii) sits **far below
  the ZK hard cap** (`64 ≪ 251`), so the default proof width need only be `n = 64` and the
  whole admitted domain is always provable. It is the explicit "u64 with an explicit range
  gate" option called out in the task framing, chosen for exactly these reasons.

- **Explicit range gate (the single chokepoint).** Introduce one canonical validator,
  conceptually `parseAmount(x): bigint`, that accepts an `amount_str` (or a `number`/`bigint`
  at internal call sites) and **fails closed** unless `0 ≤ x ≤ 2^64 − 1` and `x` is an exact
  integer. This **supersedes** the scattered `Number.isSafeInteger` checks: the kernel, the
  capability resolver, `commitbind.intentAmount`, and `policyproof` all route through it, so
  there is exactly one definition of "a valid amount." `Number.isSafeInteger` stays as a
  *defense-in-depth* guard at the JS boundary (it is strictly *narrower* than `u64`, so it
  can only reject, never wrongly admit), but the *protocol* domain is `u64`.

  > Honesty note: because the v:1 wire type is a JS `number`, a v:1-only deployment **cannot**
  > faithfully represent `2^53 ≤ amount < 2^64`. The canonical `u64` domain is reachable in
  > full **only on the v:2 path**, where the amount travels as `amount_str` (string) and is
  > parsed to `bigint` — never through a lossy `number`. v:1 remains capped at
  > `MAX_SAFE_INTEGER` by its own type; v:2 lifts the cap to `u64`. This is stated so the
  > audit does not mistake the design intent for a claim that v:1 already supports `u64`.

- **Bounds travel with the amount (closes T2).** `perActionCeiling` / `aggregateCap` /
  `observedAggregate` are all amounts and **all** adopt the same canonical domain and the same
  `parseAmount` gate. The v:2 PSP `PolicyBounds` are derived from the *kernel-admitted* grant
  ceilings by the **same** parse, and the v:2 receipt records the explicit numeric bounds
  (already done by `policyProofDigest`, which binds `perActionCeiling` / `aggregateCap` /
  `aggregate` / `n`). So "the bounds the proof used" and "the bounds the kernel compared
  against" are the same canonical integers, bound into the signed body.

- **ZK width pinned to the domain (closes T1).** Fix the v:2 default proof width at
  **`n = 64`** so the proof's range `[0, 2^64)` **equals** the canonical amount domain.
  Because `aggregate + amount` can reach `≈ 2^65`, the *aggregate* clause must prove over a
  slightly wider `n` (e.g. `n = 66`, still `≪ 251`) — this is a concrete item for the audit
  to confirm (the sum must not exceed `2^n` for the chosen aggregate width). With `n = 64`,
  *every* kernel-admissible amount is provable and *no* provable amount exceeds the admitted
  domain: the proof interval and the admission interval coincide.

### (b) Kernel-admission check that the committed `C` binds the admitted amount (closes T3)

Today `decide()` is a pure decision over `number` inputs and emits no commitment. The v:2
design adds an **optional, additive admission obligation** that runs *only* when the caller
supplies a commitment (so v:1 admission is byte-identical and the kernel stays pure — see
below):

1. **Input (additive, optional).** Extend the admission path with an optional
   `amountCommitment?: { C: Pt; opening: bigint }` alongside `KernelInput`. When present and
   the intent carries an amount, the kernel performs the binding check; when absent, behavior
   is exactly v:1.

2. **The binding check (reuse, don't reinvent).** At admission, with the plaintext amount and
   the opening in hand, the kernel calls the **existing** `commitbind.verifyBoundAmount`-style
   check: recompute `expected = commit(parseAmount(intent.amount), opening)` and require
   `constantTimeEqual(expected.toBytes(), C.toBytes())`. This is the **full opening check**
   already implemented in `commitbind.ts` (the `verifyBoundAmount` path), promoted from a
   library call to an **admission precondition**. If it fails, `decide()` returns
   `effect: 'deny'` with reason `amount-commitment does not open to the admitted amount`
   (fail-closed, consistent with the kernel's safe-fallback discipline).

3. **The structural binding to the intent (ADR-0013, unchanged).** The `C` the kernel checks
   is the **same** `C` that ADR-0013 hashes into the bound intent digest
   (`boundIntentDigest(intent, C)`), so a malicious issuer cannot later swap a different `C'`
   into the receipt without changing the digest the kernel/receipt commits to. ADR-0013
   already establishes the *point*-binding (`C ↔ intent`); this ADR adds the missing *value*-
   binding **at admission** (`C` opens to the amount the kernel actually compared against the
   ceiling). Together they close the "two unlinked amount commitments" gap as a **protocol**,
   not just a primitive:

   - **intent ↔ admitted amount:** the kernel compared `parseAmount(intent.amount)` against
     `perActionCeiling` / `aggregateCap` (existing `authorizesIntent`).
   - **admitted amount ↔ `C`:** the new admission check (`C = commit(parseAmount(intent.
     amount), opening)`).
   - **`C` ↔ intent (structural):** ADR-0013's `boundIntentDigest(intent, C)`.
   - **everything ↔ signed receipt:** the v:2 body carries `C` and the bound digest under the
     ML-DSA-87 signature + the transparency-log leaf (below).

   So the only `C` that can appear in a valid, signed, logged v:2 receipt is one that opens
   to the very amount the kernel admitted. The malicious issuer can no longer present an
   in-bounds `C` divorced from the intent's stated amount.

4. **Purity is preserved.** The check is a **pure function of explicit inputs** (`intent`,
   the supplied `C`/`opening`) — no clock, no I/O, no state — so the kernel's core properties
   (deterministic, default-deny, holds no state) are unchanged. The commitment/opening enter
   as **data**, exactly as `observedAggregate` and `revoked` already do (the same pattern the
   kernel uses to stay pure while consuming externally-computed values). The kernel does **not**
   mint randomness; the opening is supplied by the issuer/binder, matching `commitbind.ts`'s
   trust model (the binder holds plaintext amount + blinding).

   > Trust-model honesty (carried from ADR-0013 / ADR-0014): this binds the admitted amount
   > to `C`; it does **not** defend against a kernel/binder that is itself malicious at
   > admission. That remains the decentralized-quorum / attestation model's job. This check
   > removes the *issuer-substitution* attack, not the *corrupt-admitter* attack.

### (c) Additive, version-tagged v:2 `ReceiptBody` (closes T4 — does NOT touch v:1)

Introduce a **`v: 2`** receipt body as a **discriminated union** with v:1 on the `v` tag.
v:1 bodies, their bytes, their signatures, and their KATs are **untouched**; a v:2 body is a
*superset* gated entirely behind `v === 2`:

```
ReceiptBody = ReceiptBodyV1 | ReceiptBodyV2     // discriminated on `v`

ReceiptBodyV2 = {
  v: 2,
  // ── all v:1 fields, unchanged in name, type, and canonical order ──
  suite, evaluatorVersion, effect, tier, jurisdiction, timestamp,
  commitments: {                       // v:1 commitments, unchanged
    intent, capability, policy, inputHash, decisionHash,
  },
  // ── ADDITIVE v:2 block (absent ⇒ this is a v:1 body) ──
  amount: {
    domain: "u64",                     // pins the canonical domain into the signed body
    commitment: <hex compressed ristretto255 C>,     // the bound Pedersen C
    boundDigest: <hex SHA3-256 boundIntentDigest(intent, C)>,  // ADR-0013 link
    psr: <hex policyProofDigest(...)>, // ADR-0006 PSP binding digest (already specified)
    n: 64,                             // proof width = canonical domain width
  },
}
```

Design rules (each is a hard constraint for the implementer + auditor):

- **Additive only.** Every v:1 field keeps its exact name, type, and position in the
  canonical dCBOR map; the v:2 `amount` block is a **new top-level key**. A v:1 verifier that
  has never heard of v:2 still verifies a v:1 body bit-for-bit. The discriminant `v` (already
  present and signed) is the version gate.

- **`v:1` KATs/leaves are immutable.** Because v:2 is a new `v` value, *no existing v:1 leaf
  changes* — the v:1 transparency-log leaf bytes, signatures, and the frozen
  `conformance/vectors/ps-kat.json` dCBOR/sig vectors are byte-identical. New **v:2** vectors
  are *added*, never substituted (KAT plan below).

- **What's in the leaf vs off-leaf.** Following ADR-0014, only commitments/digests go in the
  signed body (the leaf). The Pedersen `C` (compressed point) and the binding digest are
  *binding, hiding* values — safe to log (the amount is information-theoretically hidden by
  `C` and excluded from `boundDigest`'s preimage per CB-001). The **opening `r`** and the
  **full `PolicySatisfactionProof`** are **NOT** in the leaf: `psr` carries only the
  `policyProofDigest`, exactly as ADR-0006 already specifies, so the heavy proof object rides
  off-leaf and is fetched/verified out of band. The salt (ADR-0014) stays on the `Receipt`
  wrapper, off-leaf, unchanged.

- **The `psr` field already has a home.** `policyProofDigest(commitment, bounds, proof,
  policyBinding)` (in `policyproof.ts`) already returns the exact value "a v:2 receipt carries
  in `commitments.psr`." This ADR simply *places* it (and `C`, `boundDigest`, `domain`, `n`)
  in the additive `amount` block and binds the whole thing under the signature. No new crypto
  primitive is introduced — this is wiring + a schema-version bump, consistent with ADR-0013's
  de-risking decision (schema change + reuse existing openings, not a new SNARK).

- **Verification.** v:2 external verification = v:1 verification (signature + leaf↔body +
  Merkle inclusion, all on `body`) **plus** the optional amount-block checks for a verifier
  that wants them: recompute `boundIntentDigest(disclosedIntent, C)` and match `boundDigest`;
  recompute `policyProofDigest(...)` from the off-leaf proof and match `psr`; run
  `verifyPolicySatisfaction(C, bounds, proof)`. A privacy verifier does all of this **without
  the amount or the opening**. A v:1 verifier ignores the block entirely.

## Soundness / security argument (claims to be PROVEN by audit, not asserted here)

This section states what the design is *intended* to guarantee and, explicitly, what it does
**not** yet establish. **None of these is proven; all route to external audit.**

- **Intended end-to-end binding (the malicious-issuer chain).** *If* (i) the kernel's
  admission check `C = commit(parseAmount(intent.amount), opening)` is exact and constant-
  time, (ii) ADR-0013's `boundIntentDigest` is collision-resistant binding of `C` to the
  intent skeleton, (iii) the v:2 body binds `C`, `boundDigest`, and `psr` under ML-DSA-87 and
  the RFC 6962 log, *then* a valid logged v:2 receipt's `C` opens to exactly the amount the
  kernel admitted, and the PSP attests a property of *that* amount. The "two unlinked
  commitments" gap is closed **conditional on (i)–(iii)**. Each conjunct is an audit
  obligation.

- **Amount confidentiality (carried, not newly claimed).** `C` is a Pedersen commitment:
  *perfectly hiding* (information-theoretic, PQ) for the amount's **secrecy** — no adversary,
  incl. quantum, recovers the amount from `C` or the logged leaf. This is unchanged from
  ADR-0006 and is the one property the project treats as strong. `boundDigest` excludes the
  amount from its preimage (CB-001), so it adds no leak.

- **Proof soundness is CLASSICAL and UNAUDITED.** The PSP's *soundness/binding* rests on
  discrete-log over ristretto255 — **classical**. A future quantum adversary could **forge** a
  satisfaction proof for an out-of-bounds amount (ADR-0006). Pinning `n = 64` to the `u64`
  domain removes the *width-mismatch* unsoundness (T1) but does **not** make the proof PQ-
  sound. The forward path (PQ commitment scheme) is noted in `docs/STATUS.md` and is out of
  scope here.

- **Residual assumptions, explicit:**
  - **ROM, not QROM.** The Fiat–Shamir PSP's zero-knowledge is argued in the **classical
    random-oracle model**; it is **NOT** analyzed in the **QROM**. "The proof reveals nothing
    to a *quantum* verifier" is **UNPROVEN** (per `policyproof.ts`).
  - **Range-cap correctness.** `n = 64` (and the wider aggregate width) must satisfy the
    `zkrange` cap `2^(n+1) ≤ L`; trivially true here (`66 ≪ 251`), but the *aggregate sum not
    exceeding `2^n`* obligation must be checked by the auditor.
  - **Canonicalization.** Compressed ristretto255 encoding of `C`, dCBOR canonical ordering
    of the new `amount` block, and exact public-input binding of `C` / bounds into `psr` must
    be confirmed byte-exact.
  - **Constant-time admission check.** The kernel's new equality check must be constant-time
    (`constantTimeEqual` on point bytes) to avoid a timing oracle on `C`.
  - **No new primitive.** By construction this introduces *no* new cryptographic primitive
    (reuses Pedersen openings, the existing range proof, SHA3 binding, ML-DSA-87, RFC 6962) —
    deliberately, to keep the audit surface minimal (ADR-0013 rationale).

## Implementation plan (what would change, behind which flags)

All behind a **v:2 feature gate** (`RECEIPT_V2` capability flag / build feature). v:1 default
unchanged.

1. **`amount` canonical type (new, additive).** A `crypto/`- or `capabilities/`-level
   `parseAmount(x): bigint` with the `u64` range gate; an `AMOUNT_MAX = 2n ** 64n - 1n`
   constant. No existing signature changes; callers opt in.
2. **`capabilities/grant.ts`.** Leave `authorizesIntent` numeric guards as defense-in-depth;
   on the v:2 path, route the comparison through `parseAmount` so ceilings/aggregates use the
   canonical domain. (v:1 numeric behavior preserved.)
3. **`commitbind.ts`.** `intentAmount` already returns `bigint` with a safe-integer guard;
   on v:2 it widens to the `u64` gate (still rejecting `> 2^64−1`). `verifyBoundAmount`
   reused verbatim as the kernel's admission check.
4. **`kernel/kernel.ts` + `kernel/types.ts`.** Add optional `amountCommitment?: { C, opening }`
   to the admission input; when present, perform the binding check and deny fail-closed on
   mismatch. Pure, additive; absent ⇒ identical to v:1.
5. **`receipts/receipt.ts`.** Add `ReceiptBodyV2` (discriminated on `v: 2`) with the additive
   `amount` block; `buildReceipt` gains an optional v:2 path that, given `C` / `boundDigest` /
   `psr` / `n`, emits a v:2 body. v:1 builder path untouched. `receiptLeaf` /
   `verifyReceipt` / `verifyReceiptInclusion` operate on `body` and need no change (they
   canonical-encode whatever body they're given); add v:2-aware amount-block verification as
   *new* functions, not edits to v:1 paths.
6. **`policyproof.ts`.** No change to the crypto; `policyProofDigest` is already the `psr`
   value. Possibly add a thin `buildV2Amount(intent, bounds, proof, opening)` helper that
   assembles the `amount` block.

**Flags:** `RECEIPT_V2` (off by default) gates the new body, the kernel input field, and the
amount-block verification. With the flag off, the code path, the emitted bytes, and the KATs
are exactly today's.

## KAT / conformance-regen plan (v:1 frozen, v:2 added)

- **v:1 KATs are NOT regenerated.** `conformance/vectors/ps-kat.json` (hash / MAC / AEAD /
  sig / dCBOR vectors, version `PS-KAT-1`) and the v:1 receipt leaves stay **byte-identical**.
  The v:2 body is a new `v` value, so no existing leaf or dCBOR vector changes. `kat.test.ts`
  continues to pass unmodified.
- **New v:2 vectors are ADDED** under a new vector-set version (e.g. `PS-KAT-2`) or a new
  `v2:` section: a frozen `(intent, C, opening, bounds, proof)` tuple with the expected
  `boundDigest`, `psr`, canonical v:2 body bytes, and a deterministic ML-DSA-87 signature
  (seed-pinned, as the existing sig KATs are). These are *additive* fixtures.
- **New conformance check `C24`** (next free id after C23): asserts (1) the kernel **denies**
  when `C` does **not** open to the admitted amount (malicious-substitution at admission);
  (2) the kernel **admits** and the v:2 body carries the matching `C` / `boundDigest` / `psr`
  when it does; (3) a v:1 verifier verifies the v:2 body's v:1 fields unchanged; (4) a
  privacy verifier validates the amount block **without** the amount/opening; (5) `n = 64`
  spans the full `u64` domain (`amount = 2^64 − 1` is provable; `amount = 2^64` is rejected by
  `parseAmount`). C24 is **additive** to the suite (C1–C23 unchanged).
- **Re-verification:** run the full conformance + KAT suite with `RECEIPT_V2` off (must be
  byte-identical to today) and on (C24 + new v:2 KATs pass). The grant milestone is met only
  when both hold and the external audit has reviewed the binding argument.

## Alternatives considered

1. **Keep three domains, document the gap — REJECTED.** Leaves T1 (width mismatch) as a live
   unsoundness in any future v:2 PSP and T3 (no admission binding) unfixed. The whole point of
   the funded R&D is to close these.
2. **Canonical domain = "JS safe integer ≤ 2^53" — REJECTED.** Encodes a reference-language
   artifact into the protocol, cannot represent realistic large minor-unit amounts, and still
   mismatches the ZK width. `u64` is the language-neutral superset.
3. **Canonical domain = unbounded bigint with per-proof `n` — REJECTED.** Collides with the
   `zkrange` hard cap (`n ≤ 251`), reintroduces a variable-width mismatch, and has no natural
   interop/serialization target. A fixed `u64` with `n = 64` makes the proof interval *equal*
   the domain.
4. **Mutate v:1 `ReceiptBody` to add `C` in place — REJECTED.** Breaks v:1 signatures, the
   transparency-log leaf bytes, and the frozen KATs / C23. A version-tagged additive v:2 is
   mandatory.
5. **Carry the full `PolicySatisfactionProof` in the leaf — REJECTED.** Bloats the log leaf
   and gains nothing: `policyProofDigest` already binds the proof; the heavy object rides
   off-leaf (ADR-0006).
6. **Re-derive bounds independently in the disclosure layer — REJECTED.** That is exactly the
   T2 unlinkage; v:2 binds the *kernel-admitted* bounds into the signed body via the existing
   `policyProofDigest` bounds binding.

## Consequences

- **Closes T1–T4 *by design*** (pending audit): one canonical `u64` amount domain end-to-end;
  proof width pinned to the domain; an admission-time check that `C` opens to the admitted
  amount; an additive, version-tagged v:2 body carrying `C` / `boundDigest` / `psr`. The
  malicious-issuer "two unlinked commitments" attack is closed as a **protocol**, not just a
  library primitive.
- **No v:1 regression, no KAT churn.** Everything is gated behind `RECEIPT_V2`; with the flag
  off, bytes and vectors are identical. v:2 vectors and C24 are purely additive.
- **No new cryptographic primitive, minimal audit surface** (reuses Pedersen openings, the
  existing range proof, SHA3 binding, ML-DSA-87, RFC 6962) — consistent with ADR-0013's
  de-risking.
- **Residual, explicitly UNPROVEN:** proof *soundness* stays **classical** (discrete-log) and
  **UNAUDITED**; zero-knowledge is **ROM-only, not QROM**; the binding chain holds **only if**
  each conjunct (admission check exactness/constant-time, ADR-0013 binding, signature/log
  binding) is sound — all audit obligations. Structural binding does **not** defend against a
  malicious *admitter* (quorum/attestation model's job, unchanged).
- **Forward compatibility.** The `amount.domain: "u64"` tag in the signed body lets a future
  PQ-commitment migration (STATUS.md forward upgrade) introduce, e.g., `domain: "u64/pq"`
  without another schema break.

## Honesty / status note

This ADR is a **design decision record for funded R&D (M3 / M4), to be implemented and
externally audited** — **not** a security result. The construction is **unimplemented** and
**unaudited**. No production-privacy, soundness, non-infringement, "audited," "production-
ready," or FIPS claim is made or implied. The amount's **confidentiality** under Pedersen is
information-theoretic/PQ; the PSP's **soundness** is classical and unestablished; the zero-
knowledge is ROM-only and **not** QROM-analyzed. All residual assumptions above are open until
the external ZK / crypto audit closes them.

## References

- ADR-0006 — Zero-Knowledge Policy-Satisfaction Receipts (the PSP; `psr` / `policyProofDigest`).
- ADR-0013 — v:2 commitment-to-intent structural binding (replaced the heavy ZK equality
  circuit; `boundIntentDigest`, `verifyBoundAmount`).
- ADR-0014 — Salted / hiding v:1 intent commitment (off-leaf salt; v:1 body immutability).
- `disclosure/src/policyproof.ts` — `PolicyBounds` (bigint), `provePolicySatisfaction`,
  `verifyPolicySatisfaction`, `policyProofDigest`.
- `disclosure/src/commitbind.ts` — `intentAmount`, `boundIntentDigest`, `verifyBoundAmount`,
  `bindAmountCommitment` (the binding primitive promoted to an admission check here).
- `disclosure/src/zkrange.ts` — Pedersen `commit`, `shiftCommitment`, range proof, the
  `n ≤ 251` hard cap (ZKRANGE-001 / -002), scalar order `L`.
- `kernel/src/kernel.ts`, `kernel/src/types.ts`, `kernel/src/policy.ts` — `decide`,
  `KernelInput`, `authorizesIntent` integration point.
- `capabilities/src/types.ts`, `capabilities/src/grant.ts` — `ActionIntent.amount` (number),
  `CapabilityGrant` ceilings, the PS-CAP / KERNEL-TIME numeric guards.
- `receipts/src/receipt.ts` — `ReceiptBody` (v:1), `buildReceipt`, `receiptLeaf`,
  verification paths.
- `conformance/test/kat.test.ts`, `conformance/vectors/ps-kat.json` — frozen KAT contract;
  `conformance/src/suite.ts` — C1–C23 (C24 added here).
- `docs/STATUS.md` — v:2 linkage status; PQ-commitment forward upgrade.
