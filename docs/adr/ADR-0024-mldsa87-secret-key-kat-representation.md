<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0024 — Canonical ML-DSA-87 secret-key KAT representation for cross-implementation parity

**Status: PROPOSED — design only, UNIMPLEMENTED.** No code, KAT, or behaviour change ships with this ADR.
It records a decision about *what* the conformance suite should pin for the ML-DSA-87 secret key and routes
the underlying interop assumption to external audit / council. Like the rest of `crypto/`, any construction
described here is an **internal-review-level design**, not an audited or proven result. Date: 2026‑06‑21.
Track‑B item **B9** (apex sprint backlog).

## Context

`tools/gen-kat.mjs` freezes the deterministic outputs of the suite's primitives to exact bytes in
`conformance/vectors/ps-kat.json` (version `PS-KAT-1`). For signatures it pins **keygen-from-seed** via
`sigVector()`:

```js
function sigVector(sigId, seedLen) {
  const seed = pattern(seedLen, 1, 0)
  const kp = getSigner(sigId).keygen(seed)
  return {
    seedHex: hx(seed),
    publicKeyLen: kp.publicKey.length,   // ML-DSA-87: 2592
    secretKeyLen: kp.secretKey.length,   // ML-DSA-87: 4896
    publicKeySha3: hx(SHA3_SHAKE256.digest(kp.publicKey)),
    secretKeySha3: hx(SHA3_SHAKE256.digest(kp.secretKey)),
  }
}
```

The TS reference (`crypto/src/sign.ts`) wraps `@noble/post-quantum`'s `ml_dsa87`. Its
`keygen(seed)` returns the **expanded 4896‑byte FIPS 204 secret key** (`sk = (ρ, K, tr, s1, s2, t0)` in the
FIPS 204 §7.2 `skEncode` packing). So `ps-kat.json` carries, for `ML-DSA-87`:

- `secretKeyLen: 4896`
- `secretKeySha3: db6218a2…` — the SHA3‑256 of that expanded secret key.

**The interop gap.** The Rust hot-path crate (`rust/src/lib.rs`, `ml-dsa = "0.1.1"`) stores the signing key
in **seed form**: `SigningKey::<MlDsa87>::from_seed(&B32::from(seed))` keeps the 32‑byte ξ and re-derives the
expanded key internally. It deliberately exposes **no expanded-secret-key accessor** — only
`public_key_bytes()` (`vk.encode()` → ρ‖t1). The crate and the KAT note both call this out:

> *"The secret key is intentionally not cross-checked: this crate stores it in seed form, @noble in expanded
> form … two correct but representationally different encodings of the same key, so they are NOT
> byte-comparable."* — `rust/src/lib.rs`

Consequently `ts_kat_vectors_reproduce` (the Rust differential test) cross-checks SHA3‑256, HMAC‑SHA‑384,
AES‑256‑GCM, and the **ML-DSA-87 public key** — but **skips** `secretKeySha3`. Today `secretKeySha3` is a
**TS-only, single-implementation** value: it guards against silent TS/@noble regressions but provides **zero
cross-implementation assurance**. The same is true of `SLH-DSA-SHAKE-256f`, which is TS-only entirely.

ML-DSA secret keys legitimately have **two on-the-wire encodings**:

| Form | Bytes (ML-DSA-87) | What it is | Who emits it |
|---|---|---|---|
| **Seed** ξ | 32 | The keygen entropy; FIPS 204 `KeyGen_internal(ξ)` is deterministic, so ξ fully determines (pk, sk) | Rust `ml-dsa` (`from_seed`), FIPS 204 "seed-only" storage option |
| **Expanded** sk | 4896 | FIPS 204 §7.2 `skEncode(ρ,K,tr,s1,s2,t0)` | `@noble` `keygen().secretKey`, OpenSSL/BoringSSL "private key" DER |

Both are *correct*. They are **not** byte-equal, and neither is "more canonical" in the abstract — FIPS 204
defines both the expanded encoding (`skEncode`/`skDecode`) **and** the seed-based deterministic keygen.
NIST's own ACVP and FIPS 204 IPD discussion explicitly allow storing only the 32‑byte seed and expanding on
use. So the KAT currently pins one of the two forms (expanded) and the Rust crate can only natively produce
the other (seed) — hence the deliberate skip.

This is the residual, honestly-documented hole in B-track signature parity: **the secret key is the one
ML-DSA artifact the suite does not cross-validate.**

## Decision

**Adopt option (b): standardize the ML-DSA-87 secret-key KAT on the shared SEED form, and stop treating the
expanded-SK digest as a cross-implementation contract.** Concretely (deferred to implementation):

1. **Promote the 32‑byte seed ξ to the canonical cross-impl secret-key KAT object.** The seed is *already* the
   pinned input (`seedHex`) and is the **one representation both implementations natively agree on byte-for-
   byte** (Rust holds ξ; @noble accepts ξ as keygen input). Cross-impl parity is then asserted **transitively
   and soundly**: same seed → (FIPS 204 deterministic keygen) → same expanded sk → **same public key**, and
   the public key digest (`publicKeySha3`) is *already* cross-checked by Rust. Equal pk from equal seed under a
   deterministic, standardized keygen is the operative parity guarantee for the secret key.

2. **Reclassify `secretKeySha3` (expanded form) as a TS-reference self-consistency pin, not a parity claim.**
   Keep emitting it (it usefully catches @noble encoding regressions and documents the expanded length), but
   **explicitly label it single-implementation** in the KAT `note` and in `tools/gen-kat.mjs`. It must not be
   read as evidence of TS↔Rust agreement, because the Rust crate does not produce that byte string.

3. **Add a seed→pk derivation cross-check (already implied) as the parity assertion of record**, and document
   that the secret-key parity argument is *derivation-based* (seed + deterministic keygen + matching pk), not
   *byte-identity-based* (matching expanded sk bytes).

This is the **minimal, audit-trivial** choice: it changes documentation/classification, not cryptography, and
it keeps the conformance contract honest — every byte the KAT claims is "cross-implementation" actually is.

We **reject option (a)** (expose an expanded-SK accessor in the Rust crate and pin its hash cross-impl) as the
canonical contract, for the reasons in *Alternatives*. Option (a) MAY be added later as an **optional,
flag-gated supplementary** check, but it is **not** the canonical parity mechanism and is not required for B9.

## Soundness / security argument (UNAUDITED)

The parity guarantee rests on a single, standards-backed property:

> **FIPS 204 `KeyGen_internal(ξ)` is a deterministic function of the 32‑byte seed ξ.**

Therefore, for any two conforming implementations A and B:

```
ξ_A == ξ_B  ⇒  (pk_A, sk_A) == (pk_B, sk_B)   as abstract keys
            ⇒  pk_A == pk_B                    byte-for-byte (pk encoding is canonical: ρ‖t1)
```

The KAT already pins `seedHex` (the shared ξ) and cross-checks `publicKeySha3` in Rust. So **equal published
pk-digest from the equal published seed is a sound witness that both implementations ran the same
deterministic keygen on the same seed** — which is exactly the cross-impl property a secret-key KAT is meant
to establish. Pinning the *expanded sk bytes* would assert the **stronger and unnecessary** claim that both
implementations also chose the same *serialization* of the internal key state; that is an encoding-equality
claim, not a key-equality claim, and one of our two implementations declines to serialize at all.

**Residual assumptions / limits (honest):**

- **No new cryptographic claim is made.** This ADR asserts a *contract-shape* decision; it does not prove FIPS
  204 keygen determinism — it *relies* on it as specified by NIST. If a future @noble or `ml-dsa`-crate
  release deviated from FIPS 204 deterministic keygen, the pk cross-check would catch it; the seed pin would
  not independently.
- **Derivation-based parity is weaker than byte-identity parity in exactly one respect:** it does **not**
  detect an implementation that derives the correct pk but packs an *incorrect/divergent expanded sk* that it
  nonetheless signs correctly with. In practice a wrong expanded sk that still yields the correct pk **and**
  correct signatures is not a realizable FIPS 204 implementation (the expanded sk components s1,s2,t0 are
  determined by ξ and feed both pk and signing), so the gap is theoretical. We record it rather than hide it.
- **ROM/QROM:** unchanged and out of scope. ML-DSA-87's security model (EUF-CMA, ROM heuristics for
  Fiat–Shamir-with-aborts; QROM caveats) is governed by FIPS 204 / ADR-0001, not by this KAT-representation
  decision. This ADR touches *test-vector representation only*.
- **UNAUDITED.** This is an internal design note. The external ROS / ToB audit applies; nothing here is
  validated or FIPS-certified.

## Implementation plan (DEFERRED — not in this ADR)

All work below is behind no runtime flag (it is test/vector tooling) and ships as a **separate** change, with
a full KAT regen:

1. **`tools/gen-kat.mjs`** — split the sig vector's secret-key fields into two clearly-labelled groups:
   - **Cross-impl (canonical):** `seedHex`, `publicKeyLen`, `publicKeySha3`.
   - **TS-reference self-consistency (single-impl):** `secretKeyLen`, `secretKeySha3`, tagged in-vector (e.g.
     a sibling object `tsOnly: { secretKeyLen, secretKeySha3 }`) so no consumer mistakes it for parity.
   - Update the top-level `note` to state plainly: *the ML-DSA-87 / SLH-DSA secret key is cross-validated via
     seed→public-key derivation, not via expanded-secret-key byte identity.*
2. **`conformance/vectors/ps-kat.json`** — regenerate with `npm run kat`; **bump the KAT version**
   (`PS-KAT-1` → `PS-KAT-2`) because the sig vector shape changes (consumers, incl. the Rust loader, assert
   `version`).
3. **`rust/src/lib.rs`** (`ts_kat_vectors_reproduce`) — bump the asserted version to `PS-KAT-2`; read the
   secret-key fields from the new `tsOnly` location only for length sanity (optional), keep the **pk** digest
   as the parity assertion; update the doc comment to reference this ADR instead of the inline rationale.
4. **`crypto/src/sign.ts`** — no change required; optionally add a doc comment noting that
   `keygen().secretKey` is the **expanded** FIPS 204 sk and that the seed is the cross-impl key object.
5. **`docs/ASSURANCE.md`** — update the signature row to state secret-key parity is derivation-based
   (seed→pk), removing any implication that the 4896-byte digest is cross-checked.
6. **Conformance:** no new C-number is required (this tightens documentation/representation, not behaviour); if
   the council prefers an explicit gate, add a check asserting *"every field the KAT labels cross-impl is
   reproduced by ≥2 implementations."*

**Optional follow-up (NOT B9):** if/when a future `ml-dsa` crate release exposes a FIPS 204 `skEncode`
accessor (expanded-SK serialization), add a *flag-gated supplementary* `expandedSecretKeySha3` cross-check.
That would upgrade derivation-based parity to byte-identity parity for the secret key — strictly additive, and
only meaningful once both sides can emit the identical FIPS encoding.

## Alternatives

1. **Option (a): expose an expanded-SK accessor in the Rust crate and pin its hash cross-impl — REJECTED as
   canonical.**
   - The pinned crate (`ml-dsa = "0.1.1"`) does **not** offer a stable expanded-`skEncode` accessor; it is
     seed-first by design. Achieving byte-identity would mean reconstructing FIPS 204 `skEncode(ρ,K,tr,s1,s2,t0)`
     by hand from the crate's internals (fragile, version-coupled, and re-implementing exactly the
     serialization the crate chose not to expose), or forking/patching the dependency.
   - It also asserts an **encoding-equality** property we don't actually need (see Soundness): two FIPS-correct
     implementations are free to *store* the secret key differently (seed vs expanded vs DER) yet be fully
     interoperable. Forcing a single serialization elevates an implementation detail to a conformance gate.
   - It is **not free of risk**: hand-rolled secret-key serialization in test tooling handles long-term secret
     material and is a new place to get constant-time / zeroization wrong (even in a test). The seed form
     touches less secret-key surface.
   - Verdict: valuable as an **optional, additive** check *iff* the crate later exposes the accessor; wrong as
     the *required* parity mechanism today.

2. **Option (b): standardize on the shared seed-form vector only — CHOSEN.** Minimal, leans on the
   representation both impls already agree on, and makes the cross-impl claim *true*. (Detailed above.)

3. **Status quo: keep pinning the expanded `secretKeySha3` and silently skip it in Rust — REJECTED.** This is
   what ships today. It is honestly documented in code comments, but the KAT `note` still lists the secret key
   ambiguously and the vector *looks* like a contract it isn't. B9 exists to remove that ambiguity; doing
   nothing leaves a "looks-cross-impl, isn't" field in the frozen vectors.

4. **Drop `secretKeySha3` entirely — REJECTED.** It still has value as a **TS/@noble self-consistency** pin
   (catches an @noble encoding/length regression). The fix is to *reclassify and label* it, not delete it.

5. **Pin both forms and add a TS-side "seed↔expanded" derivation check — PARTIALLY ADOPTED.** Keeping both
   forms (one canonical/cross-impl, one TS-only) is exactly option (b)'s shape; an explicit TS assertion that
   `expand(seed) == secretKey` is a reasonable *self-consistency* extra but is not the cross-*implementation*
   contract and is left optional.

## Consequences

- **The conformance contract becomes honest:** every field labelled cross-implementation is reproduced by ≥2
  implementations; the one field that isn't (expanded `secretKeySha3`) is explicitly marked single-impl.
- **Secret-key parity is derivation-based (seed→pk), documented as such.** Slightly weaker than byte-identity
  in one theoretical respect (noted above), but it is the strongest claim our two implementations can *jointly*
  back today, and it is genuinely cross-impl rather than aspirational.
- **KAT version bump (`PS-KAT-1`→`PS-KAT-2`)** on implementation: the Rust loader and any external consumer
  pinning `version` must update in lockstep (single coordinated change; the vectors live in-repo).
- **No FTO movement, no new claims.** This is representation/test plumbing within the existing FIPS 204
  primitive selected in ADR-0001; it neither narrows nor widens the design-around, makes no
  non-infringement/FIPS/audited assertion, and changes no governed behaviour ("govern the verb, never the
  eye"). The signing primitive, suite IDs, and wire envelope are untouched.
- **Future-proof:** if `ml-dsa` later exposes `skEncode`, upgrading to byte-identity parity is a small,
  additive, flag-gated change — option (a) returns as a *bonus*, not a *dependency*.
- **SLH-DSA-SHAKE-256f** gets the same honest treatment by extension: it is TS-only today and the note should
  say so; a Rust/Python second implementation can later cross-check its seed→pk derivation under the same rule.

## References

- `tools/gen-kat.mjs` — `sigVector()`; the KAT `note` describing per-vector cross-impl coverage.
- `conformance/vectors/ps-kat.json` — `sig["ML-DSA-87"]` (`seedHex`, `publicKeyLen` 2592, `secretKeyLen` 4896,
  `publicKeySha3`, `secretKeySha3`).
- `crypto/src/sign.ts` — `wrap()` / `getSigner()` over `@noble/post-quantum` `ml_dsa87`; `keygen().secretKey`
  is the expanded FIPS 204 sk.
- `rust/src/lib.rs` — `MlDsaKeypair::from_seed` (seed-form storage), `public_key_bytes()`, the deliberate
  "no secret-key accessor" comment, and `ts_kat_vectors_reproduce` (skips secret-key byte compare).
- `rust/Cargo.toml` — `ml-dsa = "0.1.1"` (seed-first API surface).
- ADR-0001 — crypto suite / FIPS 204 ML-DSA-87 selection and the ROM/QROM posture.
- ADR-0002 — TS reference vs Rust hot-path; "MUST pass the same `conformance/` vectors (differential
  testing)" — this ADR clarifies *which* sig fields that promise actually covers.
- FIPS 204 §7 — `KeyGen_internal(ξ)` deterministic keygen; `skEncode`/`skDecode` expanded secret-key encoding.
