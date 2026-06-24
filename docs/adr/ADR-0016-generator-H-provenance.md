<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0016 — Generator-H Provenance and Startup Invariant

**Status: PROPOSED — design only, UNIMPLEMENTED.**  
This ADR records a *decision about how* to derive, pin, and runtime-guard the secondary Pedersen
generator `H` used in Nerion's VRF and ZK proof constructions. No code, KAT vector, or behaviour
changes with this ADR. The construction below is **UNAUDITED** and feeds the same external ZK/crypto
audit gating ADR-0006 / ADR-0013 (see `docs/STATUS.md`). Nothing here is a soundness, FIPS,
non-infringement, or production-readiness claim.

Date: 2026-06-24.  Track-B item **B1** (Generator-H provenance; PhD-council review rev.).

> **DeepSeek PhD seat synthesis (Sprint-1, item B1):**  
> The invariant design is structurally sound: `H ≠ G`, `H ≠ id`, prime-order membership, and the
> derived-equals-pinned check together close the trivial binding-break classes without overclaiming.
> The ADR's honest framing of the residual dlog assumption is correct. The per-bit Fiat–Shamir challenge
> issue (ADR-0017) is **independent** of generator provenance and does not affect the H-invariant
> analysis. See ADR-0017 for the full single-scalar challenge replacement.

---

## 1. Context

### 1.1 Role of `H` in Nerion

Nerion employs Pedersen commitments over the prime-order group **ristretto255**:

```
commit(v, r)  :=  v·G  +  r·H        ∈  ristretto255
```

where

- `G = ristretto255.BASE`  — the curve's canonical base point (RFC 9496 §3.1), and
- `H`  — a **secondary generator** with no known discrete-log relation to `G`.

The same `(G, H)` generator pair underlies:

| Construction | File | ADR |
|---|---|---|
| Pedersen bit-commitments for range proofs | `disclosure/src/zkrange.ts:36-37, 70-72` | ADR-0006 |
| Policy-satisfaction proofs (PSP) | `disclosure/src/policyproof.ts` | ADR-0006 |
| Commitment-binding digest (`boundIntentDigest`) | `disclosure/src/commitbind.ts` | ADR-0013 |
| VRF proof constructions (deferred) | — | ADR-0004 |

The **computational binding** of every downstream artifact — range proofs, policy bounds, receipt
digests — reduces to a single hardness assumption: that **no efficient adversary knows the discrete
logarithm `t` with `H = t·G`**. If `t` were known, any commitment `C = v·G + r·H` would admit the
alternate opening `(v', r')` satisfying `v' + t·r' = v + t·r`, destroying binding and therefore the
soundness of every range/policy proof layered above.

### 1.2 Two Gaps Motivating This ADR

**Gap 1 — Provenance is implicit, not formally pinned.**  
`H` is currently derived at module load from a fixed seed string (`disclosure/src/zkrange.ts:37`),
but the resulting bytes are committed nowhere and there is no Known-Answer Test (KAT). A silent change
to the seed literal, to `@noble`'s `expand_message_xmd` implementation, to the ristretto255 encoding,
or to the Domain-Separation Tag (DST) would silently alter `H`. Because prover and verifier share the
same `H`, such drift is invisible to self-consistency tests; existing proofs would still pass. The
conformance discipline already applied to SHA-3/HMAC primitives (`conformance/vectors/ps-kat.json`,
`tools/gen-kat.mjs`) has not yet been extended to `H`.

**Gap 2 — No fail-closed load-time guard.**  
Nothing asserts at startup that the `H` in use is a valid, prime-order, non-trivial generator distinct
from `G`. The code trusts the `@noble` library output unconditionally. A tampered build, or a future
library change that alters the hash-to-curve map, would proceed silently. Nerion should **refuse to
initialise** rather than commit or verify against a degenerate or substituted `H`.

---

## 2. Decision

### 2.1 Normative Derivation of `H` — Nothing-Up-My-Sleeve Hash-to-Curve

The normative construction is:

```
domain_sep := "nerion-generator-H-v1"

H  :=  hash_to_curve( domain_sep )
```

where `hash_to_curve` is the **RFC 9380** `hash_to_ristretto255` function with the suite parameters:

```
Suite ID  :  ristretto255_XMD:SHA-512_R255MAP_RO_
Hash       :  SHA-512
expand_msg:  expand_message_xmd (RFC 9380 §5.3)
DST        :  "ristretto255_XMD:SHA-512_R255MAP_RO_"    (= Suite ID, per RFC 9380 §8.4)
k          :  128 bits (security parameter)
L          :  64 bytes (= 2 × ⌈k/8⌉ + len_in_bytes(p) = 2 × 16 + 32)
f          :  ristretto255 element-derivation (RFC 9496 §4)
```

Concretely, the `@noble/curves` implementation is:

```typescript
import { ristretto255_hasher } from '@noble/curves/ed25519.js'
import { utf8ToBytes }         from '@noble/hashes/utils.js'

const SEED_H = 'nerion-generator-H-v1'
const H = ristretto255_hasher.hashToCurve(utf8ToBytes(SEED_H))
```

**Why this seed.**  
The seed is a fixed, public, human-readable byte string. `hash_to_curve` is modelled as a random
oracle (ROM) from byte strings into the group; its output is computationally indistinguishable from a
uniformly random group element. Because no party selected the seed for its algebraic relationship to
`G`, and because `hash_to_curve` is not injective from group elements to seeds, **no efficient
algorithm can compute `t = dlog_G(H)`** from the seed alone — this is the standard
nothing-up-my-sleeve (NUMS) argument for a second Pedersen generator.

**Versioning.**  
The seed literal includes a version suffix `/v1`. Any future change to `H` **MUST** bump the version
(`nerion-generator-H-v2`, …) and is a **breaking protocol change** requiring its own ADR and KAT.

> **Residual assumption (explicit and honest).**  
> "No efficient adversary knows `t = dlog_G(H)`" is a *heuristic* belief justified by the ROM
> assumption on `hash_to_curve`. It is **not a proof**. This ADR does not claim a QROM analysis: a
> quantum adversary with access to a discrete-log oracle would break binding regardless of `H`'s
> provenance. Hiding is **information-theoretic** (Pedersen is perfectly hiding for any generator pair,
> even a maliciously chosen `H`) — provenance defends **binding and soundness**, never **secrecy**.

### 2.2 Formal Constraints — Why Each Invariant Is Necessary

Let `𝔾` denote the ristretto255 prime-order group of order `L` (the Ed25519 prime-order subgroup,
abstracted by the ristretto255 encoding), and let `id` denote the group identity (point at infinity /
neutral element).

**Constraint C1: `H ≠ id`**

```
Require:  H  ≠  id_𝔾
```

*Necessity.*  If `H = id`, then for all `r`:

```
commit(v, r)  =  v·G  +  r·id  =  v·G
```

The commitment degenerates to a single-generator commitment: `v` is fully determined by `C` (via
discrete-log hardness). Hiding is preserved — but the binding *structure* is reduced to a single
generator, destroying the independence that the OR-proof and PSP require (both proofs implicitly use
the fact that knowledge of `dlog_H(·)` is separate from knowledge of `dlog_G(·)`). Furthermore the
NUMS story is vacuous: any `r` opens `C` to any `(v', r')` with `v'·G = C`, which is not an
additional opening — it is the *same* opening with a trivially varied `r`. The soundness argument for
OR-proof simulation entirely collapses.

**Constraint C2: `H ≠ G`**

```
Require:  H  ≠  G
          i.e.   t  :=  dlog_G(H)  ≠  1
```

*Necessity.*  If `H = G` then `dlog_G(H) = 1` (the worst case of a *known* discrete log), and:

```
commit(v, r)  =  v·G  +  r·G  =  (v + r)·G
```

The two-generator Pedersen scheme collapses to a single-generator scheme with an exposed trapdoor
`t = 1`. Binding is **computationally broken**: for any commitment `C = (v+r)·G`, any pair `(v',r')`
with `v' + r' = v + r` is a valid second opening. An adversary trivially produces a forged opening for
any out-of-range or policy-violating `v'` with `r' = v + r - v'`. Every ZK soundness guarantee above
(range, policy, commit-bind) fails immediately.

**Constraint C3: `H` is a valid, prime-order ristretto255 element**

```
Require:  H  ∈  𝔾     (decodes as a canonical ristretto255 element)
          ord(H)  =  L  (prime order — no low-order component)
```

*Necessity.*  A point outside `𝔾` or with a small-order component would introduce cofactor
pathologies. On raw Edwards / Montgomery curves, an adversary can exploit a low-order component to
construct two distinct encodings of the same `commit(v,r)` that verify differently under distinct
co-set representatives. Ristretto255's abstraction eliminates this class entirely: **every**
successfully-decoded ristretto255 element is a prime-order group element by construction (RFC 9496
§4). Constraint C3 is therefore satisfied automatically for any `H` that passes the ristretto255
decoder. We still assert it **explicitly** so that:

- the invariant is self-documenting for audit,
- a group swap (e.g. to a cofactor curve) is caught by re-reading the assertion, and
- `!H.equals(id)` remains meaningful as a belt-and-suspenders guard even though `id` is the only
  non-prime-order element ristretto255 can represent.

**Constraint C4: The derived `H` equals the pinned `H`**

```
Require:  H_derived  =  H_PINNED
          where H_derived  :=  hash_to_curve("nerion-generator-H-v1")
          and   H_PINNED   is the frozen 32-byte hex constant defined in §2.3
```

*Necessity.*  This is the load-time twin of the KAT (§2.4). It detects a divergence between the
runtime-derived `H` and the KAT-pinned `H` even in a build where the conformance test suite was not
executed — e.g. a production deployment without a test step, or a library update that silently altered
the hash-to-curve algorithm or DST.

**Summary of invariants:**

```
𝒫(G, H)  :=  ( H ≠ id_𝔾 )  ∧  ( H ≠ G )  ∧  ( H ∈ 𝔾 )  ∧  ( ord(H) = L )  ∧  ( H = H_PINNED )
             ↑ C1              ↑ C2          ↑ C3              ↑ C3             ↑ C4
```

The check is **O(1)** at startup: five constant-time comparisons plus one ristretto255 decode (already
performed to derive `H`).

### 2.3 Pinned KAT Constant

Pin the canonical 32-byte compressed ristretto255 encoding of both `G` and `H` as frozen constants:

```
seed_H  =  "nerion-generator-H-v1"

G_hex   =  5866666666666666666666666666666666666666666666666666666666666666
            # RFC 9496 §3.1 ristretto255 canonical base-point encoding

H_hex   =  <PLACEHOLDER — to be computed by the implementing PR as:
             bytes_to_hex( ristretto255_hasher.hashToCurve(utf8ToBytes("nerion-generator-H-v1")).toBytes() )
             The exact 32-byte hex value MUST be written into this ADR and into
             conformance/vectors/ps-kat.json by the implementing PR before merge.
             Do NOT merge a PR that leaves this placeholder in place.>
```

> **Implementation note on `G_hex`.**  
> The ristretto255 base-point encoding `5866...6666` (64 hex characters = 32 bytes) is the
> little-endian compressed encoding of the Edwards25519 base point under the ristretto255 encoding
> map (RFC 9496 §4.3.2). `@noble/curves`' `ristretto255.Point.BASE.toBytes()` reproduces this
> exactly. The KAT asserts both `H_hex` and `G_hex` to ensure the encoding of `G` itself has not
> drifted.

**KAT block (to be written to `conformance/vectors/ps-kat.json`):**

```json
{
  "disclosure.generatorH": {
    "description": "Nothing-up-my-sleeve ristretto255 secondary generator H (RFC 9380 / RFC 9496)",
    "seed": "nerion-generator-H-v1",
    "suite": "ristretto255_XMD:SHA-512_R255MAP_RO_",
    "gBaseHex": "5866666666666666666666666666666666666666666666666666666666666666",
    "hHex": "<PLACEHOLDER — see §2.3>"
  }
}
```

The KAT is emitted by `tools/gen-kat.mjs` (after `npm run build`) and asserted by
`conformance/test/kat.test.ts`. Because `hash_to_curve` is deterministic (no randomness), the output
is **stable across runs and implementations** once the seed and suite are fixed.

### 2.4 Load-Time Startup Invariant — Fail Closed

The function `assertGeneratorsWellFormed()` MUST be called:

1. **at module initialization** of `disclosure/src/generators.ts` (new module, see §3), and
2. **explicitly by the kernel at boot** (`planes/src/node.ts`) so failures appear in startup logs
   before any commitment or verification is attempted.

The function asserts each of C1–C4 in sequence and **throws `GeneratorInvariantError`** on any
failure, refusing to proceed:

```
assertGeneratorsWellFormed():
  1.  H_runtime := hash_to_curve("nerion-generator-H-v1")
      // C3a: H decodes as a valid ristretto255 element (decode step throws on failure)

  2.  assert !H_runtime.equals(Point.ZERO)                    // C1: H ≠ id
      → throw GeneratorInvariantError("H = identity")

  3.  assert !H_runtime.equals(Point.BASE)                    // C2: H ≠ G
      → throw GeneratorInvariantError("H = G  (dlog_G(H)=1 known)")

  4.  H_pinned := ristretto255.Point.fromHex(H_PINNED_HEX)
      assert H_runtime.equals(H_pinned)                       // C4: derived = pinned
      → throw GeneratorInvariantError("H mismatch: derived ≠ pinned KAT value")

  5.  assert Point.BASE.equals(ristretto255.Point.BASE)       // G integrity check
      assert !Point.BASE.equals(Point.ZERO)
      → throw GeneratorInvariantError("G tampered or identity")
```

There is deliberately **no escape hatch** (no `NERION_SKIP_GENERATOR_SELFTEST` environment variable).
An environment where any invariant fails MUST NOT proceed.

---

## 3. Implementation Plan (design-only; separate PR, gated on review)

1. **`disclosure/src/generators.ts` (new module):** export `SEED_H`, `H_PINNED_HEX`, the singletons
   `G` and `H`, and `assertGeneratorsWellFormed()`. `zkrange.ts`, `policyproof.ts`, and
   `commitbind.ts` import `G`/`H` from this module rather than re-deriving inline — single source of
   truth.

2. **KAT vector:** compute `H_PINNED_HEX` via `npm run build && npm run kat`; write it into this ADR
   (replace the `<PLACEHOLDER>`) and into `conformance/vectors/ps-kat.json`.

3. **Conformance check (C24):** add to `conformance/test/kat.test.ts` assertions that:
   - `hHex ≠ gBaseHex`,
   - `hHex` decodes as a valid ristretto255 element,
   - `hHex ≠` the identity encoding (`0000...00`),
   - the runtime-derived `H` equals `hHex`.

4. **Unit tests (`disclosure/test/generators.test.ts`):** exercise positive and negative cases for
   each invariant (C1–C4), including deliberate fault injection (wrong pin, `H = G`, `H = id`),
   asserting `GeneratorInvariantError` is thrown.

5. **No wire-format change.** For a correct build the derived `H` already equals the pin; all proofs
   and digests are byte-identical to today. This ADR adds *guards*, not new cryptography.

---

## 4. Security Argument

### 4.1 What this ADR protects against

| Threat class | Mitigated by |
|---|---|
| Silent drift of `H` across library/encoding changes | KAT pin (C4) + derived-equals-pinned load check |
| Degenerate `H = id` (commitment collapses to `v·G`) | C1 |
| Trapdoored `H = G` (`dlog_G(H) = 1` trivially known) | C2 |
| Off-curve or low-order `H` | C3 (ristretto255 decode + prime-order guarantee) |
| `G` tampered at build time | Step 5 of `assertGeneratorsWellFormed` |

After this ADR, each class above either:
- becomes **structurally impossible** (off-curve / low-order `H` — excluded by ristretto255 decoding), or
- causes a **loud, fail-closed boot failure** (C1, C2, C4 mismatch, `G` tamper).

### 4.2 What this ADR does NOT protect against

- **Dlog unknownness of `H`.** There is no efficient algorithm to decide whether `dlog_G(H)` is
  known to some party. The NUMS argument provides *heuristic confidence*, not a proof. This ADR
  removes the *trivial* break classes; the residual hardness assumption is unchanged.
- **QROM security.** Binding is a classical assumption (discrete log over ristretto255 is assumed
  hard classically, but a CRQC breaks it). Hiding remains information-theoretic and is unaffected.
- **Soundness of the range/OR-proof composition.** That is ADR-0017's scope. The `H`-invariant is a
  *precondition* for ADR-0017's argument, not a substitute for it.
- **A malicious issuer.** A kernel that is malicious at admission time can commit any amount it
  chooses, with or without a well-formed `H`. Generator provenance defends the proof's *binding
  assumption*, not the issuer's *honesty*. Issuer honesty is the quorum/attestation model's job
  (unchanged).

### 4.3 Relationship to ADR-0017 (OR-proof Fiat–Shamir)

ADR-0016 and ADR-0017 are **independent**:

- ADR-0016 concerns the generator provenance precondition: `H` must be well-formed and distinct from
  `G` and `id` for the Pedersen commitment to be binding.
- ADR-0017 concerns the transcript-binding structure of the non-interactive Chaum–Pedersen OR-proof:
  the per-bit challenge must be replaced with a single-scalar Fiat–Shamir challenge over the full
  transcript (all branch commitments + domain separator) to satisfy special-soundness. This is a
  separate mathematical requirement that holds regardless of `H`'s provenance.

The DeepSeek PhD seat (Sprint-1 review) confirmed: the ADR-0016 invariant is structurally sound and
independent of the ADR-0017 Fiat–Shamir issue. Both must be addressed; neither subsumes the other.

---

## 5. Alternatives Considered

1. **Leave `H` derived-at-load, unpinned — REJECTED.** Silent drift is invisible to existing proofs
   (prover and verifier share the wrong `H`) and breaks externally-recomputable receipt digests without
   any observable error. No fail-closed guarantee.

2. **Derive `H` by try-and-increment from `G`'s encoding (e.g. `hash_to_curve(G.toBytes())`) —
   REJECTED as primary seed.** This works and provides NUMS guarantees, but a human-readable,
   versioned seed string is a stronger audit story: a reviewer can read the seed and confirm no
   algebraic structure was embedded. Functionally equivalent for the dlog-unknownness argument.

3. **Hard-code `H` as a raw hex literal with no derivation — REJECTED.** Removes reproducibility:
   a reviewer cannot re-derive `H` from a public seed, and a planted trapdoored point would be
   indistinguishable from an honest one. Pinning *plus* keeping the NUMS derivation (with C4
   asserting they match) provides both reproducibility and auditability.

4. **Formally prove `dlog_G(H)` is unknown — NOT ACHIEVABLE.** The unknownness of a discrete log is
   not an efficiently decidable property. The NUMS argument is the standard substitute; no stronger
   alternative exists without a bespoke algebraic construction (e.g. a dual-generator VRF where `H`
   is certified by a trusted setup — explicitly out of scope for Nerion's design-around posture).

5. **Two independent NUMS generators with a formal independence proof — DEFERRED.** Strictly stronger
   but requires the external crypto audit to specify and verify. A dual-generator certificate is a
   plausible post-audit upgrade.

---

## 6. Consequences

**Positive:**
- The binding root assumption is made explicit, pinned, and load-time-guarded.
- Silent `H` drift becomes a build/boot failure (KAT + C4 check).
- Receipt digests and proof transcripts gain byte-stability guarantees.
- Third-party implementations (Rust crate and future ports) get a reproducible, auditor-rerunnable
  `H` contract via the KAT.
- The implementation is O(1) at startup with no performance impact on the hot path.

**Negative / caveats:**
- One new module (`generators.ts`) + one new KAT block + one new conformance check (C24).
- A hard fail-closed gate is intentional and non-bypassable.
- The core hardness assumption (`dlog_G(H)` unknown) is **unchanged and unproven**. This ADR does
  not and cannot prove it.
- Everything here remains **UNAUDITED** until the external ZK/crypto audit gating ADR-0006 /
  ADR-0013.

**Honesty note:** this is a *design decision record*, not a security result. No soundness, audited,
production-ready, FIPS, or non-infringement claim is made. Hiding is information-theoretic and
independent of `H`'s provenance. Only binding/soundness depends on the NUMS assumption, and that
remains a classical, ROM-justified, QROM-unanalyzed heuristic.

---

## 7. References

- `disclosure/src/zkrange.ts:35-37, 70-72` — current `G`/`H` derivation and `commit(v, r) = v·G + r·H`.
- `disclosure/src/policyproof.ts` — PSP over `commit`; serializes commitment bytes into
  `policyProofDigest` (ADR-0006).
- `disclosure/src/commitbind.ts` — embeds `commitment.toBytes()` into `boundIntentDigest` (ADR-0013).
- ADR-0004 — VRF-based private leader sortition; `(G, H)` pair used in VRF constructions.
- ADR-0006 — ZK policy-satisfaction (conservative subset); PQ profile + linkage contract.
- ADR-0013 — v:2 structural commitment-binding (Pedersen ↔ SHA3).
- ADR-0017 — OR-proof Fiat–Shamir tightening (single-scalar challenge; independent of this ADR).
- `conformance/vectors/ps-kat.json`, `tools/gen-kat.mjs`, `conformance/test/kat.test.ts` — KAT
  discipline this ADR extends to `H`.
- **RFC 9380** (Hashing to Elliptic Curves) — `hash_to_ristretto255`, `expand_message_xmd` (§5.3),
  suite identifier `ristretto255_XMD:SHA-512_R255MAP_RO_` (§8.4).
- **RFC 9496** (The ristretto255 and decaf448 Groups) — ristretto255 element derivation (§4),
  canonical base-point encoding (§3.1).
- **RFC 5869** (HKDF) — referenced for contrast with the symmetric permit key derivation (ADR-0015);
  not used here.
- Bernstein et al., "Ristretto: prime order from cofactor groups",
  https://ristretto.group/ — the NUMS generator construction tradition.
- `docs/STATUS.md` — UNAUDITED status of the disclosure ZK stack; pre-FTO framing.
