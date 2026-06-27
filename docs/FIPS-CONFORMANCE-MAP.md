<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion ↔ FIPS 203 / 204 / 205 Conformance Map

> **Scope & honesty statement.** Nerion is **CNSA-2.0 aligned** and **UNAUDITED**.
> It is **not** FIPS 140-3 (CMVP) validated. Nerion does **not** implement the
> post-quantum primitives itself — it delegates them to
> [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
> through thin wrappers (`crypto/src/kem.ts`, `crypto/src/sign.ts`). This document
> maps the normative MUST/SHALL requirements of the three FIPS standards Nerion
> relies on to *where* each is satisfied, and states the known gaps plainly. It
> makes no certification claim.

## Delegation boundary

```
 Nerion protocol code                        @noble/post-quantum (the primitive)
 ────────────────────                        ───────────────────────────────────
 getKem(id)      → wrap(XWing | MLKEM1024P384) → ML-KEM-768/1024 KeyGen/Encaps/Decaps
 getSigner(id)   → wrap(ml_dsa87 | slh_dsa_*)  → ML-DSA-87 / SLH-DSA-SHAKE-256f
```

The FIPS §7 input checks (type/modulus/hash) and the Verify length checks are
**performed inside `@noble`**. Nerion's contribution to conformance is twofold:

1. It only registers **hybrid** KEMs (classical + PQ via a vetted combiner) and
   CNSA-2.0-tier signature schemes — never a bare, non-IND-CCA2 component
   (FIPS 203 §1: "K-PKE … shall not be used [standalone]").
2. It **locks the observable fail-closed behavior** of the delegation boundary
   with negative-conformance tests (`crypto/test/fips-conformance-negative.test.ts`),
   so a dependency bump cannot silently regress input rejection or implicit
   rejection. These tests pass today (14 cases, full gate green).

A FIPS input check is considered satisfied by **either** a thrown error **or** a
typed rejection (`verify → false`, `decaps → non-matching secret`): the binding
requirement is that a malformed input is *never accepted as valid*.

## FIPS 203 — ML-KEM (key encapsulation)

| # | Requirement | Citation | Enforced by | Nerion status |
|---|---|---|---|---|
| 1 | Encaps SHALL run only on a checked encapsulation key | §7.2 | `@noble` | DELEGATED |
| 2 | Encapsulation-key **type check** (length `384k+32`) | §7.2(1) | `@noble` | TESTED — wrong-length ek rejected |
| 3 | Encapsulation-key **modulus check** (`ByteEncode₁₂(ByteDecode₁₂(ek))==ek`, coeffs ∈ [0,q−1]) | §7.2(2), Eq.7.1 | `@noble` | DELEGATED (covered by length+roundtrip behavior) |
| 4 | **Ciphertext type check** (length `32(du·k+dv)`), checked **every** Decaps | §7.3(1) | `@noble` | TESTED — wrong-length ct rejected |
| 5 | Decapsulation-key type check (length `768k+96`) | §7.3(2) | `@noble` | DELEGATED |
| 6 | Decaps **hash check** `H(ek)==dk[768k+32:768k+64]` | §7.3(3), Eq.7.2 | `@noble` | DELEGATED |
| 7 | **Implicit rejection**: on `c≠c′` return `K̄=J(z‖c)` — a deterministic pseudo-random secret of normal length, never an error/flag | §6.3, Alg.18 | `@noble` | TESTED — tampered ct ⇒ deterministic, same-length, ≠ honest secret |
| 8 | The implicit-reject flag is secret and MUST be destroyed; never returned in any form | §6.3 | `@noble` | DELEGATED (no flag is observable at the wrapper) |
| 9 | No floating-point arithmetic | §3.3 | `@noble` (TS/bigint) | DELEGATED |
| 10 | Zeroize sensitive intermediates | §3.3 | `@noble` / JS GC | GAP — JS cannot guarantee zeroization; documented limitation |
| 11 | Seeds/`d,z` from an approved RBG of adequate strength | §3.3, §7.1 | host RBG | DELEGATED to deployment (`webcrypto`) |

## FIPS 204 — ML-DSA (lattice signatures)

| # | Requirement | Citation | Enforced by | Nerion status |
|---|---|---|---|---|
| 1 | Verify MUST reject any **signature σ of wrong length** | § inputs ("…shall return [false]") | `@noble` | TESTED — wrong-length σ never accepted |
| 2 | Verify MUST reject any **public key pk of wrong length** | § inputs | `@noble` | TESTED — wrong-length pk never accepted |
| 3 | Verify rejects a forged/zero signature | (soundness) | `@noble` | TESTED — all-zero σ rejected |
| 4 | Hedged signing (fresh `rnd`) is the default; deterministic permitted | §3.4 | `@noble` | DELEGATED (note: which variant `@noble` uses is a verification item) |
| 5 | Rejection sampling aborts/retries out-of-range `z`, `r0` | § (Sign) | `@noble` | DELEGATED |
| 6 | **Context string** domain separation: `M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M` | §5.2 (pure) | — | **GAP** — Nerion's `sign(message, sk)` wrapper passes **no `ctx`** (empty context). Conformant for empty-ctx use, but the wrapper does not expose `ctx`. Tracked as an enhancement; see "Open items". |
| 7 | No floating-point; zeroize sensitive intermediates | §3.6 | `@noble` / JS | GAP (zeroization, as KEM #10) |
| 8 | Seed `ξ` fresh from approved RBG ≥192-bit strength | §3.6 | host RBG | DELEGATED |

## FIPS 205 — SLH-DSA (stateless hash-based signatures)

| # | Requirement | Citation | Enforced by | Nerion status |
|---|---|---|---|---|
| 1 | Verify rejects wrong-length signature / public key | § (Verify) | `@noble` | TESTED (same suite, `SLH-DSA-SHAKE-256f`) |
| 2 | Stateless — no per-signature state to maintain | § (design) | `@noble` | DELEGATED (a key SLH-DSA advantage over stateful LMS/XMSS) |
| 3 | Context string domain separation | § inputs | — | GAP (same as FIPS 204 #6) |
| 4 | Used for long-term / root-of-trust signing only | Nerion design | `crypto/src/sign.ts` | BY DESIGN — `SLH-DSA-SHAKE-256f` registered for root signing |

## Open items (honest gaps, ordered)

1. **ML-DSA / SLH-DSA context string (FIPS 204 §5.2 / FIPS 205).** The signing
   wrapper does not pass a `ctx`. Empty-context signing is conformant, but adding
   an optional `ctx` parameter would let Nerion bind a domain tag (e.g. permit vs
   receipt vs root) into the signature itself. *Additive, no KAT change to the
   empty-ctx path; candidate enhancement.*
2. **Zeroization (FIPS 203 §3.3, FIPS 204 §3.6).** JavaScript/TypeScript cannot
   guarantee secret material is wiped from memory. This is an inherent limitation
   of the reference implementation and is disclosed, not hidden. The Rust
   hot-path (`rust/`) is the path to address this for production custody.
3. **`@noble` hedged-vs-deterministic variant.** Confirm and document which
   ML-DSA signing variant `@noble` implements (hedged is sufficient and preferred).
4. **CMVP / FIPS 140-3.** Not initiated. Stated accurately wherever Nerion's
   posture is described.

## Verification

```bash
# The negative-conformance suite that backs the TESTED rows above:
npx vitest run crypto/test/fips-conformance-negative.test.ts
# Full gate (476 tests incl. these 14):
npm run gate
```

*Sources: NIST FIPS 203 (ML-KEM) §§3.3, 6.3, 7.1–7.3; FIPS 204 (ML-DSA) §§3.4, 3.6, 5.2; FIPS 205 (SLH-DSA). Read page-by-page during the 2026-06 corpus deep-read; see `docs/PQC-CORPUS-FINDINGS.md`.*
