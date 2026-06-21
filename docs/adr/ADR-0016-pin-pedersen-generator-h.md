<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0016 — Pin the Pedersen generator `H` provenance + fail-closed startup invariants

**Status: PROPOSED — design only, UNIMPLEMENTED.** This ADR records a *decision about how* to pin
and defend the second Pedersen generator `H`. No code, KAT vector, or behaviour changes with this
ADR. The construction below is **UNAUDITED** and routes to the same external ZK / crypto audit that
gates ADR-0006 / ADR-0013 (`docs/STATUS.md`). Nothing here is a soundness, non-infringement, or
production-readiness claim. Date: 2026-06-21. Track-B item **B1**.

## Context

The Pedersen commitment used throughout `disclosure/` is

```
commit(v, r) = v·G + r·H        (zkrange.ts:70-72)
```

over the audited prime-order group **ristretto255** (`@noble/curves`). The two generators are
derived today in `disclosure/src/zkrange.ts`:

- `G = Point.BASE` — the curve's standard base point (zkrange.ts:35).
- `H = ristretto255_hasher.hashToCurve(utf8ToBytes('PolarSeek/disclosure/generator-H/v1'))`
  (zkrange.ts:36-37) — a *nothing-up-my-sleeve* (NUMS) derivation: `H` is the image of a fixed,
  human-readable domain-separation seed under a hash-to-curve map, so no party chose `H`'s bits and
  no one is handed a discrete-log trapdoor `t` with `H = t·G`.

`H` is the binding backbone of every downstream artifact: the bit-commitments and Chaum–Pedersen
OR-proofs in `zkrange.ts`, the policy-satisfaction proof (`policyproof.ts`, ADR-0006), and the
structural commitment-binding digest (`commitbind.ts`, ADR-0013, which embeds `commit(...).toBytes()`
into the SHA3 pre-image). The **computational binding** of all of these rests on exactly one
assumption: that **no one knows `dlog_G(H)`**. If an adversary knew `t = dlog_G(H)`, then for any
commitment `C = v·G + r·H = (v + t·r)·G` they could open `C` to a *different* `(v', r')` pair with
`v' + t·r' = v + t·r` — i.e. forge a second opening, breaking binding and therefore the soundness of
every range / policy proof built on top.

Two gaps motivate this ADR:

1. **Provenance is implicit, not pinned.** The repo derives `H` at module load from a seed string but
   does **not** commit the resulting `H` bytes anywhere, and there is **no KAT** that freezes them.
   A silent change — to the seed literal, to the `@noble` hash-to-curve algorithm/DST, to the
   ristretto255 encoding, or even a transcription slip — would silently change `H`. A different `H`
   does not *announce itself*: existing proofs would still self-verify (prover and verifier share the
   same wrong `H`), so the regression is invisible to the current tests. The deterministic-output
   discipline the suite already applies to its primitives (`conformance/vectors/ps-kat.json`,
   `tools/gen-kat.mjs`) is **not yet extended to `H`.**

2. **No fail-closed load-time check.** Nothing asserts at startup that the `H` actually in use is a
   valid, prime-order, non-trivial generator distinct from `G`. The current behaviour *trusts* the
   library output. We want the process to **refuse to start** rather than commit/verify against a
   degenerate or substituted `H`.

This ADR specifies (a) the NUMS provenance argument, (b) the exact pinned `H` bytes + a KAT, (c)
fail-closed startup invariants, and (d) why this protects binding and proof stability.

## Decision

### (a) `H` provenance — nothing-up-my-sleeve hash-to-curve from a fixed public seed

Keep the existing NUMS derivation and **document it as the normative construction**:

```
H = hash_to_ristretto255( "PolarSeek/disclosure/generator-H/v1" )
```

where `hash_to_ristretto255` is `@noble/curves`' `ristretto255_hasher.hashToCurve`:
`expand_message_xmd(msg, DST, 64, SHA-512)` (RFC 9380 §5.3) feeding the RFC 9496 ristretto255
element-derivation, with the default domain-separation tag
`DST = "ristretto255_XMD:SHA-512_R255MAP_RO_"`.

The seed is a fixed, public, human-readable byte string. Because `H` is the image of a *hash* of a
seed nobody chose for its algebraic relationship to `G`, there is **no known `t` with `H = t·G`** —
this is the standard NUMS argument for a second Pedersen generator. The seed is **versioned** (`/v1`);
any future change to `H` MUST bump it (`/v2`, …) and is a breaking protocol change with its own ADR
and KAT.

> **Residual assumption (explicit, honest).** "No one knows `dlog_G(H)`" is a *heuristic* belief
> justified by the NUMS construction, **not a proof**. The NUMS argument assumes the hash-to-curve map
> behaves like a random oracle into the group (ROM); modelling it as a random function from which the
> dlog is unknown. This is the conventional assumption for NUMS generators but is **not unconditionally
> proven**, and we do **not** claim a QROM (quantum random-oracle) analysis. As noted in
> `policyproof.ts`, binding is the *classical* assumption here; the amount's hiding is information-
> theoretic and independent of `H`'s provenance (Pedersen is perfectly hiding for *any* generator pair,
> even a maliciously chosen `H` — provenance defends **binding/soundness**, never **secrecy**).

### (b) Pin the exact `H` bytes in-repo + a KAT

Pin the canonical 32-byte compressed ristretto255 encoding of `H` (and, for context, `G`) as a frozen
constant and a Known-Answer Test, regenerated by the existing tooling. Derived deterministically from
the seed above (`Point.toBytes()`):

```
seed   = "PolarSeek/disclosure/generator-H/v1"
G_base = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76   (ristretto255 BASE, for reference)
H_bytes= c0ec23401b116b32d76d762a6b95936afe412769729c55c50cb325ceb759a546   (the pinned generator H)
```

(The `H_bytes` value is reproduced by deriving `H` exactly as `zkrange.ts:36-37` does and reading
`H.toBytes()`. It is recorded here as the *intended* pin; the implementing PR adds it to the KAT file
so the bytes become a checked-in contract — see the KAT plan.)

- **Frozen constant.** A `H_PINNED_HEX` constant (e.g. in a new `disclosure/src/generators.ts`)
  carrying the expected compressed bytes, alongside the seed literal.
- **KAT vector.** A `disclosure.generatorH` block in `conformance/vectors/ps-kat.json`
  (`{ seed, gBaseHex, hHex }`), emitted by `tools/gen-kat.mjs`, asserted by
  `conformance/test/kat.test.ts`. This freezes the bytes across *any* future change to the seed, the
  `@noble` hash-to-curve algorithm/DST, or the ristretto encoding, and gives the Rust hot-path crate
  (and any other implementation) a concrete, auditor-rerunnable contract to reproduce `H` — exactly
  the role the KAT file already plays for SHA3/HMAC/dCBOR.

### (c) Load-time / startup invariants — fail closed

At module initialization (and re-checkable as an exported `assertGeneratorsWellFormed()` the kernel
calls at boot), assert the following and **throw, refusing to proceed**, on any failure. These are the
defenses against a degenerate or substituted `H` (or `G`):

1. **`H` decodes to a valid group element.** `Point.fromBytes(H_PINNED_HEX)` must succeed (canonical
   ristretto255 encoding; non-canonical / off-curve byte strings are rejected by `@noble`'s decoder).
2. **`H` matches the pin.** The runtime-derived `H` (from the seed) MUST equal `H_PINNED_HEX`
   byte-for-byte. This is the load-time twin of the KAT: it catches a divergence between the *derived*
   `H` and the *pinned* `H` even in a build where the KAT test was not run.
3. **`H` has the full prime order `L` (no low-order / small-subgroup component).** On ristretto255 this
   is *structural*: ristretto255 is a prime-order abstraction — every successfully-decoded ristretto
   element is already in the prime-order group, so there are **no cofactor / low-order points to
   exclude** (unlike raw Edwards/Montgomery encodings). The invariant is therefore satisfied by
   construction *for ristretto255*; we still assert `!H.equals(Point.ZERO)` (the identity is the one
   order-1 element) and treat "valid decode ⇒ prime order" as a **documented property of the chosen
   group**, to be re-confirmed in audit and re-checked explicitly if the group is ever swapped.
4. **`H ≠ identity` (`H ≠ Point.ZERO`).** A zero `H` would make `commit(v, r) = v·G`, fully revealing
   `v` and destroying both hiding and the second-generator structure.
5. **`H ≠ G`.** If `H = G` then `commit(v, r) = (v + r)·G`, collapsing the two-generator commitment to
   a single generator (`dlog_G(H) = 1`, the worst case), trivially breaking binding.
6. **`G` is the expected base point.** `G.equals(Point.BASE)` and (defensively) `!G.equals(Point.ZERO)`,
   so a tampered `G` is also caught.

> Properties we **cannot** assert at startup and which therefore remain audit obligations: the actual
> *unknownness* of `dlog_G(H)` (no efficient test exists — that is the hardness assumption itself), and
> independence of `G` and `H` beyond `H ≠ G` and `H ≠ id`. The invariants above are *necessary*
> well-formedness checks, **not** a proof of binding.

### (d) Why this protects BINDING and proof stability

- **Binding.** Computational binding of `v·G + r·H` reduces *exactly* to "no one knows `dlog_G(H)`".
  Pinning a NUMS-derived `H` and asserting `H ≠ G`, `H ≠ id`, and prime order removes the *trivial*
  ways binding could be broken (a trapdoored, substituted, or degenerate `H`) and documents the single
  residual assumption. Every downstream guarantee — `zkrange`'s range soundness, `policyproof`'s
  "amount within bounds", and `commitbind`'s point-binding digest — inherits binding from this one
  generator pair, so pinning `H` is the *root* of those guarantees.
- **Proof / digest stability.** `commitbind.ts` hashes `commitment.toBytes()` into a public, externally
  recomputable receipt digest (`boundIntentDigest`), and `policyproof.ts` serializes commitment bytes
  into `policyProofDigest`. If `H` silently changed, the *same logical commitment* would encode to
  *different bytes*, so previously issued receipts/digests would no longer recompute — a silent
  cross-version break in the transparency-log-anchored receipt body. The KAT + the derived-equals-pinned
  invariant turn that silent break into a **loud, fail-closed** error at build and at boot.

## Soundness / security argument (honest, unaudited)

- **What is protected:** the *trivial* break classes for binding — a maliciously chosen `H` with a known
  dlog, an accidental `H = G`, a degenerate `H = id`, a low-order `H`, and a silent drift of `H`'s bytes
  across code/library/encoding changes. After this ADR, each is either impossible-by-pin (drift, via KAT +
  load check) or fail-closed-at-startup (degeneracy, equality, base-point tamper).
- **What is NOT proved:** that `dlog_G(H)` is *genuinely* unknown. That is the NUMS hardness assumption,
  justified heuristically in the ROM, **not** proven, and **not** analyzed in the QROM. Binding remains a
  **classical** assumption (a quantum adversary that can compute discrete logs breaks it regardless of
  provenance); this matches and does not weaken the PQ profile already documented in `policyproof.ts`
  (hiding is information-theoretic / PQ; the *proof's integrity* is classical).
- **Scope honesty:** this ADR hardens *generator provenance and well-formedness*. It does **not** touch the
  separately-unaudited soundness of the range-proof composition itself (ADR-0006) or the commitment-binding
  trust model (ADR-0013, which still does not defend against a kernel malicious *at admission*). No claim
  here is audited, proven, production-ready, FIPS-validated, or a non-infringement statement.

## Implementation plan (what would change, behind which flags)

Design-only today; when implemented (separate PR, gated on review):

1. **`disclosure/src/generators.ts` (new):** export `SEED_H`, `H_PINNED_HEX`, the derived `G`/`H`, and
   `assertGeneratorsWellFormed()` running invariants (1)–(6). `zkrange.ts` imports `G`/`H` from here
   instead of re-deriving inline, so there is a single source of truth.
2. **Load-time gate:** `generators.ts` runs `assertGeneratorsWellFormed()` once at module init (throws on
   failure). The kernel additionally calls it explicitly at boot so failure is observable in startup logs,
   not just on first commitment. No feature flag — these are *fail-closed* invariants; an environment where
   they fail must **not** run. (A `POLARSEEK_SKIP_GENERATOR_SELFTEST` escape hatch is deliberately **not**
   provided.)
3. **No behavioural change to honest paths:** for a correct build the derived `H` already equals the pin,
   so commitments, proofs, and digests are **byte-identical** to today. This ADR adds checks, not new
   cryptography, and changes **no** wire format.

## KAT / conformance-regen plan

1. Add a `disclosure.generatorH` block to `tools/gen-kat.mjs` output:
   `{ "seed": "...generator-H/v1", "gBaseHex": "e2f2ae0a…", "hHex": "c0ec2340…" }`, written to
   `conformance/vectors/ps-kat.json` by `npm run kat` (after `npm run build`, per the tool's prereq).
2. Add an assertion in `conformance/test/kat.test.ts` that re-derives `H` from the seed and checks it
   equals `hHex`, and that `hHex ≠ gBaseHex`, `hHex` decodes, and `hHex ≠` the identity encoding.
3. Add a focused `disclosure/test/generators.test.ts` exercising each invariant (1)–(6), including
   *negative* cases (a deliberately wrong pin, `H` set to `G`, `H` set to identity) asserting
   `assertGeneratorsWellFormed()` throws.
4. **Conformance:** introduce a new conformance check (next free **C-id**, e.g. C24) asserting the pinned
   `H` is well-formed and matches the derived value, and wire it into the conformance count/registry per the
   repo's existing bookkeeping. Regen is deterministic: `npm run build && npm run kat` reproduces the exact
   pinned bytes; no randomness is involved, so the vector is stable across runs and implementations.

## Alternatives considered

1. **Leave `H` derived-at-load, unpinned (status quo) — REJECTED.** Silent drift of `H` is invisible to
   existing tests (prover and verifier share the wrong `H`) and silently breaks externally-recomputable
   receipt digests. No fail-closed guarantee.
2. **Choose `H` by `try-and-increment` from `G`'s encoding (e.g. `H = hashToCurve(G.toBytes())`) —
   REJECTED as the *primary* seed.** Works, but a fixed *human-readable* domain-separation seed is a
   stronger, more auditable NUMS story (a reviewer can read the seed and confirm nobody embedded a
   structure). Functionally equivalent for the dlog-unknownness argument.
3. **Hard-code `H` as a raw hex literal with no derivation — REJECTED.** Removes the NUMS *story*: a
   reviewer could not independently re-derive `H` from a public seed, and a planted trapdoored point would
   be indistinguishable from an honest one. Pinning *plus* keeping the seed-derivation (with the
   derived-equals-pinned invariant) gives both reproducibility and auditability.
4. **Two independent NUMS generators with a formal independence proof — DEFERRED.** Stronger but needs the
   external crypto audit to specify; out of scope for a provenance-pinning ADR.

## Consequences

- **Positive:** binding's single root assumption is made explicit, pinned, and load-time-guarded; silent
  `H` drift becomes a build/boot failure; receipts/digests gain byte-stability guarantees; the Rust crate
  and third parties get a reproducible `H` contract via the KAT.
- **Cost / caveats:** one new module + one new KAT block + one conformance check; a hard fail-closed gate
  (intended). The core hardness assumption (`dlog_G(H)` unknown) is **unchanged and unproven**; this ADR
  does not and cannot prove it. Everything here remains **UNAUDITED** until the external ZK/crypto audit
  that also gates ADR-0006 / ADR-0013.
- **Honesty note:** this is a *design decision record*, not a security result. No soundness, audited,
  production-ready, FIPS, or non-infringement claim is made. The amount's hiding is independent of this
  ADR (information-theoretic / PQ); only binding/soundness depends on `H`'s provenance, and that remains a
  classical, ROM-justified, QROM-unanalyzed assumption.

## References

- `disclosure/src/zkrange.ts:35-37, 70-72` — current `G`/`H` derivation and `commit(v, r) = v·G + r·H`.
- `disclosure/src/policyproof.ts` — PSP over `commit`; serializes commitment bytes into `policyProofDigest`
  (ADR-0006).
- `disclosure/src/commitbind.ts` — embeds `commitment.toBytes()` into the public `boundIntentDigest`
  (ADR-0013).
- ADR-0006 — ZK policy-satisfaction (conservative subset); PQ profile + linkage contract.
- ADR-0013 — v:2 structural commitment-binding (Pedersen ↔ SHA3).
- `conformance/vectors/ps-kat.json`, `tools/gen-kat.mjs`, `conformance/test/kat.test.ts` — the existing
  frozen-KAT discipline this ADR extends to `H`.
- RFC 9380 (hash-to-curve, `hash_to_ristretto255`, `expand_message_xmd`) and RFC 9496 (ristretto255
  element-derivation) — the `@noble/curves` `ristretto255_hasher.hashToCurve` construction.
- `docs/STATUS.md` — UNAUDITED status of the disclosure ZK stack; pre-FTO framing.
