<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Soundness argument sketch — Nerion ZK range proof (for external-auditor review)

**Date:** 2026-06-27 · **Companion to:** [`docs/council/zk-audit-prep-2026-06-27.md`](../council/zk-audit-prep-2026-06-27.md) (item P1)

> **What this is.** A written **argument sketch** for the soundness of the bespoke range
> proof in `disclosure/src/zkrange.ts`, produced to answer the audit-prep dossier's P1
> item ("there is no written soundness theorem / extractor"). It exists so the funded
> external ZK audit can **verify or refute a concrete construction** rather than
> reconstruct one from scratch.
>
> **What this is NOT.** Not a machine-checked proof, not a tight knowledge-error bound,
> not a QROM analysis. Soundness is **classical** (discrete-log over ristretto255) and
> argued in the **random-oracle model**. The group (`@noble` ristretto255) and hash
> (SHAKE256) are assumed ideal/audited; the protocol composition is **UNAUDITED**. The
> auditor must verify the extractor, quantify the forking/knowledge-error loss, confirm
> the no-wrap disjointness formally, and assess ROM→QROM.

Notation is **additive** for readability (`vG + rH`); the code uses multiplicative group
notation (`G^v · H^r`). `L` is the prime group order, `L = 2^252 + δ`, `δ ≈ 2^124.6`.

---

## 1. Statement

Public: a commitment `C`, a threshold `T` with `1 ≤ T ≤ 2^n`, and a verifier-fixed width
`n ≤ 251`. The prover claims knowledge of `(v, r)` with

```
C = vG + rH      and      0 ≤ v < T.
```

`G` is the group base; `H = hashToCurve("PolarSeek/disclosure/generator-H/v1")` is a
nothing-up-my-sleeve generator with **unknown** `dlog_G(H)` (the binding assumption).

---

## 2. Building block — per-bit OR-proof (CDS over two Schnorr-on-`H` instances)

For each bit commitment `C_i`, the prover shows `C_i ∈ {rH} ∪ {G + rH}` — i.e. `C_i`
commits to `0` or to `1` — with a Chaum–Pedersen/CDS 1-of-2 OR-proof on base `H`, where
`P0 = C_i` (commitment to 0 ⇒ `P0 = r_iH`) and `P1 = C_i − G` (commitment to 1 ⇒
`P1 = r_iH`). Code: `proveBit`/`verifyBit` (`zkrange.ts:135/154`).

**2-special-soundness (extractor).** Take two accepting transcripts that share the first
messages `(t0, t1)` but have distinct global challenges `c ≠ c'`:

```
(t0, t1 ; c0, c1, s0, s1)      with  c0 + c1 = c
(t0, t1 ; c0', c1', s0', s1')  with  c0' + c1' = c'
```

Since `c ≠ c'`, there is a branch `b ∈ {0,1}` with `c_b ≠ c_b'`. The verifier's branch
equation is `s_b·H = t_b + c_b·P_b`; subtracting the two transcripts on branch `b`:

```
(s_b − s_b')·H = (c_b − c_b')·P_b   ⇒   P_b = w·H,   w = (s_b − s_b')·(c_b − c_b')^{-1} mod L.
```

- `b = 0`: `P0 = C_i = wH` ⇒ `C_i` opens to **bit 0** with randomness `w`.
- `b = 1`: `P1 = C_i − G = wH` ⇒ `C_i = G + wH` ⇒ **bit 1** with randomness `w`.

So the extractor outputs a valid opening of `C_i` to an element of `{0,1}`. In the
non-interactive (Fiat–Shamir) setting this is obtained by the standard ROM rewinding /
forking argument; **the knowledge-error bound and forking loss are left for the auditor
to quantify.** The verifier additionally enforces the split `c0 + c1 = c (mod L)`
(`zkrange.ts:158`), which is what makes the two-transcript branch argument apply.

---

## 3. Aggregation — bits compose to the committed value

`verifySub` (`zkrange.ts:201-214`) checks `Σ_i 2^i · C_i = C_target` in the group.
Substituting each extracted `C_i = b_i·G + r_i·H`:

```
Σ_i 2^i·C_i = (Σ_i 2^i·b_i)·G + (Σ_i 2^i·r_i)·H = C_target.
```

By the **computational binding** of Pedersen (a second opening would yield `dlog_G(H)`),
`C_target = vG + rH` has a unique `(v, r)` mod `L`, hence

```
v ≡ Σ_i 2^i·b_i   (mod L).
```

**No-wrap (the ZKRANGE-002 condition).** Each `b_i ∈ {0,1}` and `n ≤ 251`, so
`Σ_i 2^i·b_i ∈ [0, 2^n − 1] ⊆ [0, 2^{251} − 1] ⊂ [0, L)` because `2^n ≤ 2^{251} < L`.
A congruence between two values both in `[0, L)` is an **integer equality**, so

```
v = Σ_i 2^i·b_i ∈ [0, 2^n).
```

The cap is enforced on both prove and verify sides (`zkrange.ts:223`, `:258-259`).

---

## 4. Dual-range ⇒ strict inequality `v < T`

The proof contains **two** sub-proofs: that the amount commitment `C` and the diff
commitment open to values in `[0, 2^n)`. The verifier **reconstructs** the diff target
(`zkrange.ts:263`):

```
C_diff = (T − 1)·G − C = ((T−1) − v)·G + (−r)·H = commit(T−1−v, −r).
```

By §3 applied to the diff sub-proof, the extracted diff value `d` satisfies
`d ∈ [0, 2^n)` and (binding) `d ≡ (T − 1 − v) (mod L)`.

- If `v ≤ T − 1`: then `T − 1 − v ∈ [0, T−1] ⊆ [0, 2^n)`, consistent.
- If `v ≥ T`: then `T − 1 − v < 0`, so `(T − 1 − v) mod L = L − (v − T + 1)`. Since
  `v < 2^n ≤ 2^{251}` and `T ≥ 1`, this residue is `≥ L − 2^{251} > 2^{251} ≥ 2^n`, i.e.
  **outside** `[0, 2^n)`. That contradicts `d ∈ [0, 2^n)`.

Hence any accepting proof forces `v < T`. The `n ≤ 251` (`2^{n+1} ≤ L`) cap is precisely
what keeps the positive window `[0, 2^n)` and the negative-diff residues
`{L − k : 1 ≤ k ≤ 2^n}` **disjoint** mod `L`; at `n = 252` they can overlap and a large
`v` would falsely satisfy the diff range (the documented off-by-one ZKRANGE-002).

**Concrete `n = 252` counterexample (why the cap is necessary).** Take `T = 1` (claiming
`v = 0`) and the malicious `v = 1 + δ` (a valid 252-bit value, `v ≈ 2^{124.6} < 2^{252}`).
The amount range proof on `C` accepts (`v ∈ [0, 2^{252})`). The verifier reconstructs
`C_diff = (T−1)G − C = −C`, which commits to `−v ≡ L − v = (2^{252}+δ) − (1+δ) = 2^{252} − 1`,
and `2^{252} − 1 ∈ [0, 2^{252})`, so the diff range proof **also** accepts — falsely proving
`0 ≤ v < 1` while `v = 1 + δ ≠ 0`. With `n ≤ 251` this is impossible: `L − 2^n ≥ 2^{251} > 2^n`,
so the two windows cannot overlap. (Arithmetic re-checked numerically; `δ` is 125-bit.)

> **Independent check (2026-06-27).** The §4 crux was reviewed adversarially by a council
> seat (DeepSeek), which **confirmed** the argument, verified `L − 2^{251} = 2^{251} + δ > 2^{251}`,
> agreed `n ≤ 251` is **tight**, and supplied the `n = 252` counterexample above. The Gemini
> and OpenAI seats were unavailable/partial this run (provider throttling), so this is a
> two-reviewer check (this author + DeepSeek), not a full council consensus — and still not a
> substitute for the external audit.

---

## 5. Statement binding (strong Fiat–Shamir)

Every per-bit challenge is `SHAKE256(stmt ‖ tag_i ‖ C_i ‖ P0 ‖ P1 ‖ t0 ‖ t1)`, where
`stmt = SHAKE256(tag(n, T) ‖ C ‖ all amount C_i ‖ all diff C_i)` (`zkrange.ts:104-132`).
**All** commitments are fixed in `stmt` before any challenge is derived
(`proveBelow:235` precedes `proveSub`), and each per-bit tag is scoped by sub-proof and
index (`bit/${prefix}/${i}`). This is the standard strong-FS transform of the interactive
Σ-protocol; knowledge soundness transfers in the ROM with the usual forking loss. Because
no sub-statement challenge can be computed before every commitment is fixed, the
weak-FS / "Frozen-Heart" forgery class does not apply.

---

## 6. What remains for the external audit

1. **Verify the extractor** of §2 and the ROM forking argument; **quantify the
   knowledge error** (this sketch does not).
2. **Confirm the no-wrap disjointness** (§3–§4) formally, including the exact `δ` margin.
3. **Binding reduction**: confirm the §3 binding step reduces cleanly to discrete-log over
   ristretto255 with the actual generators.
4. **ROM → QROM**: this argument is classical-ROM only; a quantum forger is out of scope
   here (the hidden amount's _secrecy_ remains unconditional — perfect Pedersen hiding).
5. **Generator provenance**: that `H` is a uniform hash-to-curve output with unknown
   `dlog_G(H)` (pinned by `disclosure/test/zkrange-generators.test.ts`).

## 7. Code map

| Step                             | Code                                                            |
| -------------------------------- | --------------------------------------------------------------- |
| Bit OR-proof / extractor surface | `proveBit`/`verifyBit` `zkrange.ts:135/154`; split check `:158` |
| Aggregation `Σ 2^i C_i = target` | `verifySub` `zkrange.ts:201-214`                                |
| No-wrap cap `n ≤ 251`            | `proveBelow:223`, `verifyBelow:258-259`                         |
| Diff target reconstruction       | `verifyBelow:263`                                               |
| Strong-FS statement hash         | `statementHash` `zkrange.ts:104-132`                            |

_Every claim above is an argument to be checked, not a certified result. See
[`ASSURANCE.md`](../ASSURANCE.md) for the layer's overall status._
