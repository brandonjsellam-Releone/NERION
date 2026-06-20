<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0013 — v:2 commitment‑to‑intent equality proof (Pedersen ↔ SHA3)

**Status: ACCEPTED — design recorded + binding PRIMITIVE IMPLEMENTED & tested (`disclosure/commitbind.ts`, 6 tests). UNAUDITED; full v:2 receipt-body wiring still pending; soundness unestablished until external audit.**
This records the *decision about how* to close the v:2 gap; it is the funded R&D deliverable
(grant milestones M3–M4), to be implemented and **externally audited before any soundness claim**.
Date: 2026‑06‑20. **Revised the same day after adversarial council review (DeepSeek + Grok): the heavy
ZK‑circuit approach was replaced by a structural commitment‑binding design — see Decision.**

## Context
PolarSeek receipts (and the deferred v:2 policy‑satisfaction receipt) can carry two independent commitments
to the transaction amount:

- `commitments.intent = SHA3‑256(canonical dCBOR(intent))` — links the receipt to the exact intent and anchors
  it in the RFC 6962 transparency log. **Binding, but not hiding and not algebraic.**
- `commitments.psr = a·G + r·H` — a Pedersen commitment to amount `a` on ristretto255. **Perfectly hiding**,
  algebraic, the basis of the ZK range / policy‑satisfaction proofs (ADR‑0006).

**The gap** (caught by adversarial review; see STATUS "v:2 DEFERRED"): nothing proves these two commitments are
to the *same* amount. Because Pedersen is perfectly hiding, a **malicious issuer** can commit an in‑bounds
amount in `psr` while `intent` says otherwise — the policy‑satisfaction proof would then verify against an
amount the intent never contained. Closing this needs a zero‑knowledge proof that the value inside the Pedersen
commitment equals the amount field inside the SHA3‑committed intent.

## Problem statement
Prove, in zero knowledge, knowledge of `(m, a, r)` such that:
1. `SHA3‑256(m) = intent_digest` (m is the canonical intent preimage),
2. `a = amount_field(m)` (a is the amount extracted from the canonical intent), and
3. `C = a·G + r·H` (the Pedersen commitment opens to `a`),

revealing nothing about `a`, `r`, or the non‑amount fields of `m`.

The difficulty: (1) is a **hash** relation (SHA3 / Keccak — not algebraically structured), while (3) is an
**algebraic** relation on an elliptic‑curve group. A classical sigma protocol composes across algebraic
statements but has **no known efficient construction** directly bridging a hash commitment and a group
commitment. Equality therefore requires expressing the hash relation in the *same* proof system as the
algebraic one.

## Decision (revised 2026‑06‑20 after adversarial council review — DeepSeek + Grok)
**Bind the Pedersen commitment structurally instead of proving cross‑commitment equality in ZK.** Embed the
amount's Pedersen commitment `C = a·G + r·H` (compressed ristretto255 bytes) **inside the canonical CBOR
intent `m` before hashing**, so `intent_digest = SHA3‑256(m)` binds `C` **by construction**. The admission
kernel — which already holds the plaintext amount `a` and blinding `r` at decision time — verifies
`C = commit(a, r)` before issuing. The receipt then carries that same `C`, and the only remaining ZK
obligation is a **standard Pedersen opening / the existing range & policy‑satisfaction proofs over `C`** —
**no general‑purpose circuit, no Keccak‑in‑circuit, no new SNARK dependency.**

Rationale (council): the original "prove SHA3↔Pedersen equality in a ZK circuit" framing **solved a
self‑inflicted problem** created by committing the amount twice (implicitly in the SHA3 blob, and in Pedersen)
without binding them. Putting `C` in the intent makes the link structural — a one‑field schema change that
*removes* the heavy‑circuit requirement and *strengthens* binding (Grok). It also dodges a likely
**infeasibility**: ristretto255 is non‑native to Groth16/PLONK/Halo2 over BN254/BLS12‑381, so proving
`C = a·G + r·H` in‑circuit needs non‑native field emulation — potentially hundreds of thousands to millions of
constraints (DeepSeek). Keeping SHA3 in the *witness circuit* was also a non‑sequitur: the transparency log
only needs the *public* digest, not an in‑circuit recomputation.

## Alternatives considered
1. **General‑purpose ZK circuit proving SHA3‑preimage + amount‑extraction + Pedersen‑opening (the previous
   primary) — REJECTED.** Solves a self‑inflicted problem; Keccak‑in‑circuit is large/slow and the
   ristretto255 Pedersen opening is **non‑native** to standard SNARK curves (field emulation → possibly
   infeasible).
2. **Bespoke sigma protocol bridging SHA3 and Pedersen — REJECTED.** No efficient construction (Keccak has no
   algebraic homomorphism); MPC‑in‑the‑head exists but is interactive with large proofs.
3. **Re‑commit with a ZK‑friendly hash (Poseidon) / SNARK‑friendly curve cycle (Pallas/Vesta) — UNNECESSARY**
   under structural binding, and it would add a newer, less‑audited hash or a curve migration.

## Consequences
- **One‑field intent‑schema change:** the canonical intent gains a `commit` field carrying `C`; the kernel
  verifies `C = commit(amount, r)` at admission (it already holds both); the receipt reuses that `C`. The v:2
  malicious‑issuer gap closes **structurally** — the issuer cannot substitute a different `C` (SHA3 binds it)
  and the kernel checked `C` opens to the intent's stated amount.
- **No new proving‑system dependency** — reuses the existing sigma‑protocol range / policy‑satisfaction proofs
  over `C`. This **dramatically de‑risks the grant's hardest deliverable** (was: build a novel SNARK; now: a
  schema change + reuse existing openings).
- **Caveats still requiring the audit:** (a) a **range check on `a`** so the committed value is a valid bounded
  non‑negative amount (the existing range proof covers this); (b) **ristretto canonicalization** of the
  embedded `C` bytes; (c) **public‑input binding** of `C`; (d) the kernel's admission‑time `C = commit(a, r)`
  check must be exact. The opening/range‑proof soundness remains classical and **unestablished until the
  external ZK audit**.
- **Trust note:** structural binding ties `C` to the intent the kernel admitted; it does **not** add a
  cryptographic defense against a kernel that is itself malicious at admission — that remains the
  decentralized‑quorum / attestation trust model's job, not this proof's.
- **Grant mapping:** M3 = schema + kernel binding‑check design; M4 = implementation + reuse‑integration +
  re‑verification. Lower risk than the original SNARK plan.

## Honesty note
This ADR is a *design decision record*, not a security result. The construction is unimplemented and unaudited;
the amount‑confidentiality of the underlying Pedersen commitment is information‑theoretic/PQ, but the soundness
of this equality proof is classical and **unestablished** until built and audited.
