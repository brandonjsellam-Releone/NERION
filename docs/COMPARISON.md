<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Where Nerion fits — vs. the tools you already use

> Nerion governs **what an autonomous agent is allowed to _do_** (typed actions), with
> **post-quantum, externally-verifiable** evidence. That overlaps several familiar
> categories without replacing any of them — it *composes* their ideas. This page places
> Nerion against tools you likely already run, so you can see the gap it fills.
>
> **Honesty first:** Nerion is **UNAUDITED**, pre-product (Local/Private dev), CNSA-2.0
> *aligned* (not validated), and its ZK layer's soundness is **classical** (transitional,
> not-yet-PQ). None of the contrasts below are quality or security claims — see
> [ASSURANCE.md](ASSURANCE.md) and verify everything yourself via [REPRODUCE.md](REPRODUCE.md).

## At a glance

| Capability | Policy engines (OPA/Rego, Cedar) | Capability/identity (UCAN, macaroons, biscuit, SPIFFE/SPIRE) | Supply-chain transparency (in-toto, SCITT, SLSA, Sigstore) | **Nerion** |
|---|---|---|---|---|
| Decides allow/deny on an **action** | ✅ | partial (conveys authority) | ✗ (attests artifacts) | ✅ (`decide()`, default-deny) |
| **Post-quantum** authorization | ✗ (classical) | ✗ (classical sigs) | mostly classical | ✅ ML-DSA-87 / ML-KEM-1024 / SLH-DSA |
| **Externally-verifiable receipt** of the decision (no operator trust) | ✗ | ✗ | ✅ for artifacts | ✅ ML-DSA-87 receipt + Merkle inclusion, CLI-verifiable |
| **Decentralized** (no single host can mint a receipt) | ✗ | ✗ | varies | ✅ k-of-n quorum receipts |
| **Zero-knowledge** policy satisfaction (prove compliance, reveal nothing) | ✗ | ✗ | ✗ | ✅ (bespoke, **UNAUDITED**, classical soundness) |
| Tamper-evident **action** audit log | ✗ | ✗ | ✅ for builds | ✅ RFC-6962 transparency log |

## How Nerion relates to each

- **Policy engines (OPA/Rego, AWS Cedar).** They answer *"is this request allowed?"* — and
  Nerion's `decide()` does too (stateless, default-deny, fail-closed). The difference is
  *afterward*: OPA emits a decision log for **you** to trust; Nerion emits a **post-quantum,
  independently-verifiable receipt** anchored in a transparency log, plus optional
  zero-knowledge proof of policy satisfaction. **Use both:** keep your policy language;
  Nerion makes the decision *provable to a third party* and *quantum-durable*.

- **Capability / identity systems (UCAN, macaroons, biscuit, SPIFFE/SPIRE).** These convey
  and attenuate **authority** ("this principal may call X"). Nerion's capability layer is
  similar (least-privilege, attenuating-only delegation), but adds (a) a *verifiable record
  that the authority was exercised*, and (b) ZK proof of *policy* satisfaction, not just
  possession of a token. Nerion deliberately *reuses* these patterns rather than competing.

- **Supply-chain transparency (in-toto, SCITT, SLSA, Sigstore).** These attest **artifacts
  and builds** — what was produced. Nerion attests **runtime agent actions** — what an agent
  *did*, before it executes. It reuses the same transparency-log plumbing (SCITT-style,
  RFC 6962) and signature envelopes (COSE/RFC 9052, RATS/EAT), pointing them at the action
  layer instead of the artifact layer.

- **Proprietary "commit-point gate" / single-visibility designs.** Nerion is the open
  (Apache-2.0), post-quantum, decentralized, govern-the-verb alternative. The technical
  contrast — and the explicit caveat that this is **engineering intent, not a legal
  non-infringement opinion (Nerion is pre-FTO; no characterization of any third party's IP
  is made)** — is in [DESIGN_AROUND.md](DESIGN_AROUND.md) / [CLEANROOM.md](CLEANROOM.md). This
  page makes no proprietary comparison beyond that pointer.

## When Nerion is (and isn't) the right tool

**Reach for Nerion when** you need: provable, least-privilege bounds on **autonomous agent
actions**; **post-quantum** authorization that survives "harvest-now, forge-later"; receipts a
third party can verify **without trusting the operator**; or ZK proof of compliance without
revealing the action.

**Nerion is _not_** a perception/content-safety layer (it governs the verb, never the eye), a
key-management product (it uses your HSM/KMS, see `keystore/`), a generic policy *language*
(bring OPA/Cedar), or production-ready today (Local/Private dev; UNAUDITED; pre-FTO). For an
artifact/build attestation need, use in-toto/SCITT/SLSA — Nerion complements, not replaces them.

*See it for yourself: [REPRODUCE.md](REPRODUCE.md) turns every claim above into a runnable check.*
