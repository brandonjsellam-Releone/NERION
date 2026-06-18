# PolarSeek — Design-Around & "Apex" Differentiation Strategy

> **Honest boundary first.** Engineering design-around is a legitimate, common
> practice — but it is **not** a legal non-infringement opinion, and nothing
> here guarantees we are "clear of" any patent. We have detailed visibility into
> only **US 9,607,214 B2**; SIGA *claims* 45 patents across 20 jurisdictions
> with a 2012 priority. "Go around **all** patents" cannot be assured by
> engineering alone without the full claim set and qualified patent counsel.
> A written FTO opinion is a hard gate before any public non-infringement claim
> or launch — see [FTO_TODO.md](./FTO_TODO.md). This document is the *technical*
> strategy that makes that FTO as strong as possible.

## 1. Two-axis strategy

**Axis A — Non-infringement by construction (operate in a different field).**
SIGA's asserted chain is perception- and state-based: *camera → static/dynamic
frame decomposition → object-identity continuity → zone occupancy over time →
state-change trigger → gate → record*. PolarSeek implements **none** of these
links. We govern **typed actions** with a **stateless** kernel. Every forbidden
element is enumerated and CI-enforced in [CLEANROOM.md](./CLEANROOM.md) (F1–F8).

**Axis B — Defensive posture (build only on public prior art).** Every PolarSeek
component is a composition of **open, pre-dated standards** — NIST PQC,
IETF RATS/SCITT/COSE/CBOR, UCAN/macaroons, OPA/Cedar. This means the building
blocks are public prior art, strengthening both a non-infringement story (we are
in a different, published technical space) and, if ever needed, an invalidity
analysis. We never read SIGA claims to copy — only to avoid.

## 2. The structural inversion (why we are *different*, not just compliant)

| Dimension | SIGA "Sovereign OS / Commit-Point Gate" | **PolarSeek** |
|---|---|---|
| What is governed | **Perception** + governance fused (the eye) | **Typed actions** only (the verb) |
| Core mechanism | Frame decomposition + object/zone tracking → state-change gate | **Stateless pure-function admission** over one explicit intent |
| State model | Stateful "cognitive loop", real-time state determination | **No cross-decision state**; aggregates enter only as a **signed scalar** |
| Authority model | Policy envelope + zone rules | **Object-capability** (UCAN/macaroon), **attenuation-only**, default-deny |
| Trust topology | **One perpetual sovereign host** (monopoly) | **Decentralized** multi-operator transparency network; **no single veto** |
| Crypto | Classical (2012-era) | **Post-quantum-native + crypto-agile** (SuiteID) |
| Verifiability | Trust-the-sovereign receipt | **Public** SCITT inclusion proofs + **zero-knowledge** selective disclosure |
| Business model | Patent-rent extraction | **Open standard + conformance certification** mark |
| Naming | "commit-point gate", "cognitive loop" | "**admission kernel**", "**admission decision**" (linguistic firewall) |

The point of the table: PolarSeek is not a re-skin of the patented system with
the camera removed. It is an **architecturally inverted** system — capability
security + statelessness + public verifiability — that happens to address an
overlapping market (lawful, auditable machine action) from the opposite
direction.

## 3. Why we are *better* (the "apex" case — concrete, not hype)

Each claim below is a **target with a verification method**, not a boast. "Apex"
means *provable* superiority, audited by the multi-model council and, ultimately,
by external auditors.

1. **Post-quantum-native, by construction.** SIGA's 2012 architecture is
   classical → exposed to harvest-now-decrypt-later. PolarSeek's receipts and key
   establishment are PQ (ML-DSA-87, ML-KEM-1024) with hybrid transport and
   negotiable `SuiteID`. *Verify:* KATs + suite-negotiation tests (green today).
2. **Formally-verifiable determinism.** "Replayable" means **byte-identical**
   re-derivation, and the kernel's soundness/attenuation properties are targeted
   for a **machine-checked** spec (TLA+/Lean, `kernel/spec/`). Most systems
   *assert* determinism; we intend to *prove* it. *Verify:* replay-equality
   tests + the formal model (P1 exit).
3. **Public verifiability with zero disclosure (Plane 2).** Anyone can verify a
   **receipt's** ML-DSA-87 signature + log inclusion **without trusting the
   issuer** and **without leaking PII** (commitments + ZK for "amount <
   threshold"-style properties). Note: the hot-path **PermitToken is
   session-MAC'd (HMAC-SHA-384), not publicly verifiable** — public verifiability
   is deliberately a Plane-2 property, not a Plane-1 one. *Verify:* an external
   CLI verifies a receipt with no issuer trust (P2 exit).
4. **Decentralized trust, centralized accountability.** Multiple independent,
   mirrorable log operators with gossiped roots and **split-view detection**;
   threshold/MPC governance with **no single veto**; a named accountable-operator
   legal entity for liability. The opposite of a single sovereign chokepoint.
5. **Least-privilege capability security.** Attenuation-only grants (an agent can
   only narrow authority, never broaden it), per-action ceilings, signed-scalar
   aggregate caps, step-up predicates — a stronger, more composable authority
   model than a perception-driven policy envelope.
6. **Latency without compromise.** The three-plane split (hot <1 ms stateless,
   nearline batched PQ, offline settlement) targets invisible latency on the hot
   path while keeping full PQ assurance off the critical path. *Verify:*
   benchmarks once the Rust hot-path lands (target, not yet measured — see
   [adr/ADR-0002](./adr/ADR-0002-ts-reference-and-kem-pairing.md)).

## 4. Genuinely novel contributions (flag for counsel: own-IP + defensive publication)

These combinations appear novel relative to the prior art we build on. **Do not
treat as patentable or as ours without counsel.** Two tracks: (a) **defensive
publication** to keep them free and block others from patenting; (b) possible
**own filings** where counsel sees genuine novelty.

- **Signed-scalar aggregate inputs to a stateless kernel** — sequence/rate
  enforcement with zero in-kernel state, the aggregate authenticated as an
  explicit scalar (the deliberate antithesis of state-change-triggered gating).
- **SuiteID-bound signing/MAC transcripts** for downgrade resistance across a
  crypto-agile protocol (the suite is inside the authenticated bytes).
- **ReplayBundle byte-identical determinism contract** spanning pinned evaluator
  hash + canonical CBOR + explicit time/fact snapshots.
- **Risk-tiered three-plane routing** (T0–T3 selecting how much assurance runs
  synchronously) as a unified latency/assurance dial.

## 5. Linguistic firewall (CI-enforced)

Never use, in code/docs/marketing/API names: *commit-point gate, cognitive loop,
perception, (frame) decomposition, static/dynamic features, zone occupancy,
object tracking, sovereign gate.* Use: *admission kernel, admission decision,
action intent, capability, receipt, transparency log.* Enforced by
`tools/cleanroom-lint.mjs`.

## 6. What turns "design-around" into "clear to operate"

This is engineering. The following is **required** before any public claim — see
the [FTO_TODO.md](./FTO_TODO.md) checklist: enumerate/verify the full SIGA patent
family and claims; chart PolarSeek's admission path element-by-element against
them; have counsel test the "verb-not-eye" and statelessness boundaries; assess
the "commit-point gate" terminology risk; complete export-control classification
of the crypto; and name the accountable legal entity the opinion is addressed to.
