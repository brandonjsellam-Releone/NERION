# Nerion — Audit‑Funding Outreach (DRAFTS — you send, I only draft)

> These are the **parallel** audit‑funding paths that are open **now**, independent of the NLnet Restack
> pause (Restack opens ≈ Sept 2026). Use them to source/co‑fund the independent ZK/crypto audit (Gate 2).
> **The assistant cannot send these** — they are drafts for **you** to review, personalise, and send.
> Personalise the bracketed `[...]` bits and trim to your own voice before sending.

## Sequencing (recommended)

1. **NLnet Restack = primary** (bundles audit support; submit when the call opens ~Sept 2026).
2. **OSTIF = audit‑sourcing partner** — best engaged _once NLnet funding is being secured_ (say so; it
   materially improves standing). Strong technical match ("complex cryptography"), weaker fit for a brand‑new
   project, so lead with the crypto depth + the co‑funding angle.
3. **OTF Red Team Lab = secondary** audit path, gated by an internet‑freedom narrative (frame deliberately).

---

## 1. OSTIF — Open Source Technology Improvement Fund

**Channel:** <https://ostif.org/get-an-audit/> (intake form / email). **Ask:** a scoped ZK‑protocol +
cryptography review, co‑funded with NLnet.

**DRAFT**

> Subject: Audit interest — Nerion, a post‑quantum + zero‑knowledge protocol (NLnet co‑funding in progress)
>
> Hi OSTIF team,
>
> I maintain **Nerion**, an open‑source (Apache‑2.0), post‑quantum, zero‑knowledge protocol for governing
> the _actions_ of AI agents — typed tool‑calls / API requests / transaction intents, not perception. The
> codebase is complete and reproducible (365 tests, a 24/24 internal conformance report), built on audited
> `@noble` primitives. The part I want reviewed is the layer **on top** of those primitives: bespoke
> zero‑knowledge constructions that are currently **unaudited** —
>
> - a Pedersen/ristretto255 **range proof** (bit‑decomposition + Chaum‑Pedersen OR‑proofs, SHAKE256
>   Fiat‑Shamir) — soundness, special‑soundness/simulation, generator‑provenance, strong‑FS (Frozen‑Heart);
> - a hidden‑amount **policy‑satisfaction proof** and a new **Pedersen↔SHA3 commitment‑equality proof**.
>
> I'm being honest that this is **pre‑adoption R&D**, not widely‑deployed infrastructure — but it's a strong
> match for OSTIF's complex‑cryptography focus, and I'm in the process of securing **NLnet / NGI Open Internet
> Stack (Restack)** funding which bundles audit support, so this could be **co‑funded** rather than fully
> sponsor‑funded. Could we talk about scope and whether this fits your pipeline?
>
> Repo + auditor pack: [public repo URL] · Audit scope: docs/AUDIT_PACKAGE.md · Contact: brandon.sellam@gmail.com
>
> Thanks, Brandon Sellam

---

## 2. OTF — Open Technology Fund, Red Team Lab

**Channel:** <https://www.opentech.fund/labs/red-team-lab/>. **Ask:** a third‑party crypto audit on the
internet‑freedom relevance. **Frame:** protecting at‑risk users from centralized‑visibility surveillance.

**DRAFT**

> Subject: Red Team Lab — audit interest for Nerion (privacy‑preserving AI‑action governance)
>
> Hi OTF team,
>
> **Nerion** is an open‑source (Apache‑2.0) protocol that lets AI agents act only within provable,
> least‑privilege bounds, while producing **post‑quantum, zero‑knowledge** evidence that reveals nothing about
> the action itself. Its internet‑freedom relevance: it is an open, decentralized alternative to centralized
> "see‑every‑action" governance systems — no single host can mint a receipt, and compliance is provable
> _without_ exposing what a user's agent did. That matters for journalists, civil‑society, and at‑risk users
> who need automated tools that don't create a central surveillance chokepoint.
>
> The zero‑knowledge layer is **unaudited**; I'm seeking an independent crypto/ZK review. I'd value a
> conversation about whether this is "otherwise relevant to internet freedom" enough for the Red Team Lab.
>
> Repo: [public repo URL] · Threat model: docs/THREAT_MODEL.md · Contact: brandon.sellam@gmail.com
>
> Thanks, Brandon Sellam

---

## Honesty guardrails (keep these in whatever you send)

- Say **pre‑adoption / no external adopters yet** — do not imply deployment.
- Say the ZK layer is **UNAUDITED**; the `@noble` primitives underneath are audited, the compositions are not.
- Make **no** non‑infringement / FIPS / production claims.
- If you used AI to draft, that's fine for an email — but make the final wording **yours**.
