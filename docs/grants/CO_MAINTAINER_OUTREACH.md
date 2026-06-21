# Nerion — technical co-maintainer outreach (crypto / security)

> **DRAFT for Brandon to post/send — personalise + trim to your voice.** Goal: recruit (and then *name*)
> an EU-based technical co-maintainer with cryptography or security depth **before** the NLnet Restack
> submission. This is the single highest-leverage move for the §3 "can-execute" bar — it converts the
> biggest reviewer doubt (a PQ/ZK protocol led by a finance/dev founder) into a strength. See
> [`NLnet-NGI-Application.md`](./NLnet-NGI-Application.md) §3.

## The role (how to frame it)
Technical co-maintainer for **Nerion** — open-source (Apache-2.0), **post-quantum, zero-knowledge
execution-governance protocol for AI/agent actions** ("govern the verb, never the eye"). Part-time /
advisory to start. Would co-own the cryptographic surface — ZK range/policy proofs, PQ signatures/KEMs,
the v:2 commitment-binding R&D — and help shape the **independent external audit** the project is
sourcing via NLnet / NGI Zero. **EU-based preferred** (deepens the European-Dimension story).

## Where to look
- **ZK / applied-crypto:** ZK Hack, zkSecurity, Zellic, Veridise, 0xPARC communities; IACR / Real World Crypto.
- **Post-quantum:** the `pqc-forum`, Open Quantum Safe / liboqs contributors, ENISA PQC circles.
- **OWASP** (you're a member): your local chapter + the **GenAI Security Project** working group.
- **NLnet/NGI ecosystem:** the NGI Zero community channels; you can even list "seeking a crypto co-maintainer" on the application itself.
- **Rust / `@noble` crypto** contributors (Nerion builds on audited `@noble` + a Rust crate).

## Draft message
> **Subject:** Co-maintainer (cryptography/security) — Nerion, an open PQ + ZK agent-action governance protocol (NLnet track)
>
> Hi — I'm Brandon Sellam, founder of TRELYAN and maintainer of **Nerion** (Apache-2.0): an open,
> post-quantum, zero-knowledge protocol that governs what AI agents are allowed to *do* — typed tool-calls
> and transaction intents — and emits externally-verifiable, post-quantum, zero-knowledge evidence. The
> code is complete and reproducible (public repo, full test + conformance suite, SBOM). The novel ZK/crypto
> compositions layered on **audited `@noble` primitives are themselves UNAUDITED** — and that's exactly what
> an independent audit (which I'm sourcing through NLnet / NGI Zero) is meant to validate.
>
> I'm looking for a **technical co-maintainer with cryptography or security depth** to co-own that surface:
> ZK soundness (Pedersen/ristretto255 range + policy proofs, strong/transcript-binding Fiat-Shamir), PQ
> signatures/KEMs, and the commitment-binding design — and to help scope the audit. Part-time / advisory to
> start; EU-based a plus. Repo + design ADRs: https://github.com/brandonjsellam-Releone/NERION
>
> Interested, or know someone who might be? — Brandon (fondation@trelyan.ch)

## Honesty guardrails (keep in whatever you send)
- The ZK layer is **UNAUDITED**; the `@noble` primitives underneath are audited, the compositions are not.
- **Pre-adoption R&D** — no production / non-infringement / FIPS claims.
- OWASP membership is community standing, not a certification.

## Ideal co-maintainer profile + screening

**Must-have (one of the two crypto tracks):**
- **ZK / applied crypto:** Sigma protocols, Pedersen/ristretto255 commitments, Bulletproofs-style range proofs, Fiat-Shamir (and why transcript-binding matters -- Frozen-Heart), special-soundness / HVZK reasoning.
- **Post-quantum:** ML-DSA / ML-KEM / SLH-DSA, lattice or hash-based constructions, hybrid KEMs, FIPS 203/204/205 familiarity.
- Plus, either track: Rust and/or TypeScript; comfort reading/writing audit-grade crypto code.

**Nice-to-have:** **EU-based** (deepens the NLnet European-Dimension); prior open-source crypto maintainership; formal verification; standards work (COSE/RATS/SCITT, RFC 9380 hash-to-curve).

**5 screening questions:**
1. How do you make a Fiat-Shamir transform transcript-binding to resist Frozen-Heart / weak-FS -- what MUST go into the challenge hash?
2. Pedersen commitments: which property (hiding vs binding) is information-theoretic and which is computational, and which one does a quantum computer break? What does that imply for our range proofs?
3. Sketch a special-soundness extractor for a Chaum-Pedersen OR-proof (bit in {0,1}).
4. How would you scope an independent audit of ~2-3 novel ZK constructions (~1.5-3k LOC over audited @noble) -- what's first?
5. ristretto255 for range proofs -- what do you like / worry about? How would you pin generator-H provenance?

(Strong answers to 1-3 + sensible 4-5 = a real fit. See ADR-0016 / ADR-0017 in ../adr/ for how we already reason about these.)

## Tailored hooks per lane (swap into the draft message above)
- **ZK lane:** "...the unaudited part is a Pedersen/ristretto255 range + policy-satisfaction proof (bit-decomposition + Chaum-Pedersen OR-proofs, SHAKE256 Fiat-Shamir) plus a new commitment-equality binding -- I want a ZK co-maintainer to co-own soundness and the audit."
- **PQ lane:** "...it is PQ-native (ML-DSA-87 / ML-KEM-1024+P-384 hybrid / SLH-DSA), CNSA-2.0-aligned, with a signed CycloneDX CBOM -- I want a PQ co-maintainer to co-own the migration toward PQ-binding commitments (see ADR-0022)."
- **OWASP / Rust / NLnet lane:** "...built on audited @noble + a Rust hot-path crate, REUSE-compliant and SBOM'd, targeting OWASP GenAI agent-action risks -- looking for a security-minded co-maintainer; EU-based a plus for our NLnet track."

## How to name them in NLnet section 3 (once you have someone)
Add one sentence after your bio:
> "Cryptographic execution is co-owned with **[Name]** ([one-line credential -- e.g. ZK auditor at X / PQ researcher at Y], **[EU country]**), who co-maintains the ZK/PQ surface and the audit interface -- closing single-maintainer risk and deepening the team's cryptographic depth and European footprint."

That single line is what flips the Stage-2 "can you execute?" question from a doubt into a strength.
