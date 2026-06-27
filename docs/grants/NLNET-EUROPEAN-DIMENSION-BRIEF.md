# Nerion — NLnet Restack: European-Dimension SUPPORTING BRIEF

> **What this is.** A **research / fact-base** that deepens the *European-dimension* substance
> for the NLnet **Restack** application. It **complements — does not replace** —
> [`NLnet-NGI-Application.md`](./NLnet-NGI-Application.md), and captures EU-relevant work built
> *after* that dossier was written (the W3C-VC / eIDAS-2.0 projection, EU AI Act alignment, the
> machine-checked TLA⁺ model, FIPS negative-conformance tests).
>
> 🚨 **NLnet bans AI-written proposal text.** This file is **fact-base only — NOT paste-ready
> prose.** Brandon writes the submitted words himself (or discloses AI assistance and justifies it,
> per the Restack FAQ). Treat every paragraph below as source material to paraphrase, not copy.
>
> **Honesty:** Nerion is **UNAUDITED**, pre-product (Local/Private dev), **CNSA-2.0 aligned (not
> validated)**, **pre-FTO**. The grant funds the audit. No claim here is a certification.

---

## 0. Applicant EU-nexus — **FOR BRANDON TO STATE ACCURATELY (do not let anyone else assert these)**

The Restack **European-dimension** criterion is satisfied by the *applicant*, and NLnet permits
**applying as an individual** (no legal entity required — Restack FAQ). The EU nexus rests on:

- **French / EU citizenship** + an **EU residence** (Paris) — *Brandon states and, if asked, documents this.*
- Applying **as an individual** sidesteps any company-structure question entirely.

> ⚠️ **MUST-RECONCILE before submitting.** The dossier's draft bio calls TRELYAN "the Swiss
> foundation behind Nerion." That is **inconsistent** with the now-confirmed fact that **TRELYAN
> Inc. is a US corporation** and Brandon is a **US citizen of French origin** (likely dual). For
> Restack this is cleanly resolved by **applying as an individual French/EU citizen** and not
> foregrounding the US corporate vehicle (which is the *separate* US-federal/SBIR track). Do **not**
> describe TRELYAN as a Swiss foundation unless that is actually true. This brief deliberately makes
> **no** assertion about citizenship, residency, tax status, or entity form — those are yours to state.

Everything in §§1–4 below is **technical EU substance** that is true regardless of the applicant
facts, and is what strengthens the "European dimension beyond the applicant."

---

## 1. eIDAS-2.0 / EU Digital Identity Wallet fit

eIDAS 2.0 (**Regulation (EU) 2024/1183**) introduces the **EU Digital Identity (EUDI) Wallet** and
**electronic attestations of attributes (EAA)**. Nerion now ships a **presentation-layer projection**
(`sdks/ts/src/vc-projection.ts`) that maps its native artifacts into that ecosystem's vocabulary:

- a Nerion **PermitToken → a W3C Verifiable Credential 2.0** (`NerionPermitCredential`),
- a Nerion **ActionReceipt → a W3C Verifiable Presentation**,
- a permit → a **simplified eIDAS-2.0 electronic-attestation** shape,
- plus a **`did:nerion` DID method** outline for the issuer/governance-authority identifier.

**Scope, honestly:** this is **Phase-A — purely presentational and additive** (no new cryptography;
the VC `proof` block only *references* the canonical native **ML-DSA-87** signature). **Phase-B** —
eIDAS-2.0 *qualified*-signature alignment — needs an **accredited module (CMVP-class)** and is out of
scope for this grant. The point for Restack: Nerion is built to **interoperate with the EUDI-Wallet /
SSI stack** the EU is standardising, rather than as a closed silo.

*Verify article/regulation references against the consolidated text before submitting.*

## 2. EU AI Act alignment

The **EU AI Act (Regulation (EU) 2024/1689)** sets accountability duties for **high-risk AI systems**.
Nerion is the **execution-governance substrate** that makes several of those duties *cryptographically
enforceable* rather than procedural — "**govern the verb, never the eye**": auditable, least-privilege
control over what an AI system is permitted to **do**.

| AI Act duty (high-risk AI) | Nerion contribution (substrate, not a compliance program) |
|---|---|
| **Art. 12** record-keeping / automatic logging | Every decision logged to a **tamper-evident Merkle transparency log** with inclusion proofs |
| **Art. 13** transparency to deployers | Externally verifiable receipts; reproducible decision history |
| **Art. 14** human oversight | Fail-closed `decide()` + k-of-n quorum governance + revocation give operators a hard stop |
| **Art. 15** accuracy, robustness, cybersecurity | Post-quantum (ML-DSA-87) authorization; default-deny; deterministic kernel |

**Honest boundary:** Nerion is a *protocol/substrate*; the **deployer still owns its AI-Act compliance
program**. Nerion supplies the machine-verifiable accountability layer, not a conformity assessment.
*(Confirm the article mapping against the consolidated AI Act before relying on it in the proposal.)*

## 3. EU digital sovereignty + ENISA hybrid-PQC

- **Open Internet Stack / tech-sovereignty fit.** Nerion is a **vendor-neutral, Apache-2.0,
  post-quantum building block** for European digital autonomy — an open commons alternative to
  centralized, single-visibility commercial designs. Exactly the "Restack" thesis: interoperable open
  infrastructure over lock-in.
- **ENISA hybrid-migration alignment.** Nerion ships **hybrid KEMs (ML-KEM-1024 + P-384)**, matching
  **ENISA's recommendation to deploy hybrid schemes during the PQC transition** rather than a pure-PQ
  leap. A signed CycloneDX **CBOM** machine-flags any remaining quantum-vulnerable legs.
- **The EU resilience hook:** "**harvest-now, forge-later**" applied to AI-agent authorization — an
  adversary capturing today's classically-signed agent authorizations could forge agent commands once
  a CRQC matures. Nerion binds every agent action to a PQ signature, removing that future-forgery surface.

## 4. EU standards, reproducibility & NGI fit

- **Standardisation** through **IETF / W3C / ETSI / OASIS** — including an intended "govern-the-verb"
  profile and COSE/RATS codepoints — and presentation at **European venues (FOSDEM, IETF, RIPE)**.
- **Reproducible open security research** — the NGI ethos. `docs/REPRODUCE.md` makes **every claim
  runnable** (`npm run gate`, `npm run conformance` → **23/23**, KAT byte-exactness, the TLC model check).
- **Rigorous evidence the dossier predates:** a **TLA⁺ accountable-safety model now MACHINE-CHECKED
  with TLC** across multiple configurations (a model of an *abstraction*, not an implementation proof —
  CI runs it on every change); **FIPS 203/204/205 negative-conformance tests** + a conformance map;
  **~469 automated tests / 23-of-23 conformance**. *(These replace the dossier's stale "365 assertions
  / 12 ADRs" — use the current figures.)*

### Restack eligible-activity mapping (the EU-substance work)

| Restack eligible activity | This brief's substance |
|---|---|
| Scientific research | ZK soundness; the machine-checked accountable-safety model |
| FOSS design/development | the eIDAS-2.0/W3C-VC projection; did:nerion |
| Formal proofs + security audits + CI | TLC model-checking in CI; the bundled ZK/crypto audit (dossier core) |
| Standardisation (incl. body membership) | IETF/W3C/ETSI/OASIS; govern-the-verb profile |
| Documentation | this brief; REPRODUCE.md; EU-AI-Act / DID method docs |
| Packaging for deployability | SDK + projection for EUDI/SSI consumers |

---

## How to use this brief

1. Reconcile the **applicant EU-nexus** (§0) — state French/EU citizenship + EU residence accurately; apply as an individual.
2. Fold the **§§1–4 substance** into the dossier's §4 *European Dimension* — **in Brandon's own words** (NLnet AI-ban).
3. Refresh the dossier's **stale numbers** to current (~469 tests / 23-of-23 / machine-checked TLA⁺) when he rewrites it.
4. Keep the **honesty frame**: UNAUDITED / pre-product / CNSA-aligned / pre-FTO — the grant funds the audit.

*Fact-base only. Conformant is not validated; machine-checked is not implementation-proven; a
design-around is not a legal opinion. Brandon writes and submits the proposal himself.*
