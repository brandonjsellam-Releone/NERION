<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AI-Security Controls → Nerion Hardening Map

> **What this is.** A mapping of the AI-security controls in the deep-read corpus
> — the SANS *Own AI Securely* Secure AI Blueprint, the *Security for AI Blueprint*
> (six-layer LLM framework), NIST CSWP.29 / NIST CSF, and NIST AI RMF — onto
> Nerion's "**govern the verb, never the eye**" execution-governance model.
>
> **Honesty statement.** Nerion is a **protocol**, not a deployed AI system. It
> hardens the *action-authorization and audit* layer of an AI agent system; a
> deployer must still supply the surrounding controls (model defense, data
> privacy, network security). Nerion is **CNSA-2.0 aligned and UNAUDITED**. This
> map claims coverage of the *governance/accountability* surface, not the whole
> AI attack surface.

## Where Nerion sits in the SANS three-track model

SANS distils its controls into three tracks: **Protect AI · Utilize AI · Govern AI**
(SANS, *Own AI Securely*, 2025, p.3). Nerion is squarely a **Govern AI** technology
— the track SANS defines as ensuring "every AI system is **documented, auditable,
and aligned with global standards**." Nerion makes that property *cryptographic and
machine-verifiable* rather than procedural:

| SANS Govern-AI requirement | Nerion mechanism |
|---|---|
| Every AI system documented & auditable | Every agent action bound to a signed Action Manifest, logged to a tamper-evident Merkle log with inclusion proofs |
| Accountability / oversight | Non-repudiable ML-DSA-87 (FIPS 204) signatures on every decision; per-plane key isolation |
| Aligned with global standards | CNSA-2.0 algorithm set; FIPS 203/204/205 (see `FIPS-CONFORMANCE-MAP.md`); EU AI Act / NIST AI RMF mappings below |

## Control-area mapping

| # | Control area | Source (cited) | How Nerion addresses it | Gap / deployer responsibility |
|---|---|---|---|---|
| 1 | **Agent action authorization** | SANS *Govern AI* (p.3); AI Blueprint "LLM Agents" layer (p.6) | `decide()` is stateless & **fail-closed**: returns `deny` unless a verifiable PQ capability authorizes the *specific* action. Govern the verb (the action), never the eye (the model's perception). | Deployer must route all consequential agent actions through `decide()`. |
| 2 | **Non-repudiation & audit trail** | SANS Govern AI; NIST AI RMF (MANAGE/MEASURE); EU AI Act Art.13 | Every decision logged to a Merkle log; ML-DSA-87 signatures make each decision attributable and tamper-evident; inclusion proofs enable third-party verification. | Log retention/availability is a deployment concern. |
| 3 | **Prompt-injection / tool-use safety** | AI Blueprint threat-modeling for LLMs (p.12); SANS Protect AI | Nerion does not parse prompts (by design — "never the eye"). Its defense is that a *hijacked* agent still cannot exceed its **signed authority**: an injected instruction to perform an unauthorized action yields `deny`. This bounds the blast radius of prompt injection without trying to detect it. | Input-side prompt-injection *detection* is out of scope; Nerion limits impact, deployer adds detection. |
| 4 | **Rogue / hallucinating agent containment** | SANS Protect AI; AI Blueprint attack surface | Even an agent that controls its own runtime cannot forge new authorizations — capability signatures are PQ (ML-DSA-87) and verified by an independent kernel. | Requires the kernel to run in a trust boundary the agent cannot tamper. |
| 5 | **Key custody (KMS/HSM/attestation)** | AI Blueprint datacenter/cloud layers; CNSA 2.0 | `keystore/` provides pluggable custody (Azure KV / AWS KMS / PKCS#11 / sealing providers); root signing via SLH-DSA-SHAKE-256f. | HSM/CMVP-validated custody is a deployment selection; FIPS 140-3 not yet initiated. |
| 6 | **Supply-chain integrity** | AI Blueprint; NIST CSF (Protect) | Apache-2.0 open source; REUSE-3.3 license compliance; SLSA provenance + CycloneDX SBOM CI (see `apex/innovation-sprint1`); SHA-pinned actions; gitleaks. | Downstream consumers should verify provenance on release artifacts. |
| 7 | **Quantum-resistant credentials ("harvest now, forge later")** | djb, *Introduction to PQC*; CNSA 2.0 | Agent authorizations are signed with PQ signatures, so credentials captured today cannot be forged when quantum computers mature. Symmetric sizing (AES-256, SHA-384) follows the Grover-only rationale (djb §2). | — |
| 8 | **Replay / freshness** | NIST CSF (Protect); protocol design | Sequence numbers + epoch binding in permits/receipts; salted v:1 intent commitment (ADR-0014). | — |
| 9 | **Incident response / detect** | SANS *Utilize AI*; NIST CSF (Detect/Respond) | The Merkle audit log is the forensic substrate: every decision is reconstructable and tamper-evident, supporting machine-speed IR. | Detection tooling / SOC integration is deployer-supplied. |
| 10 | **Governance fluency / documentation** | SANS Govern AI; EU AI Act Annex IV | `docs/THREAT_MODEL.md`, `ASSURANCE.md`, `STATUS.md`, the ADR series, and this corpus form the Annex IV-style technical-documentation package. | Org-specific risk management remains the deployer's. |

## NIST CSF function mapping (governance subset Nerion supports)

| CSF function | Nerion contribution |
|---|---|
| **Identify** | Action Manifest enumerates what an agent is authorized to do; capability/grant model makes authority explicit. |
| **Protect** | Fail-closed `decide()`, PQ capability signatures, per-plane key isolation, replay protection. |
| **Detect** | Tamper-evident Merkle log; equivocation detection in the ledger. |
| **Respond** | Cryptographic attribution of every decision; revocation via capability/grant model. |
| **Recover** | Deterministic, reconstructable decision history from the log + inclusion proofs. |

## Regulatory alignment (governance surface only)

- **NIST AI RMF** — Nerion provides the *cryptographic enforcement* substrate for GOVERN/MAP/MEASURE/MANAGE accountability controls (SANS p.2 references AI RMF as the trustworthiness framework).
- **EU AI Act** — Art.13 transparency & Art.17 quality-management map to the signed-decision + Merkle-log chain (detailed in `apex/innovation-sprint1` EU-AI-ACT-ALIGNMENT).
- **America's AI Action Plan** — SANS frames the three-track model as the AAIAP alignment roadmap (p.3); Nerion is the verifiable Govern-AI primitive.

## Recommended follow-ups (additive, ordered)

1. Publish a one-page "Nerion as your Govern-AI control" brief mapping rows 1–2 to a deployer's AI RMF profile.
2. Add a worked example: an agent under prompt injection attempting an out-of-scope action → `decide()` deny → logged. (Demonstrates row 3 containment concretely.)
3. Cross-reference this map from `docs/ASSURANCE.md` so auditors see the AI-governance surface alongside the crypto surface.

*Sources: SANS, "Own AI Securely with SANS" (2025), pp.2–3; "Security for AI Blueprint" (F. Cardoso), pp.4–14; NIST CSWP.29; NIST CSF; NIST AI RMF; D.J. Bernstein, "Introduction to post-quantum cryptography." Read during the 2026-06 corpus deep-read; see `docs/PQC-CORPUS-FINDINGS.md`.*
