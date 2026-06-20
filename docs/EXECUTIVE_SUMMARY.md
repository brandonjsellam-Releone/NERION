<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Executive Summary

**An open, post‑quantum, decentralized protocol for governing what AI agents are allowed to _do_.**

## The problem
Autonomous AI agents increasingly take real actions — tool‑calls, API requests, financial transactions. The
unsolved control problem is **provable, auditable, least‑privilege bounds on those actions**, with evidence
that survives both a future quantum adversary and an audit. Today's approaches either trust a central operator
that must *see every action* (a single point of visibility, control, and failure), or bolt on classical
signatures a cryptographically‑relevant quantum computer (CRQC) will break.

## The thesis — *govern the verb, never the eye*
Nerion governs **typed actions** (the verb), never perception (the eye). A denied action never executes;
every allowed action emits a post‑quantum, externally‑verifiable receipt — with **no operator in the trust
loop**.

## What is real today (independently reproducible from the open source)
- **Built + verified:** **297 passing tests**, a **20/20 machine‑checked conformance report**
  (`npm run conformance`) — reproducible by anyone from the Apache‑2.0 source.
- **Post‑quantum‑native:** ML‑DSA‑87 / ML‑KEM‑1024 / SLH‑DSA (FIPS 203/204/205), hybrid KEMs, and a
  **CNSA 2.0 conformance oracle** that emits a signed, transparency‑log‑anchored verdict.
- **Decentralized accountability:** **k‑of‑n quorum receipts** — no single host can mint one — over a pure
  proof‑of‑stake settlement layer with accountable finality.
- **Zero‑knowledge compliance:** prove an action satisfied policy (e.g. amount ≤ ceiling) **without revealing
  the amount** — a move a see‑everything governor structurally cannot make.
- **Standards‑grounded:** RFC 9052 (COSE), RFC 6962 (Merkle transparency), RATS/EAT, SCITT‑style logs,
  CycloneDX CBOM, SLSA / in‑toto provenance.

## Why it is categorically different from a centralized "commit‑point gate"
| Axis | Centralized gate | **Nerion** |
|---|---|---|
| Trust | one operator sees every action | **decentralized k‑of‑n; no operator in the loop** |
| Crypto | classical (CRQC‑breakable) | **post‑quantum‑native, CNSA 2.0‑aligned** |
| Privacy | must see the payload to attest | **zero‑knowledge — prove compliance, reveal nothing** |
| Openness | proprietary | **open Apache‑2.0 standard** |

*(A centralized gate can be simpler and lower‑latency; the axes above are the structural properties where an
open, decentralized, post‑quantum design leads — not a claim that it wins on every dimension.)*

## Government fit (public standards only — no classified inputs)
Grounded entirely in the authoritative public corpus: **NSA CNSA 2.0**, NIST **FIPS 203/204/205** + SP 800‑208,
**SCITT / RATS**, NIST **Zero Trust**, and the **NSM‑10 / OMB M‑23‑02** cryptographic‑inventory direction (the
signed CBOM supports that inventory requirement). No classified material was used, accessed, or is needed.

## Institutional‑finance fit
For agentic transaction flows, Nerion provides **least‑privilege authority that cannot be over‑exercised,
regulator‑ready evidence anyone can verify, and privacy‑preserving compliance proofs** — auditable governance
of what an AI may transact, without exposing the transaction itself.

## Honest status — what is NOT yet closed
Candor is the point — and the credibility edge. Nerion is **code‑complete and conformant, _not_ validated.**
Four external gates remain, **none closable by code alone, and none claimed closed:**
1. **Patent FTO opinion** (counsel) — the project is pre‑FTO and makes **no** non‑infringement claim.
2. **External cryptography / ZK audit** — the novel ZK compositions over audited primitives are **UNAUDITED**.
3. **FIPS 140‑3 hardware** (HSM / TEE) — key custody is wired to a cloud KMS and verified live; a hardware
   boundary is the next rung.
4. **FIPS CMVP validation** (accredited lab).

*Conformant is not validated; built is not audited; provisioned is not in‑use; a design‑around is not a legal
opinion.*

## The ask
A pilot, and the funding to close gate 2 (an independent ZK / cryptography audit) — a grant **application** to an
EU open‑source R&D programme (NLnet Restack) is in preparation (**not yet secured**). Everything claimed above is
verifiable **today** from the open source; everything not yet closed is labeled as such.
