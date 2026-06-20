# PolarSeek Launch Readiness — Code‑Complete, NOT Launch‑Cleared

**Status (2026‑06‑20):** P0–P4 software build complete — **291 tests pass**, `npm run conformance` →
**20/20 CONFORMANT**, Rust hot‑path foundation compiles. **That is the entirety of what code can
close.** Four independent gates stand between "code complete" and any public non‑infringement claim,
GA launch, or paid pilot sign‑off — and **none of the four is closable by PolarSeek alone.** Each
requires an external party (patent counsel, a crypto/ZK audit firm, a hardware/cloud vendor, an
accredited CMVP/CST lab) to act independently.

This index states, per gate, exactly what PolarSeek has **prepared** (to accelerate the external
party), what the external party **must do**, and what stays **blocked** until done. Full packages:
[FTO_PACKAGE.md](./FTO_PACKAGE.md), [AUDIT_PACKAGE.md](./AUDIT_PACKAGE.md),
[DEPLOY_HARDWARE.md](./DEPLOY_HARDWARE.md).

> **HARD RULE** ([FTO_TODO.md](./FTO_TODO.md) banner + STATUS.md): no public statement that PolarSeek
> "does not infringe / is clear of / designs around / is FIPS‑validated / is audited / is
> production‑ready" may be made, and no GA launch or paid pilot sign‑off may proceed, until **all
> four** gates are closed by their respective external parties. The gates are jointly blocking:
> closing three of four still leaves launch blocked.

---

## Gate 1 — Freedom‑To‑Operate (FTO) patent opinion
*(vs. SIGA "Sovereign OS" / "Commit‑Point Gate" family; anchor US 9,607,214 B2)*

- **Prepared (engineering input, NOT a legal opinion):** an element‑by‑element design‑around mapping
  skeleton — the load‑bearing **"govern the verb, never the eye"** wedge (no perception/cognitive‑loop
  pillar) plus governance‑only fallbacks (stateless pure‑function kernel; no "commit‑point gate"
  branding; decoupled SCITT/COSE receipts) — **each flagged as a hypothesis, not a finding**; the
  dual‑claim split (perception "eye" vs. governance "gate") counsel must make; prior‑art *candidates*;
  a CI‑enforced clean‑room record ([CLEANROOM.md](./CLEANROOM.md), `npm run lint:cleanroom`); and the
  verbatim disclaimer + counsel checklist.
- **External party must do:** qualified patent counsel independently verifies the actual SIGA patent
  numbers/priority/jurisdictions (the ~45‑granted / 2012 / ~20‑jurisdiction / ~500‑provisional claims
  are **unverified deck inputs**), charts every claim, maps PolarSeek's **as‑built** path element‑by‑
  element (literal **and** doctrine‑of‑equivalents), and **delivers a written jurisdiction‑specific FTO
  opinion** addressed to the accountable entity.
- **Blocks:** everything outward‑facing — any non‑infringement statement, any "designs around"
  marketing, investor/customer infringement assurance, and GA launch. A **hard launch stop independent
  of the other three.**

## Gate 2 — External cryptography / ZK protocol audit
*(Trail of Bits / NCC / Cure53‑grade)*

- **Prepared:** a quote‑ready scope over the **five unaudited compositions** PolarSeek wrote on audited
  `@noble` primitives — (A) ZK range proof `zkrange`, (B) policy‑satisfaction `policyproof`, (C) ECVRF
  `vrf`, (D) k‑of‑n quorum receipts, (E) COSE_Sign1/RATS — with per‑component **claims‑to‑verify** (not
  asserted facts), the **three known residual gaps we surfaced ourselves** (v:2 Pedersen↔SHA3 equality
  gap; ≥2/3 view‑change round‑skip / LEDGER‑007; software OTS‑state reuse‑under‑restore), the threat
  model, runnable test vectors (RFC 9381 VRF KATs; 3‑language KATs; `npm run conformance`), and eight
  specific auditor questions.
- **External party must do:** independently verify or **refute** each claim (soundness, ZK/hiding,
  binding, fail‑closed, the PQ‑vs‑classical split) without rubber‑stamping our reasoning; confirm or
  invalidate the three known gaps and their exploitability; deliver a signed report stating which
  components (if any) may carry a production claim **after remediation**.
- **Blocks:** any production privacy/soundness claim resting on the ZK/VRF/quorum/COSE work — most of
  all the **ZK Policy‑Satisfaction headline differentiator**. Until then the crypto stays "audited
  group, **UNAUDITED protocol**." Does **not** block the local dev demo (no production claim).

## Gate 3 — FIPS 140‑3 L3+ HSM / TEE hardware wiring

- **Prepared:** the injectable adapter **seams are built + unit‑tested with fakes** (never run against
  live silicon here): `Pkcs11WrapEngine`/`Pkcs11KeyProvider`, the `HbsSignEngine` + `OtsStateStore` +
  reserve‑before‑sign `HbsKeyProvider`, the Azure KV / AWS KMS sealing backends (Azure KV is
  *provisioned* — credentials only, never exercised end‑to‑end), and the `QuoteVerifier` registry +
  N‑of‑M appraisal. Model‑B custody means a classical‑only HSM/KMS suffices to custody PQC keys.
- **Honest corrections (the runbook overstated these):** the three bindings (`Pkcs11WrapEngine`,
  `HbsSignEngine`, per‑format `QuoteVerifier`) are **net‑new code the operator must write and validate
  against their specific hardware** — "config not architecture" is an expectation, not a guarantee.
  The N‑of‑M attestation defense **defeats nothing today** (hardware attestation fails closed until
  real verifiers are wired). The software OTS‑state store is **provably not reuse‑safe** and is
  hard‑gated dev‑only.
- **External party must do:** procure a **CMVP‑listed** FIPS 140‑3 L3+ PKCS#11 HSM whose certificate
  covers SP 800‑208 LMS/XMSS with an **in‑boundary hardware monotonic counter** (in writing);
  provision confidential‑compute + quote‑verification SDK/roots; **write + validate the three bindings
  against that silicon**; re‑run the gate + a live provision→sign→verify round‑trip on‑hardware.
- **Blocks:** any hardware‑rooted custody, TEE‑attestation, or reuse‑safe HBS code‑signing claim, and
  Consortium/Public‑tier deployment. Prerequisite for Gate 4 Path A.

## Gate 4 — FIPS 140‑3 CMVP validation

- **Prepared:** PolarSeek **emits the surrounding evidence** a validator consumes — signed CNSA 2.0
  verdict (C16), signed CBOM (C17), COSE_Sign1/RATS (C19), `npm run conformance` → 20/20, and the
  standalone receipt verifier — all signed + log‑anchored + externally verifiable.
- **Critical honesty constraint:** assembling this evidence and **consuming** a CMVP‑validated HSM/CSP
  boundary **does NOT make PolarSeek FIPS 140‑3 validated**; PolarSeek's in‑process ML‑DSA/ML‑KEM
  signing remains **outside** that vendor certificate. CNSA 2.0 "conformant (transitional)" is
  machine‑checked against our **own oracle** — it is **not** third‑party CMVP validation. **No
  configuration in this repo produces a FIPS validation.**
- **External party must do:** **Path A** (pilots) — place FIPS‑relevant ops behind an already‑CMVP‑
  validated module and document PolarSeek as a *consumer*, explicitly noting the PQC signing stays
  outside; or **Path B** — contract an accredited CST lab (Leidos/atsec/DEKRA/Acumen), define a
  boundary, CAVP/ACVP‑validate, budget 9–18 months + the NIST MIP queue.
- **Blocks:** any "FIPS 140‑3 validated" statement and any procurement requiring CMVP‑validated crypto.
  The one gate STATUS.md explicitly flags "mostly not closable by code."

---

## Bottom line

PolarSeek has done **everything an engineering org can do to accelerate these gates** — the clean‑room
firewall + linter, the element‑by‑element design‑around skeleton, the five‑component audit scope with
self‑flagged leads + test vectors, the built‑and‑fake‑tested HSM/TEE/KMS adapter seams, and the signed
CNSA 2.0 / CBOM / COSE‑RATS / SBOM‑SLSA evidence artifacts — **but it has closed none of them, and must
never imply otherwise.** Design‑around is engineering intent, not a legal opinion. Conformant is not
validated. Built is not audited. Provisioned is not in‑use.
