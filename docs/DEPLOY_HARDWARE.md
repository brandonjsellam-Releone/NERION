# PolarSeek Hardware / Cloud / FIPS Deployment Runbook (operator‑facing)

> A runbook an **operator follows to provision toward** a hardware‑rooted deployment. It does **not**
> take PolarSeek to a FIPS‑hardened / TEE‑attested / HSM‑custodied state — the operator + vendors + an
> accredited lab close those gates, never this document. **No configuration here produces a FIPS 140‑3
> validation.** See [LAUNCH_READINESS.md](./LAUNCH_READINESS.md).

## 0. Honest starting point

PolarSeek is **Local/Private dev**: software unit‑ and conformance‑tested **with fakes** (291 tests,
20/20 conformance) — **no hardware/integration/audit coverage**. The custody/attestation **adapter
seams are built and offline‑tested with fakes; none has been exercised against live silicon or a live
cloud KMS.** "Framework built" ≠ "custody works on real hardware."

## 1. The three bindings the operator must write + validate (net‑new code)

These are **net‑new code the operator must write AND validate against their specific hardware** —
"config not architecture" is an engineering **expectation, not a guarantee**, and the seams are
**untested against real silicon here**:

| Binding | Plugs into (built seam) | Operator writes |
|---|---|---|
| `Pkcs11WrapEngine` | `keystore` SealingKeyProvider / Pkcs11* | a pkcs11js→C binding to the HSM's wrap/unwrap |
| `HbsSignEngine` | `keystore` `HbsKeyProvider` + `OtsStateStore` | the LMS/XMSS sign call backed by a **hardware‑counter** state store (never the software store) |
| `QuoteVerifier` (one per TEE format) | `attest` QuoteVerifierRegistry | the per‑format quote verification + golden enclave measurements |

**Until wired:** keys are software‑custodied (dev‑grade); TEE attestation **fails closed** (no hardware
enclave is verified — the N‑of‑M heterogeneous‑attestation defense exists in the framework but
**defeats nothing today**); the HBS code‑signing path **refuses to construct** on the unsafe software
store.

## 2. FIPS 140‑3 L3+ HSM (Gate 3 — procurement + bindings)

Procure a **CMVP‑listed** FIPS 140‑3 (or interim 140‑2) **Level 3** PKCS#11 HSM whose certificate
**covers SP 800‑208 LMS/XMSS with an in‑boundary hardware monotonic counter** — get this **in writing**
(candidates: Thales Luna 7, Entrust nShield 5, AWS CloudHSM, Marvell, Utimaco). **Model‑B custody**
(wrap only the small PQC **seed** with the HSM's classical key; re‑derive + sign) means a classical‑only
HSM suffices to custody PQC keys — but note PolarSeek's **in‑process ML‑DSA/ML‑KEM signing stays OUTSIDE
the HSM boundary.** For stateful HBS, the index reservation **must** happen inside the HSM's hardware
counter (the software store is provably reuse‑unsafe under restore).

## 3. Cloud KMS sealing + confidential‑compute TEE

- **Azure Key Vault** — *provisioned* (tenant `redacted-vault`, app `redacted-app` w/ Crypto
  User; IDs only, secret in `.env`) but **never exercised end‑to‑end here**; KV has **no PQC support**
  and serves only as a **sealing KEK**. The provider is **implemented + offline‑tested with a fake
  sealer**, not run against the live KV.
- **AWS KMS** — an **implemented, offline‑tested** sealing provider (fakes); never run against live KMS.
  GCP KMS is a stub.
- **TEE** — Azure CVM+MAA / GCP Confidential Space / AWS Nitro: provision capacity + the
  quote‑verification SDK and published roots (Intel PCS / AMD KDS / Arm CCA), then write the per‑format
  `QuoteVerifier`. Until then attestation verifies nothing.

## 4. FIPS 140‑3 validation (Gate 4 — accredited lab)

**Hard stop:** assembling PolarSeek's evidence (signed CNSA 2.0 verdict, CBOM, COSE/RATS, SBOM/SLSA) and
**consuming** a CMVP‑validated HSM/CSP boundary **does NOT make PolarSeek FIPS 140‑3 validated.** CNSA
2.0 "conformant (transitional)" is machine‑checked against PolarSeek's **own oracle** — it is **not**
CMVP validation; never conflate the two.

- **Path A (pilots):** place FIPS‑relevant operations behind an **already CMVP‑validated** module (the
  Gate‑3 HSM, or Azure Managed HSM / AWS CloudHSM FIPS endpoints) and **document PolarSeek as a
  consumer** of that boundary, explicitly noting the in‑process PQC signing is **outside** the
  certificate. (Requires Gate‑3 procurement + bindings. **Not** "FIPS in weeks.")
- **Path B (validate PolarSeek's own crypto):** contract an accredited CST lab (Leidos, atsec, DEKRA,
  Acumen), define a cryptographic boundary, produce the FSM/security‑policy, complete CAVP/ACVP, and
  budget **9–18 months + the NIST Module‑In‑Process queue.** (LMS/XMSS validate only inside FIPS 140‑3
  L3+ hardware, so Path B for HBS still routes through Path A's HSM.)

## 5. Evidence PolarSeek already emits (supports, does not close, Gate 4)

Signed CNSA 2.0 verdict (`conformance/cnsa-oracle.ts`, C16); signed CBOM (`cbom.ts`, C17); COSE_Sign1 +
RATS/EAT (`crypto/cose.ts`, C19); signed SBOM + SLSA provenance (`supplychain.ts`, C20); the standalone
external receipt verifier (`npm run verify:cli`); `npm run conformance` → 20/20. All signed,
transparency‑log‑anchored, externally verifiable — and **none confers FIPS validation, audit, or
non‑infringement status.**
