# Nerion ↔ TNO PQC Migration Handbook alignment

> **Source:** *The PQC Migration Handbook — Guidelines for Migrating to Post-Quantum Cryptography*, 2nd
> ed., December 2024, by **AIVD · CWI · TNO** (the Dutch national authorities). **Method:** an 8-agent
> Team-Apex page-by-page scan of all 117 pages (2026-06-21) extracting 184 recommendations, then a
> high-effort mapping of every *protocol-relevant* recommendation against Nerion's actual source.
>
> **This is an honest alignment, NOT a compliance certificate.** Nerion's primitives are the AUDITED
> `@noble` libraries, but the **compositions are UNAUDITED and pre-FTO** — every "SATISFIED" below is
> functional/structural, **not** a validated-implementation claim. A real migration also needs
> organisational process + an independent audit, which the handbook (and Nerion) say plainly.

## 1. Recommendation → Nerion status (protocol-relevant subset)

| # | TNO rec (page) | Status | Note (cite) |
|---|---|---|---|
| 1 | PQC primary; no QKD dependency (p.3,13–14) | **SATISFIED** | ML-KEM/ML-DSA/SLH-DSA only; no QKD (`crypto/src/suites.ts`). |
| 2 | Crypto-agility: swappable IDs / negotiated suites (p.3–4,19,48,63,100) | **SATISFIED** | `SuiteID` registry + `negotiate()`; never hard-coded. |
| 3 | No new weaknesses / downgrade paths (p.3,4,9) | **PARTIAL → A2** | `negotiate()` filters to `active`, but no explicit anti-downgrade test. |
| 4 | Asset discovery → full inventory (p.3,29) | **SATISFIED** | `cbom.ts buildCbom()` enumerates every active-suite algorithm. |
| 6 | PQ confidentiality for SNDL secrets (p.8,46) | **SATISFIED** | KEMs hybrid-PQ from day one (`kem.ts`). |
| 7 | AES-256 / SHA-384-class adequate (p.13,69,91,111) | **SATISFIED** | AES-256-GCM/HMAC-SHA-384/SHA3 tagged Grover-resistant. |
| 8 | Replace RSA/ECDH/ECDSA (Shor) (p.13) | **SATISFIED** | No classical-only PK load-bearing; classical only inside hybrids, CBOM-flagged. |
| 10 | Deploy HYBRID (DE/FR/NL) (p.14,77,80,100,109,111) | **SATISFIED** | X-Wing + ML-KEM-1024+P-384 (`@noble/post-quantum/hybrid`). |
| 11 | Keep combiner simple/constant-time (p.14) | **SATISFIED (delegated)** | Audited noble KEM-combiner; not independently audited in-repo. |
| 13 | Build to NIST std, keep agility for later (p.3,9,15,45) | **SATISFIED** | HQC + Falcon pre-registered as non-active agility entries. |
| 16 | CycloneDX is the canonical CBOM format (p.33–35,114) | **PARTIAL → A3** | Signed CBOM exists but schema is bespoke, not CycloneDX `cryptoProperties`. |
| 17 | Surface PQC status of crypto DEPENDENCIES (p.9,32) | **PARTIAL → A4** | Lists algorithms, not `@noble` versions / `dependsOn` graph. |
| 18 | Verify advanced/ZK primitives are themselves PQ (p.19,24) | **PARTIAL → A7/B2** | **ZK range proof rests on Pedersen/DL — NOT post-quantum.** Sharpest honest gap. |
| 20 | Per-asset fields: NIST level/keytype/size/lifetime/status (p.34,35) | **SATISFIED (A1 ✅)** | `CryptoAsset` now carries `nistLevel`, `sizesBytes`, `status` (`cbom.ts`). |
| 21 | CBOM dependency graph `ref`/`dependsOn` (p.35) | **MISSING → A4** | No dependency edges yet. |
| 22 | CBOM key-mgmt + IV/nonce metadata (p.35,36) | **MISSING → A5** | No nonce/key-management block yet. |
| 24 | Quantum-weakness scoring 0/1/2 (p.38) | **SATISFIED (equiv)** | `QuantumClass` is the 0/1/2 mapping. |
| 25 | App weakness = MAX; never leave weak option negotiable (p.38) | **SATISFIED** | Only `active` suites negotiable. |
| 26 | Hybrid = AND (best score), not OR (p.38,68) | **SATISFIED** | Both legs feed one KDF. |
| 43 | IND-CCA2 KEM / EUF-CMA sig; cat 1/3/5 (p.71) | **SATISFIED** | ML-KEM (IND-CCA2), ML-DSA/SLH-DSA (EUF-CMA). |
| 44 | Stateful HBS: certified-module, never-export, crash-safe (p.72,88,89) | **PARTIAL** | `hbs-state.ts` reserve-before-sign; software path hard-gated, NOT SP 800-208-conformant. |
| 45 | KEM ≥ cat-3 (EU agencies) (p.77,86) | **SATISFIED** | PS-1 cat-3, PS-5 cat-5. |
| 46 | Signature = ML-DSA ≥ cat-3 (p.78,89) | **SATISFIED** | ML-DSA-87 (cat-5). |
| 47 | Avoid Falcon unless verified constant-time SCA-safe (p.77,90,98) | **SATISFIED** | FN-DSA is a throwing stub. |
| 48 | Offer conservative/unstructured KEM (McEliece/Frodo/HQC) (p.70,87,97) | **PARTIAL → B3** | Only HQC pre-registered, and as a stub. Diversity declared, not available. |
| 49 | SLH-DSA hash-based fallback (p.78,90,113) | **SATISFIED** | `slh_dsa_shake_256f` implemented. |
| 50 | Only standardised FIPS/ISO algos (p.75,113) | **SATISFIED** | FIPS 203/204/205/197/198-1/202. |
| 51 | Align CNSA 2.0 (p.76,113) | **SATISFIED** | Signed CNSA-2.0 verdict oracle (`cnsa-oracle.ts`). |
| 52 | Hybrid sig = two algos, accept iff BOTH valid (p.77) | **MISSING → B1** | Single-scheme ML-DSA-87; composite is Track B. |
| 55–57 | Constant-time; binary-level CT verification; SCA/FI/DFA (p.97–99,114) | **MISSING → A6/B4** | No in-repo binary CT / masking; inherits noble. Honestly UNAUDITED. |
| 58 | Expert/evaluated (FIPS-140-3) impls; don't roll your own (p.99,100,112) | **PARTIAL** | "Never roll your own" honored; noble not FIPS-validated. |
| 61 | Target FIPS 140-3 (p.100) | **N/A-roadmap → B5** | No module validation yet. |
| 67 | Build on vetted CT impls (liboqs/PQClean) (p.110,114) | **SATISFIED (intent)** | Built on audited `@noble`; HQC stub points to liboqs. |

*(Full 68-row mapping produced by the team; ~30 SATISFIED, the rest the gap list below.)*

## 2. Where Nerion already exceeds the handbook
- **Signed, transparency-anchored inventory, not a spreadsheet** — the CBOM is emitted *deterministically from the live SuiteID registry*, ML-DSA-87-signed, and Merkle/RFC-6962-anchored.
- **A machine-checkable conformance ORACLE, deny-by-default** — the handbook's weakness scoring (p.38) is a manual rubric; Nerion ships an executable, signed CNSA-2.0 verdict + a 23-check conformance gate.
- **Agility is structurally enforced** — pending/weak suites are catalog-visible but non-negotiable by construction (operationalizes p.38).
- **Hybrid-AND is the default**, KDF-combined via the audited combiner (the handbook's strongest recommendation as baseline).
- **Honest agility stubs** — HQC/Falcon are throwing `NotImplementedError` stubs with FIPS-tracking notes (exactly p.13/p.45/p.47 behavior).

## 3. Prioritized gaps
**TRACK A — buildable now (additive, gate-safe):**
- **A1 ✅ SHIPPED** — enrich CBOM `CryptoAsset` with NIST level + spec sizes + lifecycle status (p.34–35).
- **A2** — explicit anti-downgrade conformance check (`negotiate()` refuses a stale/weak offer) (p.63/67).
- **A3** — emit a CycloneDX-1.6 `cryptoProperties` projection alongside the signed native CBOM (p.34/114).
- **A4** — CBOM dependency edges (`dependsOn`) + `@noble` version capture (p.35).
- **A5** — key-lifecycle / HSM-custody metadata into the inventory (p.35/36).
- **A6** — explicit constant-time / UNAUDITED-composition disclosure in `ASSURANCE.md` (p.98).
- **A7** — disclose "ZK range proof is not yet PQ" in CBOM/THREAT_MODEL (p.18).
- **A8** — publish a PQ KEM/signature benchmark artifact (p.94/110).

**TRACK B — ADR / design only (wire/primitive/audit-gated):**
- **B1** composite/dual signatures (accept iff both valid) (p.77).
- **B2** post-quantum ZK range proof (replace DL/Pedersen) — the deepest gap.
- **B3** make an unstructured/conservative KEM (FrodoKEM/HQC) actually available (p.97).
- **B4** binary-level constant-time + SCA/FI/DFA assurance plan (p.98–99).
- **B5** FIPS-140-3 module / certified-impl swap behind the `wrap()` seam (p.100).

## 4. Status
**A1 implemented + merged** (this doc's first action). A2–A8 are queued for the 6-hourly engine /
follow-up cycles; B1–B5 are ADR/design-gated and must not ship behavior silently. The honest headline for
reviewers: **Nerion is structurally well-aligned to the TNO handbook's *protocol* guidance (agility,
hybrid-AND, signed CBOM, CNSA oracle), and openly documents where it is not yet there (binary CT, SCA
countermeasures, FIPS-140-3 validation, and a post-quantum ZK layer).**
