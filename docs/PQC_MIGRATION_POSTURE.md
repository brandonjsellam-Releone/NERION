<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — PQC Migration Posture

> Mapping Nerion to the **AIVD / CWI / TNO _PQC Migration Handbook_ (2nd ed., Dec 2024)** —
> "Guidelines for Migrating to Post-Quantum Cryptography." Nerion is **PQC-native**: it was built
> post-quantum-first, so it is not _migrating_ — it is a **reference for the migrated end-state**.
> This document records that posture against the handbook's framework so adopters and auditors can
> place Nerion precisely.
>
> **Honesty bar:** Nerion is a reference implementation; its primitives are provided by the audited
> `@noble/*` libraries, but the protocol composition is **not yet externally audited**. No FIPS
> certification, audit, or non-infringement is claimed. Quantum-security levels below are the design
> targets of the named standards, not certified results.

## 1. The handbook's three-step framework, applied

The handbook structures migration as **(1) Quantum-Vulnerability Diagnosis → (2) Planning →
(3) Execution**. Nerion's position in each:

| Step         | Handbook intent                       | Nerion                                                                                                                                                  |
| ------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Diagnosis | inventory crypto; assess quantum risk | **No quantum-vulnerable primitive is load-bearing.** The full inventory is the CBOM ([`nerion.cbom.json`](../nerion.cbom.json), CycloneDX 1.6, §2.3.4). |
| 2. Planning  | when/how to migrate; maturity         | N/A as a migration; Nerion ships the migrated target. The SuiteID registry is the agility plan (§4.4).                                                  |
| 3. Execution | swap primitives without new vulns     | Done at design time: every signed/encrypted object carries its SuiteID; no algorithm is hard-coded in protocol logic.                                   |

Nerion is an **"urgent adopter" end-state** (handbook §2.1.1): it governs high-impact AI/agent
actions (payments, infra) where a harvest-now-decrypt-later (HNDL) break would be unacceptable, so
it uses NIST Level-5 parameters (the CNSA 2.0 algorithm set) from day one.

## 2. No-Regret Moves (§1.6) — status

| No-regret move                    | Nerion                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cryptographic asset management    | ✓ CBOM (`nerion.cbom.json`) + SBOM (`nerion.spdx`)                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Review cryptographic policies     | ✓ policy is explicit + versioned (`evaluatorVersion`); suites carry `standards` provenance                                                                                                                                                                                                                                                                                                                                                                                       |
| Conduct (quantum) risk assessment | ✓ design assumes a CRQC adversary; classical-only primitives (ECDH/X25519) are confined to hybrid-KEM fallback, never standalone confidentiality. **Residual (present design limitation):** the ristretto255 ZK range-proof's _hiding_ is information-theoretic (PQ), but its _soundness_ rests on classical discrete-log — the proof system is **not** post-quantum-sound, so a future CRQC could forge a compliance proof. Tracked for the PQ-commitment migration (ADR-0022). |
| Cryptographic agility             | ✓ SuiteID registry (see §4 below)                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Inventory regulatory requirements | ✓ CNSA 2.0 (§5.2.6), FIPS 203/204/205 tracked per suite                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Back-up plan                      | ✓ non-lattice diversity registered (HQC-256 KEM) + compact-sig agility (FN-DSA), both non-active pending standardization                                                                                                                                                                                                                                                                                                                                                         |

## 3. Cryptographic Maturity (§1.7)

The handbook's maturity criteria, met: complete asset overview (CBOM); risk insight (no load-bearing
quantum-vulnerable primitive); policy aligned to regulation (CNSA 2.0 Cat-5); continuous monitoring
(`npm run gate` + 24/24 conformance + the Team Apex adversarial sweeps gate every change).

## 4. Cryptographic Agility (§4.4) — the SuiteID registry

The handbook (§4.4.1) names distinct forms of agility. Nerion provides several — the SuiteID
registry (`crypto/src/suites.ts`) supplies **migration** and **compliance** agility, and Nerion's
hybrid-KEM constructions are an instance of **composability** agility:

- **Migration agility** — replace one algorithm with another. Suites `PS-1`, `PS-5`, `PS-5-HQC`,
  `PS-5-FN` are registered; `negotiate()` selects the most-preferred **active** suite common to both
  peers. New suites are added without touching protocol logic (primitives resolve via the suite).
- **Compliance agility** — multiple configurations coexist for different regimes: `PS-1` (general /
  Cat-3 transition) and `PS-5` (regulated CNSA 2.0 Cat-5) are both active and negotiated per peer.
- **Composability agility** — hybrid-AND composition is first-class: X-Wing (X25519 + ML-KEM-768)
  and ML-KEM-1024 + ECDH P-384 are KEM compositions; the suite design is built for it.

**Downgrade defense (handbook §4.4.1 warning).** The handbook warns that supporting multiple
algorithms in an "OR" fashion invites downgrade attacks. Nerion closes this by **binding the SuiteID
into the signed/MAC'd message** at every layer — capabilities (CAP-001), attestation evidence
(ATTEST-SUITE-001), ledger votes/blocks/view-change (cross-suite hardening), governance approvals
(GOV-SUITE-001), and signed tree heads (STH-SUITE-001, Team Apex 2026-06-22). A relayed _signed object_
cannot be relabeled to a weaker shared-signature suite and still verify. (This protects **signed
objects**; downgrade resistance during live suite **negotiation** is a separate transcript-binding
concern at the negotiation layer, not claimed here.) Non-active suites (`pending-standardization`,
`not-load-bearing`) appear in the catalog but are **never negotiated**.

## 5. Recommended Primitives (§4.2, Tables 4.1 / 4.2)

Nerion's **PS-5** tier uses the handbook's **Recommended algorithms** at **NIST security category 5**,
aligned with the **CNSA 2.0** algorithm set (§5.2.6). ("Category 5" is NIST's security-strength
category — ~256-bit — _not_ a NIST certification and _not_ a FIPS 140-3 level; CNSA 2.0 separately
names the specific algorithms, so this is **alignment** with the CNSA 2.0 algorithm direction, not a
compliance or certification claim.) The general **PS-1** tier is **NIST category 3** (X-Wing wraps
ML-KEM-768). **Two deliberate divergences** are documented below the table — the **signature**
deployment and the **hash** choice — which mean PS-5 is _not_ CNSA-2.0-compliant (see §6).

| Functionality         | Handbook "Recommended"  | Nerion (PS-5)                                |
| --------------------- | ----------------------- | -------------------------------------------- |
| Key encapsulation     | ML-KEM (hybrid w/ ECDH) | ML-KEM-1024 + ECDH P-384 (L5)                |
| Signature (stateless) | ML-DSA / SLH-DSA        | ML-DSA-87 (L5); SLH-DSA-SHAKE-256f available |
| Hash                  | SHA-2 / SHA-3           | SHA3-256 / SHAKE256 †                        |
| AEAD                  | AES-GCM(-SIV)           | AES-256-GCM                                  |
| MAC / KDF             | HMAC-SHA-2 / KMAC       | HMAC-SHA-384 / HKDF-SHA-384                  |

**Documented divergence (honest).** The handbook (Table 4.1, note 2) recommends deploying ML-DSA in a
**hybrid** combination with EdDSA/ECDSA, reflecting the more conservative BSI/ANSSI/NLNCSA stance.
Nerion's signatures are **pure ML-DSA-87**, following **NSA CNSA 2.0**, which mandates Level-5 PQC and
does _not_ require a classical signature hybrid (unlike the KEM, which Nerion _does_ hybridize). This
is a deliberate, regulation-aligned choice, not an oversight; signature-hybrid agility could be added
as a future suite if an adopter's regulator requires it.

**† Hash divergence (honest).** CNSA 2.0 specifies **SHA-384**; Nerion's primary hash is
**SHA3-256 / SHAKE256** (SHA-384 is used _inside_ HMAC/HKDF). SHA3-256 provides 256-bit preimage but
only **128-bit collision** resistance, so collision-critical structures (Merkle leaves, intent
commitments) rely on SHAKE256 / domain separation. This is an algorithm-family divergence from strict
CNSA 2.0, recorded here rather than papered over.

## 6. Regulatory alignment (§5.2.6 CNSA 2.0)

CNSA 2.0 specifies ML-KEM-1024, ML-DSA-87, AES-256, SHA-384, with PQC deployment becoming mandatory
for national-security systems by 2030/2033. Nerion's `PS-5` tier uses the CNSA 2.0 **KEM, signature,
and AEAD** algorithms (ML-KEM-1024, ML-DSA-87, AES-256) at Level 5; for the primary hash it uses
SHA-3/SHAKE256 (SHA-384 appears in HMAC/HKDF) — the documented divergence above. So Nerion is
**aligned with** the CNSA 2.0 algorithm direction, not certified CNSA-2.0-compliant.

To be unambiguous for procurement/audit readers: **PS-5 is _not_ CNSA-2.0-compliant** — CNSA 2.0's
hybrid-signature and SHA-384 requirements are not met (both documented above). BSI and ANSSI likewise
mandate hybrid signatures for high-assurance use, which the pure-ML-DSA-87 deployment does not meet.
These are deliberate, regulation-aware engineering choices, stated plainly so no reviewer infers a
compliance status that is not claimed.

---

**Generated artifacts:** [`nerion.cbom.json`](../nerion.cbom.json) (CBOM, §2.3.4) ·
[`nerion.spdx`](../nerion.spdx) (SBOM). Re-derive the CBOM from `crypto/src/suites.ts` whenever the
suite registry changes. The CBOM is a cryptographic **inventory**, not a compliance attestation — PQ
posture also depends on transcript binding, implementation correctness, randomness, and external
audit. Source: AIVD/CWI/TNO, _The PQC Migration Handbook_, 2nd ed., December 2024.
