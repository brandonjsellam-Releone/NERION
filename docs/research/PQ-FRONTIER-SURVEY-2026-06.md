<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# PQ-crypto frontier survey — implications for the Nerion roadmap (2026-06)

A grounded, **public** state-of-the-art sweep (council SCOUT seat + web), distilled into roadmap
implications for the apex backlog. **Honesty discipline applies:** this is a literature/standards scan,
not a claim that Nerion leads the field; where a finding rests on training knowledge rather than a
freshly-fetched primary source it is marked **[verify]**, and nothing here should become a marketing or
assurance claim without a primary citation. The headline result is reassuring rather than grandiose: **the
public SOTA corroborates the honest caveats Nerion already publishes** (classical ZK soundness, "transitional"
CNSA alignment, threshold-signatures-not-yet-standardized). That *is* the moat — being right and saying so.

## 1. NIST PQC standards status

- **FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA): finalized 2024-08-13** and stable. **FN-DSA/Falcon
  (FIPS 206): draft still pending**; **HQC: selected 2025-03 as a backup KEM, draft standard (FIPS 207)
  in progress, final ~2027** [verify exact dates]. (csrc.nist.gov PQC project; nist.gov 2024-08 release.)
- **Nerion implication — already aligned.** The suite is on *final* standards (ML-KEM-1024 / ML-DSA-87 /
  SLH-DSA). HQC is correctly **registered-but-stubbed** (`crypto/kem.ts` throws NotImplemented — there is no
  final standard to implement), and FN-DSA is correctly **registered-but-not-load-bearing**. No action; keep
  the stubs honest. When FIPS 207 lands, wire HQC as the third hybrid leg.

## 2. CNSA 2.0 (NSA)

- Approved set: **ML-KEM-1024, ML-DSA-87, LMS/XMSS (SP 800-208), AES-256, SHA-384/512**; software/firmware
  signing expected PQC-capable now, broad adoption ~2030, exclusive CNSA 2.0 by ~2033-2035 (sector-dependent)
  [verify]. An **IETF `draft-becker-cnsa2-tls-profile`** exists. (postquantum.com guide; ietf.org draft.)
- **Nerion implication — the "transitional, not pure-CNSA" label is correct.** Pure CNSA 2.0 hashing is
  **SHA-384/512, not SHA3**, and the KEM is **ML-KEM-1024 alone, not a hybrid**. The C15/C16 oracle's
  "transitional" verdict (hybrid KEM + SHA3) is the honest call. The backlog **"CNSA pure-hash flip"** is a
  real, well-scoped option: offer a *pure-CNSA profile* (SHA-384/512 + ML-KEM-1024-only) alongside the
  hybrid/SHA3 default — an opt-in, ADR-first, not a default change (frozen wire-tags/KATs are guardrailed).

## 3. Post-quantum ZK range proofs (Nerion's dominant audit-risk surface)

- **Classical Bulletproofs / discrete-log range proofs are quantum-broken in SOUNDNESS** — a quantum
  adversary solving discrete log can forge a proof of a false statement. Hiding (Pedersen) stays
  information-theoretic; *binding/soundness* is the casualty. (zksecurity Bulletproofs; lattice-ZK for
  confidential transactions, PolyU.)
- **PQ alternatives exist but cost size/speed:** lattice-based range proofs (Lyubashevsky-style; AFT 2024
  LIPIcs vol. 316), hash/VOLE-based ZK (Ligero, Brakedown), and STARKs (hash-based, transparent, plausibly
  PQ). Proof sizes are **~1-2 orders of magnitude larger** than Bulletproofs' ~700 bytes [verify magnitudes].
- **Fiat-Shamir soundness is classical-ROM by default; QROM soundness needs extra analysis** and is *not*
  automatic (Don-Fehr-Majenz-Schaffner; Simons "Fiat-Shamir in the QROM"; Majenz slides). Trail of Bits —
  the likely external auditor — literally published "Disarming Fiat-Shamir footguns" on incomplete transcript
  binding.
- **Nerion implication — the published caveat ("soundness is CLASSICAL; ZK proven in classical ROM, not
  QROM") is exactly right, and this is the #1 roadmap item.** Two grounded moves: (a) **strong-FS hygiene
  now** — the existing audit already folds threshold/bounds/commitment into the transcript (ZKRANGE-002,
  policyproof); keep hardening transcript completeness per the ToB footguns checklist (cheap, high-value,
  audit-pleasing). (b) **PQ migration path (ADR, larger effort):** a **STARK-style hash-based** range proof
  is the cleanest *fully-PQ, transparent, no-trusted-setup* target; a **lattice range proof** preserves more
  homomorphic structure (relevant to §5). Either is a size/perf tradeoff to prototype behind a v:2 flag — do
  NOT swap the default unaudited.

## 4. Threshold / MPC post-quantum signatures

- **NIST opened a dedicated threshold-crypto track in 2026** (MPTS 2026; **NIST IR 8214C**) explicitly
  seeking multi-party schemes for the standardized primitives. **Threshold ML-DSA and lattice FROST-style
  schemes (Trilithium, Tanuki) are research-grade**, with limited public implementations and **no finalized
  standard** as of mid-2026. (csrc.nist.gov threshold-cryptography; NIST IR 8214C.)
- **Nerion implication — the current design is the correct call; do NOT build unaudited threshold lattice
  sigs now.** Quorum receipts use **independent k-of-n ML-DSA signatures** (a decentralized multi-attestation),
  NOT single-key threshold-MPC — and the module docstring already states a true threshold scheme "would need a
  threshold scheme AND would be classical." SOTA confirms this. **Re-scope the backlog "threshold-ML-DSA" item
  to "track NIST IR 8214C"**: keep the independent-signature quorum as the production path; revisit only when a
  standardized threshold lattice signature exists. (This *removes* a risky unaudited-crypto item from the
  near-term engine — a net de-risking.)

## 5. PQ commitments (the Pedersen → PQ migration, ADR-0022)

- **A quantum adversary breaks Pedersen's BINDING** (discrete log) → can equivocate (open to two values);
  hiding stays info-theoretic. **PQ options:** *lattice* commitments (Ajtai/SIS; BDLOP) give computational
  PQ hiding+binding **and retain linear homomorphism**, at larger size; *hash-based* commitments give PQ
  binding but are **not homomorphic** (which would break the range/aggregate-sum structure). (Cloudflare
  lattice primer; AFT 2024.)
- **Nerion implication — target a lattice (BDLOP-style) commitment for v:2, not hash-based.** The
  range/aggregate-cap proofs rely on the commitment's additive homomorphism (the `C_sum` aggregate clause),
  so the migration must preserve it — lattice commitments do, hash commitments don't. Accept the move from
  *information-theoretic* to *computational (PQ)* hiding + a size increase, and **document it honestly** in
  ADR-0022. Note: the v:1 log-leaf hiding (RCPT-001 salted-SHA3 intent commitment) is **already hash-based =
  PQ**; only the v:2 *amount* commitment (Pedersen) carries the classical-binding gap.

## Prioritized takeaways for the engine / council

1. **Keep the honesty caveats verbatim — SOTA backs every one** (classical ZK soundness, transitional CNSA,
   threshold-not-standardized). This is the most valuable finding; resist any "world's-most" temptation.
2. **De-risk the backlog:** re-scope `threshold-ML-DSA` from "build" to "track NIST IR 8214C" (research-grade,
   unstandardized — not engine-safe to implement now).
3. **#1 crypto roadmap = the PQ-ZK/commitment migration**, as a v:2 *prototype behind a flag*: STARK-style
   (transparent, fully-PQ) range proof and/or BDLOP lattice commitment (homomorphism-preserving), ADR-first,
   never swapping the audited default.
4. **Cheap now:** a Fiat-Shamir transcript-completeness pass against the Trail-of-Bits footguns checklist
   (the external auditor's own list) across zkrange/policyproof — low risk, directly audit-pleasing.
5. **Pure-CNSA profile** (SHA-384/512 + ML-KEM-1024-only) as an opt-in, ADR-first.

## Sources (public)

NIST CSRC PQC project & 2024-08 release; postquantum.com CNSA 2.0 guide; IETF `draft-becker-cnsa2-tls-profile`;
zksecurity Bulletproofs range-proof series; "Lattice-based Zero-knowledge Proofs for Blockchain Confidential
Transactions" (PolyU); AFT 2024 (LIPIcs vol. 316) lattice range proofs; Trail of Bits "Disarming Fiat-Shamir
footguns" (2024-06); Simons Institute "Fiat-Shamir in the QROM" + Majenz QIP slides; NIST CSRC
threshold-cryptography (MPTS 2026) + NIST IR 8214C; Cloudflare lattice-crypto primer; openquantumsafe.org;
Starkware "is Starknet quantum-prepared". (Full URLs in the session research transcript; re-fetch primaries
before citing any figure marked **[verify]**.)
