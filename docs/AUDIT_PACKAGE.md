# PolarSeek Cryptography / ZK Audit — Scope Package (auditor‑ready)

> **NOTHING IN THIS PACKAGE IS AUDITED.** Every security property in §2–§3 is a **CLAIM ASSERTED BY THE
> PROJECT, not an established fact** — until an external firm's report exists, treat all such statements
> as **unverified leads.** The self‑flagged caveats and self‑found fixes below are leads, not a
> substitute for review. Passing the bundled test vectors demonstrates **KAT conformance only** — it is
> **not** evidence of overall protocol security or production‑readiness.

For: a Trail of Bits / NCC Group / Cure53‑grade cryptographic‑protocol engagement. Scope is the
**protocol compositions PolarSeek wrote on top of the audited `@noble` primitives** — the group and
hash primitives (ristretto255, ML‑DSA‑87, SHAKE256, AES‑256) are audited; the **compositions are not.**

## 1. In‑scope components (five compositions)

| # | Component | File | Self‑flagged status |
|---|---|---|---|
| A | ZK range proof — Pedersen/ristretto255 + bit‑decomposition + Chaum‑Pedersen OR‑proofs, SHAKE256 Fiat‑Shamir, dual‑range, n≤252 cap | `disclosure/zkrange.ts` | "audited group, **UNAUDITED protocol**" |
| B | Policy‑satisfaction composition (hidden‑amount ≤ ceiling / aggregate ≤ cap) | `disclosure/policyproof.ts` | UNAUDITED |
| C | ECVRF (RFC 9381 suite 0x03, ed25519‑TAI) | `ledger/vrf.ts` | classical VRF (PQ caveat) |
| D | k‑of‑n independent‑signature quorum receipts | `receipts/quorum.ts` | composition unaudited |
| E | COSE_Sign1 + RATS/EAT envelope | `crypto/cose.ts` | ML‑DSA COSE codepoint IANA‑provisional |

## 2. Per‑component claims to verify (project claims — auditor confirms or refutes)

- **A:** the project **claims** the dual‑range construction (prove `amount∈[0,2^n)` AND
  `threshold‑1‑amount∈[0,2^n)`) with strong Fiat‑Shamir (statement‑binding challenge) is sound and
  closes the Frozen‑Heart/weak‑FS class, and that the n≤252 cap is **intended** to prevent modular
  wraparound. **Verify** the soundness, the OR‑proof simulation/special‑soundness, and the generator‑H
  nothing‑up‑my‑sleeve provenance.
- **B:** the project **claims** the amount's confidentiality is information‑theoretic (Pedersen perfect
  hiding) as a *primitive* property; whether **this composition** preserves it (correct generators, no
  transcript leakage) and whether soundness reduces to discrete‑log is **the auditor's to confirm** —
  do **not** treat "no harvest‑now‑decrypt‑later risk" as established for the composition.
- **C:** the project **claims** a VRF break is a liveness/fairness degradation that does **not** forge
  blocks/attestations/finality (those stay ML‑DSA‑87). **Verify** this blast‑radius boundary +
  malleability.
- **D:** the project **claims** safety reduces to ML‑DSA‑87 EUF‑CMA (PQ) with liveness availability‑
  bound, and that verify is **coded to** reject permissive‑set substitution (setId recompute) and
  **fail closed** with k≥1 enforced. **Verify** these as written behavior, and the quorum‑vs‑threshold
  semantics (it is k‑of‑n independent sigs, not threshold‑MPC).
- **E:** the project **claims** COSE_Sign1 canonicalization + the byte‑exact protected‑header alg
  binding are correct per RFC 9052. **Verify**, incl. the ML‑DSA COSE codepoint provisional status.

## 3. Three KNOWN residual gaps the project surfaced itself (confirm + assess exploitability)

1. **v:2 Pedersen↔SHA3 equality gap** — the ZK Policy‑Satisfaction receipt is **not** verifier‑sound
   against a malicious issuer without a commitment‑to‑intent equality proof (two independent amount
   commitments, nothing proving same value). The project deferred shipping the v:2 linkage for exactly
   this reason. Is the analysis correct? Is the proposed Pedersen↔SHA3 equality proof the right fix?
2. **≥2/3 view‑change round‑skip (LEDGER‑007)** — a ≥2/3 coalition can grind the VRF round. The project
   **states** safety is unaffected (each block still needs its own 2/3 attestations); the auditor must
   **confirm that safety truly is unaffected** and that it is fairness‑only.
3. **Software OTS‑state reuse‑under‑restore** — `SoftwareOtsStateStore` is provably not reuse‑safe under
   a consistent restore‑from‑backup (→ silent total forgery). It is hard‑gated dev‑only; confirm the
   gating is sufficient and the HW‑counter requirement is correctly stated.

## 4. Threat model, test vectors, questions

- **Threat model:** [THREAT_MODEL.md](./THREAT_MODEL.md).
- **Runnable vectors (KAT conformance ONLY — not a security assurance):** RFC 9381 VRF KATs
  (`ledger/test/vrf-rfc9381.test.ts`); 3‑language SHA3/HMAC conformance KATs; `npm run gate`;
  `npm run conformance` → 23/23.
- **Eight auditor questions:** Frozen‑Heart/weak‑FS; OR‑proof simulation soundness; generator‑H
  provenance; commitment‑to‑intent linkage; VRF malleability; quorum‑vs‑threshold semantics; COSE
  canonicalization; the PQ‑vs‑classical split (state the *primitive* property and the *composition*
  claim separately).

## 5. What the firm must do

Independently scope/quote; verify or **refute** each per‑component claim **without rubber‑stamping the
project's own reasoning**; confirm/invalidate the three known gaps and their real‑world exploitability;
run the vectors and report independently whether they pass **and** whether they cover the claimed
guarantees; answer the eight questions with severity‑rated written findings; and deliver a report
stating which components (if any) may carry a production privacy/soundness claim **after remediation**.
Until that report exists, **no** production privacy/security claim may rest on any of this. Patent FTO
is out of scope (see [FTO_PACKAGE.md](./FTO_PACKAGE.md)).
