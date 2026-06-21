<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Assurance & Claims Matrix

Radical honesty, made structural. Every claim below carries an **evidence tier** and its **limits**, so a
reviewer or auditor can see exactly what is proven, what is merely tested, and what is not yet established.
This matrix is the authoritative source if any marketing copy and this table ever disagree.

**Evidence tiers:** `Implemented` (code exists) · `Tested` (automated tests/KATs) · `Conformance‑checked`
(passes an in‑repo `npm run conformance` check against Nerion's *own* spec) · `Audited` (independent external
review — **none yet**) · `Validated` (accredited/formal, e.g. FIPS CMVP — **none yet**) · `Production‑ready`
(**no** — maturity is Local/Private dev).

| Claim | Tier | Evidence | Limitation (honest) |
|---|---|---|---|
| PQC signatures/KEM (ML‑DSA‑87, ML‑KEM‑1024, SLH‑DSA) | Implemented · Tested (KAT) | `crypto/`, pinned KAT vectors | **Algorithm‑compatible, NOT FIPS‑validated**; no accredited module; side‑channel resistance unassessed |
| CNSA 2.0 alignment (PS‑5, Cat‑5) | Conformance‑checked (C15/C16) | signed CNSA verdict oracle | **"Transitional," not pure‑CNSA** (hybrid KEM + SHA3); alignment ≠ NSA validation/approval |
| Hybrid KEM (ML‑KEM‑1024 + P‑384) | Implemented · Tested | `crypto/` | the classical P‑384 leg is quantum‑vulnerable (flagged in the CBOM) |
| ZK range proof + policy‑satisfaction | Implemented · Tested · Conformance (C11/C13) | `disclosure/zkrange.ts`, `policyproof.ts` | **UNAUDITED, bespoke** construction. **Soundness is CLASSICAL** (discrete‑log) — a future quantum computer could *forge* a satisfaction proof. Zero‑knowledge proven in the **classical ROM, not QROM**. A **Team Apex** multi‑model *code* audit (2026‑06‑21) found + fixed an off‑by‑one soundness bug — **ZKRANGE‑002** (n=252 wraparound: a negative `diff` aliases into [0,2ⁿ) since L=2²⁵²+d); bit‑length now capped at **n ≤ 251** + regression test. Production used n=32 throughout (never exploitable). See [council/team-apex-zkrange-2026-06-21.md](council/team-apex-zkrange-2026-06-21.md). Internal multi‑model review ≠ external audit. |
| Amount confidentiality (Pedersen hiding + salted v:1 commitment) | Implemented · Tested · Conformance (C23) | perfectly‑hiding Pedersen commitment; **salted intent commitment (ADR‑0014)** | **Information‑theoretic / PQ for the Pedersen COMMITMENT itself** — a quantum adversary cannot *recover* the amount from the commitment/proof. **RCPT‑001 (Team Apex 2026‑06‑21) — FIXED:** the *v:1 receipt* previously logged `commitments.intent = SHA3(full intent)` (**unsalted**), so a low‑entropy `amount` was **brute‑forceable** from the PUBLIC log leaf by anyone who knew the rest of the intent (the CB‑001 class, in the receipt that is actually logged). The intent commitment is now **salted** with a high‑entropy per‑receipt salt — `SHA3(canonical{domain, salt, intent})` (ADR‑0014) — and the salt is carried **off‑leaf** on the `Receipt`, revealed only to authorized verifiers, so the published leaf no longer leaks the amount. **Scope (honest):** this makes the **log leaf hiding** and supports *full‑intent* selective disclosure; it does **not** give amount‑privacy‑*with‑proofs* (reveal nothing, prove only a predicate) — that remains the **v:2** PSP/Pedersen path (ADR‑0006/ADR‑0013), with which the salted leaf composes. Salted‑commitment hiding is **classical/ROM and UNAUDITED**. See [council/team-apex-zkrange-2026-06-21.md](council/team-apex-zkrange-2026-06-21.md). |
| v:2 commitment‑to‑intent binding | Implemented · Tested · Conformance (C21) | `disclosure/commitbind.ts`, ADR‑0013; **Team Apex found + fixed CB‑001** (2026‑06‑21) | **UNAUDITED**. Defends against a *substituting* issuer; does **not** defend against a kernel malicious at admission (that's the quorum/attestation model). **CB‑001:** the public binding digest had hashed the *plaintext amount*, making it **brute‑forceable** over enumerable values and nullifying the commitment's hiding; the amount is now **omitted** from the digest (bound only by the perfectly‑hiding commitment + opening‑checked `verifyBoundAmount`). Caught **before** receipt‑wiring. See [council/team-apex-zkrange-2026-06-21.md](council/team-apex-zkrange-2026-06-21.md). |
| Decentralized k‑of‑n quorum receipts | Implemented · Tested · Conformance (C12) | `receipts/`, ADR‑0005 | Proves a quorum *signed*, **not** that the action was safe, the policy correct, or the signers independent/Sybil‑resistant |
| Action enforcement (a denied action never executes) | Implemented · Tested · Conformance (C8/C22); **Team Apex 2026‑06‑21: `decide()` validated fail‑closed** (no fail‑open path) | kernel → PermitToken; [ADR‑0015](adr/ADR-0015-per-audience-permit-keys.md); MCP adapter | Enforcement is **at admission**: the actuator must honor the permit. An out‑of‑scope actuator that ignores Nerion is outside the trust boundary. **PERMIT‑001 (FIXED):** Plane‑1 PermitTokens are a **symmetric HMAC**; the MAC key is now a **per‑(session,audience) HKDF‑SHA‑384 derivation** and each resource is provisioned with **only its derived key**, so a key‑holding resource can no longer re‑MAC a *different‑audience* permit (conformance **C22**, [ADR‑0015](adr/ADR-0015-per-audience-permit-keys.md)). The Plane‑1 hot‑path HMAC is preserved (asymmetric issuer signatures were weighed and kept as an opt‑in). The permit also MAC‑binds the decision `effect`. **Residual:** per‑audience keys do not stop a resource acting within its *own* authority; correct **key distribution** (derived keys only, never the raw session secret) is a deployment obligation. |
| Transparency log (RFC 6962 / SCITT‑style) | Implemented · Tested · Conformance (C10) | `translog/` | single‑operator log unless externally gossiped; split‑view detection included |
| 365 automated tests · 23/23 conformance | Tested · Conformance‑checked | `npm run gate`, `npm run conformance` | Demonstrates **implementation consistency against Nerion's own spec — NOT external security validation, formal proof, or coverage/fuzzing guarantees** |
| EU AI Act relevance | — | — | Nerion is **infrastructure / a protocol, not an "AI system"** under the Act. It is **complementary to** the Act's accountability/transparency goals — **not** "compliant with" or regulated by it |
| Independent security/ZK audit | **Not done** | OSTIF + OTF Security Lab #22493 (→ Radically Open Security) **submitted, not yet accepted/scoped** | No completed audit; no audit "backing" until a report exists |
| Patent FTO (vs SIGA "object‑tracking" family) | **Not done** | engineering recon ([FTO_CLAIM_CHART.md](FTO_CLAIM_CHART.md)) | **Not a legal opinion.** Nerion governs the *typed intent* and ingests **no perceptual data** — even when an upstream system derived that intent from perception. Counsel must still model the perception→intent boundary |
| FIPS 140‑3 validation | **Not done** | — | requires accredited‑lab CMVP |
| Production readiness | **No** | — | Local/Private dev maturity; four external launch gates remain ([LAUNCH_READINESS.md](LAUNCH_READINESS.md)) |

## What Nerion does NOT claim
- It is **not** post‑quantum *end‑to‑end*: the ZK layer's soundness is a labeled **classical/transitional** leg (the top roadmap item is migrating the commitment layer to a PQ scheme).
- It is **not** audited, FIPS‑validated, FTO‑cleared, or production‑ready.
- A quorum receipt is **not** proof that an action was wise or safe — only that authority was checked and recorded.

*Conformant is not validated; built is not audited; provisioned is not in‑use; a design‑around is not a legal
opinion. This matrix is reviewed by an adversarial multi‑model panel ("Team Apex") and updated as tiers change.*
