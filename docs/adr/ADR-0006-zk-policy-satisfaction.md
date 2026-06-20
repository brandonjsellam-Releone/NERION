# ADR-0006: Zero-Knowledge Policy-Satisfaction Receipts (conservative subset)

**Status:** Accepted (conservative subset shipped) — team-designed, adversarially audited, and
crypto-reviewed by the multi-model council. Apex-upgrade #2 of the "above the apex" roadmap. The full
ZK-PSR (set-membership clauses) is **deferred** pending a new, separately-reviewed primitive.

## Context

SIGA's "Sovereign OS" must SEE every action payload to attest/bill it (central visibility). The
categorical move SIGA structurally cannot make is **proving an action complied with policy without
revealing the action**. PolarSeek already has the building block: `disclosure/zkrange` — Pedersen
commitments + a dual range proof on the audited ristretto255 group (UNAUDITED protocol composition).

## Decision

Add `disclosure/policyproof.ts`: a **Policy-Satisfaction Proof (PSP)** that proves an action's amount
satisfied the kernel's NUMERIC policy bounds — `amount ≤ perActionCeiling`, and optionally
`aggregate + amount ≤ aggregateCap` — **without revealing the amount**.

- `commitAmount(amount)` → Pedersen `commit(amount, r)` + opening.
- `provePolicySatisfaction(amount, opening, bounds)` → `proveBelow(amount, opening, ceiling+1)` and
  (when capped) `proveBelow(amount+aggregate, opening, cap+1)` over the homomorphic
  `C_sum = C_amount + G^aggregate`. The **same opening** binds both clauses to the **same amount**.
- `verifyPolicySatisfaction(commitment, bounds, proof)` → fail-closed; reconstructs `C_sum` from the
  PUBLIC (trusted/signed) `aggregate`; rejects an `n` mismatch, a capped policy missing the aggregate,
  a missing aggregate proof, or a stray aggregate proof under an uncapped policy.
- `policyProofDigest(commitment, bounds, proof, policyBinding)` → the value a future **v:2** receipt carries
  in `commitments.psr`, binding the proof to the policy identity (`evaluatorVersion`) **and the explicit
  numeric bounds** (ceiling / cap / aggregate / n — added by the Team Apex audit 2026-06-21) and transitively
  ML-DSA-87-signing + log-anchoring it via the receipt body.

**Deliberately the CONSERVATIVE subset:** it composes ONLY the existing audited-group range proof — no
new cryptographic primitive. The **ZK set-membership clauses** (action-type / counterparty ∈ allowed
set) are **DEFERRED**: they need a new k-way Chaum-Pedersen OR-proof that is not yet built or reviewed.
The unsalted `selective.commitField` fallback is **NOT** used for those clauses — the design audit
showed it is brute-forceable over small enumerable domains.

## Consequences — honest caveats (binding)

- **UNAUDITED protocol composition.** The ristretto255 group + SHAKE256 hash are audited (@noble); the
  range-proof composition (and this PSP on top) are not. No production privacy claim until an external
  ZK audit + FTO review.
- **Post-quantum profile (corrected by the crypto council — the common error runs the other way):**
  the hidden amount's **confidentiality is INFORMATION-THEORETIC** (Pedersen is *perfectly* hiding) —
  **no adversary, including quantum, can recover the amount**, and there is **no harvest-now-decrypt-later
  risk to the amount**. What is CLASSICAL is the proof's **soundness/binding** (discrete-log): a future
  quantum adversary could **forge** a satisfaction proof for an out-of-bound amount. Receipt-envelope
  integrity is PQ (ML-DSA-87); the ZK proof's integrity is classical; the amount's secrecy is
  unconditional.
- **Linkage contract (soundness prerequisite, the audit's strongest finding):** the PSP proves a
  property of the COMMITTED amount. End-to-end soundness requires the ISSUER to commit the SAME amount
  the kernel decided on and bind the commitment into the signed receipt (the v:2 `commitments.psr`
  wiring — not yet built). Until then, callers MUST supply the decided amount.
- **Range width:** amounts/ceilings must fit `< 2^n` (default n=32; hard cap 252 so `2^n < L`, ZKRANGE-001).
- **Deferred:** the v:2 ReceiptBody schema change + node issuance wiring + the set-membership OR-proof.

## Re-audit / council findings (applied)

- **Gemini (crypto-verification seat)** caught a textbook error in the first draft caveat: it claimed a
  quantum adversary could *recover* the hidden amount (harvest-now-decrypt-later). That is wrong —
  Pedersen is perfectly hiding; the quantum risk is *forgery*, not disclosure. Caveat corrected above.
  (Notably the two generalist seats accepted the error; the dedicated crypto seat caught it.)
- **DeepSeek** caught a cap-bypass: a verifier setting `aggregateCap` but omitting `aggregate` would
  silently skip the cap check. Fixed: `verifyPolicySatisfaction` now fails closed on that misconfig.
- Soundness of the two-clause composition (same opening binds the same amount), zero-knowledge, and the
  `≤ ⟺ < bound+1` encoding were confirmed correct by all three seats.

Conformance check **C13** asserts an in-bound amount verifies (hiding the amount), a proof does not
verify against a tighter ceiling, and an out-of-bound amount cannot be proven (13/13 CONFORMANT).

## Credits

Team workflow (ground → design → adversarial soundness/ZK/binding audit → synthesis: SHIP-SUBSET).
Council crypto-review (DeepSeek, Grok, Gemini) on the implemented code. Roadmap #3 = govern-the-verb
runtime negative oracle.
