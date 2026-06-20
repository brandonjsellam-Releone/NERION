# ADR-0005: Decentralized k-of-n quorum receipts (no single host signs)

**Status:** Accepted — designed by the multi-agent team, red-teamed by the multi-model council, and
adversarially re-audited against the implemented code. Apex-upgrade #1 of the "above the apex" roadmap.

## Context

PolarSeek receipts (`receipts/receipt.ts`) were issued by a **single issuer key**. The competing
SIGA "Sovereign OS / Commit-Point Gate" architecture's **#1 structural weakness** is its single
Founding Sovereign Host — every receipt, key, and kill switch funnels through one jurisdiction (a
single point of capture/failure). A single-issuer receipt has the same shape of weakness. We want
**decentralized receipt issuance**: no single host can mint a valid receipt.

## Decision

Add `receipts/quorum.ts`: a **k-of-n quorum receipt**. A `ReceiptBody` is wrapped in a
`QuorumReceiptBody { receipt, quorum: { setId, k, epoch, suite } }` and **k validators each
independently ML-DSA-87-sign the same canonical bound body**. `verifyQuorumReceipt(receipt, set, k,
epoch)` counts DISTINCT valid member signatures and requires ≥ k. A stake-weighted variant
(`verifyQuorumReceiptByStake`) counts distinct valid stake instead.

**This is NOT threshold-MPC / FROST.** It is k-of-n *independent* signatures (a decentralized
multi-attestation). A true threshold signature would need a threshold scheme **and** would be
**classical, not post-quantum**. We deliberately chose independent ML-DSA-87 so **safety stays fully
post-quantum**. Zero new cryptographic primitives — pure composition of audited ML-DSA-87 (FIPS 204)
+ SHAKE256 + deterministic CBOR + the existing `governance/quorum.ts` distinct-member counting.

### Validator-set binding (the load-bearing defense)

The signed body commits `setId = SHAKE256(canonical([ctx, sorted [pubkey,stake], k, epoch]))`.
`verify` **recomputes** `setId` from the verifier's OWN trusted (finalized PoS) `ValidatorSet` and
**rejects on mismatch**. This closes the attack the multi-model council unanimously flagged: a
verifier fed a **permissive or attacker-substituted validator set** would otherwise accept a receipt
signed by an attacker's own "validators." Because `setId` binds membership + stake + k + epoch
(order-independently) and is covered by every signature, an attacker cannot match the real set's
`setId` without holding k real member keys. Suite is bound the same way (committed in the body +
`a.suite === q.suite` per-attestation), closing cross-suite confusion.

## Consequences — honest caveats (binding)

- **Safety is fully post-quantum** (ML-DSA-87 EUF-CMA, no classical primitive — unlike the ed25519
  VRF of ADR-0004). **Liveness** depends on k validators being available — an availability property
  of any quorum, not a cryptographic assumption.
- It is **not** threshold cryptography; the name "quorum receipt" / "k-of-n multi-attestation" is the
  honest one. (The council corrected an earlier "threshold" label.)
- Receipts carry **hashes only, no PII** (unchanged) — the privacy posture that contrasts with SIGA's
  central-visibility model is preserved.
- **Additive**: the single-issuer path is untouched; a follow-up `NodeConfig` flag can switch
  `planes/node.ts` admission to quorum issuance keyed off the ledger's finalized `ValidatorSet`.
- **FTO still required** before any public claim — design-around is engineering intent, not a legal
  opinion ([FTO_TODO.md](../FTO_TODO.md)). Crypto composition is audited primitives, but the
  composition itself is not externally audited.

## Re-audit findings (applied)

The adversarial re-audit of the *implemented* code confirmed set-binding, dedupe, cross-suite,
substitution, and no-regression are **sound**, and found one **fail-OPEN**: a non-positive threshold
(`k=0`, `stakeThreshold=0`) accepted a receipt with **zero** signatures (`0 < 0` is false). Fixed:
both verifiers — and the pre-existing identical hole in `governance/quorum.ts` `enact()` — now
**fail closed on a non-positive threshold**, with regression tests. Conformance check **C12** asserts
k-finalizes / (k-1)-fails / set-substitution-rejected (12/12 CONFORMANT).

## Credits

Team workflow (recon → design → 6-way adversarial verify → synthesis) selected this as #1 of 3
confirmed apex upgrades. Council (DeepSeek, Grok, Mistral) converged on the validator-set-binding
fix. The implemented-code re-audit (forgery / set-binding / regression lenses) caught the k=0
fail-open. Roadmap #2 = ZK Policy-Satisfaction Receipts; #3 = govern-the-verb runtime negative oracle.
