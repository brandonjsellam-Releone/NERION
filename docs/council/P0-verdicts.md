# P0 — Multi-Model Council Verdicts

Date: 2026-06-17/18. Seats run: **Gemini** (technical/standards verify),
**watsonx** (IP/FTO + regulatory diligence), **DeepSeek** (adversarial review).
The council is a blocking gate; this records verdicts and their resolution.

## Gate outcome

**PASS with required corrections applied.** No unresolved *high-severity* finding
blocks the P0 crypto milestone. Several findings are real and are either (a) fixed
now, or (b) explicitly tracked as P1 requirements (the kernel/planes they concern
are unbuilt and already flagged in the threat model). Marketing/claim hygiene
findings are accepted and applied.

## Seat 1 — Gemini (technical verification)

Verdicts and resolution:

| Gemini verdict | Our resolution |
|---|---|
| FIPS 203/204/205 final 2024-08-13 — **CORRECT** | kept |
| FIPS 206 not final — **CORRECT** | kept |
| HQC 2025-03-11 / FIPS 207 — **UNVERIFIABLE ("fictitious")** | **Overruled by primary source.** NIST news (nist.gov, 2025-03) confirms HQC selected **2025-03-11**, draft ~2026, final 2027. FIPS *number* not yet officially designated → ADR softened to "FIPS number TBD". |
| SP 800-227 & SP 800-230 — **WRONG ("fictitious")** | **Overruled by primary source.** csrc.nist.gov confirms **SP 800-227 FINAL 2025-09-18** and **SP 800-230 IPD 2026-04-13**. Kept. |
| CNSA 2.0 algorithms/timeline — **CORRECT** | kept |
| PS-1 (Cat-3 X-Wing) + ML-DSA-87 (Cat-5) — **IMPRECISE (level mismatch)** | **Accepted.** ADR-0001 now states PS-1's security *floor* is Cat-3 (the KEM); ML-DSA-87 is deliberately over-provisioned so one signing stack serves both tiers. |

**Why Gemini was wrong on the dates:** the Gemini seat has no live web access and
reasons from training with a cutoff predating these 2025–26 NIST actions; it
correctly labeled them "unverifiable from my knowledge," not "false." Per the
spec rule *primary source wins, don't trust a single model*, we re-fetched NIST
CSRC/nist.gov directly and confirmed the workflow's web-cited facts. Net: no
crypto/standards claim in ADR-0001 is wrong; one precision edit (HQC number) and
one labeling edit (PS-1 floor) applied.

## Seat 2 — watsonx (IP/FTO + regulatory diligence)

- Confirms "govern the verb, never the eye" + stateless kernel **may be** a sound
  engineering design-around for the perception/cognitive-loop/zone/state-change
  claims, **but** residual risk remains under the **doctrine of equivalents** and
  from **governance-layer claims that are not perception-based**.
- Endorses the honest posture (engineering intent, not a legal opinion; FTO
  required before any public claim).
- Red flags a sophisticated counterparty will raise: insufficient FTO depth;
  unclear handling of governance-layer claims; regulatory uncertainty (EU AI Act,
  eIDAS, MiCA/MTL, SOC2/ISO); over-dependence on a single patent-counsel opinion.

**Resolution:** all consistent with [FTO_TODO.md](../FTO_TODO.md) and
[DESIGN_AROUND.md](../DESIGN_AROUND.md). The governance-layer-claims risk is added
emphasis — DESIGN_AROUND §6 and FTO_TODO item (b) already require counsel to chart
the admission path against *governance* claims, not only perception claims.

## Seat 3 — DeepSeek (adversarial review) — verdict: "DO-NOT-SHIP" (for a *shipping product*)

DeepSeek reviewed as if this were a production system and is right that it must
not ship as one. Findings and disposition:

| Finding | Disposition |
|---|---|
| **PermitToken replay** (no sequence/nonce, "fresh attestation" hand-waved) | **Accepted, tracked.** Threat model T-P1-1 / M-P1-1 / R2 already require single-use attestation-nonce + audience + action-hash binding + short expiry + resource idempotency. The kernel is **unbuilt**; this is the #1 P1 requirement. |
| **HMAC ≠ public verifiability; misattributed to Plane 1** | **Accepted, fixed.** DESIGN_AROUND now states public verifiability is a **Plane-2** property; the Plane-1 PermitToken is session-MAC'd and not publicly verifiable. |
| **Statelessness does not escape *governance* claims** | **Accepted** — same point as watsonx; FTO must test it (FTO_TODO item b). |
| **<1 ms / "decentralized" are pre-implementation** | **Accepted.** README/DESIGN_AROUND/STATUS label `<1 ms` a **target** and Planes 2–3 **unbuilt**. No external claim asserts them as present. |
| **HMAC key single point of failure** | **Accepted, tracked.** M-P1-3 prescribes per-resource HKDF-derived keys + HSM + rotation; DeepSeek's threshold-MAC idea added to the P1 backlog. |
| **Crypto-agility "untested" with one algorithm family** | **Partially accepted.** Two KEM constructions and two signature schemes are implemented and negotiation + **SuiteID-bound downgrade resistance are tested**; HQC (the non-lattice leg) remains the honest gap. |

## Net

The council strengthened the work: it forced a primary-source re-verification of
standards, corrected a security-level labeling imprecision, fixed a
public-verifiability misattribution, and sharpened the FTO scope to include
governance-layer claims. None of these block the P0 *crypto* milestone (51 tests
green); the replay/key-management findings are P1 kernel requirements and were
already in the threat model. Re-run the full council before P1 exit and before any
public claim.
