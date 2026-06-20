# Nerion — ZK / cryptography auditor shortlist (for the Gate-2 quote)

> Companion to [AUDIT_FUNDING_OUTREACH.md](./AUDIT_FUNDING_OUTREACH.md). **You request the quote(s); the
> assistant only shortlists + drafts.** Goal of this step (GRANT_TARGETS checklist #4): get **one indicative
> quote** so the M2–M5 milestone budget rests on a real figure, not an estimate.
>
> **Pricing below is indicative** (from public engagement ranges, 2025–2026) and **must be confirmed by an
> actual quote** — do not put these numbers in the application; put the number a firm gives you.

## What to ask them to review (lead with the highest-risk item)
1. **ZK range proof** — `disclosure/zkrange.ts`: Pedersen/ristretto255 + bit-decomposition + Chaum-Pedersen
   OR-proofs, SHAKE256 Fiat-Shamir, dual-range, n≤252. Soundness, special-soundness/simulation,
   generator-H provenance, **strong (transcript-binding) Fiat-Shamir / Frozen-Heart** resistance.
2. **ZK policy-satisfaction proof** — `disclosure/policyproof.ts`: hidden-amount `≤ ceiling` / `aggregate ≤ cap`.
3. **New Pedersen↔SHA3 commitment-equality design** (ADR-0013) — the funded dev deliverable.

Scope ≈ 2–3 novel constructions, ~1,500–3,000 LoC. Hand them `docs/AUDIT_PACKAGE.md` + `docs/THREAT_MODEL.md`.

## Shortlist (request indicative quotes from 2–3)

| Firm | Base | ZK / crypto strength | NLnet/OSTIF-co-funding angle | Indicative* |
|------|------|----------------------|------------------------------|-------------|
| **zkSecurity** (zksecurity.xyz) | US/remote | **ZK-proving-systems specialist** — exactly this problem class (proof-system soundness, Fiat-Shamir, commitment schemes) | Boutique; engageable via grant funding | ~€20k–45k, 2–4 wk |
| **Cure53** | **Germany (EU)** | Strong security review; crypto-capable | **NGI0's frequent in-kind audit partner**; EU base helps the European-Dimension story | ~€20k–45k, 2–4 wk |
| **Radically Open Security (ROS)** | **Amsterdam (EU)** | Pentest + crypto; NL non-profit ethos | **The classic NLnet/NGI0 audit channel** — best "co-funded via Restack" fit | ~€15k–40k, 2–4 wk |
| **Trail of Bits** | US | **Gold-standard applied-crypto + ZK** (cryptography team, zkdocs) — the benchmark the dossier names | Premium; engage via NLnet audit support | ~€40k–80k+, 3–6 wk |
| **Least Authority** | **Berlin (EU)** | Privacy/ZK audits (Zcash, Ethereum components) | Works with open-source/grant-funded & non-profits; EU base | ~€25k–50k, 3–5 wk |
| **Veridise** | US | ZK + **formal-verification** focus (circuit soundness, academic roots) | Good if you want a formal-methods angle | ~€30k–60k, 3–5 wk |
| **Zellic** | US | Heavy ZK-circuit / proving-system audit volume | Market-rate web3/ZK shop | ~€30k–60k, 2–5 wk |

*Indicative only — get a real quote.

## Recommendation
- For the **NLnet/Restack co-funding + European-Dimension** narrative: lead with **Radically Open Security** or
  **Cure53** (EU-based, NGI0-aligned) — strongest "one Restack grant funds R&D *and* the audit" story.
- For the **deepest ZK-soundness** signal: **zkSecurity** (specialist match) or **Trail of Bits** (the named
  benchmark). **Veridise** if you want a formal-verification flavor.
- **Suggested play:** request indicative quotes from **3** — e.g. ROS *(NLnet channel)* + zkSecurity *(ZK depth)*
  + Trail of Bits *(benchmark)* — compare, and drop the most credible figure into M2. Mention NLnet/NGI0
  co-funding is being secured (it materially improves standing and pricing flexibility).
- The quote-request email is the OSTIF/auditor draft in
  [AUDIT_FUNDING_OUTREACH.md](./AUDIT_FUNDING_OUTREACH.md) — reuse it, swap the recipient, attach the repo URL
  once the repo is public.
