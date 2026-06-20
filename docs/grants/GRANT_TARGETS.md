# Nerion Grant Targets + Submission Steps

> The assistant **drafts**; **you submit.** I can't click Submit, send these emails, or push the repo for
> you — each step below is a manual action you perform. The application ([NLnet‑NGI‑Application.md](./NLnet-NGI-Application.md))
> is ready to paste as‑is.

## Ranked funders (best fit first)

**1. NLnet Foundation — Open Internet Stack "Restack". ← PRIMARY, but opens ≈ September 2026 (not live now).**
**LIVE STATUS (verified 2026‑06‑20 via nlnet.nl):** NLnet **paused all general open calls on 2026‑06‑12**
(final NGI Zero Commons Fund call closed 2026‑06‑01) to take stock after a decade of NGI. **"After the summer"**
it reopens the regular process **plus three new Open Internet Stack programmes: Restack, CodeSupply, ELFA.**
Right now **only two pilots are open** — NGI TALER (GNU Taler *payments*) and NGI Fediversity (Nix/NixOS
*hosting*), deadline 1 Aug 2026 — and **Nerion fits neither** (both are narrow single-domain pilots).
**Restack is the clean home:** per <https://nlnet.nl/restack/> it will award **€7M through 2030**, grants
**€5k–50k (scalable significantly on proven potential)**, and is **explicitly open to "disruptive technologies
on every layer," middleware, "norms and standards," and building blocks** — a PQC+ZK governance standard for
AI‑agent actions fits squarely. **Bundled audit CONFIRMED** (Restack page, verbatim): *"we provide all kinds of
help too — ranging from accessibility scans and security audits to reproducible packaging…"* — so one Restack
grant funds **both** Nerion's R&D **and** the Gate‑2 crypto audit. Funded by Horizon Europe (GA 101299072);
part of the EU Tech‑Sovereignty package. **Plan: prep now, submit to Restack at open (~Sept 2026).** Watch the
exact date via the NGI Zero newsletter (<https://lists.ngi-0.eu/subscribe/ngizero-newsletter>) and the Restack
"Guide for Applicants" + FAQ (preliminary versions already linked from the Restack page). Submit at
<https://nlnet.nl/propose/> when live; contact brandon.sellam@gmail.com.

**2. OSTIF (Open Source Technology Improvement Fund).**
Moderate‑to‑weak fit for a *new* project (favors established, widely‑used infra: OpenSSL, curl, git) — but
the strongest **auditor‑sourcing + management** partner once NLnet money is in hand, and a strong technical
match (it prices for "complex cryptography"). USD 30k–200k audits, sponsor‑funded. **Use as the
audit‑sourcing partner after NLnet, not the primary grant.** **Contact:** <https://ostif.org/get-an-audit/>
— mention NLnet/NGI0 funding is being secured to co‑fund (materially improves standing).

**3. Open Technology Fund (OTF) — Red Team Lab.**
Conditional fit, gated by an **internet‑freedom narrative** (protecting at‑risk users from
centralized‑visibility surveillance), not usage. Funds third‑party crypto audits for internet‑freedom OSS;
non‑OTF projects can request an audit if "otherwise relevant to internet freedom." **Secondary audit path
only, with a deliberate mission framing.** Apply: <https://www.opentech.fund/labs/red-team-lab/>.

**4. Sovereign Tech Agency — Bug Resilience. ← DEFER.**
Weak fit now: eligibility hinges on being a **vital, widely‑relied‑upon** base technology with real
dependents. Nerion has zero dependents today → out of scope. **Revisit post‑adoption.**

## Pre‑submission checklist (do BEFORE pasting into any form)

1. ✅ **DONE 2026‑06‑20 — live call confirmed.** NLnet's general calls are **paused**; the best‑fit successor
   **Restack opens ≈ Sept 2026** ("after the summer"). Only NGI TALER + NGI Fediversity are open now (don't fit).
   **Action shifts from "submit now" to "prep now, submit to Restack at open."** Re‑check the Restack page +
   newsletter for the exact open date before submitting.
2. **Publish the public Apache‑2.0 repo first** (LICENSE + code are ready; near‑zero cost) so reviewers
   have open‑source evidence at review time, not a promise.
3. **Reconcile the stale doc numbers before pushing** (see below) so a reviewer cloning the repo sees one
   consistent figure.
4. **Get one indicative auditor quote** (ToB / NCC / Cure53, or OSTIF) for a ZK range‑proof + OR‑proof
   review; drop the real figure into the milestone budget so cost‑effectiveness rests on a quote.
5. ✅ **DONE 2026‑06‑20 — bundled audit CONFIRMED for Restack.** The Restack page states the programme provides
   "security audits" as in‑kind support alongside the grant, so one Restack award can fund **both** the R&D **and**
   the Gate‑2 crypto/ZK audit. (OSTIF/OTF remain parallel options if a deeper or faster audit is wanted.)

## Submit (NLnet, primary)
6. Go to <https://nlnet.nl/propose/>. 7. Paste application §1–8 into the matching fields; requested EUR
45,000. 8. Use brandon.sellam@gmail.com + the public repo URL. 9. Keep §7 (Honest Status) **verbatim** —
candor is the credibility edge. 10. Submit; save the reference number.

## After NLnet (only as needed)
11. Want an auditor sourced/managed? Contact OSTIF (stating NLnet funding secured). 12. Internet‑freedom
audit path? OTF Red Team Lab. 13. **Do NOT apply to Sovereign Tech** until Nerion has real dependents.
