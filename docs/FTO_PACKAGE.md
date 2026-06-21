# ENGINEERING INPUT (NOT A LEGAL OPINION): PolarSeek FTO Preparation Brief for Patent Counsel

> **Read first.** This is **engineering analysis** prepared to accelerate and focus a qualified patent
> attorney's freedom‑to‑operate work. It is **expressly NOT** a freedom‑to‑operate opinion, NOT a
> non‑infringement opinion, and NOT a guarantee. It does not — and must not be read to — conclude that
> PolarSeek avoids, does not infringe, is clear of, or designs around any SIGA patent or claim.
> **Never cite or file this under a title shortened to "FTO Brief" or "FTO Opinion."**
>
> Wherever this brief uses words like *distinction*, *candidate*, *clears*, or *designs around*, read
> them as **engineering hypotheses about where SIGA's claims may stop** — none is a finding that
> PolarSeek is outside any claim. Only counsel's written opinion can make that finding.

## 0. Status of the implementation (material to any claim comparison)

Claims read on what is actually **made, used, sold, or offered**. As of 2026‑06‑20 PolarSeek's software
build is complete (P0–P4: crypto, capabilities, kernel, receipts, translog, attest, planes, ledger,
governance, disclosure, settlement, keystore, conformance — **313 tests pass, 23/23 conformance**).
Counsel must compare against the **as‑built** implementation, not a description or an intended design.

## 1. Target patent family to clear

- **Anchor (only patent with detailed engineering visibility):** **US 9,607,214 B2** — SIGA "Sovereign
  OS" / "Commit‑Point Gate," claimed 2012 priority (**verify**). The asserted claim chain (per SIGA's
  Feb‑2026 deck, treated as **unverified input**): camera/sensor → static/dynamic decomposition across
  sequential frames ("the cognitive loop") → object‑identity continuity → zone/polygon occupancy over
  time → state‑change trigger → gate → record. Every link is perception‑ and state‑based.
- **The dual‑claim theory counsel must split:** SIGA asserts a **dual** monopoly over **both** AI
  *perception* (the "eye") **and** *governance* (the "gate"). Counsel must determine, per claim, which
  read on perception vs. governance vs. the fused chain — because PolarSeek's entire design‑around
  hypothesis rests on the governance claims being **tethered to the perception limitations**. If any
  governance/recording claim stands **without** the perception limitations, the wedge weakens and the
  governance‑only fallbacks (§2.B) must carry their own weight.
- **Broader estate (claimed, UNVERIFIED — counsel must enumerate + verify):** ~45 granted patents;
  ~2012 priority; ~20 jurisdictions; ~500 provisionals (a serious **submarine‑claim** hazard — pending
  claims can be tailored to a shipped competitor product). None of these counts is independently
  verified.

## 2.A The load‑bearing wedge — PolarSeek's *intended design* includes no perception/cognitive‑loop pillar (a distinction for counsel to confirm)

All‑elements rule (engineering, not legal): a claim is literally infringed only if **every** element is
present; a missing element defeats literal infringement of *that* claim but **not** necessarily under
the doctrine of equivalents (DOE) — counsel must analyze DOE per element. This is a **skeleton** to
populate against actual claim language, not a conclusion.

| SIGA element | Where PolarSeek's intended design does not practice it | CI signal |
|---|---|---|
| **[F1]** camera/sensor frame ingestion | kernel accepts only **typed action intents** (tool‑call/API/transaction) in canonical CBOR; no image/frame/pixel/sensor type is ever an input | `lint:cleanroom` F1 |
| **[F2]** static/dynamic decomposition across frames ("cognitive loop", Claim 1) | **no** feature decomposition, **no** per‑frame loop; admission is one pure policy evaluation over one explicit intent — *the single most important candidate distinction for counsel to test* (verify it is a true claim limitation, not a preferred embodiment) | F2 |
| **[F3]** object‑identity continuity across frames | no tracked entity persists across calls; subject refs are opaque caller IDs, never re‑identified/correlated | F3 |
| **[F4]** zone/polygon occupancy over time | no spatial/geometric model; authority = typed capability scopes, not geography‑over‑time | F4 |
| **[F8]** "attention = decomposition" stretched onto LLM/tensor inference | admission is bounded policy evaluation over CBOR, **not** neural inference/tensor decomposition — the most likely DOE vector; counsel should test it directly | F8 |

## 2.B Governance‑only fallbacks (if a governance claim survives without the perception limitations)

- **[F5]** stateless **pure‑function** kernel — holds no cross‑decision state, reads no clock, no
  "state‑change trigger" (the kernel never tracks state changes; any aggregate is an externally‑signed
  scalar input — a **candidate** DOE distinction vs. "state‑change tracking" counsel must test).
- **[F6]** no "commit‑point gate" terminology anywhere (marking/willfulness/estoppel angle).
- **[F7]** decoupled, standards‑based receipts (SCITT/COSE/RATS) rather than a fused
  perception‑to‑receipt mechanism.

## 3. Prior‑art candidates (each to be confirmed by counsel before any reliance)

Items PolarSeek treats as **candidate prior art believed** to pre‑date or be independent of the
(unverified) SIGA 2012 filings — counsel must independently verify each publication date and the
"different field" narrative: FIPS 203/204/205 + the NIST PQC corpus; IETF SCITT / RATS (RFC 9334) /
COSE (RFC 9052); UCAN / macaroons (attenuation‑only capabilities); RFC 6962 Certificate Transparency;
RFC 9381 ECVRF. See [PRIOR_ART_NOTES.md](./PRIOR_ART_NOTES.md).

## 4. What counsel must independently do (the checklist)

Enumerate + verify the actual SIGA patent numbers, priorities, and jurisdictions; account for the
provisional/continuation/submarine pipeline; chart independent + dependent claims and split
perception/governance/fused; map PolarSeek's **as‑built** admission path element‑by‑element and opine
**literally and under DOE** whether the wedge places PolarSeek outside **all** asserted claims or only
the perception subset; rule on the stateless‑kernel and signed‑scalar‑vs‑state‑change DOE questions;
rule on "commit‑point gate" terminology; complete export‑control / dual‑use classification (EAR/ECCN,
Wassenaar) per jurisdiction; identify the accountable legal entity the opinion is addressed to; and
**deliver a written, jurisdiction‑specific FTO opinion on file.** Engineering opines on none of this.
