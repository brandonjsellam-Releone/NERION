# Nerion — Beyond-Apex Frontier (v1)

> **Status:** research-engineering ideation. Every item below is **UNAUDITED** and **pre-FTO**.
> "Beyond-apex" and "benchmark leadership" are **aspirations pending measurement**, not present
> claims. No item asserts novelty, patentability, non-infringement, "audited", FIPS-validated, or
> "production-ready". EU-AI-Act references are **preparatory technical alignment only** — never a
> "compliant AI system" claim. All work is **branch-only**; a human maintainer reviews and merges.
> The govern-the-verb design-around is **engineering intent, not a legal opinion** — FTO counsel
> gates any public claim.

## What this is

A forward-looking frontier audit of **beyond-backlog** upgrades — engineering directions *not*
already on the [21-day sprint backlog](./APEX_SPRINT_BACKLOG.md) (A1–A42 / B1–B12, separately owned
by the running engines) — aimed at putting Nerion ahead of the state of the art and in *independent,
reproducible* benchmarks while staying strictly inside every guardrail (the `Ps1` wire-tag / `ps-*.json`
KAT freeze, verb-only governance with no in-gate cross-decision state, measured-vs-modeled honesty).

### How it was produced (Team Apex)

1. **Generate** — six independent lenses (PQ-crypto, ZK/proofs, consensus, governance, benchmarking,
   security/formal), each reading the real modules (`crypto/` 27 files, `ledger/` 23, `kernel/`,
   `disclosure/`, `capabilities/`, …) and ADRs, proposing candidates grounded in cited files.
2. **Adversarially verify** — a per-lens skeptic refuted each candidate against the backlog and
   guardrails. 24 of the original candidate set survived (14 `REAL_BEYOND_APEX` + 9 `INCREMENTAL`);
   duplicates/overclaims were killed (CF-1, CF-3, ZK-PB-02, BENCH-02), and "machine-checked" framing
   was deflated where the underlying object is really a strong property test.
3. **Cross-model council verdict** — the synthesized dossier was put to the live external council
   seats (DeepSeek, Grok, OpenAI, Mistral, IBM watsonx, Hermes; Gemini timed out). **Their corrections
   are folded into the execution plan below.**

## Council cross-verdict (6 external seats)

| Seat | Verdict | Headline |
|---|---|---|
| DeepSeek | FIX-FIRST | Add a **FORMAL-TOOLCHAIN-BOOTSTRAP**; mark BLOCKED items; elevate PQC-1 & CF-4. |
| Grok | FIX-FIRST | Rust CI/ledger (A1/A29) blocks BENCH-03/04/05; "sub-500 µs" stays MODELED until hardware-timed. |
| OpenAI | FIX-FIRST | **BENCH-01 should be #1, not ZK-PB-03**; add external-baseline methodology; promote provenance & PQC-1. |
| Mistral | REVISE | EU-AI-Act framing must be "preparatory" not "alignment"; ship BENCH-01 / SAF-2 / SAF-5; consider human-oversight. |
| watsonx | REVISE | FTO is engineering intent, not legal cover; route critical items to audit + counsel before any claim. |
| Hermes | FIX-FIRST | Foundational `bench/` before the narrow ZK harness; every artifact needs a "research prototype" banner. |

**Unanimous: FIX-FIRST / REVISE — none SHIP-as-is, none DO-NOT-SHIP.** The strategy is sound; the
*ordering and readiness honesty* needed correction. Consensus changes applied:

- **BENCH-01 is the keystone (rank 1)**; ZK-PB-03 folds in as its ZK module, not ahead of it.
- **Two net-new items added** (below): `FORMAL-TOOLCHAIN-BOOTSTRAP` and `BENCH-BASELINE`.
- **Every item carries a readiness tag**; toolchain-absent and Rust-dependent items are marked BLOCKED.
- **Benchmark provenance (BENCH-05) folds into BENCH-01 from day one** (signed traces + env capture).
- **Cheap unblocked hygiene (PQC-1) and the govern-the-verb-moat items (GOV-POLICY-ALGEBRA,
  GOV-MANIFEST-BIND) ranked above raw latency.**

## Corrected execution plan (by readiness)

Readiness: **READY** = no blocker · **GATED** = needs a Track-B ADR / prior item · **BLOCKED:tool** =
needs an absent prover toolchain · **BLOCKED:rust** = needs backlog A1 (Rust CI) / A29 (Rust ledger).

### Tier 0 — keystones (do first; everything else reports against these)
| # | id | Item | Owner | V/E/R | Readiness |
|---|---|---|---|---|---|
| 1 | BENCH-01 | Stand up the missing `bench/` dir: micro (decide() throughput, permit verify, ML-DSA-87 sign/verify, dCBOR, ZK range) + macro end-to-end T2 governed-payment gate latency; signed JSON results, env capture, fixed seed — **provenance (BENCH-05) included from day one** | Engineering | 5/M/low | **READY** |
| 2 | ZK-PB-03 | Reproducible ZK proof-size / verify-latency harness for the disclosure layer (RangeProof bytes & `verifyBelow` ms vs n; PSP aggregate overhead; SHA3-Merkle inclusion vs allow-list size) — the denominator that makes every ZK claim MEASURED | Engineering | 5/S/low | **READY** (folds under BENCH-01) |

### Tier 1 — ready now, high value (no external blocker)
| # | id | Item | Owner | V/E/R | Readiness |
|---|---|---|---|---|---|
| 3 | SAF-2 | Cross-impl **differential** fuzzing (TS vs Rust vs Python) with a semantic-equivalence oracle on dCBOR / replay-canon / AEAD-accept boundary | Engineering | 5/M/low | **READY** (tri-language arm deepens as the Rust surface matures) |
| 4 | GOV-PARAMS-BLINDNESS | Type-level `ParamsBlind` view + property test that `decide()` structurally cannot read `intent.params` — the core "govern the verb, never the eye" invariant, from finite spot-check → unbounded + structural | Engineering | 4/S/low | **READY** |
| 5 | PQC-1 | Machine-checked global domain-separation **label registry** + injectivity/coverage gate (no inline-literal escape; prefix-freeness) — *council-elevated* | Security | 3/M/low | **READY** |
| 6 | GOV-POLICY-ALGEBRA | Total verb-only **policy algebra**: totality + order-independence + conflict-freedom (shadow/gap lint) — closer to the moat than raw latency | Engineering | 4/M/low | **READY** (Track-B if `evaluatorVersion()` output changes) |
| 7 | GOV-MANIFEST-BIND | Bind Action-Manifest `riskClass`/`policyHash` to the kernel's applied tier/evaluator (close verbId↔tier laundering) — EU-AI-Act framing = **preparatory only** | Engineering | 3/S/low | **READY** |
| 8 | SAF-5 | Measured constant-time evidence (dudect / Welch-t under load) on the enumerated secret-compare oracles — closes the SIDE_CHANNEL_AUDIT residual | Security | 4/M/med | **READY** (null result *bounds*, not proves; platform-specific) |
| 9 | PQC-4 | Key-committing AEAD for the KEM-seal path (close the AES-256-GCM non-commitment / partitioning-oracle gap) — seal path is pre-load-bearing | PQ-Crypto | 3/M/med | **READY** (additive open-side check) |
| 10 | CF-2 | Accountable-safety slashable-evidence **extractor** (BigInt-stake ≥1/3 culpable set from two conflicting finalized verdicts) + theorem-as-predicate ADR | R&D | 3/M/med | **READY** |
| 11 | ZK-PB-04 | Bulletproofs-style **O(log n)** inner-product aggregation of the dual-range proof (classical/dlog; small-proof complement to PQ-large) | R&D | 3/L/med | **READY** (Track-B + conformance-regen; `Ps1` frozen) |
| 12 | PQC-2 | Frozen KEM-combiner **negative-KAT** (truncation/extension class + regression-pin vs a future `@noble` bump) | Engineering | 2/M/low | **READY** |
| 13 | PQC-3 | Reproducible **composed-QROM security-margin** artifact (ML-DSA-87 + SHAKE256 + HKDF-SHA-384) — analytic script+memo, no prover toolchain | R&D | 3/L/med | **READY-analytic** (MODELED; routes to external audit) |
| 14 | ZK-PB-01 | Hash-based (FRI/STARK) **PQ-sound** policy-satisfaction proof for the numeric clause (assumption-class upgrade vs classical dlog) | PQ-Crypto | 3/L/high | **READY-research** (behind `allowUnauditedZk`; Track-B; highest risk) |

### Tier 2 — prerequisite-gated (needs the bootstrap first)
| # | id | Item | Owner | V/E/R | Readiness |
|---|---|---|---|---|---|
| — | **FORMAL-TOOLCHAIN-BOOTSTRAP** | *Council-added prerequisite.* Provision + CI-wire TLAPS / Lean / Tamarin / ProVerif / EasyCrypt (confirmed **absent** in the build env) and prove one trivial lemma checks in CI. Gates all "machine-checked" work below. | R&D | 5/M/low | **READY** (must precede 15–18) |
| — | **BENCH-BASELINE** | *Council-added.* Adversarial comparative methodology: canonical workloads, warmup/cold-start rules, hardware/OS disclosure, P50/95/99/999 + variance, **signed raw traces**, correctness-gates-before-speed, and baseline adapters for **OPA / Cedar / UCAN-macaroons / SPIFFE-SPIRE** under same-security-level rules. Makes BENCH numbers persuasive, not self-referential. | Engineering | 5/M/low | **GATED** (on BENCH-01) |
| 15 | GOV-NI-PROOF | Machine-checked **non-interference** theorem (decision constant in the perception/params channel) in TLA+/Lean | R&D | 4/L/low | **BLOCKED:tool** |
| 16 | SAF-1 | Tamarin/ProVerif symbolic model of the Plane-1 permit + Plane-2 receipt protocol (unbounded-session Dolev-Yao) | PQ-Crypto | 4/L/med | **BLOCKED:tool** |
| 17 | SAF-3 | Machine-checked **fail-closed/default-deny** over the finite decision lattice + replay/evaluator-mismatch deny paths | Engineering | 3/M/low | **Partial-READY** (exhaustive enumeration now; "machine-checked" framing needs tool) |
| 18 | SAF-4 | EasyCrypt/Lean mechanized **range-proof soundness** (the n≤251 no-aliasing bound is the must-ship core; OR-proof special-soundness extractor is a stretch) | PQ-Crypto | 3/L/med | **BLOCKED:tool** (Lean for the core lemma) |

### Tier 3 — Rust / ADR-gated
| # | id | Item | Owner | V/E/R | Readiness |
|---|---|---|---|---|---|
| 19 | BENCH-03 | TS-reference vs Rust hot-path differential perf on the shared byte-exact KAT corpus (criterion + BENCH-01) | Engineering | 3/M/low | **BLOCKED:rust** (A1) |
| 20 | BENCH-04 | 10-agent-swarm governance round-trip vs the stated AGENCY-MATRIX **sub-500 µs P99** government target, plane-by-plane | Engineering | 4/M/med | **BLOCKED:rust**+bench (honest TS-ref P99 may miss 500 µs — report plainly; never fold nearline PQ signing into the gate) |
| 21 | CF-4 | Self-certifying PQ weak-subjectivity **checkpoint** (epoch+height+≥2/3 bundle+consensusSetId) | R&D | 3/M/low | **GATED** (B5 / ADR-0020) |
| 22 | CF-5 | Differential/metamorphic **finality oracle** (cross-impl agreement rate) | Engineering | 2/M/low | **BLOCKED:rust** (A29 ledger arm) |
| 23 | ZK-PB-05 | Batched/amortized **verifier-side** multi-receipt PSP + Merkle-membership (RLC fused MSM) — auditor-stream, off-gate | Engineering | 3/M/med | **GATED** (on ZK-PB-03) |

### Candidate needing a screen (do not schedule yet)
- **GOV-HUMAN-OVERSIGHT** (Mistral) — a time-locked human veto for critical governance decisions (EU-AI-Act Art. 52 framing). **Caveat:** a veto path must stay **off the synchronous gate and stateless-compatible**, or it drifts into in-gate cross-decision state (the SIGA commit-point territory the design-around avoids). Screen against govern-the-verb before any build. *Note:* the Mistral/watsonx seats also surfaced Swiss-foundation / FINMA / MiCA items — out of scope here (Nerion is a software protocol, not a financial instrument); recorded only so the bias is visible.

## Cross-cutting themes

1. **Measurement is the moat.** The field leaves the performance/proof-cost axis blank; Nerion's
   largest defensible edge is reproducible, honestly-labeled numbers. The `bench/`+ZK harnesses are
   the keystones that convert every other lens from MODELED to MEASURED.
2. **Evidence-ladder climbing.** Promote load-bearing invariants from TEST/LOGIC → property-tested →
   type-enforced → machine-checked. Not new capability — stronger substantiation auditors look for.
3. **Govern-the-verb integrity is a hard guardrail.** Several items (ZK-PB-05, BENCH-04, SAF-3,
   GOV-HUMAN-OVERSIGHT) are only safe because they stay verb-only / verifier-side / off the gate;
   any drift to in-gate cross-decision state both misrepresents latency and re-enters SIGA territory.
4. **Close self-asserted-trust gaps with cryptographic self-consistency** (GOV-MANIFEST-BIND, CF-4,
   CF-2, PQC-1): bind declared artifacts to enforced decisions / named sets.
5. **PQ assumption-class hardening beyond "cite the standard"** (PQC-3 composed-QROM, PQC-4 key-
   committing AEAD, ZK-PB-01 hash-based soundness, SAF-4) — labeled MODELED/UNAUDITED, audit-gated.
6. **Cross-impl parity as both assurance and headroom** (TS/Rust/Python on a shared KAT corpus):
   underwrites SAF-2, BENCH-03, CF-5 — several arms gated on the Rust surface existing.

## Top benchmark plays (honestly framed)

1. **Governance round-trip latency** — the blank axis. Publish decide() p50/95/99, permit-verify
   p50, end-to-end T2 gate latency (BENCH-01), then the 10-agent hot-path P99 against the
   AGENCY-MATRIX sub-500 µs target (BENCH-04). *Honesty:* TS-reference, single-host, MEASURED-vs-
   target, plane-by-plane — never fold nearline PQ signing into the gate.
2. **Comparative governance benchmark vs OPA / Cedar / UCAN / SPIFFE** (BENCH-BASELINE) under
   same-security-level rules with signed raw traces and an anti-cherry-picking policy. *This is what
   makes the numbers persuasive rather than self-referential.*
3. **ZK disclosure cost profile** — RangeProof bytes + verify-ms vs n (ZK-PB-03), then O(n) OR-proof
   vs O(log n) IPA (ZK-PB-04) and amortized per-receipt verify vs batch size (ZK-PB-05). Baseline:
   Nerion's own current code as the reproducible denominator; secondary: published Bulletproofs/STARK.
4. **Tri-language differential robustness** — N-million cross-impl (TS/Rust/Python) differential-fuzz
   cases with 0 unresolved semantic divergences on the canonical-CBOR / AEAD boundary (SAF-2).
   *Honesty:* found+fixed internally is not an external audit.
5. **Invariant-strength as soundness benchmark** — % of injected shadow/gap policy faults caught vs
   Cedar/OPA-lint (GOV-POLICY-ALGEBRA); adversarial-params decision-divergence count (GOV-PARAMS-
   BLINDNESS); machine-checked theorem count 4→N incl. non-interference (GOV-NI-PROOF). *Honesty:*
   MODELED/structural, explicitly not "proven-secure".

## Honesty & guardrail register (must hold on every artifact)

- **Banner on every deliverable:** "Research prototype. UNAUDITED, pre-FTO. No security or non-
  infringement claims. Benchmark numbers are reproducible artifacts, not superiority claims unless run
  against stated baselines. Formal items are planned/partial unless linked to machine-checkable
  artifacts."
- **MEASURED vs MODELED stays explicit.** Latency/coverage = MEASURED; QROM/soundness/non-interference
  = MODELED or model-checked-of-the-model, never proofs of the deployed system. No bare "faster/smaller".
- **PQ vs classical never blurred.** ZK-PB-01 (PQ-sound, large) and ZK-PB-04 (small, classical/dlog-
  breakable) are different assumption classes.
- **`Ps1` / `ps-*.json` KAT freeze is untouchable** without a Track-B ADR + conformance-regen plan.
- **No in-gate cross-decision state.** Verb-only, stateless per-action decision; the three-plane
  separation is load-bearing for both latency honesty and the FTO design-around.
- **EU-AI-Act = preparatory technical alignment**, never "compliant". FTO = engineering intent;
  counsel gates any public claim (watsonx, standing rule).
- **"Council-verified" ≠ audited.** It means multi-model cross-examination, not a security/FTO audit.

## Ownership & immediate next 3

- **Engineering** owns the keystones (BENCH-01, ZK-PB-03, SAF-2) + the ready governance items.
- **R&D** owns FORMAL-TOOLCHAIN-BOOTSTRAP, GOV-NI-PROOF, CF-2/CF-4, PQC-3.
- **PQ-Crypto** owns SAF-1, SAF-4, PQC-4, ZK-PB-01.
- **Security** owns PQC-1, SAF-5.
- **Innovation** continues the spike line that seeded several of these (NZK / LED / CAP / KER).

**Council-consensus first three to ship:** **BENCH-01** (with provenance baked in) → **SAF-2** →
**GOV-PARAMS-BLINDNESS** (or **ZK-PB-03** as the ZK module of BENCH-01). Provision the formal
toolchain in parallel so Tier-2 unblocks.

---

*Provenance: produced 2026-06-24 by Team Apex — a 6-lens generate→adversarial-verify Workflow (13
agents) cross-examined by 6 live external council seats (DeepSeek · Grok · OpenAI · Mistral · watsonx ·
Hermes). Branch-only; awaits human review and merge. Supersedes nothing; complements
[APEX_SPRINT_BACKLOG.md](./APEX_SPRINT_BACKLOG.md) and [FRONTIER.md](./FRONTIER.md).*
