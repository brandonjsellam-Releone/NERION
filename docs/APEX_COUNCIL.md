# Team Apex — the multi-model council ("powerhouse / GOD mode")

**Team Apex** is Nerion's adversarial, multi-model review powerhouse. No single model is
trusted as an author: every autonomous upgrade and every design decision is generated
and/or cross-examined by **eight independent model lineages**, and a human maintainer
adjudicates and is accountable. This is a *process for producing evidence*, not an
autonomous author — exactly the posture disclosed in the grant application.

## The ten seats

| Seat | Lineage | Council tool(s) | Role |
|------|---------|-----------------|------|
| **Claude** | Anthropic (apex: Opus / Fable 5) | workflow `agent()` / main loop | Orchestrator + implementer + adversarial verifier |
| **ChatGPT** | OpenAI (apex) | `openai_review` / `openai_chat` | Independent review |
| **Gemini** | Google (apex) | `gemini_verify_technical` / `gemini_fact_check` | Technical / standards verification |
| **Grok** | xAI (apex) | `grok_review` / `grok_chat` | Independent review |
| **DeepSeek** | DeepSeek V4-Pro | `deepseek_review` / `deepseek_chat` | Critical second opinion |
| **Mistral** | Mistral (apex) | `mistral_independent_review` | EU-lineage independent review |
| **Watsonx** | IBM watsonx | `watsonx_second_opinion` / `watsonx_due_diligence` | IP / governance diligence |
| **Perplexity** | Sonar | `perplexity_research` | Live-web fact-check (SCOUT) |
| **NVIDIA** | Nemotron-3 Super 120B (NIM) | `nvidia_review` / `nvidia_chat` | Systems/hardware-optimised independent review (added 2026-06-24; 550B ultra is catalogue-listed but not currently serving, so the largest serving Nemotron-3 is used) |
| **Moonshot** | Kimi K2.7 | `moonshot_review` / `moonshot_chat` | Long-context / multilingual independent review (added 2026-06-24) |

(Hermes is also available as an auxiliary review seat.)

## Review protocol (applied every apex cycle)

1. **Generate / implement.** Claude (orchestrator) implements the next backlog item on a
   dedicated `apex/cycle-*` branch, or drafts a Track-B design/ADR.
2. **Council review — fan out.** The diff (or design) is sent to every *available* seat in
   parallel. Each returns a structured verdict: approve / revise / reject + rationale.
   Perspective diversity is the point — different lineages catch different failure modes.
3. **Adjudicate (consensus rule).** Keep the change only if the council reaches consensus:
   **no blocking objection** and a **majority approve**. Any seat raising a correctness,
   soundness, or honesty/FTO concern blocks until resolved or the change is dropped.
4. **Gate.** Independently, `npm run gate` (+ `npm run conformance`, + `reuse lint` if
   licensing changed, + `cargo` checks for Rust) MUST pass before the branch is pushed.
5. **Human adjudication.** Branches are pushed for the maintainer to review and merge.
   The council never merges to `main`, never writes the grant proposal, never relaxes the
   UNAUDITED / pre-FTO posture.

## Non-negotiable guardrails

- Branch-only; never auto-merge to `main`.
- Never change cryptographic behavior or the frozen wire-tags / KATs (`SuiteID Ps1`,
  `conformance/vectors/ps-*.json`) without a Track-B ADR + council sign-off + conformance regen.
- Never add a non-infringement / "audited" / "production-ready" / FIPS-validated claim.
- Never commit secrets or real cloud identifiers.
- Copyright stays **TRELYAN**; new files carry REUSE/SPDX headers.

## Where this runs

The scheduled task **`nerion-apex-sprint`** fires on a recurring cadence through the
3-week sprint (→ 2026-07-11) and executes one council-reviewed cycle per run against
[`APEX_SPRINT_BACKLOG.md`](./APEX_SPRINT_BACKLOG.md). See [`APEX_SPRINT_LOG.md`](./APEX_SPRINT_LOG.md)
for the per-cycle record.
