# Nerion — Apex Teams

Three standing **multi-model teams**, each drawing on the eight TRELYAN council seats at their apex
models (see [APEX_COUNCIL.md](./APEX_COUNCIL.md); `apex-model-upgrade` keeps each seat on its latest
flagship daily). Shared seats, distinct missions and cadences. Every team runs under the same
**non-negotiable guardrails**: UNAUDITED / pre-FTO posture preserved, no overclaim, frozen wire-tags/KATs
untouched without a Track-B ADR, **branch/draft-only output**, and the **human maintainer adjudicates**
and merges/sends.

## The seats (shared across all three teams)
| Seat | Lineage | Role on the team |
|------|---------|------------------|
| **Claude** | Anthropic (Opus) | orchestrator · implementer · adversarial verifier |
| **ChatGPT** | OpenAI (apex) | independent review · ideation |
| **Gemini** | Google (apex) | technical / standards verification |
| **Grok** | xAI (apex) | contrarian · red-team |
| **DeepSeek** | DeepSeek V3/R1 | deep reasoning · critique |
| **Mistral** | Mistral (apex, EU) | EU-lineage independent review |
| **Watsonx** | IBM watsonx | IP · governance · diligence |
| **Perplexity** | Sonar (Scout) | live-web research |
| **Hermes** | agentic | auxiliary review |

## 1. Engineering Team — engine: `nerion-apex-sprint` *(every 6h, ≥ daily)*
**Mission: implement + harden — max upgrade, what-to-FIX.** Each cycle picks the next item from
[APEX_SPRINT_BACKLOG.md](./APEX_SPRINT_BACKLOG.md), implements on a branch, keeps `npm run gate` +
`npm run conformance` green, runs the 8-model council review, and pushes a branch for human merge. Runs an
adversarial trust-surface sweep when the backlog is exhausted / every 4th cycle. **This is the existing
perpetual engine — do not duplicate it.**

## 2. R&D Team — engine: `nerion-rd-daily` *(daily)*
**Mission: research the frontier — what-to-ADD + deep design-soundness checks. DESIGN/RESEARCH ONLY (no
behavior/KAT change).** Each day:
1. **Scout** (Perplexity) pulls the current SOTA — PQ crypto, ZK proof systems, agent-authorization/identity
   standards (IETF agent-auth, OAuth-for-agents, eIDAS 2.0/EUDI, W3C VC), transparency logs/SCITT, NIST/ETSI/BSI/ANSSI.
2. **Frontier (what to ADD):** the council proposes + adversarially vets the most ambitious *defensible*
   directions beyond the backlog → additive [FRONTIER.md](./FRONTIER.md) updates, tiered
   buildable-now / research-bet / speculative, each with its hardest open problem named.
3. **Deep check (rotates one area/day):** zkrange/policyproof · ledger consensus · kernel admission /
   govern-the-verb · attest/session binding · key custody/HBS-state · capabilities/delegation → a dated
   report under `docs/research/` listing soundness gaps and "what-to-fix" items (handed to the Engineering
   backlog as notes — **not** implemented here).
4. **Output:** ADRs / FRONTIER / design proposals + the deep-check report, on an `rd/daily-*` branch for
   human review. Honest tiers; never overclaim.

## 3. Marketing Team — engine: `nerion-marketing-weekly` *(weekly, DRAFTS only)*
**Mission: positioning, narrative, outreach DRAFTS — for the maintainer to review and send. NEVER
auto-post / auto-send / publish.** Each week, into `docs/marketing/`: a project one-liner + elevator pitch,
a README hero/positioning block, a short announcement/blog draft, a few community/dev posts
(FOSDEM/IETF/HN/Mastodon style), an FAQ, and a tightening pass on the public narrative (rotating focus).
**Hard guardrails:** drafts in-repo only (no external posting/sending); preserve UNAUDITED / pre-FTO; **no**
non-infringement / "audited" / "production-ready" / FIPS / certified claims; pre-adoption (no false
adopter/deployment claims); the **NLnet grant proposal + §3 are OFF-LIMITS** (NLnet bans AI-written
proposals) — marketing copy only.

## Cross-team guardrails (non-negotiable)
- **Branch/draft-only.** Never auto-merge to `main`; never auto-post/send/publish; the human adjudicates everything.
- Never change frozen wire-tags/KATs (`SuiteID Ps1`, `conformance/vectors/ps-*.json`) without a Track-B ADR + council sign-off + conformance regen.
- Never edit the grant proposal / §3; never write or submit grant text.
- Never add non-infringement / audited / production-ready / FIPS claims; keep UNAUDITED / pre-FTO framing.
- © TRELYAN; SPDX/REUSE coverage on new files; keep `npm run gate` + `npm run conformance` green.

**Kill switch:** create `docs/APEX_SPRINT_STOP` (pauses all team engines) or disable the relevant scheduled task.
