# Nerion — Apex Teams

Six standing **multi-model teams** (+ a model-upkeep job), each drawing on the eight TRELYAN council
seats at their apex models (see [APEX_COUNCIL.md](./APEX_COUNCIL.md); `apex-model-upgrade` keeps each
seat on its latest flagship daily). Shared seats, distinct missions and cadences. Every team runs under
the same **non-negotiable guardrails**: UNAUDITED / pre-FTO posture preserved, no overclaim, frozen
wire-tags/KATs untouched without a Track-B ADR, **branch/draft-only output**, and the **human maintainer
adjudicates** and merges/sends.

## The seats (shared across every team)
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

## 1. Security / Hardening — engine: `nerion-apex-sprint` *(every 6h, perpetual)*
**Mission: harden + fix — the authoritative beyond-apex engine.** Each cycle picks the next item from
[APEX_SPRINT_BACKLOG.md](./APEX_SPRINT_BACKLOG.md), implements on a branch, keeps `npm run gate` +
`npm run conformance` green, runs the 8-model council review, and pushes a branch for human merge. When the
backlog is exhausted / every 4th cycle it runs an adversarial trust-surface sweep (fan-out lenses → refute →
re-derive survivors) to find new fail-open/binding findings. **This is the existing perpetual engine — do
not duplicate it.** Kill switch: `docs/APEX_SPRINT_STOP`.

## 2. R&D — engine: `nerion-rd-daily` *(daily)*
**Mission: research the frontier — what-to-ADD + deep design-soundness checks, as a PhD specialist panel
(post-quantum crypto · cryptography/ZK · consensus · backend/protocol · frontend · app-dev/DX). DESIGN/DOCS
ONLY (no code/KAT change).** Each day:
1. **Scout** (Perplexity) pulls the current SOTA — PQ crypto, ZK proof systems, agent-authorization/identity
   standards (IETF agent-auth, OAuth-for-agents, eIDAS 2.0/EUDI, W3C VC), transparency logs/SCITT, NIST/ETSI/BSI/ANSSI.
2. **Frontier (what to ADD):** the council proposes + adversarially vets the most ambitious *defensible*
   directions beyond the backlog → additive [FRONTIER.md](./FRONTIER.md) updates, tiered
   buildable-now / research-bet / speculative, each with its hardest open problem named.
3. **Deep check (rotates one area/day):** zkrange/policyproof · ledger consensus · kernel admission /
   govern-the-verb · attest/session binding · key custody/HBS-state · capabilities/delegation → a dated
   report under `docs/research/` listing soundness gaps and "what-to-fix" items (handed to the backlog as notes).
4. **Output:** ADRs / FRONTIER / design proposals + the deep-check report, on an `rd/daily-*` branch for
   human review. Honest tiers; never overclaim.

## 3. Engineering — engine: `nerion-engineering-daily` *(daily)*
**Mission: BUILD — implement R&D's vetted buildable-now additions and own the feature / frontend / app / DX
surfaces the Security engine doesn't touch.** One excellent, fully-verified change per day on an
`eng/daily-*` branch, `npm run gate` + `npm run conformance` green, council sign-off, pushed for human merge.
Explicitly **non-overlapping with the Security engine** (#1): if the candidate is core-security it defers to
the sprint and picks a feature/frontend/app/DX item instead. Backend / frontend / app-dev specialist lenses.

## 4. Deepsearch / Market-Research — engine: `nerion-deepsearch-market-daily` *(daily)*
**Mission: live-web intelligence — Perplexity-led.** Daily scan of PQC standards (NIST/ETSI/BSI/ANSSI),
agent-auth/eIDAS/SCITT, competitors (esp. SIGA), funding/NLnet-Restack dates, regulatory and adoption
signals → a dated `docs/market/INTEL-<date>.md` dossier with an **action feed** for the other teams.
**DOCS ONLY; cite every claim; no legal conclusions about SIGA** (engineering/market awareness, not legal advice).

## 5. Innovation — Nerion Labs *(engine: `nerion-innovation-daily` · daily, 11:00 local — `0 11 * * *`)*

**Mission: Nerion Labs is the protocol's skunkworks. It builds RUNNING, DISPOSABLE prototypes in a
hermetically isolated `labs/` sandbox to answer high-variance, falsifiable, CROSS-ARCHITECTURE questions
that documents cannot settle — "could an entirely DIFFERENT mechanism deliver post-quantum action-governance
better/cheaper/faster than our current ZK+PQ admission kernel — proof-elimination, a stateful-yet-equivalent
kernel, a non-ZK trust substrate?" Its load-bearing deliverable is a measured number from a prototype that
actually ran plus a KILL or GRADUATE verdict — never a design essay, never production code, and never a
legal/novelty/patentability/non-infringement claim. A GRADUATE verdict is a human-routed HANDOFF (to R&D to
formalize, or Engineering to productionize); Innovation itself never formalizes, never ships, and never
touches `main`.**

**The dividing line vs R&D and Engineering is a two-part CONJUNCTION, both independently checkable.** An item
belongs to Innovation ONLY if BOTH are true; if either is false it is R&D's or Engineering's:
- **(1) MODE — it requires EXECUTING disposable code.** R&D is contractually design/docs-only and paper-level:
  it cannot compile, run, benchmark, or produce an executed counterexample. Innovation's only valid output is a
  measured metric or a reproduced executed break.
- **(2) TARGET — it tests whether a DIFFERENT architecture could replace a CORE assumption** (the proof system,
  the kernel model, the trust substrate). R&D *extends and validates the architecture we already have, on paper*;
  Innovation *empirically tests whether that architecture should be replaced, by running an alternative*.
  Engineering *hardens and ships the ONE production architecture*; Innovation *explores N disposable
  alternatives that never have to pass conformance and are expected to die*.

> One sentence: **R&D writes the map of the possible inside the current design; Engineering ships the current
> design; Innovation runs disposable code to benchmark whether a different design obsoletes it.** R&D may not
> run code; Engineering's code is meant to live forever on `main`; Innovation's code is meant to die after it
> yields a number.

**Daily cadence note.** Innovation fires daily but holds a **single active spike** at a time and advances it
exactly one lifecycle step per cycle — long spikes span many days. Daily firing therefore deepens one moonshot
build-measure-break loop; it does not force shallow restarts. (Dial to every-other-day if a spike wants more
soak time.)

**Not a duplicate of the THRONDAR `innovation-lab-daily-brief`.** That live daily task is a *prose IP brief for
a different product (THRONDAR verifiable-AI)*; it writes one-page ideas to a OneDrive folder and **touches no
Nerion code** under `C:\Users\User\polarseek`. Nerion Labs is Nerion-only and builds running prototypes in
`labs/` — no overlap, no retirement needed.

**Daily flow** (one cycle advances exactly ONE active spike one lifecycle step):

1. **PREFLIGHT + kill-switch.** Abort ("Innovation paused") if `docs/APEX_SPRINT_STOP` or `docs/INNOVATION_STOP`
   exists, or if the sandbox-isolation self-check fails. Clean up any stale worktree. Work on a fresh
   `innovation/<spike-id>` branch (NEVER `main`). **Guard self-test:** plant a known violation (a `labs/`→prod
   import and a frozen-asset reference) and assert each guard exits non-zero; if any guard passes a planted
   violation, abort — the sandbox is not real.
2. **SELECT (single-active-spike).** Keep iterating the active spike; never open a second. If none is active,
   OPEN the highest-value bet from `labs/BACKLOG.md`. **Intake is read-only and bounded:** R&D's
   `docs/FRONTIER.md` *research-bet / speculative* tiers (READ-ONLY) plus a maintainer-seeded architectural-bet
   list. **Innovation runs NO independent SOTA/frontier scout** — all field-scouting stays in R&D (the #1
   anti-clone rule). Write `labs/spikes/<spike-id>/SPIKE.md`: the single falsifiable question, the contradicted
   core assumption, pre-registered KILL thresholds (e.g. proof ≤10 KB AND prover ≤100 ms), a hard time-box, and
   FTO/crypto risk flags.
3. **FTO PRE-SCREEN (engineering screening only).** Screen the bet against `docs/CLEANROOM.md` F1–F8 and the
   SIGA Commit-Point-Gate claim chain. REJECT/park any spike drifting toward frame/sensor ingestion,
   static/dynamic decomposition, object-identity continuity, zone-occupancy-over-time, in-gate cross-decision
   state, a "commit-point gate", or doctrine-of-equivalents creep on F5 — keep *govern-the-verb-not-the-eye*
   inside the lab too. This is ENGINEERING screening, NEVER a non-infringement or FTO claim.
4. **BUILD/EXTEND** the throwaway prototype under `labs/spikes/<spike-id>/` — its own manifest/deps, toy/mock
   crypto clearly marked non-production, **zero import of `crypto/ kernel/ ledger/ keystore/ attest/`**, no read
   of `conformance/ vectors/ ps-*.json`, no Azure KMS, no prod credentials, no network egress.
5. **RUN + BREAK (executed-and-measured is a HARD gate).** Benchmark against the current architecture's
   published numbers; run an adversarial/soundness probe. Capture metrics + failure modes to
   `labs/spikes/<spike-id>/RESULTS.md`. **A cycle with no compiled-and-run prototype and no measured number is a
   VOID cycle, logged as such — never published as a feasibility opinion.** This holds even on a KILL: a KILL
   must be backed by an executed prototype + metrics/break, not a cited prose argument (that would be an R&D
   soundness note).
6. **GUARD CHECK.** Run, over the `labs/` diff: cleanroom-lint (extended to scan `labs/`), the `labs/`↔prod
   isolation lint, the frozen-asset diff-guard, the banned-claims/honesty lint, and reuse lint. Any failure
   blocks the branch.
7. **VERDICT.** At terminal state, **KILL** (one-paragraph autopsy in `labs/GRAVEYARD.md`; move the code to
   `labs/_graveyard/`) OR **GRADUATE** (a one-page handoff: pointer + numbers, routed to R&D to formalize an ADR,
   or to Engineering to productionize). Time-box-exceeded spikes are auto-KILLed. Innovation authors NO ADR,
   edits NO FRONTIER tier, writes NO prod crypto; promotion = a human-adjudicated CLEAN re-implementation by
   Engineering from the note, never a code merge of `labs/`. A genuinely new construction is logged only as a
   neutral **engineering feasibility note** (`labs/feasibility/FEAS-<date>-<slug>.md`) — *technical problem /
   mechanism / trade-offs / measurements / prior-art-context only*; NO "earliest-invention-date", inventor,
   novelty, patentability, or priority fields; at most flag "may warrant counsel review" — never recommend,
   draft, or post a publication.
8. **LOG + EMIT.** Update `labs/SPIKES.md` (state table) and `labs/INNOVATION_LOG.md` (append-only: target,
   sources, council verdict incl. Watsonx, recommendation, branch). Commit to `innovation/<spike-id>` with
   SPDX/REUSE + © TRELYAN + the re-emitted `docs/FTO_TODO.md` banner; push for human review. Never auto-merge,
   never auto-accept an ADR, never post.

**Hard guardrails (innovation-specific, on top of the cross-team guardrails below):**
- **Build-or-fail / no R&D drift:** no executed prototype + no measured number = a VOID cycle; Innovation is
  READ-ONLY on `FRONTIER.md`, runs no independent scout, and emits no prose "we recommend exploring X"
  direction. Outputs are {executed prototype, measurements, KILL/GRADUATE verdict, one-line handoff} only.
- **FTO firewall (engineering ideation ONLY):** no artifact may assert or imply novelty, patentability,
  inventiveness-over-prior-art, non-infringement, "designs around", "clear of", or "unaffected by" any patent —
  a hard council block. No "invention disclosure" naming, no priority/inventor/earliest-date record.
  Patentability/novelty/FTO are counsel-only.
- **No competitor-claim reading:** never fetch/open/read/paraphrase/transcribe SIGA claims, figures, or decks;
  field awareness only from open standards/papers/public talks (sourced via R&D), each logged date+url+summary;
  for patent-scope context CITE `docs/FTO_CLAIM_CHART.md` / `docs/PRIOR_ART_NOTES.md` rather than re-reading claims.
- **Four-way sandbox isolation (CI-enforced, BUILT before first run — these guards do not exist in the repo
  today):** `labs/` excluded from gate/conformance/build/package and the tsconfig/cargo workspace; bidirectional
  `labs/`↔prod import ban; frozen-asset diff-guard hard-rejecting any change to SuiteID "Ps1", `conformance/`,
  `vectors/`, `ps-*.json`, or any KAT on an `innovation/` branch; `labs/` runs on mocks with no Azure KMS / no
  prod credentials / no network egress. Disposability invariant: any `labs/` artifact must be deletable with zero
  protocol impact — if a spike can't be isolated this way, it must not be run.
- **No new crypto into prod, ever:** a prototyped construction never becomes load-bearing by promotion; it stays
  scratch/UNAUDITED in `labs/` and can only enter prod via Engineering re-implementation from scratch under a
  council-signed Track-B ADR + KAT-regen + external audit. No single author both prototypes and productionizes
  the same idea (anti-laundering).
- **Honesty discipline:** prototyped ≠ built, built ≠ audited, measured-in-a-toy-harness ≠ sound, "graduated" ≠
  shipped, a design-around ≠ freedom-to-operate. Every `RESULTS.md`/feasibility note carries its toy/mock
  caveats, the UNAUDITED/pre-FTO banner, and survives the banned-claims lint. Negative results reported as
  faithfully as positive ones.
- **Naming hygiene:** all Innovation artifacts live ONLY under `labs/`; NEVER write to the production
  `disclosure/` dir (it is inside the cleanroom-scanned admission path) and avoid the word "disclosure".
- **Single-active-spike ops:** at most one non-terminal spike; pre-registered KILL thresholds + a hard
  time-box (exceeded ⇒ auto-KILL); GRAVEYARD autopsies + `labs/_graveyard/` so dead ends are disposable.
- **Quarterly human IP-risk review** of accumulated `labs/` outputs + the recorded prototype/prior-art
  interaction log; Watsonx IP/governance seat weighs in every cycle (or is logged unreachable); any
  FTO/honesty/contamination objection blocks until resolved or the spike is parked.

**Handoff.** Promotion is always a HUMAN-routed handoff, never a code merge of `labs/`. Design-shaped findings
route to R&D (which formalizes a proposed Track-B ADR + an additive FRONTIER tier — Innovation authors neither);
build-shaped findings route to Engineering as a scoped backlog item with the prototype as a REBUILD REFERENCE
only (Engineering re-implements clean under its full discipline + audit). The pipe is de-circularized: the same
idea is never active in two teams in the same cycle, and no single author both prototypes and productionizes it.

## 6. Marketing — engine: `nerion-marketing-weekly` *(weekly, DRAFTS only)*
**Mission: positioning, narrative, outreach DRAFTS — for the maintainer to review and send. NEVER
auto-post / auto-send / publish.** Each week, into `docs/marketing/`: a project one-liner + elevator pitch,
a README hero/positioning block, a short announcement/blog draft, a few community/dev posts
(FOSDEM/IETF/HN/Mastodon style), an FAQ, and a tightening pass on the public narrative (rotating focus).
Fed by the daily Deepsearch/Market team. **Hard guardrails:** drafts in-repo only (no external posting/sending);
preserve UNAUDITED / pre-FTO; **no** non-infringement / "audited" / "production-ready" / FIPS / certified claims;
pre-adoption (no false adopter/deployment claims); the **NLnet grant proposal + §3 are OFF-LIMITS** (NLnet bans
AI-written proposals) — marketing copy only.

## Plus: model upkeep — `apex-model-upgrade` *(daily)*
Keeps every council seat on its latest verified flagship model. Infrastructure, not a council team. Leave ON.

## Cross-team guardrails (non-negotiable)
- **Branch/draft-only.** Never auto-merge to `main`; never auto-post/send/publish; the human adjudicates everything.
- Never change frozen wire-tags/KATs (`SuiteID Ps1`, `conformance/vectors/ps-*.json`) without a Track-B ADR + council sign-off + conformance regen.
- Never edit the grant proposal / §3; never write or submit grant text.
- Never add non-infringement / audited / production-ready / FIPS claims; keep UNAUDITED / pre-FTO framing.
- © TRELYAN; SPDX/REUSE coverage on new files; keep `npm run gate` + `npm run conformance` green.

**Kill switch:** create `docs/APEX_SPRINT_STOP` (pauses **all** team engines, each STOP-checks it), or
`docs/INNOVATION_STOP` (pauses Innovation only), or disable the relevant scheduled task.
