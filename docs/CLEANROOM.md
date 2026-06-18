# PolarSeek — Clean-Room & Non-Infringement Design Record

> **This is engineering intent, not a legal opinion and not a non-infringement
> guarantee.** It records the design choices we made to operate in a different
> technical field from the SIGA / "Sovereign OS" / "Commit-Point Gate" patent
> family, and the CI controls that enforce them. A patent-counsel
> freedom-to-operate (FTO) opinion is **required** before any public
> non-infringement claim or launch — see [FTO_TODO.md](./FTO_TODO.md).

## 1. Clean-room method

- PolarSeek is designed **only** from open, published standards (see §2).
- SIGA material (the Feb 2026 "Confidential Sovereign Memorandum" and the
  referenced patent **US 9,607,214 B2** and family) was read **solely to
  identify what to AVOID** — never to copy architecture, code, or wording. No
  SIGA source code, claim language, or figures were transcribed into PolarSeek.
- The combined legal + technical firewall is one sentence: **PolarSeek governs
  the verb (typed actions), never the eye (perception).**

## 2. Design basis (what we build *from*)

| Layer | Open standard / prior art |
|---|---|
| PQ crypto | NIST **FIPS 203** (ML-KEM), **204** (ML-DSA), **205** (SLH-DSA), **SP 800-208** (LMS/XMSS), **SP 800-227** (KEM rec.), HQC (→ FIPS 207), NSA **CNSA 2.0** |
| Hybrid KEM | IETF **X-Wing** (`draft-connolly-cfrg-xwing-kem`) and standard KEM combiners |
| Receipts / transparency | IETF **SCITT**, **COSE**, **CWT**, **CBOR** (RFC 8949 deterministic encoding) |
| Attestation | IETF **RATS** (RFC 9334); Confidential Computing Consortium TEE attestation |
| Capabilities | **UCAN** / **macaroons** (object-capability, attenuation-only) |
| Policy | **OPA/Rego** or **Cedar** (constrained, deterministic profile) |

All of the above pre-date or are independent of the SIGA filings and are public
prior art. PolarSeek is a *composition* of these, applied to a different problem
(governing typed actions), not a re-implementation of SIGA's perception loop.

## 3. Forbidden elements (CI MUST reject these in the admission path)

The SIGA claim chain (per the deck and US 9,607,214 B2) is, in essence:
**camera forwards images → static/dynamic decomposition across frames →
object-identity continuity → zone occupancy over time → state-change trigger →
gate → record.** Every link is perception- and state-based. PolarSeek
implements **none** of them. The `tools/cleanroom-lint.mjs` linter greps the
admission path for the signals below and fails the build on a hit.

| ID | SIGA element (avoid) | How PolarSeek avoids it | Lint signal (rejected) |
|----|----------------------|--------------------------|------------------------|
| **F1** | Camera / sensor **frame ingestion** as an input | Kernel accepts ONLY typed action intents (tool-call / API / transaction) in canonical CBOR. No image/video/frame/pixel/raw-sensor type is ever a kernel input. | `camera, frame_ingest, videoFrame, image_input, pixel_buffer, sensor_frame, rawSensor` |
| **F2** | **Static/dynamic decomposition** across sequential frames ("the cognitive loop", Claim 1) | No feature decomposition of any kind; no per-frame loop. Admission is one pure policy evaluation over one explicit intent. | `static_dynamic, staticFeature, dynamicFeature, sequential_frames, frameSequence, cognitive_loop, decompose_frames` |
| **F3** | **Object-identity continuity** across frames | Kernel has no tracked entity persisting across calls. Subject refs are opaque caller IDs, never re-identified or correlated across decisions. | `object_identity, identity_continuity, track_object, reidentif, object_persistence, crossFrameId, maintain_track` |
| **F4** | **Zone / polygon occupancy over time** (dwell, entry/exit) | No spatial/geometric model in admission: no zones, polygons, fields of view, dwell timers, occupancy states. Authority = typed capability scopes, not geography-over-time. | `zone_occupancy, polygon, field_of_view, fov_zone, dwell_time, destination_location, zone_entry, geofence, occupancy_over_time` |
| **F5** | **Cross-decision / stateful tracking** inside the gate ("state-change" trigger) | Kernel is a pure function `decide(intent, capability, policy, facts_snapshot, signed_scalars)`: no mutable state, no DB read, no live lookup, no wall-clock read, no in-kernel counter. | `kernel_state, mutable_state, prev_decision, last_seen, stateful, state_change_trigger, in_kernel_counter` |
| **F6** | The **"commit-point gate"** branding/coupling | We use **"admission kernel" / "admission decision"** only. We never name, model, or implement a "commit-point gate". | `commit_point, commitPointGate, commit_gate, gate_at_state_change, sovereign_gate` |
| **F7** | **Perception→enforcement→receipt** as one coupled chain | Receipts are SCITT/COSE commitments over an ACTION decision (intent/capability/policy/evaluator/attestation hashes), built in the nearline plane — structurally independent of any perception pipeline. | `perceive_decompose, perception_to_receipt, enforce_on_track, record_on_state_change` |
| **F8** | Stretch theory: **"attention = static/dynamic decomposition"** onto LLM/tensor inference | Kernel is a bounded policy evaluation over structured CBOR — not neural inference or tensor decomposition. We never characterize admission as "decomposition", "perception", or an "inference loop". | `tensor_decompose, attention_as_decomposition, inference_loop_gate, real_time_tensor_gate` |

## 4. The two hard rules (non-negotiable)

1. **The admission kernel is STATELESS per decision** — a pure function of its
   explicit inputs. No retained state, no database, no clock, no network, no
   counter mutated in-kernel. Determinism is machine-checked (planned TLA+/Lean,
   `kernel/spec/`) and verified by byte-identical replay.
2. **Aggregates/rate limits enter ONLY as a signed scalar input.** Any
   sequence/aggregate logic lives in the nearline plane and reaches the kernel
   solely as a **signed scalar value** passed in with the request — never as
   in-kernel cross-decision state. This is the doctrine-of-equivalents firewall
   against F5.

## 5. Scope

PolarSeek governs typed **ACTIONS** — tool-calls, API requests, transaction
intents. It does **not** perceive: no camera frames, no feature decomposition,
no object tracking, no zone occupancy. Any upstream perception system is a
separate, untrusted component; only its typed, signed *conclusions* (never
frames) may appear to the kernel as hashed facts in the explicit facts snapshot.

## 6. Enforcement

- `tools/cleanroom-lint.mjs` runs in CI (`npm run lint:cleanroom`) and fails on
  any forbidden signal in the admission path.
- PR review rejects: frame ingestion as an admission input; feature
  decomposition; object-identity tracking in the admission path; spatial
  zone/occupancy logic in admission; or **any cross-decision state in the
  kernel**.
- The [FTO_TODO.md](./FTO_TODO.md) banner is re-emitted in every release notes
  file until a written FTO opinion is on file.

See also: [DESIGN_AROUND.md](./DESIGN_AROUND.md) (the differentiation + novelty
strategy) and [adr/ADR-0001-crypto-suite.md](./adr/ADR-0001-crypto-suite.md).
