// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// VRF-001 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
//
// Core assumption: leader sortition uses a CLASSICAL ECVRF-EDWARDS25519 (ledger/src/vrf.ts) —
// the code already discloses this is a deliberate liveness/fairness residual (a VRF break lets a
// quantum adversary PREDICT/grind leaders, but safety stays ML-DSA-87; "no standardized PQ VRF
// exists yet", ADR-0004). So "the VRF is classical" is a NON-finding. The real question: can a
// PQ sortition replace it, and what does going PQ actually COST here?
//
// We build a PQ hash-beacon sortition (seed = finalized block hash; leader = stake-weighted
// argmin over H(beacon‖validator)) — trivially post-quantum, zero proof (publicly recomputable),
// cheap verify. Then we MEASURE the property it sacrifices: a public beacon makes the leader
// PREDICTABLE and (if the beacon is grindable) lets a beacon-setter bias the next leader — the
// exact unpredictability/grind-resistance the EC-VRF's secret-key binding provides. So the PQ gap
// here is a SECURITY (privacy/grind-resistance) gap, not a cost gap. node:crypto only; no repo imports.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes, generateKeyPairSync, sign, verify } from 'node:crypto'

const H = (...p) =>
  createHash('shake256', { outputLength: 32 }).update(Buffer.concat(p.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(String(x)))))).digest()

function makeValidators(N, equalStake = true) {
  return Array.from({ length: N }, (_, i) => ({
    i,
    pk: randomBytes(32),
    stake: equalStake ? 1n : 1n + BigInt(randomBytes(2).readUInt16BE(0)),
  }))
}

// PQ hash-beacon stake-weighted sortition: r = H(beacon) mod totalStake; pick cumulative range.
function sortition(beacon, vals, total) {
  const r = BigInt('0x' + H('nerion/sortition', beacon).toString('hex')) % total
  let acc = r
  for (const v of vals) {
    if (acc < v.stake) return v
    acc -= v.stake
  }
  return vals[vals.length - 1]
}

// Grinding worst case: an adversary who can try T candidate beacons installs a TARGET leader.
function grindSuccess(vals, total, targetIdx, T, trials) {
  let hits = 0
  for (let t = 0; t < trials; t++) {
    for (let i = 0; i < T; i++) {
      if (sortition(randomBytes(32), vals, total).i === targetIdx) {
        hits++
        break
      }
    }
  }
  return hits / trials
}

// ── run ──
console.log('VRF-001 — PQ hash-beacon sortition vs classical ECVRF (cost is paid in PREDICTABILITY, not bytes)')
console.log('Hash-beacon: PQ, proof 0 B (publicly recomputable), verify = a few hashes. EC-VRF: classical, ~80 B proof, private.\n')

for (const N of [128, 1024]) {
  const vals = makeValidators(N, true)
  const total = vals.reduce((a, v) => a + v.stake, 0n)
  const beacon = randomBytes(32)
  const t0 = performance.now()
  const leader = sortition(beacon, vals, total)
  const selMs = performance.now() - t0
  // verify = recompute (deterministic, public): anyone reaches the same leader
  const verifyOk = sortition(beacon, vals, total).i === leader.i
  console.log(JSON.stringify({ N, leader: leader.i, deterministic_public_verify: verifyOk, select_ms: +selMs.toFixed(4), proof_bytes: 0 }))
}

// EC-VRF verify-cost reference via Ed25519 proxy (1 asymmetric op; real ECVRF ~2 scalar mults).
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const m = randomBytes(32)
const sig = sign(null, m, privateKey)
let vt = performance.now()
for (let i = 0; i < 2000; i++) verify(null, m, publicKey, sig)
const ecvrfProxyUs = ((performance.now() - vt) / 2000) * 1000
console.log(JSON.stringify({ ecvrf_proxy_verify_us: +ecvrfProxyUs.toFixed(1), ecvrf_proof_bytes: 80, ecvrf_postquantum: false, ecvrf_private_unpredictable: true }))

// Grinding: worst case (fully grindable beacon). Equal stake => target fraction p = 1/N.
console.log('\nGRINDING (worst case — fully grindable beacon; target = one validator, equal stake p=1/N):')
const N = 128
const vals = makeValidators(N, true)
const total = vals.reduce((a, v) => a + v.stake, 0n)
const p = 1 / N
for (const T of [1, 8, 64, 512]) {
  const measured = grindSuccess(vals, total, 0, T, 3000)
  const theory = 1 - Math.pow(1 - p, T)
  console.log(JSON.stringify({ beacon_tries_T: T, install_target_prob_measured: +measured.toFixed(3), theory: +theory.toFixed(3) }))
}
console.log('\n' + JSON.stringify({
  hash_beacon: 'PQ, ~0-byte proof, cheap verify — but PUBLICLY PREDICTABLE; a grindable beacon lets a setter bias the leader (above)',
  ecvrf: 'classical (not PQ) — but PRIVATE + grind-resistant (each output secret-key-bound; others cannot grind it)',
  pq_gap_here: 'PREDICTABILITY / grind-resistance, NOT cost — so the classical VRF is a justified pragmatic choice (ADR-0004)',
  mitigation_note: 'if the beacon = a quorum-FINALIZED block hash (no single party controls it), single-party grinding is bounded',
}))
