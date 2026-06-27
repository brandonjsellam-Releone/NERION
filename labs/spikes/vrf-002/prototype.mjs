// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// VRF-002 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
//
// VRF-001 reopen: a raw PQ hash-beacon sortition is grindable (512 tries → 98% target install).
// Council (Grok) said the real PQ contender is a quorum-finalized seed + a (PQ) VDF delay. This
// builds a REAL sloth-style VDF (a sequential chain of modular square roots mod a prime p≡3 mod 4)
// and measures whether forcing a full VDF eval per grinding trial closes the grinding window.
//
// WHY "PQ": the delay rests on SEQUENTIALITY (sqrt-chain can't be parallelized), NOT on factoring/DL,
// and Grover gives no speedup on inherently-sequential iteration — so a sloth-class delay is
// quantum-SAFE in a way Wesolowski/Pietrzak VDFs (unknown-order groups = classical) are not.
// HONEST LIMITS (measured/stated below): sloth is a WEAK VDF — verify is O(T) (cheap per step, but
// LINEAR, not succinct); the delay adds election LATENCY; "grind-infeasible" assumes a bounded
// hardware speedup. Real, but not a free win. node:crypto only; no repo imports; no novelty/FTO claim.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes, generatePrimeSync } from 'node:crypto'

const p = generatePrimeSync(256, { bigint: true, add: 4n, rem: 3n }) // p ≡ 3 (mod 4) → sqrt = a^((p+1)/4)
const SQRT_EXP = (p + 1n) / 4n
const H = (...a) => createHash('shake256', { outputLength: 32 }).update(Buffer.concat(a.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(String(x)))))).digest()

function modpow(b, e, m) {
  let r = 1n
  b %= m
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m
    e >>= 1n
    b = (b * b) % m
  }
  return r
}
const seedToX = (seed) => {
  const x = BigInt('0x' + H('vdf/seed', seed).toString('hex')) % p
  return x === 0n ? 1n : x
}

// sloth EVAL — T sequential modular-sqrt steps (each ~log₂p modular mults: SLOW + inherently sequential).
function vdfEval(seed, T) {
  let x = seedToX(seed)
  const signs = new Uint8Array(T) // T-bit proof: whether each step's input was a QR
  for (let i = 0; i < T; i++) {
    const r = modpow(x, SQRT_EXP, p)
    signs[i] = (r * r) % p === x ? 0 : 1 // r²=x (QR) → 0 ; r²=p−x (QNR) → 1
    x = r
  }
  return { y: x, signs }
}
// sloth VERIFY — T sequential SQUARINGS (1 modular mult each: FAST). Replays the chain backward.
function vdfVerify(seed, y, signs, T) {
  let v = y
  for (let i = T - 1; i >= 0; i--) {
    let s = (v * v) % p
    if (signs[i] === 1) s = (p - s) % p
    v = s
  }
  return v === seedToX(seed)
}

// stake-weighted sortition on the DELAYED seed (leader unknown until the VDF completes)
function sortition(delayedSeed, vals, total) {
  const r = BigInt('0x' + H('vrf002/sortition', delayedSeed).toString('hex')) % total
  let acc = r
  for (const v of vals) {
    if (acc < v.stake) return v
    acc -= v.stake
  }
  return vals[vals.length - 1]
}
const seedBytes = (bi) => Buffer.from(bi.toString(16).padStart(64, '0'), 'hex')

// ── run ──
console.log('VRF-002 — quorum-seed + sloth-VDF sortition (recovers grind-resistance; honest costs measured)')
console.log(`sloth over a 256-bit p≡3(mod4); eval = T modular sqrts (slow), verify = T squarings (fast).\n`)

// correctness + tamper + eval/verify asymmetry, swept over T
for (const T of [500, 2000]) {
  const seed = randomBytes(32)
  let t = performance.now()
  const { y, signs } = vdfEval(seed, T)
  const evalMs = performance.now() - t
  t = performance.now()
  const ok = vdfVerify(seed, y, signs, T)
  const verMs = performance.now() - t
  const ts = Uint8Array.from(signs)
  ts[0] ^= 1
  const tamperRejected = !vdfVerify(seed, y, ts, T)
  console.log(
    JSON.stringify({
      T,
      eval_ms: +evalMs.toFixed(1),
      verify_ms: +verMs.toFixed(2),
      asymmetry_eval_over_verify: +(evalMs / verMs).toFixed(0),
      proof_bytes: Math.ceil(T / 8),
      honest_verifies: ok,
      tamper_rejected: tamperRejected,
    }),
  )
}

// grinding: VRF-001 raw beacon = pure hash (~µs/trial). With the VDF, each trial costs a full eval.
const Tgrind = 2000
const seed0 = randomBytes(32)
let t = performance.now()
vdfEval(seed0, Tgrind)
const evalMs = performance.now() - t
// pure-hash trial cost (the VRF-001 grinder)
const K = 20000
t = performance.now()
for (let i = 0; i < K; i++) H('vrf002/sortition', randomBytes(32))
const hashTrialMs = (performance.now() - t) / K
console.log('\nGRINDING (to reach 98% install of a target with p=1/128 ⇒ ~512 trials) — TWO framings:')
console.log(
  JSON.stringify({
    raw_hash_beacon_512_trials_ms: +(512 * hashTrialMs).toFixed(2), // VRF-001: trivially fast → grindable
    vdf_eval_ms_T2000: +evalMs.toFixed(1),
    naive_sequential_slowdown_x: +(evalMs / hashTrialMs).toFixed(0), // (A) MISLEADING: assumes 1 machine
    parallel_adversary_slowdown_x: +(evalMs / (512 * hashTrialMs)).toFixed(0), // (B) realistic: 512 candidates in ~1 eval
  }),
)
console.log(
  '\n' +
    JSON.stringify({
      grind_resistance: 'CONDITIONAL + BRITTLE — not a clean recovery (council-corrected)',
      real_mechanism: 'deadline-barrier: protects ONLY IF VDF_delay > the seed-commit decision window, calibrated vs the GLOBAL-FASTEST adversary (cloud/ASIC rental), not reference hardware',
      naive_38k_was_wrong: 'the per-machine slowdown is NOT the security claim; a parallel adversary computes 512 candidates in ~1 eval → realistic edge ~90×, and that erodes under the attacks below',
      residual_attacks: ['last-revealer head-start (final signer starts the VDF first)', 'withholding + selective reveal of a signature', 'precomputation on predictable seed components', 'ASIC/rental beats the calibrated delay'],
      honest_costs: ['WEAK VDF: verify O(T) linear (grows as the delay/T grows to widen the barrier)', 'a hard LIVENESS FLOOR = the VDF delay', 'does NOT recover PRIVATE sortition — leader is PUBLIC once the VDF completes'],
      net_vs_ecvrf: 'the VDF-beacon’s concrete gain is PQ-safety + no secret-key SPOF — NOT clean grind-resistance. EC-VRF stays competitive (private + sub-ms + succinct). NO FREE PQ REPLACEMENT.',
    }),
)
