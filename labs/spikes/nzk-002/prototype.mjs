// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// NZK-002 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
// Follow-up to NZK-001, testing the council steelman (Grok): does an OPTIMIZED hash-only
// range proof — fewer repetitions + a GGM "all-but-one" seed tree (the Picnic / MPC-in-
// the-head technique) — overturn NZK-001's naive 23.6× blow-up and reach the ~4–6× region?
//
// HONESTY: the GGM seed tree (the load-bearing efficiency mechanism) is REALLY implemented,
// verified, and tamper-tested below. The TOTAL proof size is a transparent COST MODEL that
// composes the REAL measured GGM-opening size with the standard MPCitH (Picnic/KKW) proof
// formula. The full MPC soundness is NOT implemented (modeled), so the total is an ESTIMATE
// good to ~2×. NOT audited, NOT a vetted protocol, no novelty/FTO claim. Uses only node:crypto.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes } from 'node:crypto'

const HLEN = 32
const shake = (b, n = HLEN) => createHash('shake256', { outputLength: n }).update(b).digest()
const H = (...p) => shake(Buffer.concat(p.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(String(x))))))

// ── REAL GGM all-but-one puncturable seed tree (binary, depth = log2(N parties)) ──
const childL = (s) => H('ggm/L', s)
const childR = (s) => H('ggm/R', s)

function expandSubtree(seed, subDepth) {
  let level = [seed]
  for (let d = 0; d < subDepth; d++) {
    const nx = []
    for (const x of level) {
      nx.push(childL(x))
      nx.push(childR(x))
    }
    level = nx
  }
  return level // 2^subDepth leaf seeds
}
const commitLeaves = (leaves) => H('ggm/commit', ...leaves.map((l) => H('ggm/leaf', l)))

// Open all leaves EXCEPT p*: reveal the off-path sibling at each level (depth seeds total).
function openAllButOne(root, depth, pStar) {
  const siblings = []
  let s = root
  let base = 0
  for (let d = 0; d < depth; d++) {
    const subDepth = depth - d - 1
    const half = 1 << subDepth
    const bit = (pStar >> subDepth) & 1
    const L = childL(s)
    const R = childR(s)
    if (bit === 0) {
      siblings.push({ seed: R, base: base + half, subDepth })
      s = L
    } else {
      siblings.push({ seed: L, base, subDepth })
      s = R
      base += half
    }
  }
  return siblings // depth sibling seeds + their (base, subDepth)
}

// Verifier reconstructs every leaf except p* from the sibling seeds.
function reconstructExcept(depth, siblings) {
  const leaves = new Array(1 << depth).fill(null)
  for (const { seed, base, subDepth } of siblings) {
    const sub = expandSubtree(seed, subDepth)
    for (let i = 0; i < sub.length; i++) leaves[base + i] = sub[i]
  }
  return leaves // leaves[pStar] === null
}

// Self-test the GGM primitive: honest open reconstructs all-but-one; a 1-byte tamper is caught.
function ggmSelfTest(depth, trials) {
  for (let t = 0; t < trials; t++) {
    const root = randomBytes(HLEN)
    const N = 1 << depth
    const pStar = randomBytes(2).readUInt16BE(0) % N
    const leaves = expandSubtree(root, depth)
    const commitment = commitLeaves(leaves)
    const comPstar = H('ggm/leaf', leaves[pStar])
    const siblings = openAllButOne(root, depth, pStar)

    // honest reconstruct
    const rl = reconstructExcept(depth, siblings)
    const recom = H('ggm/commit', ...rl.map((l, j) => (j === pStar ? comPstar : H('ggm/leaf', l))))
    if (!recom.equals(commitment)) return { ok: false, why: 'honest reconstruct mismatch' }
    // punctured leaf must stay hidden
    if (rl[pStar] !== null) return { ok: false, why: 'punctured leaf leaked' }
    // tamper: flip a byte of a sibling seed → must fail
    const sib = siblings.map((x) => ({ ...x, seed: Buffer.from(x.seed) }))
    sib[depth - 1].seed[0] ^= 0xff
    const tl = reconstructExcept(depth, sib)
    const tcom = H('ggm/commit', ...tl.map((l, j) => (j === pStar ? comPstar : H('ggm/leaf', l))))
    if (tcom.equals(commitment)) return { ok: false, why: 'tamper not detected' }
  }
  return { ok: true }
}

// ── MPCitH (Picnic/KKW-style) range-proof SIZE MODEL, composed from REAL parts ──
// Per repetition the proof carries: GGM all-but-one opening (depth seeds) + the punctured
// party's commitment + the online broadcast. For an n-bit range circuit the broadcast is
// the masked bit inputs (n) + one correction per booleanity multiplication gate (n), in a
// field of `fieldBytes`. Soundness per rep = 1/N = 2^-depth ⇒ τ = ceil(128/depth) reps.
// A KKW preprocessing cut-and-choose adds overhead, modelled as PREPROC_TAX.
const PREPROC_TAX = 1.3
const SEC = 128
const fieldBytesFor = (n) => Math.max(8, Math.ceil((n + 1) / 8))

function measureGgmOpenBytes(depth) {
  // real serialized size of an all-but-one opening: depth sibling seeds + 1 leaf commitment
  const root = randomBytes(HLEN)
  const sib = openAllButOne(root, depth, 0)
  return sib.reduce((a, s) => a + s.seed.length, 0) + HLEN
}

function modelProofBytes(n, depth) {
  const tau = Math.ceil(SEC / depth)
  const fb = fieldBytesFor(n)
  const ggmOpen = measureGgmOpenBytes(depth) // REAL measured
  const commit = HLEN // punctured-party commitment carried per rep
  const broadcast = (n /*masked bits*/ + n /*mult corrections*/) * fb
  const perRep = ggmOpen + commit + broadcast
  return Math.round(tau * perRep * PREPROC_TAX)
}

// classical baseline (disclosure/src/zkrange.ts): 448·n bytes; NZK-001 naive ≈ measured 23.6×
const classicalBytes = (n) => 448 * n
const naiveBytes = (n) => Math.round(classicalBytes(n) * 23.6)

function bestConfig(n) {
  let best = null
  for (let depth = 3; depth <= 12; depth++) {
    const bytes = modelProofBytes(n, depth)
    if (!best || bytes < best.bytes) best = { depth, N: 1 << depth, tau: Math.ceil(SEC / depth), bytes }
  }
  return best
}

// ── prover-cost model: the size↔time tradeoff (added per NZK-002 council review) ──
// The size optimum (large N) implies a heavy prover. Anchor a per-party cost in a REAL
// measured SHAKE256 op, model per-party-per-rep work as (n gate-commits + PRG) hash ops,
// and find the MIN proof size achievable under a prover-time BUDGET. HEAVILY MODELED:
// real MPCitH per-party cost (field arithmetic, memory traffic, superlinear effects) is
// higher, so treat the absolute ms as indicative SHAPE, not a benchmark.
function measureHashMs() {
  const x = randomBytes(32)
  const K = 20000
  const t = performance.now()
  for (let i = 0; i < K; i++) H('m', x, i)
  return (performance.now() - t) / K
}
const proverModelMs = (n, depth, hashMs) =>
  Math.ceil(SEC / depth) * (1 << depth) * (n + 2) * hashMs // τ · N · partyHashes · hashMs
function minSizeUnderProverBudget(n, budgetMs, hashMs) {
  let best = null
  for (let depth = 3; depth <= 14; depth++) {
    const pm = proverModelMs(n, depth, hashMs)
    if (pm > budgetMs) continue
    const bytes = modelProofBytes(n, depth)
    if (!best || bytes < best.bytes) best = { depth, N: 1 << depth, proverMs: Math.round(pm), bytes }
  }
  return best
}

// ── run ──
console.log('NZK-002 — optimized hash-only (MPCitH/GGM) range-proof SIZE MODEL')
console.log('GGM all-but-one tree is real+verified; total size is a model (±~2×).\n')

for (const depth of [8, 12]) {
  const t0 = performance.now()
  const r = ggmSelfTest(depth, 200)
  const ms = (performance.now() - t0) / 200
  console.log(`GGM self-test depth=${depth} (N=${1 << depth}): ${r.ok ? 'OK' : 'FAIL ' + r.why}  (${ms.toFixed(3)} ms/op)`)
}
console.log('')

console.log('SIZE-OPTIMAL (size-only, prover unconstrained — the over-eager view the council flagged):')
for (const n of [32, 64]) {
  const b = bestConfig(n)
  const cls = classicalBytes(n)
  console.log(
    JSON.stringify({
      n,
      bestDepth: b.depth,
      parties_N: b.N,
      reps_tau: b.tau,
      optimizedBytes: b.bytes,
      classicalBytes: cls,
      naiveNzk001Bytes: naiveBytes(n),
      vsClassical: +(b.bytes / cls).toFixed(1) + 'x',
      vsNaive: +(naiveBytes(n) / b.bytes).toFixed(1) + 'x smaller',
    }),
  )
}

const hashMs = measureHashMs()
console.log(`\nSIZE↔PROVER TRADEOFF (modeled; measured hashMs=${hashMs.toFixed(5)} ms/op):`)
console.log('min achievable proof size SUBJECT TO a prover-time budget — the realistic operating point:')
for (const n of [32, 64]) {
  for (const budget of [100, 1000, 10000]) {
    const b = minSizeUnderProverBudget(n, budget, hashMs)
    console.log(
      JSON.stringify(
        b
          ? {
              n,
              proverBudgetMs: budget,
              depth: b.depth,
              parties_N: b.N,
              proverModelMs: b.proverMs,
              bytes: b.bytes,
              vsClassical: +(b.bytes / classicalBytes(n)).toFixed(1) + 'x',
            }
          : { n, proverBudgetMs: budget, feasible: false },
      ),
    )
  }
}
