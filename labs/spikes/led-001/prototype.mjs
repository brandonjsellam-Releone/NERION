// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// LED-001 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
//
// Core assumption attacked: Nerion's finality / quorum receipt is k INDEPENDENT ML-DSA-87
// signatures (receipts/src/quorum.ts), a deliberate PQ-safe choice — the code notes a real
// threshold signature "would be classical (not post-quantum)". So the cert is LINEAR in k.
// Question: what does that cost as the validator set scales, and does a PQ-SOUND aggregation
// (succinct STARK-of-signatures, or a threshold-LATTICE sig) obsolete the flat independent-sig
// cert above some validator count?
//
// MEASURED real: ML-DSA-87 sizes are FIPS-204 exact (sig 4627 B, pk 2592 B). A Merkle tree over
// the k signatures is really built + inclusion-verified + tamper-tested. MODELED: aggregation
// options' sizes (STARK constant; threshold single-sig) + crossover. Verify TIME is an Ed25519
// PROXY for ML-DSA-87 — the real verify is far slower, so the proxy UNDERSTATES the burden (the
// case for aggregation is conservative). node:crypto only; no repo imports. No FTO/novelty claim.
// ─────────────────────────────────────────────────────────────────────────────

import { generateKeyPairSync, sign, verify, createHash, randomBytes } from 'node:crypto'

const MLDSA87_SIG = 4627 // FIPS-204 ML-DSA-87 signature bytes (REAL)
const MLDSA87_PK = 2592 // FIPS-204 ML-DSA-87 public key bytes (REAL)

const shake = (b, n = 32) => createHash('shake256', { outputLength: n }).update(b).digest()
const H = (...p) => shake(Buffer.concat(p.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(String(x))))))

// Current independent-signature quorum cert (real ML-DSA-87 sizes)
const certFull = (k) => k * (MLDSA87_SIG + MLDSA87_PK) // each attestation carries sig + member pubkey
const certMinRef = (k) => k * MLDSA87_SIG + Math.ceil(k / 8) // if pubkeys referenced by set-index bitmap

// Real Merkle over k sig-digests — to test whether hash-aggregation cuts the cost.
function merkleRoot(leaves) {
  let l = leaves
  while (l.length > 1) {
    const n = []
    for (let i = 0; i < l.length; i += 2) n.push(H('m', l[i], l[i + 1] ?? l[i]))
    l = n
  }
  return l[0]
}
function merklePath(leaves, idx) {
  const path = []
  let l = leaves
  let i = idx
  while (l.length > 1) {
    path.push(l[i ^ 1] ?? l[i])
    const n = []
    for (let j = 0; j < l.length; j += 2) n.push(H('m', l[j], l[j + 1] ?? l[j]))
    l = n
    i >>= 1
  }
  return path
}
function merkleVerify(leaf, idx, path, root) {
  let h = leaf
  let i = idx
  for (const sib of path) {
    h = i & 1 ? H('m', sib, h) : H('m', h, sib)
    i >>= 1
  }
  return h.equals(root)
}

// PQ-sound aggregation MODELS
const STARK_AGG_BYTES = 45000 // representative succinct proof "k distinct members signed" — CONSTANT in k (model)
const THRESH_LATTICE_BYTES = MLDSA87_SIG // threshold-lattice single sig (research-bet; quorum.ts assumes threshold=classical)

function measureVerifyMs(k, vec) {
  const t = performance.now()
  for (let i = 0; i < k; i++) verify(null, vec.msg, vec.pub, vec.sig)
  return performance.now() - t
}

// ── run ──
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const msg = randomBytes(48)
const vec = { msg, sig: sign(null, msg, privateKey), pub: publicKey }

// real Merkle self-test (honest inclusion verifies; 1-byte tamper rejected)
const leaves = Array.from({ length: 16 }, (_, i) => H('sig', i, randomBytes(8)))
const root = merkleRoot(leaves)
const idx = 5
const path = merklePath(leaves, idx)
const mOk = merkleVerify(leaves[idx], idx, path, root)
const tl = Buffer.from(leaves[idx])
tl[0] ^= 0xff
const mTamper = !merkleVerify(tl, idx, path, root)

console.log('LED-001 — finality-certificate cost vs quorum size k (independent ML-DSA-87 sigs)')
console.log(`ML-DSA-87 sizes REAL (FIPS-204: sig ${MLDSA87_SIG}B, pk ${MLDSA87_PK}B); verify time is an Ed25519 PROXY (real ML-DSA-87 is slower).`)
console.log(`Merkle inclusion self-test: ${mOk ? 'OK' : 'FAIL'}; tamper-rejected: ${mTamper ? 'OK' : 'FAIL'}\n`)

for (const k of [4, 7, 16, 67, 256]) {
  const minref = certMinRef(k)
  const merkleOverhead = 32 + Math.ceil(Math.log2(k)) * 32 // root + one inclusion path
  console.log(
    JSON.stringify({
      k,
      independent_full_KB: +(certFull(k) / 1024).toFixed(1),
      independent_minref_KB: +(minref / 1024).toFixed(1),
      verifies_required: k,
      proxy_verify_ms: +measureVerifyMs(k, vec).toFixed(2),
      merkle_agg_KB: +((minref + merkleOverhead) / 1024).toFixed(1), // still k sigs → no size win
      stark_agg_KB: +(STARK_AGG_BYTES / 1024).toFixed(1), // constant in k
      threshold_lattice_KB: +(THRESH_LATTICE_BYTES / 1024).toFixed(1), // ~1 sig (research-bet)
    }),
  )
}

console.log(
  '\n' +
    JSON.stringify({
      stark_crossover_k: Math.ceil(STARK_AGG_BYTES / MLDSA87_SIG), // above this many sigs, a constant STARK cert is smaller
      threshold_crossover_k: 2, // a single threshold sig beats independent for any k≥2 (IF a PQ threshold sig exists)
      merkle_reduces_cost: false, // measured: hashing the sigs cuts neither the k verifies nor the k-sig payload
    }),
)
