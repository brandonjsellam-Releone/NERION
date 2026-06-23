// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// REV-001 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
//
// Read-only intake (capabilities/src/capability.ts): verifyChain() has NO revocation path —
// a valid signature-chain is permanently valid until its `notAfter` timestamp. The only
// temporal bound is the signed notAfter field; there is no mechanism to invalidate a
// capability before expiry (e.g., on key compromise or policy change).
//
// The bet: can a sparse-Merkle-tree (SMT) revocation accumulator serve as a compact,
// O(log N) revocation check that could compose with verifyChain without blowing up
// proof/state size?
//
// Architecture:
//   - SMT over 2^DEPTH cap-ID slots (DEPTH=32 → 4 billion slots)
//   - Revoke(capId): insert → recompute DEPTH ancestor hashes
//   - ProveNonMembership(capId): DEPTH sibling hashes = DEPTH×32 B (constant)
//   - VerifyNonMembership(root, capId, proof): DEPTH hash-ops (constant)
//
// Measure: update time, proof size, prove time, verify time — vs N (# revocations).
// Comparators: (a) no revocation (current), (b) naive O(N) set membership proof.
// node:crypto only; no repo imports.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto'

const DEPTH = 32   // 2^32 ≈ 4 billion cap-ID slots; proof = DEPTH×32 B = 1024 B (constant)

// SHA3-256 (PQ-safe collision resistance: 128-bit post-quantum)
const H = (...bufs) => createHash('sha3-256').update(Buffer.concat(bufs)).digest()

// Precompute default subtree hashes bottom-up
// DEFAULT[0] = H("not-revoked"):  hash of an empty (non-revoked) leaf
// DEFAULT[d] = H(DEFAULT[d-1] || DEFAULT[d-1]):  hash of an empty subtree of height d
const DEFAULT = new Array(DEPTH + 1)
DEFAULT[0] = H(Buffer.from('not-revoked'))
for (let d = 1; d <= DEPTH; d++) DEFAULT[d] = H(DEFAULT[d - 1], DEFAULT[d - 1])
const EMPTY_ROOT = DEFAULT[DEPTH]

// Cap-ID → leaf index (0..2^DEPTH-1): take first 4 bytes as unsigned 32-bit big-endian.
// IMPORTANT: `>>> 0` normalises to 32-bit unsigned after any bit op, because JS bit
// operators convert operands to signed int32, which silently breaks indices > 2^31-1.
function capIndex(capId) {
  const hex = capId.padEnd(8, '0').slice(0, 8)
  const buf = Buffer.from(hex, 'hex')
  return buf.readUInt32BE(0) >>> 0   // unsigned 32-bit [0..4294967295]
}

// ── Sparse Merkle Tree ──
//
// Indexing convention (DEPTH=32 example):
//   depth 0 = leaf level  (2^32 nodes, one per cap-ID slot)
//   depth d = internal    (2^(32-d) nodes)
//   depth 32 = root       (1 node, index 0)
//
// At depth d, the node for a given leafIdx has index leafIdx >>> d.
// Left child of (d, idx): (d-1, 2*idx)     [even idx → left]
// Right child of (d, idx): (d-1, 2*idx+1)  [odd  idx → right]
// Sibling of (d, idx): (d, idx ^ 1)
// Parent  of (d, idx): (d+1, idx >>> 1)    [>>> avoids signed-shift trap]
//
// Only non-default nodes are stored; DEFAULT[d] is returned for missing entries.

class SparseMerkleTree {
  constructor() {
    this._store = new Map()   // "${depth}:${idx}" → Buffer(32)
    this._count  = 0          // non-default nodes stored
  }

  _key(depth, idx) { return `${depth}:${idx >>> 0}` }  // >>> 0 to normalise unsigned

  _get(depth, idx) {
    return this._store.get(this._key(depth, idx)) ?? DEFAULT[depth]
  }

  _set(depth, idx, hash) {
    const k = this._key(depth, idx)
    if (hash.equals(DEFAULT[depth])) {
      if (this._store.has(k)) { this._store.delete(k); this._count-- }
    } else {
      if (!this._store.has(k)) this._count++
      this._store.set(k, hash)
    }
  }

  get root() { return this._get(DEPTH, 0) }
  get storedNodes() { return this._count }

  // Revoke capId: mark leaf as REVOKED, recompute DEPTH ancestor hashes.
  revoke(capId) {
    let curIdx = capIndex(capId)                         // unsigned leaf index
    const REVOKED = H(Buffer.from('revoked'), Buffer.from(capId))
    this._set(0, curIdx, REVOKED)

    for (let d = 0; d < DEPTH; d++) {
      const sibIdx = (curIdx ^ 1) >>> 0                 // >>> 0: unsigned sibling
      const isRight = (curIdx & 1) === 1
      const left  = isRight ? this._get(d, sibIdx)  : this._get(d, curIdx)
      const right = isRight ? this._get(d, curIdx)  : this._get(d, sibIdx)
      curIdx = curIdx >>> 1                             // >>> 1: unsigned parent index
      this._set(d + 1, curIdx, H(left, right))
    }
    return this.root
  }

  // Generate non-membership proof for capId (capId must NOT be revoked).
  // proof[i] = sibling hash at depth i (leaf-level first, root-adjacent last).
  proveNonMembership(capId) {
    let curIdx = capIndex(capId)
    const leaf = this._get(0, curIdx)
    if (!leaf.equals(DEFAULT[0])) return { ok: false, proof: null }

    const proof = []
    for (let d = 0; d < DEPTH; d++) {
      proof.push(this._get(d, (curIdx ^ 1) >>> 0))    // sibling at this depth
      curIdx = curIdx >>> 1                            // move toward root
    }
    return { ok: true, proof }
  }

  // Verify non-membership: reconstruct the root from the default leaf + sibling proof.
  // Returns true iff the reconstructed root matches `root` (capId is NOT revoked).
  static verifyNonMembership(root, capId, proof) {
    if (!proof || proof.length !== DEPTH) return false
    let curIdx = capIndex(capId)
    let cur    = DEFAULT[0]                            // must be the default (not-revoked) leaf
    for (let i = 0; i < DEPTH; i++) {
      const sib     = proof[i]
      const isRight = (curIdx & 1) === 1
      cur    = H(isRight ? sib : cur, isRight ? cur : sib)
      curIdx = curIdx >>> 1
    }
    return cur.equals(Buffer.isBuffer(root) ? root : Buffer.from(root))
  }
}

// ── Sanity checks ──
function assert(cond, msg) { if (!cond) { console.error(`SANITY FAIL: ${msg}`); process.exit(1) } }

const PROOF_BYTES = DEPTH * 32   // 1024 B — constant regardless of N

console.log(`\n=== REV-001: Sparse-Merkle Revocation Accumulator (DEPTH=${DEPTH}) ===\n`)
console.log(`Empty root: ${EMPTY_ROOT.toString('hex').slice(0, 16)}...`)
console.log(`Non-membership proof size: ${DEPTH} × 32 B = ${PROOF_BYTES} B (constant, N-independent)`)
console.log()

const tree = new SparseMerkleTree()
const capA = 'deadbeef012345'   // will be revoked
const capB = 'cafebabe0123ff'   // must remain non-revoked
const capC = '0000000100000f'   // another non-revoked cap (small index)

// Empty tree: both caps have valid non-membership proofs
{ const { ok, proof } = tree.proveNonMembership(capA)
  assert(ok, 'empty-tree prove capA ok')
  assert(SparseMerkleTree.verifyNonMembership(tree.root, capA, proof), 'empty-tree verify capA') }

// Revoke capA; its proof must now fail
const root1 = tree.revoke(capA)
{ const { ok } = tree.proveNonMembership(capA)
  assert(!ok, 'revoked cap must not get non-membership proof') }

// capB (unrelated index) still has a valid non-membership proof under root1
{ const { ok, proof } = tree.proveNonMembership(capB)
  assert(ok, 'unrevoked capB prove ok after capA revocation')
  assert(SparseMerkleTree.verifyNonMembership(root1, capB, proof), 'unrevoked capB verify ok') }

// capC (small index) still works
{ const { ok, proof } = tree.proveNonMembership(capC)
  assert(ok, 'capC prove ok')
  assert(SparseMerkleTree.verifyNonMembership(root1, capC, proof), 'capC verify ok') }

// Tamper detection: flip one byte of capB's proof → verify must reject
{ const { proof } = tree.proveNonMembership(capB)
  const tampered = proof.map(b => Buffer.from(b))
  tampered[0][0] ^= 0xff
  assert(!SparseMerkleTree.verifyNonMembership(root1, capB, tampered), 'tamper rejected') }

// Proof against WRONG root (stale root) → rejected
{ const staleRoot = Buffer.alloc(32)  // all zeros, clearly wrong
  const { proof } = tree.proveNonMembership(capB)
  assert(!SparseMerkleTree.verifyNonMembership(staleRoot, capB, proof), 'stale root rejected') }

// Two revocations: capA and capC; capB still works
const tree2 = new SparseMerkleTree()
tree2.revoke(capA)
const root2 = tree2.revoke(capC)
{ const { ok: okA } = tree2.proveNonMembership(capA); assert(!okA, 'capA revoked in tree2') }
{ const { ok: okC } = tree2.proveNonMembership(capC); assert(!okC, 'capC revoked in tree2') }
{ const { ok, proof } = tree2.proveNonMembership(capB)
  assert(ok, 'capB not revoked in tree2')
  assert(SparseMerkleTree.verifyNonMembership(root2, capB, proof), 'capB verify under root2') }

console.log('All sanity checks PASSED.\n')

// ── Performance measurements ──

function ns() { return Number(process.hrtime.bigint()) }
const REPS = 2000

// Warm up V8
{ const tmp = new SparseMerkleTree()
  for (let i = 0; i < 50; i++) tmp.revoke(i.toString(16).padStart(14, '0')) }

// Measure single revoke cost
const revokeTree = new SparseMerkleTree()
{ const t0 = ns()
  for (let i = 0; i < 500; i++) revokeTree.revoke(i.toString(16).padStart(14, '0'))
  const revokeMs = (ns() - t0) / 500 / 1e6
  console.log(`Revoke (update) per-op: ${revokeMs.toFixed(4)} ms  [MEASURED, ${DEPTH} hash-ops]`) }

// Scalability across N revocations
console.log()
console.log(`${'N'.padEnd(7)} | ${'proof B'.padEnd(8)} | ${'prove ms'.padEnd(10)} | ${'verify ms'.padEnd(10)} | nodes | verOk`)
console.log(`${'-------'.padEnd(7)}-+-${'--------'.padEnd(8)}-+-${'----------'.padEnd(10)}-+-${'----------'.padEnd(10)}-+-------+-------`)

for (const N of [0, 10, 100, 1000, 10000]) {
  const t = new SparseMerkleTree()
  for (let i = 0; i < N; i++) t.revoke(i.toString(16).padStart(14, '0'))
  const root = t.root

  // Prove (a cap NOT in the tree — use index = N, which was never revoked)
  const freshCap = (N + 1_000_000).toString(16).padStart(14, '0')

  let proof
  const t1 = ns()
  for (let r = 0; r < REPS; r++) proof = t.proveNonMembership(freshCap).proof
  const proveMs = (ns() - t1) / REPS / 1e6

  const proofBytes = proof ? proof.length * 32 : 0

  // Verify
  let verOk = false
  const t2 = ns()
  for (let r = 0; r < REPS; r++) verOk = SparseMerkleTree.verifyNonMembership(root, freshCap, proof)
  const verifyMs = (ns() - t2) / REPS / 1e6

  console.log(
    `${String(N).padEnd(7)} | ${proofBytes} B${' '.repeat(6 - proofBytes.toString().length)} | ${proveMs.toFixed(4)} ms   | ${verifyMs.toFixed(4)} ms   | ${t.storedNodes} | ${verOk}`
  )
}

// ── Naive set comparison ──
console.log()
console.log('Naive-set (send full list) vs SMT non-membership proof size:')
for (const N of [1, 10, 100, 1000, 10000]) {
  const naiveB  = N * 12   // cap ID = 12 bytes; full set = N × 12 B
  const smtB    = PROOF_BYTES
  const crossover = Math.ceil(smtB / 12)
  console.log(`  N=${String(N).padEnd(6)}: naive=${naiveB.toString().padStart(6)} B, SMT=${smtB} B — SMT wins when N≥${crossover}`)
}

// ── State size ──
console.log()
console.log('SMT accumulated state (non-default stored nodes):')
for (const N of [10, 100, 1000, 10000]) {
  const t = new SparseMerkleTree()
  for (let i = 0; i < N; i++) t.revoke(i.toString(16).padStart(14, '0'))
  // Each stored node: key overhead ~20 B + 32-byte hash value ≈ 52 B
  const stateKB = (t.storedNodes * 52) / 1024
  console.log(`  N=${String(N).padEnd(6)}: ${t.storedNodes} nodes ≈ ${stateKB.toFixed(1)} KB  (worst-case = N×${DEPTH} = ${N*DEPTH} nodes ≈ ${(N*DEPTH*52/1024).toFixed(0)} KB)`)
}

console.log('\n=== Done ===')
