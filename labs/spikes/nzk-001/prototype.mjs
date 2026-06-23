// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// NZK-001 — Nerion Labs THROWAWAY prototype (see docs/APEX_TEAMS.md §5).
// DISPOSABLE / TOY / MOCK — NOT production, NOT audited, soundness + zero-knowledge
// are NOT cryptographically vetted. It measures the SIZE/TIME ENVELOPE (a conservative
// LOWER BOUND) of a HASH-ONLY (post-quantum, SHAKE256) range proof and compares it to
// the classical ristretto255 proof in disclosure/src/zkrange.ts.
//
// Architectural question (proof-elimination / non-ZK-group substrate): could a hash-only
// construction replace the classical, NON-post-quantum ristretto255 ZK range proof — the
// known PQ residual (ADR-0022 / backlog B7)? What does it cost in bytes and ms?
//
// ISOLATION: imports ONLY node:crypto. Touches nothing in the Nerion repo. Mocks only.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes } from 'node:crypto'

const DIGEST = 32 // SHAKE256 output bytes (128-bit PQ collision target)
const NONCE = 16
const LAMBDA = 128 // naive parallel-repetition soundness target (~2^-128)

const shake = (buf, outLen = DIGEST) =>
  createHash('shake256', { outputLength: outLen }).update(buf).digest()
const H = (...parts) =>
  shake(Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(String(p))))))

// Fiat–Shamir: expand a transcript into `count` challenge bits.
function fsBits(transcript, count) {
  const chunks = []
  let have = 0
  let ctr = 0
  while (have < count) {
    const d = H(transcript, 'fs', ctr++)
    chunks.push(d)
    have += d.length * 8
  }
  const all = Buffer.concat(chunks)
  const bits = new Uint8Array(count)
  for (let k = 0; k < count; k++) bits[k] = (all[k >> 3] >> (k & 7)) & 1
  return bits
}

// Cut-and-choose booleanity-CONSISTENCY proof for one bit (the cost vehicle).
// Honesty: this proves the prover committed to a CONSISTENT bit b∈{0,1} across λ aux
// commitments; it is NOT zero-knowledge (opened reps reveal b) and is NOT a vetted range
// proof. It exists to MEASURE the real byte/time cost of a hash-only transcript at λ=128.
function proveBit(domain, i, b, stmt) {
  const C = H(domain, 'C', i, Buffer.from([b]), randomBytes(NONCE))
  const auxNonces = []
  const aux = []
  for (let j = 0; j < LAMBDA; j++) {
    const r = randomBytes(NONCE)
    auxNonces.push(r)
    aux.push(H(domain, 'aux', i, j, Buffer.from([b]), r))
  }
  const transcript = Buffer.concat([stmt, C, ...aux])
  const e = fsBits(Buffer.concat([transcript, Buffer.from(`bit${i}`)]), LAMBDA)
  const openings = []
  for (let j = 0; j < LAMBDA; j++) if (e[j] === 1) openings.push([j, b, auxNonces[j]])
  return { C, aux, openings }
}

function verifyBit(domain, i, proof, stmt) {
  const { C, aux, openings } = proof
  if (aux.length !== LAMBDA) return false
  const transcript = Buffer.concat([stmt, C, ...aux])
  const e = fsBits(Buffer.concat([transcript, Buffer.from(`bit${i}`)]), LAMBDA)
  let revealed = null
  const openedIdx = new Set()
  for (const [j, b, r] of openings) {
    if (e[j] !== 1) return false
    if (b !== 0 && b !== 1) return false
    if (revealed === null) revealed = b
    if (b !== revealed) return false
    if (!H(domain, 'aux', i, j, Buffer.from([b]), r).equals(aux[j])) return false
    openedIdx.add(j)
  }
  for (let j = 0; j < LAMBDA; j++) if (e[j] === 1 && !openedIdx.has(j)) return false
  return true
}

const sizeBit = (p) =>
  p.C.length +
  p.aux.reduce((a, x) => a + x.length, 0) +
  p.openings.reduce((a, [, , r]) => a + 1 + 1 + r.length, 0)

// Merkle root over the bit commitments — the linear-binding anchor.
function merkleRoot(leaves) {
  let lvl = leaves
  while (lvl.length > 1) {
    const nxt = []
    for (let i = 0; i < lvl.length; i += 2) nxt.push(H('mrk', lvl[i], lvl[i + 1] ?? lvl[i]))
    lvl = nxt
  }
  return lvl[0]
}

function proveRange(value, n, label) {
  const domain = `nzk-001/${label}`
  const stmt = H('stmt', domain, n)
  const bitProofs = []
  for (let i = 0; i < n; i++) {
    const b = Number((BigInt(value) >> BigInt(i)) & 1n)
    bitProofs.push(proveBit(domain, i, b, stmt))
  }
  return { domain, stmt, n, bitProofs, root: merkleRoot(bitProofs.map((p) => p.C)) }
}

function verifyRange(p) {
  if (p.bitProofs.length !== p.n) return false
  if (!merkleRoot(p.bitProofs.map((x) => x.C)).equals(p.root)) return false
  for (let i = 0; i < p.n; i++) if (!verifyBit(p.domain, i, p.bitProofs[i], p.stmt)) return false
  return true
}

const sizeRange = (p) =>
  p.stmt.length + p.root.length + p.bitProofs.reduce((a, bp) => a + sizeBit(bp), 0)

// Classical baseline, derived from disclosure/src/zkrange.ts structure:
//   per subproof: n bits × (1 commitment[32B point] + BitProof[t0,t1,c0,c1,s0,s1 = 6×32])
//              = n × (32 + 192) = 224n bytes
//   full proof  = amount subproof + diff subproof = 448n bytes (ristretto255, n=32 default)
const classicalBytes = (n) => 448 * n

function bench(n) {
  const value = (1n << BigInt(n)) - 2n
  const threshold = (1n << BigInt(n)) - 1n
  const diff = threshold - 1n - value

  // correctness
  const a0 = proveRange(value, n, 'amount')
  const d0 = proveRange(diff, n, 'diff')
  const okHonest = verifyRange(a0) && verifyRange(d0)

  // soundness smoke: flip one byte of an opened nonce → must reject
  const t = proveRange(value, n, 'amount')
  const op = t.bitProofs[0].openings[0]
  op[2] = Buffer.from(op[2])
  op[2][0] ^= 0xff
  const rejectsTamper = !verifyRange(t)

  // timing
  const K = 30
  let tP = 0
  let tV = 0
  let bytes = 0
  for (let k = 0; k < K; k++) {
    let s = performance.now()
    const a = proveRange(value, n, 'amount')
    const d = proveRange(diff, n, 'diff')
    tP += performance.now() - s
    bytes = sizeRange(a) + sizeRange(d)
    s = performance.now()
    verifyRange(a)
    verifyRange(d)
    tV += performance.now() - s
  }
  return {
    n,
    lambda: LAMBDA,
    okHonest,
    rejectsTamper,
    hashOnlyBytes: bytes,
    classicalBytes: classicalBytes(n),
    blowup: +(bytes / classicalBytes(n)).toFixed(1),
    proveMs: +(tP / K).toFixed(2),
    verifyMs: +(tV / K).toFixed(2),
  }
}

console.log('NZK-001 hash-only (SHAKE256) range-proof size/time ENVELOPE vs classical ristretto255')
console.log('TOY/MOCK — not ZK, not audited; hash-only bytes are a conservative LOWER BOUND.\n')
const rows = [bench(32), bench(64)]
for (const r of rows) console.log(JSON.stringify(r))
