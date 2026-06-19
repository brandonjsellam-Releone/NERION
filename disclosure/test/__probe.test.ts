import { describe, it, expect } from 'vitest'
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js'
import { shake256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { commit, proveBelow, verifyBelow, randomScalar } from '../src/index.js'

const Point = ristretto255.Point
const L: bigint = Point.Fn.ORDER

describe('PROBE: zkrange n binding', () => {
  it('reports L bit length', () => {
    console.log('L bits =', L.toString(2).length)
    expect(L.toString(2).length).toBeGreaterThan(0)
  })

  it('honest proof for 40<100 verifies', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n)
    console.log('honest verify =', verifyBelow(C, 100n, proof))
    console.log('proof.n =', proof.n)
    expect(verifyBelow(C, 100n, proof)).toBe(true)
  })

  it('ATTACK: can a forged large-n proof make 100<100 verify?', () => {
    // Try the original-finding attack: choose n>=253 and try to prove a
    // negative diff for amount=threshold. With the CURRENT two-sided code we
    // also need amount in [0,2^n). amount=100 is fine. diff=threshold-1-amount
    // = -1 which proveBelow rejects. So try to hand-build via proveBelow with
    // large n and see if the *amount* side range can be abused. First just see
    // whether proveBelow even allows large n at all and whether verify trusts it.
    const r = randomScalar()
    // amount=100, threshold=100 -> honest proveBelow throws. Confirm:
    let threw = false
    try {
      proveBelow(100n, r, 100n, 253)
    } catch {
      threw = true
    }
    console.log('proveBelow(100,_,100,253) threw =', threw)
    expect(true).toBe(true)
  })

  it('ATTACK 2: forge a proof for 100<100 with malicious n using L-wraparound on the DIFF side', () => {
    // Replicate proveBelow internals but force diff = L-1 (== -1 mod L) which
    // bit-decomposes over n>=253 bits. amount stays honest (100, in range with
    // large n). If verifyBelow trusts proof.n and only checks the aggregation
    // equation + per-bit {0,1}, this should pass even though 100 is NOT < 100.
    const n = 253
    const threshold = 100n
    const amount = 100n
    const r = randomScalar()
    const G = Point.BASE
    const H = ristretto255_hasher.hashToCurve(utf8ToBytes('PolarSeek/disclosure/generator-H/v1'))
    const mod = (x: bigint) => ((x % L) + L) % L
    const mul = (P: any, s: bigint) => {
      const k = mod(s)
      return k === 0n ? Point.ZERO : P.multiply(k)
    }
    const neg = (P: any) => mul(P, L - 1n)
    const sub = (P: any, Q: any) => P.add(neg(Q))
    const scalarFromBytes = (b: Uint8Array) => mod(BigInt('0x' + bytesToHex(b)))
    const modpow = (base: bigint, exp: bigint, m: bigint) => {
      let rr = 1n
      let b = mod(base)
      let e = exp
      while (e > 0n) {
        if (e & 1n) rr = (rr * b) % m
        e >>= 1n
        b = (b * b) % m
      }
      return rr
    }
    const inv = (a: bigint) => modpow(a, L - 2n, L)
    const commitLocal = (value: bigint, rr: bigint) => mul(G, value).add(mul(H, rr))

    const statementHash = (thr: bigint, nn: number, cAmt: any, amountC: any[], diffC: any[]) => {
      const tag = utf8ToBytes(`PolarSeek/disclosure/stmt/v2|n=${nn}|thr=${thr}`)
      const parts = [tag, cAmt.toBytes(), ...amountC.map((p) => p.toBytes()), ...diffC.map((p) => p.toBytes())]
      return shake256(concatBytes(...parts), { dkLen: 64 })
    }
    const challenge = (stmt: Uint8Array, tag: string, ci: any, p0: any, p1: any, t0: any, t1: any) =>
      scalarFromBytes(
        shake256(
          concatBytes(utf8ToBytes(tag), stmt, ci.toBytes(), p0.toBytes(), p1.toBytes(), t0.toBytes(), t1.toBytes()),
          { dkLen: 64 },
        ),
      )
    const proveBit = (ci: any, b: number, ri: bigint, stmt: Uint8Array, tag: string) => {
      const P0 = ci
      const P1 = sub(ci, G)
      const kReal = randomScalar()
      const tReal = mul(H, kReal)
      const sFake = randomScalar()
      const cFake = randomScalar()
      const Pfake = b === 0 ? P1 : P0
      const tFake = mul(H, sFake).add(neg(mul(Pfake, cFake)))
      const t0 = b === 0 ? tReal : tFake
      const t1 = b === 0 ? tFake : tReal
      const c = challenge(stmt, tag, ci, P0, P1, t0, t1)
      const cReal = mod(c - cFake)
      const sReal = mod(kReal + cReal * ri)
      return b === 0
        ? { t0, t1, c0: cReal, c1: cFake, s0: sReal, s1: sFake }
        : { t0, t1, c0: cFake, c1: cReal, s0: sFake, s1: sReal }
    }
    const buildBits = (value: bigint, rand: bigint, nn: number) => {
      const rr: bigint[] = []
      let partial = 0n
      for (let i = 0; i < nn - 1; i++) {
        const ri = randomScalar()
        rr.push(ri)
        partial = mod(partial + ri * (1n << BigInt(i)))
      }
      rr.push(mod((mod(rand) - partial) * inv(1n << BigInt(nn - 1))))
      const bits: number[] = []
      const commitments: any[] = []
      for (let i = 0; i < nn; i++) {
        const b = Number((value >> BigInt(i)) & 1n)
        bits.push(b)
        commitments.push(commitLocal(BigInt(b), rr[i]!))
      }
      return { bits, r: rr, commitments }
    }
    const proveSub = (built: any, stmt: Uint8Array, prefix: string) => {
      const bits = built.commitments.map((ci: any, i: number) =>
        proveBit(ci, built.bits[i]!, built.r[i]!, stmt, `PolarSeek/disclosure/bit/${prefix}/${i}`),
      )
      return { commitments: built.commitments, bits }
    }

    // amount honest = 100 (fits in n=253 bits), randomness r
    const builtAmount = buildBits(amount, mod(r), n)
    // diff forged: real integer diff is -1; as a residue mod L that is L-1.
    // Decompose L-1 over n=253 bits. randomness for diff must sum to mod(-r)
    // so that Σ Ci 2^i == commit(diff, -r) == G^(threshold-1) - C.
    const forgedDiff = mod(threshold - 1n - amount) // = mod(-1) = L-1
    const builtDiff = buildBits(forgedDiff, mod(-r), n)
    const cAmt = commitLocal(amount, r)
    const stmt = statementHash(threshold, n, cAmt, builtAmount.commitments, builtDiff.commitments)
    const forged = {
      n,
      amount: proveSub(builtAmount, stmt, 'amount'),
      diff: proveSub(builtDiff, stmt, 'diff'),
    } as any

    const C = commit(amount, r)
    const result = verifyBelow(C, threshold, forged)
    console.log('FORGED 100<100 with n=253 verifies =', result)
    // We assert nothing strong; we just want the logged result.
    expect(typeof result).toBe('boolean')
  })
})
