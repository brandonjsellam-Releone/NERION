// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * EVM-native attestation profile (interchain option B — docs/research/interchain-qrl-zond.md).
 *
 * Nerion's NATIVE consensus message is dCBOR + SHAKE256, which an EVM cannot reproduce cheaply (no
 * SHAKE precompile). This profile defines a **keccak256-only**, fixed-layout commitment a
 * Solidity/Hyperion contract recomputes ON-CHAIN — so the destination verifier reconstructs the
 * signed message ITSELF (no trusted relayer message) and verifies the validator's ML-DSA-87
 * signature over it via the QRVM precompile. Validators co-sign this profile alongside consensus
 * when interchain export is wanted (OPT-IN); this module is the primitive + the TS reference
 * verifier the contract must match byte-for-byte. Purely additive — it does NOT change Nerion's
 * native consensus signing.
 *
 * Fail-closed + cross-implementation discipline (AAC Campaign #1 hardening — council + adversarial
 * review converged on all of these):
 *   - The signed message binds the DESTINATION (chainId + verifier address = Solidity
 *     `block.chainid` + `address(this)`), so a finality proof for one chain/deployment can NOT be
 *     replayed on another (cross-chain replay).
 *   - Every integer is width-checked (`u256` throws on <0 or ≥2^256, height/epoch must be safe
 *     non-negative integers) so a value ≡ another mod 2^256 can NOT alias to the same message
 *     (cross-height/epoch replay).
 *   - `blockHash` is asserted exactly 32 bytes, `verifier` exactly 20 bytes, member hex is
 *     lowercase even-length — matching the fixed-width Solidity types so no non-32-byte input can
 *     produce a message the contract is structurally unable to reproduce.
 *   - The validator set is canonicalized (sorted by DECODED pubkey bytes, duplicates rejected) so
 *     total-stake can not be inflated by a duplicate and the fold order equals the contract's
 *     raw-byte ascending order.
 *   - `verifyEvmFinality` NEVER throws: any malformed input returns `{finalized:false}` (a throw
 *     would be a liveness/DoS fail and would diverge from the contract's revert-or-reject).
 *
 * Encoding (reproducible as Solidity `keccak256(abi.encodePacked(...))`):
 *   evmSetId   = fold over DECODED-pubkey-ascending, duplicate-free members:
 *                  h0 = keccak256(SET_TAG)
 *                  h  = keccak256(h ‖ keccak256(pubkey) ‖ uint256(stake) ‖ keccak256(vrfPubkey|""))
 *                  evmSetId = keccak256(h ‖ uint256(epoch))
 *   evmMessage = keccak256( keccak256(ATT_TAG) ‖ keccak256(suite) ‖ uint256(chainId)
 *                           ‖ verifier(20) ‖ uint256(height) ‖ blockHash(32) ‖ evmSetId(32) )
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js'
import { DOMAIN_TAGS, signerFor, type Bytes, type KeyPair } from '../../crypto/src/index.js'
import type { ValidatorSet } from './types.js'

const SET_TAG = utf8ToBytes(DOMAIN_TAGS.EVM_CONSENSUS_SET)
const ATT_TAG = utf8ToBytes(DOMAIN_TAGS.EVM_ATTEST)
const EMPTY_KECCAK = keccak_256(new Uint8Array(0))

const U256_MAX = (1n << 256n) - 1n

/** Decode-side DoS caps: bound the on-chain-mirrored work before any per-signature verify. */
const MAX_VALIDATORS = 4096
const MAX_ATTESTATIONS = 8192

/** The destination this finality proof is bound to — Solidity `block.chainid` + `address(this)`. */
export interface EvmTarget {
  /** Destination EVM chain id (uint256). */
  readonly chainId: bigint
  /** 20-byte lowercase-hex verifier contract address (matches Solidity `address(this)`). */
  readonly verifier: string
}

/** 32-byte big-endian encoding of a uint256. Throws (fail-closed) on out-of-range, never wraps. */
function u256(x: bigint | number): Bytes {
  const v = typeof x === 'bigint' ? x : BigInt(x)
  if (v < 0n) throw new Error('u256: negative')
  if (v > U256_MAX) throw new Error('u256: overflow')
  const out = new Uint8Array(32)
  let t = v
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(t & 0xffn)
    t >>= 8n
  }
  return out
}

const LOWER_HEX = /^[0-9a-f]*$/

/** Decode lowercase even-length hex, or throw. Rejects the uppercase/odd/non-hex inputs that would
 *  otherwise (a) throw deep in noble mid-computation or (b) diverge from the contract's raw bytes. */
function decodeHex(label: string, hex: string): Bytes {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !LOWER_HEX.test(hex)) {
    throw new Error(`evmprofile: ${label} is not lowercase even-length hex`)
  }
  return hexToBytes(hex)
}

/** Decode hex asserting an exact byte length (mirrors a fixed-width Solidity type). */
function decodeHexExact(label: string, hex: string, n: number): Bytes {
  const b = decodeHex(label, hex)
  if (b.length !== n) throw new Error(`evmprofile: ${label} must be ${n} bytes, got ${b.length}`)
  return b
}

/** A safe non-negative integer (uint that fits a JS number exactly), or throw. */
function safeUint(label: string, x: number): number {
  if (!Number.isSafeInteger(x) || x < 0) {
    throw new Error(`evmprofile: ${label} is not a safe non-negative integer`)
  }
  return x
}

/** Lexicographic byte comparison; shorter-is-less on a common prefix (matches Solidity `_lt`). */
function cmpBytes(a: Bytes, b: Bytes): number {
  const n = a.length < b.length ? a.length : b.length
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1
}

interface CanonMember {
  readonly pubkey: string // original hex (the attestation-validator key)
  readonly pubkeyBytes: Bytes
  readonly stake: bigint
  readonly vrfHash: Bytes
}

/**
 * Validate + canonicalize the validator set: decode/validate each member's hex, coerce sub-zero
 * stake to 0, sort by DECODED pubkey bytes (contract order), and REJECT duplicate pubkeys. Throws
 * on any malformation — callers on the verify path catch and fail closed.
 */
function canonicalMembers(set: ValidatorSet): CanonMember[] {
  const members = set.validators.map((v): CanonMember => {
    const pubkeyBytes = decodeHex('pubkey', v.pubkey)
    if (pubkeyBytes.length === 0) throw new Error('evmprofile: empty pubkey')
    const stake = typeof v.stake === 'bigint' && v.stake > 0n ? v.stake : 0n
    if (stake > U256_MAX) throw new Error('evmprofile: stake overflow')
    const vrfHash =
      v.vrfPubkey !== undefined ? keccak_256(decodeHex('vrfPubkey', v.vrfPubkey)) : EMPTY_KECCAK
    return { pubkey: v.pubkey, pubkeyBytes, stake, vrfHash }
  })
  members.sort((a, b) => cmpBytes(a.pubkeyBytes, b.pubkeyBytes))
  for (let i = 1; i < members.length; i++) {
    if (cmpBytes(members[i - 1]!.pubkeyBytes, members[i]!.pubkeyBytes) === 0) {
      throw new Error('evmprofile: duplicate pubkey in validator set')
    }
  }
  return members
}

/** keccak256 EVM-reproducible validator-set id (fold over canonical, duplicate-free members). */
export function evmSetId(set: ValidatorSet): Bytes {
  let h = keccak_256(SET_TAG)
  for (const m of canonicalMembers(set)) {
    h = keccak_256(concatBytes(h, keccak_256(m.pubkeyBytes), u256(m.stake), m.vrfHash))
  }
  return keccak_256(concatBytes(h, u256(safeUint('epoch', set.epoch ?? 0))))
}

/**
 * keccak256 EVM-reproducible attestation message a validator signs (32 bytes), bound to the
 * destination `target` (chainId + verifier) so it can not be replayed on another chain/deployment.
 */
export function evmAttestMessage(
  suite: string,
  height: number,
  blockHashHex: string,
  setId: Bytes,
  target: EvmTarget,
): Bytes {
  if (setId.length !== 32) throw new Error('evmprofile: setId must be 32 bytes')
  const verifier = decodeHexExact('verifier', target.verifier, 20)
  const blockHash = decodeHexExact('blockHash', blockHashHex, 32)
  return keccak_256(
    concatBytes(
      keccak_256(ATT_TAG),
      keccak_256(utf8ToBytes(suite)),
      u256(target.chainId),
      verifier,
      u256(safeUint('height', height)),
      blockHash,
      setId,
    ),
  )
}

/** A validator's ML-DSA-87 signature over the EVM-profile attestation message. */
export interface EvmSignedAttestation {
  readonly validator: string // hex ML-DSA-87 public key
  readonly evmSig: Bytes
}

/** Co-sign the EVM-profile attestation for a block (the validator runs this for interchain export). */
export function signEvmAttestation(
  keypair: KeyPair,
  set: ValidatorSet,
  suite: string,
  height: number,
  blockHashHex: string,
  target: EvmTarget,
): EvmSignedAttestation {
  const msg = evmAttestMessage(suite, height, blockHashHex, evmSetId(set), target)
  return {
    validator: bytesToHex(keypair.publicKey),
    evmSig: signerFor(suite).sign(msg, keypair.secretKey),
  }
}

export interface EvmFinalityVerdict {
  readonly finalized: boolean
  readonly attestingStake: bigint
  readonly totalStake: bigint
}

/**
 * TS reference of `NerionFinalityVerifier.verifyFinality` — the on-chain contract must match this
 * byte-for-byte. Recomputes the setId + destination-bound message from the trusted set (NOT trusted
 * from a relayer), verifies each ML-DSA-87 signature over the recomputed message, dedups distinct
 * members, and finalizes iff a ≥finalityNum/finalityDen stake quorum signed. NEVER throws: every
 * malformed input fails closed to `{finalized:false}`.
 */
export function verifyEvmFinality(
  set: ValidatorSet,
  atts: readonly EvmSignedAttestation[],
  suite: string,
  height: number,
  blockHashHex: string,
  target: EvmTarget,
  finalityNum = 2,
  finalityDen = 3,
): EvmFinalityVerdict {
  const fail = (t: bigint): EvmFinalityVerdict => ({
    finalized: false,
    attestingStake: 0n,
    totalStake: t,
  })
  if (
    !Number.isInteger(finalityNum) ||
    !Number.isInteger(finalityDen) ||
    finalityNum < 1 ||
    finalityDen < 1 ||
    finalityNum > finalityDen
  ) {
    return fail(0n)
  }
  // Decode-side DoS cap: bound work before the per-signature ML-DSA-87 verify loop.
  if (set.validators.length > MAX_VALIDATORS || atts.length > MAX_ATTESTATIONS) return fail(0n)

  let total = 0n
  let msg: Bytes
  let stakeOf: Map<string, bigint>
  try {
    const members = canonicalMembers(set)
    total = members.reduce((a, m) => a + m.stake, 0n)
    if (total <= 0n) return fail(total)
    msg = evmAttestMessage(suite, height, blockHashHex, evmSetId(set), target)
    stakeOf = new Map(members.map((m) => [m.pubkey, m.stake]))
  } catch {
    return fail(0n) // fail-closed on ANY malformed set / header / target
  }

  const verifier = signerFor(suite)
  const seen = new Set<string>()
  let attesting = 0n
  for (const a of atts) {
    if (seen.has(a.validator)) continue // dedup distinct validators
    const s = stakeOf.get(a.validator) ?? 0n
    if (s <= 0n) continue // non-member / zero stake
    let ok = false
    try {
      ok = verifier.verify(a.evmSig, msg, hexToBytes(a.validator))
    } catch {
      ok = false
    }
    if (!ok) continue
    seen.add(a.validator)
    attesting += s
  }
  return {
    finalized: attesting * BigInt(finalityDen) >= BigInt(finalityNum) * total,
    attestingStake: attesting,
    totalStake: total,
  }
}

// ─── Interchain accountability: EVM-profile equivocation (LEDGER-EVM-ACCT-001) ────────────────────
// The native consensus path slashes a validator that double-signs two conflicting blocks at the SAME
// height (ledger/src/equivocation.ts). This is the interchain analogue over the keccak256 EVM-profile
// message, so a validator that co-signs conflicting EVM-profile attestations for interchain export is
// ALSO caught + slashable — extending accountable safety to the exported finality surface (AAC cycle-7).
// Nerion attestations are one-per-height BY DESIGN (no round), so same-height double-signing is the
// offense and honest one-block-per-height behavior ACROSS heights is NOT (each proof pins one height) —
// exactly the native LEDGER-EQUIV-001 semantics, so no `round` binding is needed.

/** A slashable proof that a validator co-signed EVM-profile attestations for TWO distinct blocks at
 *  the SAME height. Verify with {@link verifyEvmEquivocationProof} against the trusted set. */
export interface EvmEquivocationProof {
  readonly validator: string
  readonly height: number
  readonly blockHashA: string
  readonly blockHashB: string
  readonly sigA: Bytes
  readonly sigB: Bytes
}

function safeEvmVerify(
  sig: Bytes,
  msg: Bytes,
  validatorHex: string,
  verifier: ReturnType<typeof signerFor>,
): boolean {
  try {
    return verifier.verify(sig, msg, hexToBytes(validatorHex))
  } catch {
    return false
  }
}

/**
 * Detect validators who co-signed VALID EVM-profile attestations for BOTH of two distinct blocks at
 * the same height (interchain equivocation). Recomputes both messages from the trusted set + target
 * (never trusts a relayer), one proof per offending validator. Fail-closed: a malformed set/target
 * yields no proofs (never throws).
 */
export function detectEvmEquivocations(
  set: ValidatorSet,
  suite: string,
  height: number,
  target: EvmTarget,
  blockHashA: string,
  attsA: readonly EvmSignedAttestation[],
  blockHashB: string,
  attsB: readonly EvmSignedAttestation[],
): EvmEquivocationProof[] {
  if (blockHashA === blockHashB) return []
  if (attsA.length > MAX_ATTESTATIONS || attsB.length > MAX_ATTESTATIONS) return []
  let stakeOf: Map<string, bigint>
  let msgA: Bytes
  let msgB: Bytes
  try {
    const members = canonicalMembers(set)
    stakeOf = new Map(members.map((m) => [m.pubkey, m.stake]))
    const setId = evmSetId(set)
    msgA = evmAttestMessage(suite, height, blockHashA, setId, target)
    msgB = evmAttestMessage(suite, height, blockHashB, setId, target)
  } catch {
    return []
  }
  const verifier = signerFor(suite)
  const validA = new Map<string, Bytes>()
  for (const a of attsA) {
    if (validA.has(a.validator)) continue
    if ((stakeOf.get(a.validator) ?? 0n) <= 0n) continue // non-member / zero stake
    if (safeEvmVerify(a.evmSig, msgA, a.validator, verifier)) validA.set(a.validator, a.evmSig)
  }
  const out: EvmEquivocationProof[] = []
  const seen = new Set<string>()
  for (const b of attsB) {
    if (seen.has(b.validator)) continue
    const sigA = validA.get(b.validator)
    if (sigA === undefined) continue
    if (!safeEvmVerify(b.evmSig, msgB, b.validator, verifier)) continue
    seen.add(b.validator)
    out.push({ validator: b.validator, height, blockHashA, blockHashB, sigA, sigB: b.evmSig })
  }
  return out
}

/**
 * Verify a slashable EVM-profile equivocation proof against the trusted set: distinct blocks, a member
 * with stake, and BOTH signatures verify under the set's RECOMPUTED setId + target. Fail-closed (never
 * throws). A stale cross-epoch proof fails because evmSetId (which folds epoch) differs — slashing is
 * scoped to the epoch the double-sign occurred in, matching the native path.
 */
export function verifyEvmEquivocationProof(
  proof: EvmEquivocationProof,
  set: ValidatorSet,
  suite: string,
  target: EvmTarget,
): boolean {
  if (proof.blockHashA === proof.blockHashB) return false
  let msgA: Bytes
  let msgB: Bytes
  try {
    const stakeOf = new Map(canonicalMembers(set).map((m) => [m.pubkey, m.stake]))
    if ((stakeOf.get(proof.validator) ?? 0n) <= 0n) return false
    const setId = evmSetId(set)
    msgA = evmAttestMessage(suite, proof.height, proof.blockHashA, setId, target)
    msgB = evmAttestMessage(suite, proof.height, proof.blockHashB, setId, target)
  } catch {
    return false
  }
  const verifier = signerFor(suite)
  return (
    safeEvmVerify(proof.sigA, msgA, proof.validator, verifier) &&
    safeEvmVerify(proof.sigB, msgB, proof.validator, verifier)
  )
}
