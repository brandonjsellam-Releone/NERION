// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/disclosure — selective disclosure + zero-knowledge range proof.
 *
 * NOTE: the ZK range proof (zkrange) is an UNAUDITED reference built on the
 * audited ristretto255 group; the protocol composition needs external review
 * before production reliance. Selective disclosure (selective) uses only the
 * receipt's existing hash commitments and is sound.
 */

export { commitField, verifyDisclosure } from './selective.js'
export {
  commit,
  shiftCommitment,
  proveBelow,
  verifyBelow,
  RangeProofError,
  randomScalar,
} from './zkrange.js'
export type { RangeProof, Pt } from './zkrange.js'
export {
  commitAmount,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
  policyProofDigest,
} from './policyproof.js'
export type { PolicyBounds, PolicySatisfactionProof, AmountCommitment } from './policyproof.js'
export {
  intentAmount,
  boundIntentDigest,
  boundIntentDigestHex,
  verifyBoundCommitment,
  verifyBoundAmount,
  bindAmountCommitment,
  hasSaltedFields,
  PUBLIC_INTENT_FIELDS,
  CommitBindError,
} from './commitbind.js'
export type { BoundAmount } from './commitbind.js'
