// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/receipts — PQ-signed, log-anchored, externally-verifiable receipts.
 */

export {
  buildReceipt,
  receiptLeaf,
  verifyReceipt,
  verifyReceiptInclusion,
  verifyIntentDisclosure,
  INTENT_SALT_BYTES,
} from './receipt.js'
export type {
  Receipt,
  ReceiptBody,
  ReceiptCommitments,
  BuildReceiptParams,
  ExternalVerdict,
} from './receipt.js'
export {
  buildQuorumReceipt,
  verifyQuorumReceipt,
  verifyQuorumReceiptByStake,
  quorumSetId,
} from './quorum.js'
export type {
  QuorumReceipt,
  QuorumReceiptBody,
  QuorumBinding,
  QuorumAttestation,
  QuorumVerdict,
} from './quorum.js'
