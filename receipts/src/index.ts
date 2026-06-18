/**
 * @polarseek/receipts — PQ-signed, log-anchored, externally-verifiable receipts.
 */

export { buildReceipt, receiptLeaf, verifyReceipt, verifyReceiptInclusion } from './receipt.js'
export type {
  Receipt,
  ReceiptBody,
  ReceiptCommitments,
  BuildReceiptParams,
  ExternalVerdict,
} from './receipt.js'
