// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/sdk — agent + resource client and the MCP/tool-call adapter.
 */

export { PolarSeekClient } from './client.js'
export type { GuardContext } from './client.js'
export { guardTool } from './mcp.js'
export type { IntentMapper, GuardedResult } from './mcp.js'
export {
  permitToVerifiableCredential,
  receiptToVerifiablePresentation,
  permitToEidasAttestation,
} from './vc-projection.js'
export type {
  PermitView,
  IntentView,
  ReceiptView,
  W3CVerifiableCredential,
  W3CVerifiablePresentation,
} from './vc-projection.js'
