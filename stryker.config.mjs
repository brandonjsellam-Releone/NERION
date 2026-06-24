// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0
// Stryker mutation testing config — run with: npx stryker run
// Non-gating: opt-in only. Results tracked in docs/MUTATION-TESTING.md.
export default {
  packageManager: 'npm',
  reporters: ['html', 'clear-text', 'progress'],
  testRunner: 'vitest',
  coverageAnalysis: 'perTest',
  mutate: [
    // crypto primitives (actual files found in crypto/src/)
    'crypto/src/kem.ts',
    'crypto/src/sign.ts',
    'crypto/src/seal.ts',
    'crypto/src/symmetric.ts',
    'crypto/src/envelope.ts',
    'crypto/src/cnsa.ts',
    'crypto/src/cbor.ts',
    'crypto/src/cose.ts',
    'crypto/src/code-sign.ts',
    // governance kernel
    'kernel/src/decide.ts',
    // disclosure / receipts / ledger / settlement
    'disclosure/src/*.ts',
    'receipts/src/*.ts',
    'ledger/src/*.ts',
    'settlement/src/*.ts',
    // exclusions — never mutate
    '!crypto/src/suites.ts',       // hard constraint: do not touch suites.ts
    '!crypto/src/types.ts',        // type-only, no logic to mutate
    '!crypto/src/errors.ts',       // error constants
    '!crypto/src/index.ts',        // re-exports only
    '!conformance/vectors/**',     // KAT vectors — must not change
    '!**/*.test.ts',
    '!**/*.spec.ts',
    '!**/node_modules/**',
  ],
  thresholds: { high: 80, low: 60, break: null },  // non-breaking
  timeoutMS: 60000,
  // Stryker vitest runner picks up vitest.config.ts automatically.
  // If the repo root does not have one, point to the right config:
  // vitestConfigFile: 'vitest.config.ts',
}
