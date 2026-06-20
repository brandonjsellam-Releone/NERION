// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: [
      '{crypto,capabilities,kernel,receipts,translog,attest,planes,sdks,governance,conformance,disclosure,ledger,settlement,keystore,ops}/**/test/**/*.test.ts',
    ],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: [
        '{crypto,capabilities,kernel,receipts,translog,attest,planes,sdks,governance,conformance,disclosure,ledger,settlement,keystore,ops}/**/src/**/*.ts',
      ],
      reporter: ['text', 'json-summary'],
    },
  },
})
