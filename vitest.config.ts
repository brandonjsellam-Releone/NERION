import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['{crypto,capabilities,kernel,receipts,translog,attest,planes}/test/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['{crypto,capabilities,kernel,receipts,translog,attest,planes}/src/**/*.ts'],
      reporter: ['text', 'json-summary'],
    },
  },
})
