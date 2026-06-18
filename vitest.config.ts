import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['crypto/test/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['crypto/src/**/*.ts'],
      reporter: ['text', 'json-summary'],
    },
  },
})
