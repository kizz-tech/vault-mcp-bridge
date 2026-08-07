import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      reporter: ['text', 'html'],
    },
    include: ['**/*.test.ts'],
    testTimeout: 15_000,
  },
});
