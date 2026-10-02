import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    exclude: [...configDefaults.exclude, 'demo/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [...configDefaults.coverage.exclude!, 'demo/**'],
      thresholds: {
        statements: 70,
        branches: 42,
        functions: 85,
        lines: 71,
      },
    },
  },
});
