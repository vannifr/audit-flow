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
        statements: 69,
        branches: 40,
        functions: 84,
        lines: 70,
      },
    },
  },
});
