import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    exclude: [...configDefaults.exclude, 'demo/**', 'tests/contract/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [...configDefaults.coverage.exclude!, 'demo/**'],
      thresholds: {
        statements: 84,
        branches: 74,
        functions: 90,
        lines: 87,
        'src/scan/**': {
          statements: 90,
          branches: 85,
          functions: 94,
          lines: 94,
        },
        'src/evidence/**': {
          statements: 85,
          branches: 80,
          functions: 89,
          lines: 91,
        },
      },
    },
  },
});
