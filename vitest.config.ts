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
        statements: 74,
        branches: 58,
        functions: 82,
        lines: 77,
        'src/scan/**': {
          statements: 85,
          branches: 80,
          functions: 90,
          lines: 90,
        },
        'src/evidence/**': {
          statements: 83,
          branches: 74,
          functions: 82,
          lines: 88,
        },
      },
    },
  },
});
