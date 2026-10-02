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
      threshold: {
        global: {
          branches: 60,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
    },
  },
});
