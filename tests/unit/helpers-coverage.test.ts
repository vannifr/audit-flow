import { describe, it, expect } from 'vitest';

// Unit tests to cover helper functions
describe('Helper Functions Coverage', () => {
  describe('progress tracking', () => {
    it('should create progress indicator', async () => {
      const { createProgressIndicator, formatDuration, formatFindingCount, formatPhase } = await import('../../src/progress');

      const progress = createProgressIndicator();

      expect(progress).toBeDefined();
      expect(typeof progress.start).toBe('function');
      expect(typeof progress.update).toBe('function');
      expect(typeof progress.succeed).toBe('function');
      expect(typeof progress.fail).toBe('function');

      // Test start
      progress.start('Testing...');

      // Test update
      progress.update('Updated message');

      // Test succeed
      progress.succeed('Done!');

      // Test formatDuration
      expect(formatDuration(1000)).toBe('1s');
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(3661000)).toBe('1h 1m'); // Seconds are omitted when >= 1 hour

      // Test formatFindingCount
      expect(formatFindingCount(0)).toBe('No findings');
      expect(formatFindingCount(1)).toBe('1 finding');
      expect(formatFindingCount(5)).toBe('5 findings');

      // Test formatPhase
      expect(formatPhase('discovery')).toBe('Discovery Phase');
      expect(formatPhase('scanning')).toBe('Scanning Phase');
      expect(formatPhase('reporting')).toBe('Report Generation Phase');
      expect(formatPhase('unknown')).toBe('unknown'); // Unknown phases pass through
    });
  });

  describe('logger', () => {
    it('should use logger instance', async () => {
      const logger = (await import('../../src/logger')).default;

      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.debug).toBe('function');

      // Test logging
      logger.info({ test: true }, 'Test message');
      logger.warn({ test: true }, 'Test warning');
      logger.error({ test: true }, 'Test error');
      logger.debug({ test: true }, 'Test debug');
    });
  });
});