import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  checkReliability,
  checkObservability,
  checkCicd,
  checkCodeQuality,
  checkDocumentation,
  checkPrivacy,
  checkFunctionalRequirements,
  checkBlindSpots,
} from '../../src/activities/index';

// Mock external dependencies
vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(() => ''),
    promises: {
      readdir: vi.fn(() => Promise.resolve([])),
      readFile: vi.fn(() => Promise.resolve('')),
    },
  };
});

vi.mock('child_process', () => ({
  exec: vi.fn((command, options, callback) => {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    setTimeout(() => {
      callback(null, { stdout: '1\n', stderr: '' });
    }, 0);
    return { on: vi.fn() };
  }),
}));

describe('P2 Quality Check Functions - Error Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('checkReliability', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkReliability('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
      expect(result.result).toBeDefined();
    });

    it('should return result object with expected properties', async () => {
      const result = await checkReliability('/tmp/test');
      
      expect(result.result).toHaveProperty('hasErrorHandling');
      expect(result.result).toHaveProperty('hasRetryLogic');
      expect(result.result).toHaveProperty('hasCircuitBreaker');
      expect(result.result).toHaveProperty('hasHealthCheck');
      expect(result.result).toHaveProperty('tryCatchCoverage');
    });
  });

  describe('checkObservability', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkObservability('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
      expect(result.result).toBeDefined();
    });

    it('should return result object with expected properties', async () => {
      const result = await checkObservability('/tmp/test');
      
      expect(result.result).toHaveProperty('hasStructuredLogging');
      expect(result.result).toHaveProperty('hasMetrics');
      expect(result.result).toHaveProperty('hasTracing');
      expect(result.result).toHaveProperty('hasAlerting');
    });
  });

  describe('checkCicd', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkCicd('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should generate findings for missing CI/CD', async () => {
      const result = await checkCicd('/tmp/test');
      
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings[0]).toHaveProperty('id');
      expect(result.findings[0]).toHaveProperty('title');
      expect(result.findings[0]).toHaveProperty('severity');
    });
  });

  describe('checkCodeQuality', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkCodeQuality('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should return result object with expected properties', async () => {
      const result = await checkCodeQuality('/tmp/test');
      
      expect(result.result).toBeDefined();
    });
  });

  describe('checkDocumentation', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkDocumentation('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should generate findings for missing documentation', async () => {
      const result = await checkDocumentation('/tmp/test');
      
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });

  describe('checkPrivacy', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkPrivacy('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should return result object with expected properties', async () => {
      const result = await checkPrivacy('/tmp/test');
      
      expect(result.result).toBeDefined();
    });
  });

  describe('checkFunctionalRequirements', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkFunctionalRequirements('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should return result object', async () => {
      const result = await checkFunctionalRequirements('/tmp/test');
      
      expect(result.result).toBeDefined();
    });
  });

  describe('checkBlindSpots', () => {
    it('should handle non-existent directory', async () => {
      const result = await checkBlindSpots('/tmp/non-existent');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should return result object with bus factor', async () => {
      const result = await checkBlindSpots('/tmp/test');
      
      expect(result.result).toBeDefined();
      expect(result.result).toHaveProperty('busFactor');
      expect(result.result).toHaveProperty('hasOnCall');
      expect(result.result).toHaveProperty('hasExitStrategy');
    });

    it('should detect low bus factor', async () => {
      const result = await checkBlindSpots('/tmp/test');
      
      // With mock returning '1', bus factor should be 1
      expect(result.result.busFactor).toBe(1);
      // Should generate P1 finding for low bus factor
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });
});
