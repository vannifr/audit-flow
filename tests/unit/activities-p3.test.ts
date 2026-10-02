import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  measureThroughput,
  waitForHumanApproval,
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
      callback(null, { stdout: '{}', stderr: '' });
    }, 0);
    return { on: vi.fn() };
  }),
}));

vi.mock('@temporalio/activity', () => ({
  Context: {
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    sleep: vi.fn(() => Promise.resolve()),
  },
  ApplicationFailure: {
    create: vi.fn((opts) => {
      const error = new Error(opts.message);
      (error as any).type = opts.type;
      return error;
    }),
  },
}));

describe('Additional Activity Functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('measureThroughput', () => {
    it('should handle non-existent directory', async () => {
      const result = await measureThroughput('/tmp/non-existent', 'workflow-123');
      
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should return result object', async () => {
      const result = await measureThroughput('/tmp/test', 'workflow-123');
      
      expect(result).toBeDefined();
      expect(result.result).toBeDefined();
    });
  });

  describe('waitForHumanApproval', () => {
    it('should handle approval workflow', async () => {
      // This function waits for a signal, so we test error handling
      const result = await waitForHumanApproval('workflow-123', 1000);
      
      expect(result).toBeDefined();
    });
  });
});
