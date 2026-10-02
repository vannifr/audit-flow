import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateRepoUrl } from '../../src/activities/index';
import { ApplicationFailure } from '@temporalio/activity';

// Note: identifyCriticalPaths and applyReviewCorrections are workflow helpers
// They are tested in workflow.test.ts

// Mock the activity context
vi.mock('@temporalio/activity', () => ({
  Context: {
    logger: {
      info: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
    },
  },
  ApplicationFailure: {
    create: vi.fn((opts) => {
      const error = new Error(opts.message);
      (error as any).type = opts.type;
      (error as any).nonRetryable = opts.nonRetryable;
      return error;
    }),
  },
}));

describe('validateRepoUrl', () => {
  it('should accept valid GitHub HTTPS URLs', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo')).not.toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo.git')).not.toThrow();
    expect(() => validateRepoUrl('https://github.com/my-org/my-repo-name')).not.toThrow();
  });

  it('should reject non-GitHub URLs', () => {
    expect(() => validateRepoUrl('https://gitlab.com/owner/repo')).toThrow();
    expect(() => validateRepoUrl('https://bitbucket.org/owner/repo')).toThrow();
  });

  it('should reject HTTP (non-HTTPS) URLs', () => {
    expect(() => validateRepoUrl('http://github.com/owner/repo')).toThrow();
  });

  it('should reject SSH URLs', () => {
    expect(() => validateRepoUrl('git@github.com:owner/repo.git')).toThrow();
  });

  it('should reject command injection attempts', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo;rm -rf /')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo|cat /etc/passwd')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo&whoami')).toThrow();
  });

  it('should reject path traversal attempts', () => {
    expect(() => validateRepoUrl('https://github.com/owner/../../../etc/passwd')).toThrow();
  });

  it('should reject file:// protocol', () => {
    expect(() => validateRepoUrl('file:///etc/passwd')).toThrow();
  });

  it('should reject empty strings', () => {
    expect(() => validateRepoUrl('')).toThrow();
  });

  it('should reject URLs with special characters', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo`id`')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo${PATH}')).toThrow();
  });
});