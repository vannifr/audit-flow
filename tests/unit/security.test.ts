import { describe, it, expect } from 'vitest';
import { validateRepoUrl } from '../../src/activities/index';

describe('Repository URL Validation', () => {
  describe('Valid GitHub URLs', () => {
    it('should accept standard GitHub URL', () => {
      const url = 'https://github.com/owner/repo';
      expect(() => validateRepoUrl(url)).not.toThrow();
    });

    it('should accept GitHub URL with .git suffix', () => {
      const url = 'https://github.com/owner/repo.git';
      expect(() => validateRepoUrl(url)).not.toThrow();
    });

    it('should accept GitHub URL with hyphens in owner and repo names', () => {
      const url = 'https://github.com/my-org/my-repo-name';
      expect(() => validateRepoUrl(url)).not.toThrow();
    });

    it('should accept GitHub URL with dots in repo name', () => {
      const url = 'https://github.com/owner/repo.name';
      expect(() => validateRepoUrl(url)).not.toThrow();
    });
  });

  describe('Invalid URLs - Security Tests', () => {
    it('should reject command injection via semicolon', () => {
      const maliciousUrl = 'https://github.com/owner/repo;rm -rf /';
      expect(() => validateRepoUrl(maliciousUrl)).toThrow('Invalid repository URL');
    });

    it('should reject command injection via pipe', () => {
      const maliciousUrl = 'https://github.com/owner/repo|cat /etc/passwd';
      expect(() => validateRepoUrl(maliciousUrl)).toThrow('Invalid repository URL');
    });

    it('should reject command injection via ampersand', () => {
      const maliciousUrl = 'https://github.com/owner/repo&whoami';
      expect(() => validateRepoUrl(maliciousUrl)).toThrow('Invalid repository URL');
    });

    it('should reject path traversal via double dots', () => {
      const maliciousUrl = 'https://github.com/owner/../../../etc/passwd';
      expect(() => validateRepoUrl(maliciousUrl)).toThrow('Invalid repository URL');
    });

    it('should reject non-GitHub URLs', () => {
      const url = 'https://gitlab.com/owner/repo';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject HTTP (non-HTTPS) URLs', () => {
      const url = 'http://github.com/owner/repo';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject SSH URLs', () => {
      const url = 'git@github.com:owner/repo.git';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject URLs with backticks', () => {
      const url = 'https://github.com/owner/repo`id`';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject URLs with environment variables', () => {
      const url = 'https://github.com/owner/repo${PATH}';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject URLs with newlines', () => {
      const url = 'https://github.com/owner/repo\n';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject file:// protocol', () => {
      const url = 'file:///etc/passwd';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject URL-encoded semicolon', () => {
      const url = 'https://github.com/owner/repo%3Brm';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });

    it('should reject empty strings', () => {
      expect(() => validateRepoUrl('')).toThrow('Invalid repository URL');
    });

    it('should reject URLs with spaces', () => {
      const url = 'https://github.com/owner/repo name';
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });
  });
});

describe('Workflow ID Validation', () => {
  it('should accept alphanumeric workflow IDs', () => {
    const workflowId = 'audit-test-repo-1234567890';
    const pattern = /^[a-zA-Z0-9_-]+$/;
    expect(pattern.test(workflowId)).toBe(true);
  });

  it('should reject workflow IDs with path traversal', () => {
    const workflowId = '../../../etc/passwd';
    const pattern = /^[a-zA-Z0-9_-]+$/;
    expect(pattern.test(workflowId)).toBe(false);
  });

  it('should reject workflow IDs with slashes', () => {
    const workflowId = 'audit/test/repo';
    const pattern = /^[a-zA-Z0-9_-]+$/;
    expect(pattern.test(workflowId)).toBe(false);
  });
});