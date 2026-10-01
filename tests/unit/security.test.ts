import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execAsync = promisify(exec);

describe('Repository URL Validation', () => {
  describe('Valid GitHub URLs', () => {
    it('should accept standard GitHub URL', () => {
      const url = 'https://github.com/owner/repo';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(true);
    });

    it('should accept GitHub URL with .git suffix', () => {
      const url = 'https://github.com/owner/repo.git';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(true);
    });

    it('should accept GitHub URL with hyphens in owner and repo names', () => {
      const url = 'https://github.com/my-org/my-repo-name';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(true);
    });

    it('should accept GitHub URL with dots in repo name', () => {
      const url = 'https://github.com/owner/repo.name';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(true);
    });
  });

  describe('Invalid URLs - Security Tests', () => {
    it('should reject command injection via URL path', () => {
      const maliciousUrl = 'https://github.com/owner/repo;rm -rf /';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(maliciousUrl)).toBe(false);
    });

    it('should reject command injection via pipe', () => {
      const maliciousUrl = 'https://github.com/owner/repo|cat /etc/passwd';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(maliciousUrl)).toBe(false);
    });

    it('should reject command injection via ampersand', () => {
      const maliciousUrl = 'https://github.com/owner/repo&whoami';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(maliciousUrl)).toBe(false);
    });

    it('should reject path traversal via double dots', () => {
      const maliciousUrl = 'https://github.com/owner/../../../etc/passwd';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(maliciousUrl)).toBe(false);
    });

    it('should reject non-GitHub URLs', () => {
      const url = 'https://gitlab.com/owner/repo';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(false);
    });

    it('should reject HTTP (non-HTTPS) URLs', () => {
      const url = 'http://github.com/owner/repo';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(false);
    });

    it('should reject SSH URLs', () => {
      const url = 'git@github.com:owner/repo.git';
      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      expect(pattern.test(url)).toBe(false);
    });

    it('should reject URLs with special characters', () => {
      const urls = [
        'https://github.com/owner/repo$(whoami)',
        'https://github.com/owner/repo`id`',
        'https://github.com/owner/repo${PATH}',
        'https://github.com/owner/repo\n',
      ];

      const pattern = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+(\.git)?$/;
      urls.forEach(url => {
        expect(pattern.test(url)).toBe(false);
      });
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