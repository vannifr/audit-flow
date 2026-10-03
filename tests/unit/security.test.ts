import { describe, it, expect } from 'vitest';
import { validateRepoUrl } from '../../src/activities/index';

describe('Repository URL Validation', () => {
  describe('Valid GitHub URLs', () => {
    it.each([
      ['should accept standard GitHub URL', 'https://github.com/owner/repo'],
      ['should accept GitHub URL with .git suffix', 'https://github.com/owner/repo.git'],
      ['should accept GitHub URL with hyphens in owner and repo names', 'https://github.com/my-org/my-repo-name'],
      ['should accept GitHub URL with dots in repo name', 'https://github.com/owner/repo.name'],
    ])('%s', (_name, url) => {
      expect(() => validateRepoUrl(url)).not.toThrow();
    });
  });

  describe('Invalid URLs - Security Tests', () => {
    it.each([
      ['should reject command injection via semicolon', 'https://github.com/owner/repo;rm -rf /'],
      ['should reject command injection via pipe', 'https://github.com/owner/repo|cat /etc/passwd'],
      ['should reject command injection via ampersand', 'https://github.com/owner/repo&whoami'],
      ['should reject path traversal via double dots', 'https://github.com/owner/../../../etc/passwd'],
      ['should reject non-GitHub URLs', 'https://gitlab.com/owner/repo'],
      ['should reject HTTP (non-HTTPS) URLs', 'http://github.com/owner/repo'],
      ['should reject SSH URLs', 'git@github.com:owner/repo.git'],
      ['should reject URLs with backticks', 'https://github.com/owner/repo`id`'],
      ['should reject URLs with environment variables', 'https://github.com/owner/repo${PATH}'],
      ['should reject URLs with newlines', 'https://github.com/owner/repo\n'],
      ['should reject file:// protocol', 'file:///etc/passwd'],
      ['should reject URL-encoded semicolon', 'https://github.com/owner/repo%3Brm'],
      ['should reject empty strings', ''],
      ['should reject URLs with spaces', 'https://github.com/owner/repo name'],
    ])('%s', (_name, url) => {
      expect(() => validateRepoUrl(url)).toThrow('Invalid repository URL');
    });
  });
});

describe('Workflow ID Validation', () => {
  const pattern = /^[a-zA-Z0-9_-]+$/;
  it.each([
    ['should accept alphanumeric workflow IDs', 'audit-test-repo-1234567890', true],
    ['should reject workflow IDs with path traversal', '../../../etc/passwd', false],
    ['should reject workflow IDs with slashes', 'audit/test/repo', false],
  ])('%s', (_name, workflowId, expected) => {
    expect(pattern.test(workflowId)).toBe(expected);
  });
});
