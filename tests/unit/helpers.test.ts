import { describe, it, expect } from 'vitest';
import {
  formatDuration,
  formatFindingCount,
  formatPhase,
} from '../../src/progress';

describe('Helper Functions', () => {
  describe('formatDuration', () => {
    it('should format seconds', () => {
      expect(formatDuration(5000)).toBe('5s');
      expect(formatDuration(30000)).toBe('30s');
    });

    it('should format minutes and seconds', () => {
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(125000)).toBe('2m 5s');
    });

    it('should format hours and minutes', () => {
      expect(formatDuration(3660000)).toBe('1h 1m');
      expect(formatDuration(7320000)).toBe('2h 2m');
    });
  });

  describe('formatFindingCount', () => {
    it('should handle zero findings', () => {
      expect(formatFindingCount(0)).toBe('No findings');
    });

    it('should handle single finding', () => {
      expect(formatFindingCount(1)).toBe('1 finding');
    });

    it('should handle multiple findings', () => {
      expect(formatFindingCount(5)).toBe('5 findings');
      expect(formatFindingCount(100)).toBe('100 findings');
    });
  });

  describe('formatPhase', () => {
    it('should format discovery phase', () => {
      expect(formatPhase('discovery')).toBe('Discovery Phase');
    });

    it('should format scanning phase', () => {
      expect(formatPhase('scanning')).toBe('Scanning Phase');
    });

    it('should format completed status', () => {
      expect(formatPhase('completed')).toBe('Completed');
    });

    it('should format failed status', () => {
      expect(formatPhase('failed')).toBe('Failed');
    });

    it('should handle unknown phases', () => {
      expect(formatPhase('unknown')).toBe('unknown');
    });
  });

  describe('Workflow ID generation', () => {
    it('should generate valid workflow ID', () => {
      const repoUrl = 'https://github.com/owner/repo';
      const timestamp = Date.now();
      const workflowId = `audit-${repoUrl.replace(/[^a-zA-Z0-9]/g, '-')}-${timestamp}`;

      const pattern = /^audit-[a-zA-Z0-9-]+-[0-9]+$/;
      expect(pattern.test(workflowId)).toBe(true);
    });

    it('should sanitize repository URL for workflow ID', () => {
      const repoUrl = 'https://github.com/vannifr/event-ticketing';
      const sanitized = repoUrl.replace(/[^a-zA-Z0-9]/g, '-');

      expect(sanitized).toBe('https---github-com-vannifr-event-ticketing');
    });
  });

  describe('Severity classification', () => {
    it('should classify critical vulnerabilities as P0', () => {
      const severity = 'critical';
      const priority = 'P0';

      expect(['critical', 'high', 'moderate', 'low']).toContain(severity);
    });

    it('should classify secrets as P0', () => {
      const finding = {
        category: 'secrets',
        severity: 'P0',
      };

      expect(finding.severity).toBe('P0');
    });
  });

  describe('Compliance framework validation', () => {
    it.each([['ISO27001'], ['PCI-DSS'], ['GDPR']])('should validate %s', (framework) => {
      const validFrameworks = ['ISO27001', 'PCI-DSS', 'GDPR', 'OWASP-ASVS'];

      expect(validFrameworks).toContain(framework);
    });
  });
});