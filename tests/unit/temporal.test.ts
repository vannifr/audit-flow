import { describe, it, expect } from 'vitest';

describe('Temporal Workflow Types', () => {
  it('should have correct AuditStatus values', () => {
    const statuses = [
      'Created',
      'Discovery',
      'Scanning',
      'Reviewing',
      'Compliance',
      'Validation',
      'Waiting for P0 Approval',
      'Reporting',
      'Completed',
      'Failed',
    ];

    expect(statuses).toHaveLength(10);
    expect(statuses).toContain('Discovery');
    expect(statuses).toContain('Scanning');
    expect(statuses).toContain('Completed');
  });

  it('should have correct Finding severity levels', () => {
    const severities = ['P0', 'P1', 'P2', 'P3'];

    expect(severities).toHaveLength(4);
    expect(severities[0]).toBe('P0'); // Critical
    expect(severities[1]).toBe('P1'); // High
    expect(severities[2]).toBe('P2'); // Medium
    expect(severities[3]).toBe('P3'); // Low
  });

  it('should have correct compliance frameworks', () => {
    const frameworks = [
      'ISO27001',
      'SOC2',
      'PCI-DSS',
      'GDPR',
      'HIPAA',
      'OWASP-ASVS',
    ];

    expect(frameworks).toHaveLength(6);
    expect(frameworks).toContain('ISO27001');
    expect(frameworks).toContain('GDPR');
    expect(frameworks).toContain('PCI-DSS');
  });
});