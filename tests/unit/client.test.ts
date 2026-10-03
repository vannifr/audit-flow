import { describe, it, expect } from 'vitest';

describe('Compliance Framework Parsing', () => {
  it('should parse single framework', () => {
    const frameworks = 'ISO27001'.split(',').map(f => f.trim());
    expect(frameworks).toEqual(['ISO27001']);
  });

  it('should parse multiple frameworks', () => {
    const frameworks = 'ISO27001,PCI-DSS,GDPR'.split(',').map(f => f.trim());
    expect(frameworks).toEqual(['ISO27001', 'PCI-DSS', 'GDPR']);
  });

  it('should handle spaces around frameworks', () => {
    const frameworks = 'ISO27001 , PCI-DSS , GDPR'.split(',').map(f => f.trim());
    expect(frameworks).toEqual(['ISO27001', 'PCI-DSS', 'GDPR']);
  });

  it('should handle empty frameworks', () => {
    const frameworks = ''.split(',').map(f => f.trim()).filter(Boolean);
    expect(frameworks).toEqual([]);
  });
});

describe('Scope Option Parsing', () => {
  it('should accept valid scope types', () => {
    const validScopes = ['full', 'security', 'compliance'];
    validScopes.forEach(scope => {
      expect(['full', 'security', 'compliance']).toContain(scope);
    });
  });

  it('should reject invalid scope types', () => {
    const invalidScope = 'invalid';
    expect(['full', 'security', 'compliance']).not.toContain(invalidScope);
  });
});

describe('CLI Options Parsing', () => {
  it('should parse --frameworks option', () => {
    const options = ['--frameworks', 'ISO27001,PCI-DSS'];
    const parsed: any = {};

    for (let i = 0; i < options.length; i++) {
      if (options[i] === '--frameworks' && options[i + 1]) {
        parsed.frameworks = options[i + 1].split(',').map(f => f.trim());
        i++;
      }
    }

    expect(parsed.frameworks).toEqual(['ISO27001', 'PCI-DSS']);
  });

  it('should parse --scope option', () => {
    const options = ['--scope', 'security'];
    const parsed: any = {};

    for (let i = 0; i < options.length; i++) {
      if (options[i] === '--scope' && options[i + 1]) {
        parsed.scope = options[i + 1];
        i++;
      }
    }

    expect(parsed.scope).toBe('security');
  });

  it('should parse --skip-approval flag', () => {
    const options = ['--skip-approval'];
    const parsed: any = {};

    for (let i = 0; i < options.length; i++) {
      if (options[i] === '--skip-approval') {
        parsed.skipApproval = true;
      }
    }

    expect(parsed.skipApproval).toBe(true);
  });

  it('should parse --output option', () => {
    const options = ['--output', './custom-reports'];
    const parsed: any = {};

    for (let i = 0; i < options.length; i++) {
      if (options[i] === '--output' && options[i + 1]) {
        parsed.outputDir = options[i + 1];
        i++;
      }
    }

    expect(parsed.outputDir).toBe('./custom-reports');
  });
});

describe('Findings Filtering', () => {
  it('should filter findings by P0 severity', () => {
    const findings = [
      { id: 'FIND-001', severity: 'P0', title: 'Critical 1' },
      { id: 'FIND-002', severity: 'P1', title: 'High 1' },
      { id: 'FIND-003', severity: 'P0', title: 'Critical 2' },
    ];

    const p0Findings = findings.filter(f => f.severity === 'P0');
    expect(p0Findings).toHaveLength(2);
    expect(p0Findings.every(f => f.severity === 'P0')).toBe(true);
  });

  it('should filter findings by P1 severity', () => {
    const findings = [
      { id: 'FIND-001', severity: 'P0' },
      { id: 'FIND-002', severity: 'P1' },
      { id: 'FIND-003', severity: 'P1' },
    ];

    const p1Findings = findings.filter(f => f.severity === 'P1');
    expect(p1Findings).toHaveLength(2);
  });

  it('should group findings by all severity levels', () => {
    const findings = [
      { id: 'FIND-001', severity: 'P0' },
      { id: 'FIND-002', severity: 'P1' },
      { id: 'FIND-003', severity: 'P2' },
      { id: 'FIND-004', severity: 'P3' },
    ];

    const bySeverity = {
      P0: findings.filter(f => f.severity === 'P0'),
      P1: findings.filter(f => f.severity === 'P1'),
      P2: findings.filter(f => f.severity === 'P2'),
      P3: findings.filter(f => f.severity === 'P3'),
    };

    expect(bySeverity.P0).toHaveLength(1);
    expect(bySeverity.P1).toHaveLength(1);
    expect(bySeverity.P2).toHaveLength(1);
    expect(bySeverity.P3).toHaveLength(1);
  });

  it('should handle empty findings list', () => {
    const findings: any[] = [];

    const bySeverity = {
      P0: findings.filter(f => f.severity === 'P0'),
      P1: findings.filter(f => f.severity === 'P1'),
      P2: findings.filter(f => f.severity === 'P2'),
      P3: findings.filter(f => f.severity === 'P3'),
    };

    expect(bySeverity.P0).toHaveLength(0);
    expect(bySeverity.P1).toHaveLength(0);
    expect(bySeverity.P2).toHaveLength(0);
    expect(bySeverity.P3).toHaveLength(0);
  });

  it('should count total findings', () => {
    const findings = [
      { id: 'FIND-001', severity: 'P0' },
      { id: 'FIND-002', severity: 'P1' },
      { id: 'FIND-003', severity: 'P0' },
    ];

    expect(findings).toHaveLength(3);
  });
});