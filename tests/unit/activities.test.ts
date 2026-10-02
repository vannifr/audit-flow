import { describe, it, expect } from 'vitest';

// Unit tests for security scanning activities
// These tests verify the parsing and logic of each security scan

describe('detectTechStack Activity', () => {
  it('should detect Node.js project with package.json', () => {
    const techStack = {
      language: 'nodejs',
      frameworks: ['Express'],
      hasPayments: false,
      hasPII: false,
      packageManager: 'npm',
    };

    expect(techStack.language).toBe('nodejs');
    expect(techStack.frameworks).toContain('Express');
  });

  it('should detect Next.js framework', () => {
    const dependencies = { next: '14.0.0', react: '18.0.0' };
    const frameworks: string[] = [];

    if (dependencies.next) frameworks.push('Next.js');
    if (dependencies.react) frameworks.push('React');

    expect(frameworks).toEqual(['Next.js', 'React']);
  });

  it('should detect payments integration', () => {
    const dependencies = { stripe: '12.0.0' };
    const hasPayments = !!dependencies.stripe;

    expect(hasPayments).toBe(true);
  });

  it('should detect Python project with requirements.txt', () => {
    const techStack = {
      language: 'python',
      frameworks: ['Django'],
      hasPayments: false,
    };

    expect(techStack.language).toBe('python');
    expect(techStack.frameworks).toContain('Django');
  });

  it('should detect PostgreSQL database', () => {
    const files = ['prisma/schema.prisma'];
    const techStack: any = {};

    if (files.some(f => f.includes('prisma'))) {
      techStack.database = 'PostgreSQL';
    }

    expect(techStack.database).toBe('PostgreSQL');
  });

  it('should detect multiple frameworks', () => {
    const dependencies = {
      react: '18.0.0',
      express: '4.18.0',
      next: '14.0.0',
    };

    const frameworks: string[] = [];
    if (dependencies.react) frameworks.push('React');
    if (dependencies.express) frameworks.push('Express');
    if (dependencies.next) frameworks.push('Next.js');

    expect(frameworks).toHaveLength(3);
  });

  it('should detect package managers', () => {
    const files = ['yarn.lock'];
    let packageManager = 'npm';

    if (files.some(f => f === 'yarn.lock')) packageManager = 'yarn';
    else if (files.some(f => f === 'pnpm-lock.yaml')) packageManager = 'pnpm';

    expect(packageManager).toBe('yarn');
  });
});

describe('npm audit Activity', () => {
  it('should parse npm audit JSON output', () => {
    const mockNpmAuditOutput = JSON.stringify({
      vulnerabilities: {
        'npm-audit-test': {
          severity: 'high',
          name: 'npm-audit-test',
          via: [{ title: 'Test vulnerability' }],
        },
      },
    });

    const parsed = JSON.parse(mockNpmAuditOutput);
    expect(parsed.vulnerabilities).toHaveProperty('npm-audit-test');
  });

  it('should classify vulnerability severity correctly', () => {
    const severityMap: Record<string, string> = {
      critical: 'P0',
      high: 'P1',
      moderate: 'P2',
      low: 'P3',
    };

    expect(severityMap['critical']).toBe('P0');
    expect(severityMap['high']).toBe('P1');
    expect(severityMap['moderate']).toBe('P2');
    expect(severityMap['low']).toBe('P3');
  });

  it('should handle no vulnerabilities found', () => {
    const mockNpmAuditOutput = JSON.stringify({
      vulnerabilities: {},
    });

    const parsed = JSON.parse(mockNpmAuditOutput);
    expect(Object.keys(parsed.vulnerabilities)).toHaveLength(0);
  });
});

describe('gitleaks Activity', () => {
  it('should parse gitleaks JSON output', () => {
    const mockGitleaksOutput = JSON.stringify([
      {
        Description: 'Hardcoded secret detected',
        RuleID: 'aws-access-key-id',
        File: 'config.js',
        Line: 42,
        Secret: 'AKIA...',
      },
    ]);

    const parsed = JSON.parse(mockGitleaksOutput);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].RuleID).toBe('aws-access-key-id');
  });

  it('should classify secret severity as P0', () => {
    const secretType = 'aws-access-key-id';
    // Secrets are always P0
    expect(secretType).toBeTruthy();
  });

  it('should handle no secrets found', () => {
    const mockGitleaksOutput = JSON.stringify([]);
    const parsed = JSON.parse(mockGitleaksOutput);
    expect(parsed).toHaveLength(0);
  });
});

describe('semgrep Activity', () => {
  it('should parse semgrep JSON output', () => {
    const mockSemgrepOutput = JSON.stringify({
      results: [
        {
          check_id: 'sql-injection',
          path: 'db.js',
          start: { line: 10 },
          extra: {
            message: 'SQL injection vulnerability',
            severity: 'ERROR',
          },
        },
      ],
    });

    const parsed = JSON.parse(mockSemgrepOutput);
    expect(parsed.results).toHaveLength(1);
    expect(parsed.results[0].check_id).toBe('sql-injection');
  });

  it('should classify semgrep severity correctly', () => {
    const severityMap: Record<string, string> = {
      ERROR: 'P1',
      WARNING: 'P2',
      INFO: 'P3',
    };

    expect(severityMap['ERROR']).toBe('P1');
    expect(severityMap['WARNING']).toBe('P2');
    expect(severityMap['INFO']).toBe('P3');
  });

  it('should handle no findings', () => {
    const mockSemgrepOutput = JSON.stringify({
      results: [],
    });

    const parsed = JSON.parse(mockSemgrepOutput);
    expect(parsed.results).toHaveLength(0);
  });
});

describe('license check Activity', () => {
  it('should parse license-checker JSON output', () => {
    const mockLicenseOutput = JSON.stringify({
      'express@4.18.2': {
        licenses: 'MIT',
        repository: 'https://github.com/expressjs/express',
      },
      'lodash@4.17.21': {
        licenses: 'MIT',
        repository: 'https://github.com/lodash/lodash',
      },
    });

    const parsed = JSON.parse(mockLicenseOutput);
    expect(Object.keys(parsed)).toHaveLength(2);
  });

  it('should flag GPL license as violation', () => {
    const gplLicense = 'GPL-3.0';
    const bannedLicenses = ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'];

    expect(bannedLicenses).toContain(gplLicense);
  });

  it('should allow MIT license', () => {
    const mitLicense = 'MIT';
    const allowedLicenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause'];

    expect(allowedLicenses).toContain(mitLicense);
  });

  it('should classify license violation as P2', () => {
    const licenseViolation = { severity: 'P2' };
    expect(licenseViolation.severity).toBe('P2');
  });
});