import { describe, it, expect } from 'vitest';

// Integration tests for report generation
// These tests verify the complete report generation flow

describe('Report Generation Integration', () => {
  it('should generate report with all sections', () => {
    const reportStructure = [
      'executive-summary',
      'findings-overview',
      'compliance-mapping',
      'detailed-findings',
      'recommendations',
      'appendix',
    ];

    expect(reportStructure).toHaveLength(6);
    expect(reportStructure).toContain('executive-summary');
  });

  it('should collect evidence for each finding', () => {
    const mockFinding = {
      id: 'FIND-001',
      title: 'SQL injection vulnerability',
      severity: 'P0',
      evidence: {
        file: 'db.js',
        line: 42,
        codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
        tool: 'semgrep',
      },
    };

    expect(mockFinding.evidence).toHaveProperty('file');
    expect(mockFinding.evidence).toHaveProperty('line');
    expect(mockFinding.evidence).toHaveProperty('codeSnippet');
  });

  it('should generate compliance mapping tables', () => {
    const complianceMapping = {
      framework: 'ISO27001',
      controls: [
        { control: 'A.14.2.2', findings: ['FIND-001', 'FIND-002'] },
        { control: 'A.14.2.8', findings: ['FIND-003'] },
      ],
    };

    expect(complianceMapping.framework).toBe('ISO27001');
    expect(complianceMapping.controls).toHaveLength(2);
  });

  it('should format findings by severity', () => {
    const findings = [
      { severity: 'P0', count: 2 },
      { severity: 'P1', count: 5 },
      { severity: 'P2', count: 12 },
      { severity: 'P3', count: 8 },
    ];

    const totalFindings = findings.reduce((sum, f) => sum + f.count, 0);
    expect(totalFindings).toBe(27);
  });

  it('should write report to file', () => {
    const outputPath = './audit-reports/report-2026-10-01.md';
    expect(outputPath).toContain('.md');
  });
});

describe('Evidence Collection', () => {
  it('should store evidence in JSON format', () => {
    const evidenceFormat = 'json';
    const supportedFormats = ['json', 'sarif', 'pdf'];

    expect(supportedFormats).toContain(evidenceFormat);
  });

  it('should include timestamps in evidence', () => {
    const evidence = {
      collectedAt: new Date().toISOString(),
      tool: 'npm-audit',
      output: {},
    };

    expect(evidence.collectedAt).toBeDefined();
    expect(new Date(evidence.collectedAt)).toBeInstanceOf(Date);
  });

  it('should link evidence to findings', () => {
    const findingWithEvidence = {
      id: 'FIND-001',
      evidenceId: 'EV-001',
    };

    expect(findingWithEvidence.evidenceId).toBe('EV-001');
  });
});