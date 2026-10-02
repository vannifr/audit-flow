import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// More integration tests for activities
describe('Additional Activity Integration Tests', () => {
  const testRepoPath = '/tmp/test-repo-additional';

  beforeAll(() => {
    if (!fs.existsSync(testRepoPath)) {
      fs.mkdirSync(testRepoPath, { recursive: true });

      // Create package.json
      fs.writeFileSync(path.join(testRepoPath, 'package.json'), JSON.stringify({
        name: 'test-repo',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.0',
          lodash: '^4.17.21'
        }
      }, null, 2));

      // Create source files
      fs.writeFileSync(path.join(testRepoPath, 'app.js'), `
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // SQL injection vulnerability (for semgrep)
  const query = "SELECT * FROM users WHERE id = " + userId;
  res.send(query);
});

app.listen(3000);
      `);

      // Create lockfile
      try {
        execSync('npm i --package-lock-only --ignore-scripts', {
          cwd: testRepoPath,
          encoding: 'utf-8',
          timeout: 30000
        });
      } catch (e) {
        // Ignore
      }
    }
  });

  afterAll(() => {
    if (fs.existsSync(testRepoPath)) {
      fs.rmSync(testRepoPath, { recursive: true, force: true });
    }
  });

  describe('Generate Scope Document', () => {
    it('should create scope document from tech stack', async () => {
      const { generateScopeDocument } = await import('../../src/activities/index');

      const techStack = {
        language: 'nodejs',
        frameworks: ['Express'],
        hasPayments: false,
        hasPII: true,
        packageManager: 'npm'
      };

      const scope = await generateScopeDocument(techStack, ['ISO27001'], 'full');

      expect(scope).toBeDefined();
      expect(scope.frameworks).toContain('ISO27001');
      expect(scope.securityLevel).toBe(2); // Level 2 because hasPII is true
      expect(scope.inScope).toContain('Security & Compliance');
    });
  });

  describe('Map to Compliance', () => {
    it('should map findings to compliance frameworks', async () => {
      const { mapToCompliance } = await import('../../src/activities/index');

      const findings = [
        {
          id: 'FIND-001',
          title: 'SQL injection vulnerability',
          severity: 'P0' as const,
          category: 'injection',
          description: 'Unsanitized input in SQL query',
          evidence: []
        }
      ];

      const frameworks = ['ISO27001'];

      const complianceMaps = await mapToCompliance(findings, frameworks);

      expect(complianceMaps).toBeDefined();
      // mapToCompliance returns an array
      expect(Array.isArray(complianceMaps) || complianceMaps instanceof Map).toBe(true);
    });
  });

  describe('Cross Validate', () => {
    it('should validate findings with different model', async () => {
      const { crossValidate } = await import('../../src/activities/index');

      const input = {
        findings: [
          {
            id: 'FIND-001',
            title: 'Test finding',
            severity: 'P1' as const,
            category: 'security',
            description: 'Test description',
            evidence: []
          }
        ],
        // complianceMaps must match ComplianceMap interface
        complianceMaps: [
          {
            framework: 'ISO27001',
            controls: [
              {
                controlId: 'A.14.2.2',
                title: 'Security in development processes',
                status: 'non-compliant' as const,
                evidence: ['FIND-001']
              }
            ],
            overallScore: 75.5
          }
        ],
        model: 'qwen3-max'
      };

      const review = await crossValidate(input);

      expect(review).toBeDefined();
      expect(review.falsePositives).toBeDefined();
      expect(review.severityCorrections).toBeDefined();
    });
  });

  describe('Generate Report', () => {
    it('should generate report from findings', async () => {
      const { generateReport } = await import('../../src/activities/index');

      const input = {
        repoUrl: 'https://github.com/test/repo',
        workflowId: 'test-workflow-123',
        techStack: {
          language: 'nodejs',
          frameworks: ['Express'],
          hasPayments: false,
          hasPII: true,
          packageManager: 'npm'
        },
        scope: {
          frameworks: ['ISO27001'],
          scanType: 'full',
          targetFiles: [],
          exclusions: [],
          securityLevel: 2,
          repoUrl: 'https://github.com/test/repo',
          techStack: {
            language: 'nodejs',
            frameworks: ['Express'],
            hasPayments: false,
            hasPII: true,
            packageManager: 'npm'
          },
          inScope: ['Security & Compliance'],
          outOfScope: [],
          createdAt: new Date()
        },
        findings: [
          {
            id: 'FIND-001',
            title: 'Test finding',
            severity: 'P1' as const,
            category: 'security',
            description: 'Test description',
            evidence: []
          }
        ],
        // complianceMaps must match ComplianceMap interface
        complianceMaps: [
          {
            framework: 'ISO27001',
            controls: [
              {
                controlId: 'A.14.2.2',
                title: 'Security in development processes',
                status: 'non-compliant' as const,
                evidence: ['FIND-001']
              }
            ],
            overallScore: 75.5
          }
        ],
        reviewResult: {
          falsePositives: [],
          severityCorrections: [],
          missingFindings: [],
          reviewNotes: 'Test review'
        }
      };

      const report = await generateReport(input);

      expect(report).toBeDefined();
      expect(report.reportPath).toBeDefined();
      expect(report.evidencePath).toBeDefined();

      // Cleanup generated files
      if (report.reportPath && fs.existsSync(report.reportPath)) {
        fs.rmSync(path.dirname(report.reportPath), { recursive: true, force: true });
      }
    });
  });

  describe('Review Critical Paths', () => {
    it('should review critical paths in code', async () => {
      const { reviewCriticalPaths } = await import('../../src/activities/index');

      const criticalPaths = ['auth', 'user', 'password'];
      const findings = await reviewCriticalPaths(testRepoPath, criticalPaths, 'OWASP-Top-10');

      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe('Cleanup', () => {
    it('should cleanup temporary files', async () => {
      const { cleanup } = await import('../../src/activities/index');

      // Create temp directory
      const tempPath = '/tmp/cleanup-test-dir';
      fs.mkdirSync(tempPath, { recursive: true });
      fs.writeFileSync(path.join(tempPath, 'test.txt'), 'test');

      await cleanup(tempPath);

      expect(fs.existsSync(tempPath)).toBe(false);
    });
  });
});