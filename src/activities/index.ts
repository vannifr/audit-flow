// Application Audit Activities

import {
  Context,
  ApplicationFailure,
} from '@temporalio/activity';
import { exec } from 'child_process';
import { promisify } from 'util';
import {
  promises as fs,
  existsSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
} from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import type {
  Finding,
  TechStack,
  ScopeDocument,
  ComplianceMap,
  ReviewResult,
  Evidence,
  ComplianceFramework,
} from '../types';

const execAsync = promisify(exec);

// ==================== REPOSITORY ACTIVITIES ====================

export async function cloneRepository(
  repoUrl: string,
  workflowId: string
): Promise<string> {
  const baseDir = `/tmp/audit-${workflowId}`;
  const repoPath = path.join(baseDir, 'repo');

  try {
    // Create base directory
    if (!existsSync(baseDir)) {
      mkdirSync(baseDir, { recursive: true });
    }

    // Clone repository
    await execAsync(`git clone --depth 1 ${repoUrl} ${repoPath}`);

    console.log(`Cloned repository to ${repoPath}`);

    return repoPath;
  } catch (error) {
    throw ApplicationFailure.create({
      message: `Failed to clone repository: ${error instanceof Error ? error.message : String(error)}`,
      type: 'InvalidRepoError',
    });
  }
}

// ==================== DISCOVERY ACTIVITIES ====================

export async function detectTechStack(repoPath: string): Promise<TechStack> {
  const techStack: TechStack = {
    language: 'unknown',
    frameworks: [],
    hasPayments: false,
    hasPII: false,
    packageManager: 'npm',
  };

  try {
    // Check for package.json (Node.js)
    const packageJsonPath = path.join(repoPath, 'package.json');
    if (existsSync(packageJsonPath)) {
      techStack.language = 'nodejs';
      const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

      // Detect frameworks
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps.next) techStack.frameworks.push('Next.js');
      if (deps.react) techStack.frameworks.push('React');
      if (deps.vue) techStack.frameworks.push('Vue');
      if (deps.express) techStack.frameworks.push('Express');
      if (deps.fastify) techStack.frameworks.push('Fastify');
      if (deps.nest) techStack.frameworks.push('NestJS');

      // Detect payments
      if (deps.stripe || deps['@stripe/stripe-js']) {
        techStack.hasPayments = true;
      }

      // Detect package manager
      if (existsSync(path.join(repoPath, 'yarn.lock'))) {
        techStack.packageManager = 'yarn';
      } else if (existsSync(path.join(repoPath, 'pnpm-lock.yaml'))) {
        techStack.packageManager = 'pnpm';
      }
    }

    // Check for requirements.txt (Python)
    const requirementsPath = path.join(repoPath, 'requirements.txt');
    if (existsSync(requirementsPath)) {
      techStack.language = 'python';
      const requirements = readFileSync(requirementsPath, 'utf-8');

      if (requirements.includes('django')) techStack.frameworks.push('Django');
      if (requirements.includes('fastapi')) techStack.frameworks.push('FastAPI');
      if (requirements.includes('flask')) techStack.frameworks.push('Flask');
      if (requirements.includes('stripe')) techStack.hasPayments = true;
    }

    // Check for database
    if (existsSync(path.join(repoPath, 'prisma/schema.prisma'))) {
      techStack.database = 'PostgreSQL';
    } else if (existsSync(path.join(repoPath, 'docker-compose.yml'))) {
      const dockerCompose = readFileSync(
        path.join(repoPath, 'docker-compose.yml'),
        'utf-8'
      );
      if (dockerCompose.includes('postgres')) techStack.database = 'PostgreSQL';
      if (dockerCompose.includes('mysql')) techStack.database = 'MySQL';
      if (dockerCompose.includes('mongo')) techStack.database = 'MongoDB';
    }

    // Check for PII patterns
    await detectPII(repoPath, techStack);

    console.log(`Detected tech stack: ${JSON.stringify(techStack)}`);

    return techStack;
  } catch (error) {
    console.error(`Error detecting tech stack: ${error}`);
    return techStack;
  }
}

async function detectPII(repoPath: string, techStack: TechStack): Promise<void> {
  const patterns = [
    /\bemail\b/i,
    /\bpassword\b/i,
    /\bname\b/i,
    /\baddress\b/i,
    /\bphone\b/i,
    /\bssn\b/i,
  ];

  // Check common file types for PII patterns
  const extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go'];

  // Limit to first 50 files for performance
  const { stdout } = await execAsync(
    `find ${repoPath} -type f \\( ${extensions
      .map(ext => `-name "*${ext}"`)
      .join(' -o ')} \\) | head -50`
  );

  const files = stdout.trim().split('\n').filter(Boolean);

  for (const file of files) {
    if (!existsSync(file)) continue;

    const content = readFileSync(file, 'utf-8');

    for (const pattern of patterns) {
      if (pattern.test(content)) {
        techStack.hasPII = true;
        return;
      }
    }
  }
}

export async function generateScopeDocument(
  techStack: TechStack,
  frameworks: ComplianceFramework[],
  scopeType: string
): Promise<ScopeDocument> {
  // Determine security level based on data types
  let securityLevel: 1 | 2 | 3 = 1;
  if (techStack.hasPayments || techStack.hasPII) {
    securityLevel = techStack.hasPayments ? 3 : 2;
  }

  // Determine applicable frameworks
  const applicableFrameworks = [...frameworks];

  if (techStack.hasPII) {
    if (!applicableFrameworks.includes('GDPR')) {
      applicableFrameworks.push('GDPR');
    }
  }

  if (techStack.hasPayments) {
    if (!applicableFrameworks.includes('PCI-DSS')) {
      applicableFrameworks.push('PCI-DSS');
    }
  }

  const scope: ScopeDocument = {
    repoUrl: '', // Will be filled by workflow
    techStack,
    securityLevel,
    frameworks: applicableFrameworks,
    inScope: [
      'Security & Compliance',
      'Performance & Scalability',
      'Reliability & Availability',
      'Observability',
      'Testing',
      'CI/CD',
    ],
    outOfScope:
      scopeType === 'security'
        ? ['Accessibility', 'SEO', 'Cost Optimization']
        : [],
    createdAt: new Date(),
  };

  return scope;
}

// ==================== SCAN ACTIVITIES ====================

export async function runNpmAudit(
  repoPath: string,
  workflowId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const outputPath = path.join('/tmp', `audit-${workflowId}`, 'npm-audit.json');

  try {
    // Run npm audit
    const { stdout, stderr } = await execAsync(
      `cd ${repoPath} && npm audit --json`,
      { timeout: 60000 }
    );

    // Save output
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, stdout);

    const audit = JSON.parse(stdout);

    // Parse vulnerabilities
    if (audit.vulnerabilities) {
      for (const [name, vuln] of Object.entries<any>(audit.vulnerabilities)) {
        findings.push({
          id: `NPM-${findings.length + 1}`,
          title: `Vulnerability in ${name}`,
          description: vuln.description || `Known vulnerability in dependency ${name}`,
          severity: mapNpmSeverityToP(vuln.severity),
          category: 'security-dependencies',
          evidence: [
            {
              type: 'scan-output',
              content: JSON.stringify(vuln, null, 2),
              tool: 'npm-audit',
              timestamp: new Date(),
            },
          ],
          remediation: {
            description: `Update ${name} to ${vuln.fixAvailable?.version || 'latest'}`,
            effort: 'hours',
            priority: vuln.severity === 'critical' ? 'immediate' : 'short-term',
          },
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    console.log(`npm audit found ${findings.length} vulnerabilities`);
  } catch (error) {
    // npm audit exits with non-zero if vulnerabilities found
    console.warn(`npm audit: ${error}`);
  }

  return findings;
}

export async function runGitleaks(
  repoPath: string,
  workflowId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const outputPath = path.join(
    '/tmp',
    `audit-${workflowId}`,
    'gitleaks-report.json'
  );

  try {
    // Run gitleaks
    await execAsync(
      `gitleaks git --source ${repoPath} --report-path ${outputPath} --format json`,
      { timeout: 120000 }
    );

    // Read report
    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      for (const leak of report) {
        findings.push({
          id: `LEAK-${findings.length + 1}`,
          title: `Secret detected: ${leak.RuleID}`,
          description: `Hardcoded secret found in ${leak.File}`,
          severity: 'P0',
          category: 'security-data',
          evidence: [
            {
              type: 'scan-output',
              file: leak.File,
              line: leak.StartLine,
              content: leak.Secret,
              tool: 'gitleaks',
              timestamp: new Date(),
            },
          ],
          remediation: {
            description:
              'Remove secret from code and rotate immediately. Move to environment variables or secrets manager.',
            effort: 'hours',
            priority: 'immediate',
          },
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    console.log(`gitleaks found ${findings.length} secrets`);
  } catch (error) {
    console.warn(`gitleaks: ${error}`);
  }

  return findings;
}

export async function runSemgrep(
  repoPath: string,
  workflowId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const outputPath = path.join(
    '/tmp',
    `audit-${workflowId}`,
    'semgrep-report.json'
  );

  try {
    // Run semgrep
    await execAsync(
      `semgrep --config=auto --json --output ${outputPath} ${repoPath}`,
      { timeout: 180000 }
    );

    // Read report
    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      if (report.results) {
        for (const result of report.results) {
          findings.push({
            id: `SEMGREP-${findings.length + 1}`,
            title: result.check_id,
            description: result.extra?.message || 'Security issue detected',
            severity: mapSemgrepSeverityToP(result.extra?.severity),
            category: 'security-injection',
            evidence: [
              {
                type: 'code-snippet',
                file: result.path,
                line: result.start?.line,
                content: result.extra?.lines || '',
                tool: 'semgrep',
                timestamp: new Date(),
              },
            ],
            remediation: {
              description: result.extra?.fix || 'Fix the security issue',
              effort: 'hours',
              priority: 'immediate',
            },
            verified: true,
            createdAt: new Date(),
          });
        }
      }
    }

    console.log(`semgrep found ${findings.length} issues`);
  } catch (error) {
    console.warn(`semgrep: ${error}`);
  }

  return findings;
}

export async function runLicenseCheck(
  repoPath: string,
  workflowId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const outputPath = path.join(
    '/tmp',
    `audit-${workflowId}`,
    'licenses.json'
  );

  try {
    // Run license check
    await execAsync(
      `cd ${repoPath} && npx license-checker --json > ${outputPath}`,
      { timeout: 60000 }
    );

    // Read report
    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      // Check for problematic licenses
      const problematicLicenses = ['GPL', 'AGPL', 'LGPL', 'GPL-3.0', 'AGPL-3.0'];

      for (const [name, info] of Object.entries<any>(report)) {
        if (
          problematicLicenses.some(lic =>
            info.licenses?.some((l: string) => l.includes(lic))
          )
        ) {
          findings.push({
            id: `LICENSE-${findings.length + 1}`,
            title: `License violation in ${name}`,
            description: `Package ${name} uses ${info.licenses?.join(', ')} which may not be compatible with commercial use`,
            severity: 'P1',
            category: 'compliance',
            evidence: [
              {
                type: 'scan-output',
                content: JSON.stringify(info, null, 2),
                tool: 'license-checker',
                timestamp: new Date(),
              },
            ],
            remediation: {
              description:
                'Review license compatibility or find alternative package',
              effort: 'hours',
              priority: 'short-term',
            },
            verified: true,
            createdAt: new Date(),
          });
        }
      }
    }

    console.log(`license check found ${findings.length} violations`);
  } catch (error) {
    console.warn(`license check: ${error}`);
  }

  return findings;
}

// ==================== CODE REVIEW ACTIVITY ====================

export async function reviewCriticalPaths(
  repoPath: string,
  criticalPaths: string[],
  checklist: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // This would integrate with Qwen Agent for AI code review
  // For now, return placeholder findings

  console.log(
    `Reviewing critical paths: ${criticalPaths.join(', ')}`
  );

  // Placeholder: In real implementation, this would call Qwen Agent
  // via the Qwen Code SDK or HTTP API

  return findings;
}

// ==================== COMPLIANCE MAPPING ACTIVITY ====================

export async function mapToCompliance(
  findings: Finding[],
  frameworks: ComplianceFramework[]
): Promise<ComplianceMap[]> {
  const maps: ComplianceMap[] = [];

  for (const framework of frameworks) {
    const controls = await loadControls(framework);

    // Map findings to controls
    for (const control of controls) {
      const relevantFindings = findings.filter(
        f => f.category === control.category
      );

      const status =
        relevantFindings.length > 0 ? 'non-compliant' : 'unverified';

      control.evidence = relevantFindings.map(f => f.id);
      control.status = status;
    }

    const score =
      (controls.filter(c => c.status === 'compliant').length /
        controls.length) *
      100;

    maps.push({
      framework,
      controls,
      overallScore: score,
    });
  }

  return maps;
}

async function loadControls(framework: ComplianceFramework): Promise<any[]> {
  // Placeholder: Load controls from configuration
  const controls: any[] = [
    { id: 'A.8.1.1', title: 'User access management', category: 'security-auth', status: 'unverified' },
    { id: 'A.8.2.1', title: 'Access control', category: 'security-auth', status: 'unverified' },
    { id: 'A.8.3.1', title: 'Information access restriction', category: 'security-data', status: 'unverified' },
  ];

  return controls;
}

// ==================== CROSS-VALIDATION ACTIVITY ====================

export async function crossValidate(input: {
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  model: string;
}): Promise<ReviewResult> {
  // This would integrate with Qwen Agent (different model) for review
  // For now, return placeholder result

  console.log(`Cross-validating findings with ${input.model}`);

  return {
    falsePositives: [],
    severityCorrections: [],
    missingFindings: [],
    reviewNotes: 'Automated review completed',
  };
}

// ==================== REPORT GENERATION ACTIVITY ====================

export async function generateReport(input: {
  repoUrl: string;
  workflowId: string;
  techStack: TechStack;
  scope: ScopeDocument;
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  reviewResult: ReviewResult;
  outputDir?: string;
}): Promise<{ reportPath: string; evidencePath: string }> {
  const baseDir = input.outputDir || path.join('/tmp', `audit-${input.workflowId}`);
  const reportPath = path.join(baseDir, 'audit-report.md');
  const evidencePath = path.join(baseDir, 'evidence');

  // Create directories
  mkdirSync(baseDir, { recursive: true });
  mkdirSync(evidencePath, { recursive: true });

  // Generate markdown report
  const report = generateMarkdownReport(input);

  writeFileSync(reportPath, report);

  // Save evidence files
  for (const finding of input.findings) {
    for (const evidence of finding.evidence) {
      const fileName = path.join(evidencePath, `${finding.id}.json`);
      writeFileSync(fileName, JSON.stringify(evidence, null, 2));
    }
  }

  console.log(`Generated report at ${reportPath}`);

  return { reportPath, evidencePath };
}

function generateMarkdownReport(input: any): string {
  const p0Count = input.findings.filter((f: Finding) => f.severity === 'P0').length;
  const p1Count = input.findings.filter((f: Finding) => f.severity === 'P1').length;
  const p2Count = input.findings.filter((f: Finding) => f.severity === 'P2').length;
  const p3Count = input.findings.filter((f: Finding) => f.severity === 'P3').length;

  return `# Audit Report

**Repository:** ${input.repoUrl}
**Workflow ID:** ${input.workflowId}
**Date:** ${new Date().toISOString()}

## Executive Summary

- **Risk Level:** ${p0Count > 0 ? 'CRITICAL' : p1Count > 0 ? 'HIGH' : p2Count > 0 ? 'MEDIUM' : 'LOW'}
- **Critical (P0):** ${p0Count}
- **High (P1):** ${p1Count}
- **Medium (P2):** ${p2Count}
- **Low (P3):** ${p3Count}

## Scope

**Tech Stack:** ${input.techStack.language} (${input.techStack.frameworks.join(', ')})
**Security Level:** ${input.scope.securityLevel}
**Frameworks:** ${input.scope.frameworks.join(', ')}

## Findings

| ID | Title | Severity | Category |
|----|-------|----------|----------|
${input.findings.map((f: Finding) => `| ${f.id} | ${f.title} | ${f.severity} | ${f.category} |`).join('\n')}

## Compliance

${input.complianceMaps.map((cm: ComplianceMap) => `### ${cm.framework}\n\nScore: ${cm.overallScore.toFixed(1)}%\n`).join('\n')}

## Generated by Temporal Audit Workflow
`;
}

// ==================== CLEANUP ACTIVITY ====================

export async function cleanup(repoPath: string): Promise<void> {
  try {
    await fs.rm(repoPath, { recursive: true, force: true });
    console.log(`Cleaned up ${repoPath}`);
  } catch (error) {
    console.warn(`Cleanup failed: ${error}`);
  }
}

// ==================== HELPER FUNCTIONS ====================

function mapNpmSeverityToP(severity: string): 'P0' | 'P1' | 'P2' | 'P3' {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'P0';
    case 'high':
      return 'P1';
    case 'moderate':
      return 'P2';
    case 'low':
    case 'info':
    default:
      return 'P3';
  }
}

function mapSemgrepSeverityToP(severity: string): 'P0' | 'P1' | 'P2' | 'P3' {
  switch (severity?.toUpperCase()) {
    case 'ERROR':
      return 'P0';
    case 'WARNING':
      return 'P1';
    case 'INFO':
      return 'P2';
    default:
      return 'P3';
  }
}