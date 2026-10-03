#!/usr/bin/env npx ts-node
/**
 * E2E test script - runs audit activities directly without Temporal server
 * This validates that the actual security tools work correctly.
 */

import {
  validateRepoUrl,
  detectTechStack,
  generateScopeDocument,
  mapToCompliance,
  crossValidate,
  generateReport,
} from '../src/activities/index';
import { initAuditRun, cleanupRun } from '../src/scan/lifecycle';
import type { AuditRun } from '../src/scan/lifecycle';
import { defaultProcessRunner } from '../src/scan/process-runner';
import { createEvidenceStore } from '../src/evidence/store';
import { computeOutcome } from '../src/scan/status';
import type { ScanContext, ScanStep, ScanStepResult } from '../src/scan/scan-types';
import { runGitleaksScan } from '../src/scan/tools/gitleaks';
import { runSemgrepScan } from '../src/scan/tools/semgrep';
import { runNpmAuditScan } from '../src/scan/tools/npm-audit';
import { runLicenseScan } from '../src/scan/tools/licenses';
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const WORKFLOW_ID = `e2e-test-${Date.now()}`;
const RUN_ID = `e2e-${Date.now()}`;
const EVIDENCE_ROOT = process.env.TESSERA_EVIDENCE_ROOT || path.join(os.tmpdir(), 'tessera-e2e-evidence');
let RUN: AuditRun;
let TEST_REPO = '';

async function setupTestRepo() {
  console.log('\n=== Setting up test repository ===');

  RUN = await initAuditRun({ workflowId: WORKFLOW_ID, temporalRunId: RUN_ID, tmpRoot: os.tmpdir() });
  TEST_REPO = RUN.repoDir;
  fs.mkdirSync(TEST_REPO, { recursive: true, mode: 0o700 });

  // Create package.json with known vulnerable dependency
  fs.writeFileSync(
    path.join(TEST_REPO, 'package.json'),
    JSON.stringify(
      {
        name: 'e2e-test-repo',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.0',
          lodash: '^4.17.21',
        },
      },
      null,
      2
    )
  );

  // Create vulnerable code
  fs.writeFileSync(
    path.join(TEST_REPO, 'app.js'),
    `
const express = require('express');
const app = express();

// Hardcoded secret (should be detected by gitleaks)
const API_KEY = 'sk-live-1234567890abcdef1234567890abcdef';

// SQL injection vulnerability (should be detected by semgrep)
app.get('/user/:id', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  res.send(query);
});

// XSS vulnerability
app.get('/search', (req, res) => {
  res.send('<h1>Results for: ' + req.query.q + '</h1>');
});

app.listen(3000);
`
  );

  // Create auth folder - critical path for code review
  fs.mkdirSync(path.join(TEST_REPO, 'auth'), { recursive: true });
  fs.writeFileSync(
    path.join(TEST_REPO, 'auth', 'login.js'),
    `
const password = "admin123"; // Hardcoded password - P0
const api_key = "secret-key-12345"; // Hardcoded API key - P0

function validateUser(username, userPassword) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.query(query);
}

function renderProfile(user) {
  document.innerHTML = "<div>" + user.name + "</div>"; // XSS
}
`
  );

  // Create payment folder - critical path for code review
  fs.mkdirSync(path.join(TEST_REPO, 'payment'), { recursive: true });
  fs.writeFileSync(
    path.join(TEST_REPO, 'payment', 'checkout.js'),
    `
const stripe_key = "sk_test_1234567890"; // Hardcoded Stripe key - P0

function processPayment(cardNumber, cvv) {
  return charge(cardNumber, cvv);
}

function evalUserInput(data) {
  return eval(data); // Dangerous eval - P1
}
`
  );

  // Create lockfile
  try {
    execSync('npm i --package-lock-only --ignore-scripts', {
      cwd: TEST_REPO,
      encoding: 'utf-8',
      timeout: 30000,
    });
    console.log('Created package-lock.json');
  } catch (e) {
    console.log('Warning: Could not create lockfile');
  }

  console.log(`Test repo created at ${TEST_REPO}`);
}

async function runE2ETest() {
  console.log('\n=== E2E Audit Test ===\n');
  console.log(`Workflow ID: ${WORKFLOW_ID}`);
  console.log(`Test Repo: ${TEST_REPO}\n`);

  try {
    // Phase 1: Discovery
    console.log('--- Phase 1: Discovery ---');

    console.log('\n1. Validating repo URL...');
    try {
      validateRepoUrl('https://github.com/test/repo');
      console.log('   URL validation: PASS');
    } catch (e) {
      console.log('   URL validation: FAIL', e);
    }

    console.log('\n2. Detecting tech stack...');
    const techStack = await detectTechStack(TEST_REPO);
    console.log('   Detected:', JSON.stringify(techStack, null, 2));

    console.log('\n3. Generating scope document...');
    const scope = await generateScopeDocument(techStack, ['ISO27001', 'OWASP-ASVS'], 'full');
    console.log('   Scope frameworks:', scope.frameworks);
    console.log('   Security level:', scope.securityLevel);

    // Phase 2: Security Scans
    console.log('\n--- Phase 2: Security Scans ---');

    const ctx: ScanContext = {
      run: RUN,
      source: { repoDir: TEST_REPO, revision: '0'.repeat(40) },
      repoUrl: 'https://github.com/test/e2e-test',
      attempt: 1,
      deps: {
        runner: defaultProcessRunner,
        store: createEvidenceStore(EVIDENCE_ROOT, RUN_ID),
        clock: () => new Date(),
        frameworkVersion: 'e2e',
      },
      workerEnv: process.env,
      configDir: path.resolve(__dirname, '..', 'config', 'scanners'),
    };
    const steps: [string, ScanStep][] = [
      ['npm audit', runNpmAuditScan],
      ['gitleaks (secret detection)', runGitleaksScan],
      ['semgrep (SAST)', runSemgrepScan],
      ['license check', runLicenseScan],
    ];
    const results: ScanStepResult[] = [];
    for (const [index, [label, step]] of steps.entries()) {
      console.log(`\n${index + 4}. Running ${label}...`);
      const result = await step(ctx);
      results.push(result);
      console.log(`   Status: ${result.status.status}${result.status.cause ? ` (${result.status.cause})` : ''}, findings: ${result.findings.length}`);
    }
    const [npmResult, leakResult, semgrepResult, licenseResult] = results;
    const npmFindings = npmResult.findings;
    const leakFindings = leakResult.findings;
    const semgrepFindings = semgrepResult.findings;
    const licenseFindings = licenseResult.findings;
    const decision = computeOutcome({
      scanners: results.map((r) => r.status),
      untracedFindingIds: results.flatMap((r) => r.findings).filter((f) => f.evidenceRef === undefined).map((f) => f.id),
    });
    console.log(`\n   Outcome: ${decision.outcome}`);
    for (const item of decision.notPerformed) console.log(`   Not performed: ${item.summary}`);

    // Aggregate findings
    const allFindings = [...npmFindings, ...leakFindings, ...semgrepFindings, ...licenseFindings];
    console.log(`\n   Total findings: ${allFindings.length}`);

    // Phase 3: Compliance Mapping
    console.log('\n--- Phase 3: Compliance Mapping ---');

    console.log('\n8. Mapping findings to compliance frameworks...');
    const complianceMaps = await mapToCompliance(allFindings, ['ISO27001', 'OWASP-ASVS']);
    console.log(`   Generated ${complianceMaps.length} compliance mappings`);

    // Phase 4: Cross-Validation
    console.log('\n--- Phase 4: Cross-Validation ---');

    console.log('\n9. Cross-validating findings...');
    const reviewResult = await crossValidate({
      findings: allFindings,
      complianceMaps: Array.isArray(complianceMaps) ? complianceMaps : [],
      model: 'qwen3-max',
    });
    console.log('   False positives:', reviewResult.falsePositives?.length || 0);
    console.log('   Severity corrections:', reviewResult.severityCorrections?.length || 0);

    // Phase 5: Report Generation
    console.log('\n--- Phase 5: Report Generation ---');

    console.log('\n10. Generating audit report...');
    const report = await generateReport({
      repoUrl: 'https://github.com/test/e2e-test',
      workflowId: WORKFLOW_ID,
      techStack,
      scope,
      findings: allFindings,
      complianceMaps: Array.isArray(complianceMaps) ? complianceMaps : [],
      reviewResult,
      outputDir: `/tmp/audit-${WORKFLOW_ID}`,
      outcome: decision.outcome,
      notPerformed: decision.notPerformed,
      scanners: results.map((r) => r.status),
    });

    console.log(`   Report path: ${report.reportPath}`);
    console.log(`   Evidence path: ${report.evidencePath}`);

    // Verify report exists
    if (fs.existsSync(report.reportPath)) {
      const reportContent = fs.readFileSync(report.reportPath, 'utf-8');
      const lines = reportContent.split('\n').slice(0, 30);
      console.log('\n   Report preview:');
      lines.forEach((line) => console.log(`     ${line}`));
    }

    // Summary
    console.log('\n=== SUMMARY ===');
    console.log(`Total findings: ${allFindings.length}`);
    console.log(`  - NPM vulnerabilities: ${npmFindings.length}`);
    console.log(`  - Secrets detected: ${leakFindings.length}`);
    console.log(`  - Code issues: ${semgrepFindings.length}`);
    console.log(`  - License issues: ${licenseFindings.length}`);
    console.log(`\nReport generated: ${report.reportPath}`);

    // Cleanup
    console.log('\n11. Cleaning up...');
    await cleanupRun(RUN, os.tmpdir());
    console.log('   Work dir cleaned up');
    console.log(`   Evidence kept under ${path.join(EVIDENCE_ROOT, RUN_ID)}`);

    console.log('\n=== E2E TEST COMPLETE ===\n');
    return true;
  } catch (error) {
    console.error('\n!!! E2E TEST FAILED !!!');
    console.error(error);
    return false;
  }
}

// Run the test
setupTestRepo()
  .then(() => runE2ETest())
  .then((success) => {
    process.exit(success ? 0 : 1);
  })
  .catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });