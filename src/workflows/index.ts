// Application Audit Workflow

import {
  defineSignal,
  defineQuery,
  setHandler,
  condition,
  proxyActivities,
  sleep,
  workflowInfo,
} from '@temporalio/workflow';
import type * as activities from '../activities';
import type {
  AuditInput,
  AuditResult,
  AuditStatus,
  AuditState,
  Finding,
  TechStack,
  ScopeDocument,
  ComplianceMap,
  ReviewResult,
} from '../types';

// Import activities
const {
  cloneRepository,
  detectTechStack,
  generateScopeDocument,
  runNpmAudit,
  runGitleaks,
  runSemgrep,
  runLicenseCheck,
  reviewCriticalPaths,
  mapToCompliance,
  crossValidate,
  generateReport,
  cleanup,
} = proxyActivities<typeof activities>({
  startToCloseTimeout: '1 hour',
  retry: {
    initialInterval: '10 seconds',
    maximumInterval: '5 minutes',
    maximumAttempts: 3,
    nonRetryableErrorTypes: ['InvalidRepoError', 'ValidationError'],
  },
});

// Signals (human-in-the-loop)
export const p0ApprovalSignal = defineSignal<[boolean]>('p0-approval');
export const scopeChangeSignal = defineSignal<[ScopeDocument]>('scope-change');

// Queries (status checks)
export const statusQuery = defineQuery<AuditStatus>('status');
export const findingsQuery = defineQuery<Finding[]>('findings');
export const stateQuery = defineQuery<AuditState>('state');

// Workflow definition
export async function applicationAudit(input: AuditInput): Promise<AuditResult> {
  const startTime = new Date();
  const workflowId = workflowInfo().workflowId;

  // Initialize state
  const state: AuditState = {
    currentPhase: 'pending',
    findings: [],
    techStack: null,
    scope: null,
    p0Approved: false,
  };

  // Set up signal and query handlers
  setHandler(p0ApprovalSignal, (approved: boolean) => {
    state.p0Approved = approved;
  });

  setHandler(scopeChangeSignal, (newScope: ScopeDocument) => {
    state.scope = newScope;
  });

  setHandler(statusQuery, () => state.currentPhase as AuditStatus);

  setHandler(findingsQuery, () => state.findings);

  setHandler(stateQuery, () => state);

  try {
    // ==================== FASE 0: DISCOVERY ====================
    state.currentPhase = 'discovery';

    // Clone repository
    const repoPath = await cloneRepository(input.repoUrl, workflowId);

    // Detect tech stack
    state.techStack = await detectTechStack(repoPath);

    // Generate scope document
    state.scope = await generateScopeDocument(
      state.techStack,
      input.frameworks || ['OWASP-ASVS'],
      input.scope || 'full'
    );

    // Guardrail: Input validation
    if (!state.techStack || !state.techStack.frameworks.length) {
      throw new Error('Could not detect tech stack - aborting audit');
    }

    // ==================== FASE 1: AUTOMATED SCANS ====================
    state.currentPhase = 'scanning';

    // Run scans in parallel
    const [deps, secrets, sast, licenses] = await Promise.all([
      runNpmAudit(repoPath, workflowId),
      runGitleaks(repoPath, workflowId),
      runSemgrep(repoPath, workflowId),
      runLicenseCheck(repoPath, workflowId),
    ]);

    // Merge findings
    state.findings = [...deps, ...secrets, ...sast, ...licenses];

    // ==================== FASE 2: CODE REVIEW ====================
    state.currentPhase = 'reviewing';

    // Identify critical paths based on tech stack
    const criticalPaths = identifyCriticalPaths(state.techStack);

    // AI code review
    const codeReviewFindings = await reviewCriticalPaths(
      repoPath,
      criticalPaths,
      'OWASP-Top-10'
    );

    state.findings = [...state.findings, ...codeReviewFindings];

    // ==================== FASE 3: COMPLIANCE MAPPING ====================
    state.currentPhase = 'compliance';

    // Map findings to compliance frameworks
    const complianceMaps = await mapToCompliance(
      state.findings,
      state.scope.frameworks
    );

    // ==================== FASE 4: CROSS-VALIDATION ====================
    state.currentPhase = 'validation';

    // Review by different model (Qwen3-max)
    const reviewResult = await crossValidate({
      findings: state.findings,
      complianceMaps,
      model: 'qwen3-max',
    });

    // Apply review corrections
    state.findings = applyReviewCorrections(state.findings, reviewResult);

    // ==================== FASE 5: HUMAN APPROVAL ====================

    // Check for P0 findings
    const p0Findings = state.findings.filter(f => f.severity === 'P0');

    if (p0Findings.length > 0 && !input.skipApproval) {
      state.currentPhase = 'awaiting-approval';

      // Wait for human signal (with timeout)
      const approvalTimeout = 7 * 24 * 60 * 60 * 1000; // 7 days
      const approved = await condition(
        () => state.p0Approved,
        approvalTimeout
      );

      if (!approved) {
        throw new Error('Audit rejected: P0 findings not approved within timeout');
      }
    }

    // ==================== FASE 6: REPORT GENERATION ====================
    state.currentPhase = 'reporting';

    // Generate report
    const report = await generateReport({
      repoUrl: input.repoUrl,
      workflowId,
      techStack: state.techStack,
      scope: state.scope,
      findings: state.findings,
      complianceMaps,
      reviewResult,
      outputDir: input.outputDir,
    });

    // Cleanup temporary files
    await cleanup(repoPath);

    state.currentPhase = 'completed';
    const endTime = new Date();

    return {
      status: 'completed',
      findings: state.findings,
      complianceMap: complianceMaps,
      reportPath: report.reportPath,
      evidencePath: report.evidencePath,
      duration: endTime.getTime() - startTime.getTime(),
      startTime,
      endTime,
    };
  } catch (error) {
    state.currentPhase = 'failed';
    state.error = error instanceof Error ? error.message : String(error);

    throw error;
  }
}

// Helper functions
function identifyCriticalPaths(techStack: TechStack): string[] {
  const paths = ['auth', 'login', 'password', 'session', 'token'];

  if (techStack.hasPayments) {
    paths.push('payment', 'checkout', 'card', 'stripe');
  }

  if (techStack.hasPII) {
    paths.push('user', 'profile', 'email', 'address');
  }

  if (techStack.database) {
    paths.push('database', 'query', 'sql', 'model');
  }

  return paths;
}

function applyReviewCorrections(
  findings: Finding[],
  review: ReviewResult
): Finding[] {
  // Apply severity corrections
  for (const correction of review.severityCorrections) {
    const finding = findings.find(f => f.id === correction.findingId);
    if (finding) {
      finding.severity = correction.newSeverity;
    }
  }

  // Remove false positives
  return findings.filter(f => !review.falsePositives.includes(f.id));
}