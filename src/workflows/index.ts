// Application Audit Workflow

import {
  defineSignal,
  defineQuery,
  setHandler,
  condition,
  proxyActivities,
  sleep,
  workflowInfo,
  ActivityFailure,
  ApplicationFailure,
  isCancellation,
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
  ReviewAdvice,
} from '../types';
import type { AuditRun, FetchedSource } from '../scan/lifecycle';
import type { ScanFinding, ScanStepResult } from '../scan/scan-types';
import { computeOutcome } from '../scan/status';
import type { NotPerformed, ScannerId, ScannerStatusEntry } from '../scan/status';

// Import activities
const {
  initAuditRun,
  fetchSource,
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
  cleanupRun,
} = proxyActivities<typeof activities>({
  startToCloseTimeout: '1 hour',
  retry: {
    initialInterval: '10 seconds',
    maximumInterval: '5 minutes',
    maximumAttempts: 3,
    nonRetryableErrorTypes: ['InvalidRepoError', 'ValidationError', 'InvalidRunError', 'SourceUnavailableError'],
  },
});

// Signals (human-in-the-loop)
export const p0ApprovalSignal = defineSignal<[boolean]>('p0-approval');
export const scopeChangeSignal = defineSignal<[ScopeDocument]>('scope-change');

// Queries (status checks)
export const statusQuery = defineQuery<AuditStatus>('status');
export const findingsQuery = defineQuery<Finding[]>('findings');
export const stateQuery = defineQuery<AuditState>('state');

type ScanActivity = (run: AuditRun, source: FetchedSource, repoUrl: string) => Promise<ScanStepResult>;

interface SettledScan {
  entry: ScannerStatusEntry;
  findings: ScanFinding[];
}

const ALWAYS_REQUIRED: ReadonlySet<ScannerId> = new Set<ScannerId>(['gitleaks', 'semgrep']);

const SCANS: readonly (readonly [ScannerId, ScanActivity])[] = [
  ['gitleaks', runGitleaks],
  ['semgrep', runSemgrep],
  ['npm-audit', runNpmAudit],
  ['license-check', runLicenseCheck],
];

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
    scanners: [],
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

  let run: AuditRun | undefined;
  let cleaned = false;

  const removeWorkDir = async (): Promise<void> => {
    if (run === undefined || cleaned) return;
    cleaned = true;
    await cleanupRun(run);
  };

  try {
    state.currentPhase = 'discovery';

    run = await initAuditRun();

    let source: FetchedSource;
    try {
      source = await fetchSource(run, input.repoUrl);
    } catch (error) {
      if (isCancellation(error)) throw error;
      const failure = sourceFailure(error);
      state.outcome = 'incomplete';
      state.notPerformed = (failure.details?.[0] as { notPerformed: NotPerformed[] }).notPerformed;
      throw failure;
    }
    state.revision = source.revision;
    const repoPath = source.repoDir;

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
      throw ApplicationFailure.create({
        type: 'TechStackNotDetectedError',
        message: 'Could not detect tech stack - aborting audit',
        nonRetryable: true,
      });
    }

    // ==================== FASE 1: AUTOMATED SCANS ====================
    state.currentPhase = 'scanning';

    const activeRun = run;
    const settled = await Promise.all(
      SCANS.map(([scanner, scan]) => settle(scanner, scan(activeRun, source, input.repoUrl)))
    );
    const scanFindings = settled.flatMap((s) => s.findings);
    state.findings = [...scanFindings];

    // ==================== FASE 2: CODE REVIEW ====================
    state.currentPhase = 'reviewing';

    // Identify critical paths based on tech stack
    const criticalPaths = identifyCriticalPaths(state.techStack);

    const review = await settleReview(reviewCriticalPaths(repoPath, criticalPaths, 'OWASP-Top-10'));

    await removeWorkDir();

    const scanners = [...settled.map((s) => s.entry), review.entry];
    const recordIds = new Set(scanners.flatMap((s) => s.evidenceRecordIds));
    const decision = computeOutcome({
      scanners,
      untracedFindingIds: scanFindings.filter((f) => !traced(f, recordIds)).map((f) => f.id),
    });
    state.scanners = scanners;
    state.outcome = decision.outcome;
    state.notPerformed = decision.notPerformed;
    state.findings = [...scanFindings, ...review.findings];

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

    const reviewAdvice = reviewAdviceFor(state.findings, reviewResult);
    state.reviewAdvice = reviewAdvice;

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
        throw ApplicationFailure.create({
          type: 'AuditRejectedError',
          message: 'Audit rejected: P0 findings not approved within timeout',
          nonRetryable: true,
        });
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
      outcome: decision.outcome,
      notPerformed: decision.notPerformed,
      scanners,
      revision: source.revision,
    });

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
      outcome: decision.outcome,
      notPerformed: decision.notPerformed,
      scanners,
      source: { repoUrl: input.repoUrl, revision: source.revision },
      reviewAdvice,
    };
  } catch (error) {
    state.currentPhase = 'failed';
    state.error = error instanceof Error ? error.message : String(error);

    throw error;
  } finally {
    await removeWorkDir().catch(() => undefined);
  }
}

function failureType(error: unknown): string {
  const cause = error instanceof ActivityFailure ? error.cause : error;
  return cause instanceof ApplicationFailure && typeof cause.type === 'string' ? cause.type : 'unknown';
}

function sourceFailure(error: unknown): ApplicationFailure {
  const network = failureType(error) === 'SourceNetworkError';
  const notPerformed: NotPerformed = {
    scanner: 'source',
    status: 'failed',
    cause: network ? 'network' : 'source-unavailable',
    summary: network
      ? 'The source could not be fetched because of a network problem; no scanner ran.'
      : 'The source could not be retrieved; no scanner ran.',
  };
  return ApplicationFailure.create({
    type: network ? 'SourceNetworkError' : 'SourceUnavailableError',
    message: `Audit not performed: ${notPerformed.summary}`,
    nonRetryable: !network,
    details: [{ outcome: 'incomplete', notPerformed: [notPerformed] }],
    cause: error instanceof Error ? error : undefined,
  });
}

function failedEntry(scanner: ScannerId, required: boolean, heuristic: boolean, detail: string): ScannerStatusEntry {
  return {
    scanner,
    required,
    status: 'failed',
    cause: 'activity-failed',
    causeDetail: detail,
    heuristic,
    toolVersion: null,
    findingCount: 0,
    evidenceRecordIds: [],
  };
}

async function settle(scanner: ScannerId, pending: Promise<ScanStepResult>): Promise<SettledScan> {
  let result: ScanStepResult;
  try {
    result = await pending;
  } catch (error) {
    if (isCancellation(error)) throw error;
    return { entry: failedEntry(scanner, true, false, `activity failed (${failureType(error)})`), findings: [] };
  }
  if (result?.scanner !== scanner || result.status?.scanner !== scanner) {
    return { entry: failedEntry(scanner, true, false, 'activity returned a result for another scanner'), findings: [] };
  }
  const notApplicable = result.status.status === 'skipped' && result.status.cause === 'not-applicable';
  const entry: ScannerStatusEntry = {
    ...result.status,
    required: result.status.required || ALWAYS_REQUIRED.has(scanner) || !notApplicable,
    heuristic: false,
  };
  return { entry, findings: result.findings };
}

async function settleReview(pending: Promise<Finding[]>): Promise<SettledScan> {
  let found: Finding[];
  try {
    found = await pending;
  } catch (error) {
    if (isCancellation(error)) throw error;
    return { entry: failedEntry('code-review', false, true, `activity failed (${failureType(error)})`), findings: [] };
  }
  const findings: ScanFinding[] = found.map((f) => ({ ...f, scanner: 'code-review', heuristic: true }));
  return {
    entry: {
      scanner: 'code-review',
      required: false,
      heuristic: true,
      status: 'completed',
      toolVersion: null,
      findingCount: findings.length,
      evidenceRecordIds: [],
    },
    findings,
  };
}

function traced(finding: ScanFinding, recordIds: ReadonlySet<string>): boolean {
  const ref = finding.evidenceRef;
  return ref !== undefined && typeof ref.recordId === 'string' && recordIds.has(ref.recordId);
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

function reviewAdviceFor(findings: Finding[], review: ReviewResult): ReviewAdvice[] {
  const advice: ReviewAdvice[] = [];
  for (const correction of review.severityCorrections ?? []) {
    const finding = findings.find(f => f.id === correction.findingId);
    if (finding === undefined) continue;
    advice.push({
      findingId: finding.id,
      kind: 'severity-correction',
      currentSeverity: finding.severity,
      suggestedSeverity: correction.newSeverity,
      reason: correction.reason,
    });
  }
  for (const id of review.falsePositives ?? []) {
    if (findings.some(f => f.id === id)) advice.push({ findingId: id, kind: 'false-positive' });
  }
  return advice;
}