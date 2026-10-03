import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RetryState } from '@temporalio/common';
import { ActivityFailure, ApplicationFailure, CancelledFailure } from '@temporalio/workflow';
import type { AuditRun, FetchedSource } from '../../src/scan/lifecycle';
import type { ScanFinding, ScanStepResult } from '../../src/scan/scan-types';
import type { ScannerId, ScannerStatusEntry, ScannerStatusValue, StatusCause } from '../../src/scan/status';
import type { AuditInput, AuditResult, Finding } from '../../src/types';

type Fn = (...args: unknown[]) => unknown;

const harness = vi.hoisted(() => ({
  activities: {} as Record<string, Fn>,
  calls: [] as string[],
}));

vi.mock('@temporalio/workflow', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@temporalio/workflow')>();
  return {
    ...actual,
    proxyActivities: () =>
      new Proxy(
        {},
        {
          get: (_target, name: string) =>
            (...args: unknown[]) => {
              harness.calls.push(name);
              const impl = harness.activities[name];
              if (impl === undefined) throw new Error(`unexpected activity ${name}`);
              return impl(...args);
            },
        },
      ),
    workflowInfo: () => ({ workflowId: 'wf-outcome', runId: 'run-outcome' }),
    setHandler: () => undefined,
    condition: async (fn: () => boolean) => fn(),
  };
});

const { applicationAudit } = await import('../../src/workflows/index');

const RUN: AuditRun = { runId: 'run-outcome', workDir: '/tmp/tessera-run-outcome', repoDir: '/tmp/tessera-run-outcome/repo' };
const SOURCE: FetchedSource = { repoDir: RUN.repoDir, revision: 'b'.repeat(40) };
const INPUT: AuditInput = { repoUrl: 'https://github.com/acme/app', skipApproval: true };
const SCANNERS = ['gitleaks', 'semgrep', 'npm-audit', 'license-check'] as const;
const ACTIVITY: Record<(typeof SCANNERS)[number], string> = {
  gitleaks: 'runGitleaks',
  semgrep: 'runSemgrep',
  'npm-audit': 'runNpmAudit',
  'license-check': 'runLicenseCheck',
};

function recordId(scanner: ScannerId): string {
  return `scan.${scanner}.a1`;
}

function finding(id: string, scanner: ScannerId, traced = true): ScanFinding {
  const f: ScanFinding = {
    id,
    title: `finding ${id}`,
    description: 'd',
    severity: 'P2',
    category: 'security-config',
    evidence: [],
    remediation: { description: 'r', effort: 'hours', priority: 'short-term' },
    verified: true,
    createdAt: new Date(0),
    scanner,
  };
  if (traced) f.evidenceRef = { recordId: recordId(scanner), recordSha256: 'c'.repeat(64) };
  return f;
}

function step(
  scanner: ScannerId,
  status: ScannerStatusValue = 'completed',
  opts: { cause?: StatusCause; required?: boolean; findings?: ScanFinding[] } = {},
): ScanStepResult {
  const findings = opts.findings ?? [];
  const entry: ScannerStatusEntry = {
    scanner,
    required: opts.required ?? true,
    status,
    heuristic: false,
    toolVersion: status === 'unavailable' ? null : '1.0.0',
    findingCount: findings.length,
    evidenceRecordIds: [recordId(scanner)],
  };
  if (opts.cause !== undefined) entry.cause = opts.cause;
  return { scanner, status: entry, findings, evidence: { recordId: recordId(scanner), recordSha256: 'c'.repeat(64) } };
}

function activityFailure(cause: Error): ActivityFailure {
  return new ActivityFailure('Activity task failed', 'activity', '1', RetryState.MAXIMUM_ATTEMPTS_REACHED, 'worker', cause);
}

function baseline(): Record<string, Fn> {
  return {
    initAuditRun: vi.fn(async () => RUN),
    fetchSource: vi.fn(async () => SOURCE),
    detectTechStack: vi.fn(async () => ({ language: 'nodejs', frameworks: ['Express'], hasPayments: false, hasPII: false, packageManager: 'npm' })),
    generateScopeDocument: vi.fn(async () => ({ repoUrl: '', techStack: {}, securityLevel: 1, frameworks: ['OWASP-ASVS'], inScope: [], outOfScope: [], createdAt: new Date(0) })),
    runGitleaks: vi.fn(async () => step('gitleaks')),
    runSemgrep: vi.fn(async () => step('semgrep')),
    runNpmAudit: vi.fn(async () => step('npm-audit')),
    runLicenseCheck: vi.fn(async () => step('license-check')),
    reviewCriticalPaths: vi.fn(async () => []),
    mapToCompliance: vi.fn(async () => []),
    crossValidate: vi.fn(async () => ({ falsePositives: [], severityCorrections: [], missingFindings: [], reviewNotes: '' })),
    generateReport: vi.fn(async () => ({ reportPath: '/out/audit-report.md', evidencePath: '/out/evidence' })),
    cleanupRun: vi.fn(async () => undefined),
  };
}

function act(name: string): ReturnType<typeof vi.fn> {
  return harness.activities[name] as unknown as ReturnType<typeof vi.fn>;
}

function reportInput(): Record<string, unknown> {
  expect(act('generateReport')).toHaveBeenCalledTimes(1);
  return act('generateReport').mock.calls[0][0] as Record<string, unknown>;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected the workflow to fail');
    },
    (err: unknown) => err,
  );
}

beforeEach(() => {
  harness.activities = baseline();
  harness.calls = [];
});

describe('applicationAudit outcome rule (FR-001..FR-004, FR-016)', () => {
  const states: ScannerStatusValue[] = ['unavailable', 'failed', 'partial', 'skipped'];
  const cases = SCANNERS.flatMap((scanner) => states.map((state) => [scanner, state] as const));

  it.each(cases)('%s %s makes the audit incomplete and names the scanner (SC-001, TS-001, TS-002, TS-005, TS-006)', async (scanner, state) => {
    harness.activities[ACTIVITY[scanner]] = vi.fn(async () => step(scanner, state, { cause: state === 'skipped' ? 'no-lockfile' : 'tool-error' }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed.map((n) => n.scanner)).toEqual([scanner]);
    expect(result.notPerformed[0].status).toBe(state);
    expect(result.notPerformed[0].summary).toContain(scanner);
    expect(result.scanners.find((s) => s.scanner === scanner)?.status).toBe(state);
    const report = reportInput();
    expect(report.outcome).toBe('incomplete');
    expect(report.notPerformed).toEqual(result.notPerformed);
    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
  });

  it('is complete when all required scanners complete without findings, and names the completed scanners (TS-003)', async () => {
    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    expect(result.notPerformed).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.scanners.map((s) => s.scanner)).toEqual([...SCANNERS, 'code-review']);
    expect(result.scanners.filter((s) => s.status === 'completed').map((s) => s.scanner)).toEqual([...SCANNERS, 'code-review']);
    expect(result.source).toEqual({ repoUrl: INPUT.repoUrl, revision: SOURCE.revision });
    expect(result.status).toBe('completed');
    const report = reportInput();
    expect(report.outcome).toBe('complete');
    expect(report.notPerformed).toEqual([]);
    expect(report.scanners).toEqual(result.scanners);
  });

  it('passes the run and fetched source to every scan and the work dir to discovery', async () => {
    await applicationAudit(INPUT);
    for (const scanner of SCANNERS) {
      expect(act(ACTIVITY[scanner])).toHaveBeenCalledWith(RUN, SOURCE, INPUT.repoUrl);
    }
    expect(act('fetchSource')).toHaveBeenCalledWith(RUN, INPUT.repoUrl);
    expect(act('detectTechStack')).toHaveBeenCalledWith(SOURCE.repoDir);
    expect(act('reviewCriticalPaths').mock.calls[0][0]).toBe(SOURCE.repoDir);
  });

  it('passes the fetched source revision on to generateReport', async () => {
    await applicationAudit(INPUT);

    expect(reportInput().revision).toBe(SOURCE.revision);
  });

  it('counts exit-because-issues-found as findings, not as a failure (TS-004)', async () => {
    const leaks = [finding('LEAK-1', 'gitleaks'), finding('LEAK-2', 'gitleaks')];
    harness.activities.runGitleaks = vi.fn(async () => step('gitleaks', 'completed', { cause: 'issues-found', findings: leaks }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    expect(result.findings.map((f) => f.id)).toEqual(['LEAK-1', 'LEAK-2']);
    const entry = result.scanners.find((s) => s.scanner === 'gitleaks');
    expect(entry?.status).toBe('completed');
    expect(entry?.cause).toBe('issues-found');
  });

  it('is complete when npm audit and the license check are not applicable (no package.json)', async () => {
    harness.activities.runNpmAudit = vi.fn(async () => step('npm-audit', 'skipped', { cause: 'not-applicable', required: false }));
    harness.activities.runLicenseCheck = vi.fn(async () => step('license-check', 'skipped', { cause: 'not-applicable', required: false }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    expect(result.notPerformed).toEqual([]);
  });

  it.each(['gitleaks', 'semgrep'] as const)('treats %s as required even when its step claims otherwise', async (scanner) => {
    harness.activities[ACTIVITY[scanner]] = vi.fn(async () => step(scanner, 'failed', { cause: 'tool-error', required: false }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed.map((n) => n.scanner)).toEqual([scanner]);
  });

  it.each(['npm-audit', 'license-check'] as const)('only lets %s be optional when it is skipped as not applicable', async (scanner) => {
    harness.activities[ACTIVITY[scanner]] = vi.fn(async () => step(scanner, 'failed', { cause: 'tool-error', required: false }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed.map((n) => n.scanner)).toEqual([scanner]);
  });

  it('lists every scanner that did not complete (TS-006)', async () => {
    harness.activities.runGitleaks = vi.fn(async () => step('gitleaks', 'unavailable', { cause: 'not-installed' }));
    harness.activities.runNpmAudit = vi.fn(async () => step('npm-audit', 'failed', { cause: 'tool-error' }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed.map((n) => n.scanner).sort()).toEqual(['gitleaks', 'npm-audit']);
  });
});

describe('applicationAudit scanner crashes', () => {
  it.each(SCANNERS)('turns an ApplicationFailure from %s into failed/activity-failed instead of losing the audit', async (scanner) => {
    harness.activities[ACTIVITY[scanner]] = vi.fn(async () => {
      throw activityFailure(ApplicationFailure.create({ type: 'EvidenceStoreError', message: 'evidence store: disk full' }));
    });

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    const entry = result.scanners.find((s) => s.scanner === scanner);
    expect(entry).toMatchObject({ scanner, required: true, status: 'failed', cause: 'activity-failed', findingCount: 0, evidenceRecordIds: [] });
    expect(result.notPerformed).toEqual([expect.objectContaining({ scanner, status: 'failed', cause: 'activity-failed' })]);
    expect(result.scanners).toHaveLength(5);
    expect(act('generateReport')).toHaveBeenCalledTimes(1);
    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
  });

  it('treats a step result for another scanner as a failure', async () => {
    harness.activities.runSemgrep = vi.fn(async () => step('gitleaks'));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.scanners.find((s) => s.scanner === 'semgrep')?.status).toBe('failed');
  });

  it('propagates cancellation instead of recording it as a scanner failure', async () => {
    const cancelled = new CancelledFailure('cancelled');
    harness.activities.runSemgrep = vi.fn(async () => {
      throw cancelled;
    });

    const error = await rejection(applicationAudit(INPUT));

    expect(error).toBe(cancelled);
    expect(act('generateReport')).not.toHaveBeenCalled();
    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
  });
});

describe('applicationAudit evidence guard (FR-007)', () => {
  it('makes the audit incomplete when a scanner finding has no evidence record', async () => {
    harness.activities.runSemgrep = vi.fn(async () => step('semgrep', 'completed', { cause: 'issues-found', findings: [finding('SG-1', 'semgrep', false)] }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed).toEqual([expect.objectContaining({ scanner: 'evidence', status: 'untraced-findings' })]);
  });

  it('makes the audit incomplete when a finding points at a record no scanner produced', async () => {
    const forged = { ...finding('SG-2', 'semgrep'), evidenceRef: { recordId: 'scan.other.a1', recordSha256: 'c'.repeat(64) } };
    harness.activities.runSemgrep = vi.fn(async () => step('semgrep', 'completed', { cause: 'issues-found', findings: [forged] }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed.map((n) => n.scanner)).toEqual(['evidence']);
  });

  it('exempts heuristic code-review findings from the guard, labels them and records a non-required status entry', async () => {
    const review: Finding = { ...finding('REVIEW-1', 'code-review', false) };
    delete (review as ScanFinding).scanner;
    harness.activities.reviewCriticalPaths = vi.fn(async () => [review]);

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    const reviewed = result.findings.find((f) => f.id === 'REVIEW-1') as ScanFinding;
    expect(reviewed.heuristic).toBe(true);
    expect(reviewed.scanner).toBe('code-review');
    expect(result.scanners.find((s) => s.scanner === 'code-review')).toEqual({
      scanner: 'code-review',
      required: false,
      heuristic: true,
      status: 'completed',
      toolVersion: null,
      findingCount: 1,
      evidenceRecordIds: [],
    });
  });

  it('does not exempt a scanner finding that claims to be heuristic', async () => {
    const claimed = { ...finding('SG-3', 'semgrep', false), heuristic: true };
    harness.activities.runSemgrep = vi.fn(async () => step('semgrep', 'completed', { cause: 'issues-found', findings: [claimed] }));

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('incomplete');
  });

  it('keeps the audit when the heuristic review crashes, without affecting the outcome', async () => {
    harness.activities.reviewCriticalPaths = vi.fn(async () => {
      throw activityFailure(new Error('review crashed'));
    });

    const result = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    expect(result.scanners.find((s) => s.scanner === 'code-review')).toMatchObject({ status: 'failed', cause: 'activity-failed', required: false, heuristic: true });
  });
});

describe('applicationAudit source failure (TS-011)', () => {
  it.each([
    ['SourceUnavailableError', true, 'source-unavailable'],
    ['SourceNetworkError', false, 'network'],
  ] as const)('%s: no report, failure with outcome incomplete, cleanupRun called', async (type, nonRetryable, cause) => {
    harness.activities.fetchSource = vi.fn(async () => {
      throw activityFailure(ApplicationFailure.create({ type, message: 'source unavailable: repository not found', nonRetryable }));
    });

    const error = await rejection(applicationAudit(INPUT));

    expect(error).toBeInstanceOf(ApplicationFailure);
    const failure = error as ApplicationFailure;
    expect(failure.type).toBe(type);
    expect(failure.nonRetryable).toBe(nonRetryable);
    expect(failure.details?.[0]).toMatchObject({ outcome: 'incomplete', notPerformed: [{ scanner: 'source', status: 'failed', cause }] });
    expect(act('generateReport')).not.toHaveBeenCalled();
    for (const scanner of SCANNERS) expect(act(ACTIVITY[scanner])).not.toHaveBeenCalled();
    expect(act('detectTechStack')).not.toHaveBeenCalled();
    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
    expect(harness.calls.indexOf('cleanupRun')).toBeGreaterThan(harness.calls.indexOf('fetchSource'));
  });

  it('maps an invalid repository URL to SourceUnavailableError', async () => {
    harness.activities.fetchSource = vi.fn(async () => {
      throw activityFailure(ApplicationFailure.create({ type: 'InvalidRepoError', message: 'invalid repository URL', nonRetryable: true }));
    });

    const failure = (await rejection(applicationAudit(INPUT))) as ApplicationFailure;

    expect(failure.type).toBe('SourceUnavailableError');
    expect(act('generateReport')).not.toHaveBeenCalled();
  });

  it('keeps the source failure when cleanup also fails', async () => {
    harness.activities.fetchSource = vi.fn(async () => {
      throw activityFailure(ApplicationFailure.create({ type: 'SourceUnavailableError', message: 'gone', nonRetryable: true }));
    });
    harness.activities.cleanupRun = vi.fn(async () => {
      throw new Error('cleanup failed');
    });

    const failure = (await rejection(applicationAudit(INPUT))) as ApplicationFailure;

    expect(failure.type).toBe('SourceUnavailableError');
  });

  it('propagates cancellation during the fetch unchanged', async () => {
    const cancelled = new CancelledFailure('cancelled');
    harness.activities.fetchSource = vi.fn(async () => {
      throw cancelled;
    });

    expect(await rejection(applicationAudit(INPUT))).toBe(cancelled);
    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
  });
});

describe('applicationAudit cleanup (principle VIII)', () => {
  it('removes the work dir once on the success path, before the report', async () => {
    await applicationAudit(INPUT);
    expect(act('cleanupRun')).toHaveBeenCalledTimes(1);
    expect(harness.calls.indexOf('cleanupRun')).toBeLessThan(harness.calls.indexOf('generateReport'));
  });

  it.each(['detectTechStack', 'mapToCompliance', 'generateReport'])('removes the work dir when %s fails', async (name) => {
    harness.activities[name] = vi.fn(async () => {
      throw activityFailure(new Error(`${name} failed`));
    });

    await rejection(applicationAudit(INPUT));

    expect(act('cleanupRun')).toHaveBeenCalledWith(RUN);
  });

  it('fails the audit when the work dir cannot be removed on the success path', async () => {
    harness.activities.cleanupRun = vi.fn(async () => {
      throw activityFailure(new Error('cleanupRun: refusing'));
    });

    const error = await rejection(applicationAudit(INPUT));

    expect(error).toBeInstanceOf(ActivityFailure);
    expect(act('cleanupRun')).toHaveBeenCalledTimes(1);
    expect(act('generateReport')).not.toHaveBeenCalled();
  });

  it('does not call cleanupRun when the run could not be initialised', async () => {
    harness.activities.initAuditRun = vi.fn(async () => {
      throw activityFailure(new Error('init failed'));
    });

    await rejection(applicationAudit(INPUT));

    expect(act('cleanupRun')).not.toHaveBeenCalled();
    expect(act('fetchSource')).not.toHaveBeenCalled();
  });
});

describe('applicationAudit result shape', () => {
  it('extends AuditResult additively and keeps raw output out of it', async () => {
    const result: AuditResult = await applicationAudit(INPUT);
    expect(Object.keys(result).sort()).toEqual(
      ['complianceMap', 'duration', 'endTime', 'evidencePath', 'findings', 'notPerformed', 'outcome', 'reportPath', 'scanners', 'source', 'startTime', 'status'].sort(),
    );
  });
});
