// Contract: activity signatures and workflow result (FR-001..FR-008, FR-015, FR-016)
// Target modules: src/activities/run-lifecycle.ts, src/activities/scans.ts, src/types/index.ts, src/workflows/index.ts
// Rule for every activity below: inputs and results contain references, hashes, statuses and sanitized
// findings only. Raw tool output never enters the Temporal history (FR-012).

import type { Finding, AuditResult, TechStack } from '../../../src/types';
import type { ScannerId, ScannerStatusEntry, AuditOutcome, NotPerformed } from './scanner-status';
import type { EvidenceRef } from './evidence-record';
import type { SealEvidenceInput, SealEvidenceResult } from './evidence-manifest';
import type { ProcessRunner } from './run-tool';

export interface RunContext {
  runId: string;            // `${workflowId}/${temporalRunId}`
  workflowId: string;
  temporalRunId: string;
  repoUrl: string;
  workDir: string;          // <os.tmpdir()>/tessera-<temporalRunId>, 0700, removed by cleanupRun on every exit path
  bundleDir: string;        // <EVIDENCE_ROOT>/<workflowSlug>-<temporalRunId>, 0700, never removed by the framework
}

export interface SourceRef {
  repoPath: string;         // <workDir>/repo
  revision: string;         // full commit hash from `git rev-parse HEAD` (FR-008)
  evidence: EvidenceRef[];  // source.clone, source.revision, source.probe
  manifests: { packageJson: boolean; lockfile: 'package-lock.json' | 'npm-shrinkwrap.json' | 'yarn.lock' | 'pnpm-lock.yaml' | null };
}

export interface ScanStepResult {
  scanner: ScannerId;
  status: ScannerStatusEntry;
  findings: Finding[];      // sanitized, each with evidenceRef; capped at 2000 (overflow -> partial/findings-truncated)
  evidence: EvidenceRef;
}

// Created once per run; idempotent on retry (same temporalRunId -> same directories, verified with lstat).
export type InitAuditRun = (input: { workflowId: string; temporalRunId: string; repoUrl: string }) => Promise<RunContext>;

// Clone (array args, GIT_TERMINAL_PROMPT=0, timeout), rev-parse, probe and neutralize scanner control files.
// Throws ApplicationFailure 'SourceUnavailableError' (non-retryable) for invalid/not-found/auth,
// retryable 'TransientSourceError' for network causes. Evidence is written before throwing.
export type FetchSource = (run: RunContext) => Promise<SourceRef>;

// Scan activities: never throw for tool problems (status carries them); throw retryable only for transient network causes.
export type RunNpmAudit = (run: RunContext, source: SourceRef) => Promise<ScanStepResult>;
export type RunGitleaks = (run: RunContext, source: SourceRef) => Promise<ScanStepResult>;
export type RunSemgrep = (run: RunContext, source: SourceRef) => Promise<ScanStepResult>;
export type RunLicenseCheck = (run: RunContext, source: SourceRef) => Promise<ScanStepResult>;
export type ReviewCriticalPaths = (run: RunContext, source: SourceRef, criticalPaths: string[], checklist: string) => Promise<ScanStepResult>;

export type SealEvidence = (run: RunContext, input: SealEvidenceInput) => Promise<SealEvidenceResult>;

// Removes run.workDir only; refuses any path outside os.tmpdir()/tessera-*; never touches bundleDir.
export type CleanupRun = (run: RunContext) => Promise<void>;

// Factory used by the worker (default deps) and by hermetic tests (fake runner, fixed clock, tmp evidence root).
export interface ScanActivityDeps {
  runner: ProcessRunner;
  clock: () => Date;
  evidenceRoot: string;     // env TESSERA_EVIDENCE_ROOT
  tmpRoot: string;          // os.tmpdir()
  frameworkVersion: string;
  workerEnv: Readonly<Record<string, string | undefined>>;
}
export type CreateScanActivities = (deps: ScanActivityDeps) => {
  initAuditRun: InitAuditRun;
  fetchSource: FetchSource;
  runNpmAudit: RunNpmAudit;
  runGitleaks: RunGitleaks;
  runSemgrep: RunSemgrep;
  runLicenseCheck: RunLicenseCheck;
  reviewCriticalPaths: ReviewCriticalPaths;
  sealEvidence: SealEvidence;
  cleanupRun: CleanupRun;
};

// Additive extension of AuditResult (existing fields keep their names; evidencePath now points at the bundle).
export interface AuditResultExtension {
  outcome: AuditOutcome;
  notPerformed: NotPerformed[];
  scanners: ScannerStatusEntry[];
  source: { repoUrl: string; revision: string | null };
  evidence: { bundlePath: string; rootHash: string; recordCount: number };
}
export type AuditResultV2 = AuditResult & AuditResultExtension;

// Report input extension for generateReport (FR-016): outcome block and scanner table are rendered first.
export interface ReportInputExtension {
  outcome: AuditOutcome;
  notPerformed: NotPerformed[];
  scanners: ScannerStatusEntry[];
  source: { repoUrl: string; revision: string | null };
  evidence: { bundlePath: string; rootHash: string };
  techStack: TechStack;
}
