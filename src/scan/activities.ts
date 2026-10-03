import path from 'node:path';
import { ApplicationFailure, Context } from '@temporalio/activity';
import { createEvidenceStore } from '../evidence/store';
import type { EvidenceRef, EvidenceStore } from '../evidence/types';
import type { AuditRun, FetchedSource } from './lifecycle';
import { validateRepoUrl } from './repo-url';
import type { ScanContext, ScanStep, ScanStepResult } from './scan-types';
import type { ScannerId, ScannerStatusEntry } from './status';
import type { ProcessRunner } from './tool-types';
import { runGitleaksScan } from './tools/gitleaks';
import { runLicenseScan } from './tools/licenses';
import { runNpmAuditScan } from './tools/npm-audit';
import { runSemgrepScan } from './tools/semgrep';

export interface ScanActivityDeps {
  runner: ProcessRunner;
  clock: () => Date;
  evidenceRoot: string;
  tmpRoot: string;
  frameworkVersion: string;
  workerEnv: Readonly<Record<string, string | undefined>>;
  configDir: string;
}

export type ScanActivity = (run: AuditRun, source: FetchedSource, repoUrl: string) => Promise<ScanStepResult>;

export interface ScanActivities {
  runGitleaks: ScanActivity;
  runSemgrep: ScanActivity;
  runNpmAudit: ScanActivity;
  runLicenseCheck: ScanActivity;
}

const RUN_ID = /^[A-Za-z0-9_-]{1,128}$/;
const REVISION = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const STORE_PREFIX = 'evidence store:';

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function invalidRun(message: string): ApplicationFailure {
  return ApplicationFailure.create({ type: 'InvalidRunError', message: `scan activity: ${message}`, nonRetryable: true });
}

function storeFailure(scanner: ScannerId, message: string, nonRetryable: boolean): ApplicationFailure {
  return ApplicationFailure.create({ type: 'EvidenceStoreError', message: `${scanner}: ${message}`, nonRetryable });
}

function trustedRun(run: AuditRun, source: FetchedSource, tmpRoot: string): { run: AuditRun; source: FetchedSource } {
  if (typeof run?.runId !== 'string' || !RUN_ID.test(run.runId)) throw invalidRun('invalid runId');
  if (typeof tmpRoot !== 'string' || !path.isAbsolute(tmpRoot)) throw invalidRun('tmpRoot must be an absolute path');
  const workDir = path.join(path.resolve(tmpRoot), `tessera-${run.runId}`);
  const repoDir = path.join(workDir, 'repo');
  if (run.workDir !== workDir || run.repoDir !== repoDir || source?.repoDir !== repoDir) {
    throw invalidRun('run and source paths do not match <tmp>/tessera-<runId>/repo');
  }
  if (typeof source.revision !== 'string' || !REVISION.test(source.revision)) throw invalidRun('invalid source revision');
  return { run: { runId: run.runId, workDir, repoDir }, source: { repoDir, revision: source.revision } };
}

function evidenceStoreFor(scanner: ScannerId, deps: ScanActivityDeps, run: AuditRun): EvidenceStore {
  if (typeof deps.evidenceRoot !== 'string' || !path.isAbsolute(deps.evidenceRoot)) {
    throw storeFailure(scanner, 'evidence root must be an absolute path', true);
  }
  const root = path.resolve(deps.evidenceRoot);
  if (isInside(run.workDir, root) || isInside(root, run.workDir)) {
    throw storeFailure(scanner, 'evidence root must not overlap the work dir', true);
  }
  return createEvidenceStore(root, run.runId);
}

function statusEntry(entry: ScannerStatusEntry): ScannerStatusEntry {
  const clean: ScannerStatusEntry = {
    scanner: entry.scanner,
    required: entry.required,
    status: entry.status,
    heuristic: entry.heuristic,
    toolVersion: entry.toolVersion,
    findingCount: entry.findingCount,
    evidenceRecordIds: [...entry.evidenceRecordIds],
  };
  if (entry.cause !== undefined) clean.cause = entry.cause;
  if (entry.causeDetail !== undefined) clean.causeDetail = entry.causeDetail;
  return clean;
}

function evidenceRef(ref: EvidenceRef): EvidenceRef {
  const clean: EvidenceRef = { recordId: ref.recordId, recordSha256: ref.recordSha256 };
  if (ref.locator !== undefined) clean.locator = ref.locator;
  return clean;
}

function stepFailure(scanner: ScannerId, error: unknown): ApplicationFailure {
  const message = error instanceof Error ? error.message : '';
  return message.startsWith(STORE_PREFIX)
    ? storeFailure(scanner, message, false)
    : storeFailure(scanner, 'scan step could not be completed or recorded', false);
}

function scanActivity(scanner: ScannerId, step: ScanStep, deps: ScanActivityDeps): ScanActivity {
  return async (run, source, repoUrl) => {
    const trusted = trustedRun(run, source, deps.tmpRoot);
    validateRepoUrl(repoUrl);
    const store = evidenceStoreFor(scanner, deps, trusted.run);
    const ctx: ScanContext = {
      run: trusted.run,
      source: trusted.source,
      repoUrl,
      attempt: Context.current().info.attempt,
      deps: { runner: deps.runner, store, clock: deps.clock, frameworkVersion: deps.frameworkVersion },
      workerEnv: deps.workerEnv,
      configDir: deps.configDir,
    };
    let result: ScanStepResult;
    try {
      result = await step(ctx);
    } catch (error) {
      throw stepFailure(scanner, error);
    }
    return { scanner: result.scanner, status: statusEntry(result.status), findings: result.findings, evidence: evidenceRef(result.evidence) };
  };
}

export function createScanActivities(deps: ScanActivityDeps): ScanActivities {
  return {
    runGitleaks: scanActivity('gitleaks', runGitleaksScan, deps),
    runSemgrep: scanActivity('semgrep', runSemgrepScan, deps),
    runNpmAudit: scanActivity('npm-audit', runNpmAuditScan, deps),
    runLicenseCheck: scanActivity('license-check', runLicenseScan, deps),
  };
}
