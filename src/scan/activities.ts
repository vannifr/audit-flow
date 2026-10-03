import { lstat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { ApplicationFailure, Context } from '@temporalio/activity';
import { openSealedBundle, sealEvidenceBundle } from '../evidence/manifest';
import type { SealEvidenceResult } from '../evidence/manifest';
import { computeAssuranceLevel, signEvidenceBundle, verifyBundleSignature } from '../evidence/sign';
import type { AssuranceLevel } from '../evidence/sign';
import { createEvidenceStore } from '../evidence/store';
import { verifyEvidenceBundle } from '../evidence/verify';
import type { EvidenceRef, EvidenceStore } from '../evidence/types';
import type { AuditRun, FetchedSource } from './lifecycle';
import { validateRepoUrl } from './repo-url';
import { sanitizeOverrideAttempts } from './source-probe';
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
  signingKeyPath?: string | null;
  requireSignature?: boolean;
}

export type ScanActivity = (run: AuditRun, source: FetchedSource, repoUrl: string) => Promise<ScanStepResult>;

export interface SealEvidenceActivityInput {
  run: AuditRun;
  source: FetchedSource | null;
  repoUrl: string;
  usedRecordIds: string[];
  workflowId?: string;
}

export interface SealEvidenceActivityResult extends SealEvidenceResult {
  signatureRequired: boolean;
}

export type SealEvidenceActivity = (input: SealEvidenceActivityInput) => Promise<SealEvidenceActivityResult>;

export interface SignEvidenceActivityInput {
  run: AuditRun;
  rootHash: string;
}

export interface SignEvidenceResult {
  signed: boolean;
  required: boolean;
  keyId?: string;
  signedAt?: string;
  level: AssuranceLevel;
  detail?: string;
}

export type SignEvidenceActivity = (input: SignEvidenceActivityInput) => Promise<SignEvidenceResult>;

export interface ScanActivities {
  runGitleaks: ScanActivity;
  runSemgrep: ScanActivity;
  runNpmAudit: ScanActivity;
  runLicenseCheck: ScanActivity;
  sealEvidence: SealEvidenceActivity;
  signEvidence: SignEvidenceActivity;
}

const RUN_ID = /^[A-Za-z0-9_-]{1,128}$/;
const WORKFLOW_ID = /^[A-Za-z0-9_-]{1,255}$/;
const RECORD_ID = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$/;
const SEAL_PREFIX = 'evidence seal:';
const REVISION = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const STORE_PREFIX = 'evidence store:';
const SIGN_PREFIX = 'evidence sign:';
const HEX64 = /^[0-9a-f]{64}$/;

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function invalidRun(message: string): ApplicationFailure {
  return ApplicationFailure.create({ type: 'InvalidRunError', message: `scan activity: ${message}`, nonRetryable: true });
}

function storeFailure(scanner: string, message: string, nonRetryable: boolean): ApplicationFailure {
  return ApplicationFailure.create({ type: 'EvidenceStoreError', message: `${scanner}: ${message}`, nonRetryable });
}

function trustedRunOnly(run: AuditRun, tmpRoot: string): AuditRun {
  if (typeof run?.runId !== 'string' || !RUN_ID.test(run.runId)) throw invalidRun('invalid runId');
  if (typeof tmpRoot !== 'string' || !path.isAbsolute(tmpRoot)) throw invalidRun('tmpRoot must be an absolute path');
  const workDir = path.join(path.resolve(tmpRoot), `tessera-${run.runId}`);
  const repoDir = path.join(workDir, 'repo');
  if (run.workDir !== workDir || run.repoDir !== repoDir) {
    throw invalidRun('run paths do not match <tmp>/tessera-<runId>/repo');
  }
  return { runId: run.runId, workDir, repoDir };
}

function trustedRun(run: AuditRun, source: FetchedSource, tmpRoot: string): { run: AuditRun; source: FetchedSource } {
  const { workDir, repoDir } = trustedRunOnly(run, tmpRoot);
  if (source?.repoDir !== repoDir) {
    throw invalidRun('run and source paths do not match <tmp>/tessera-<runId>/repo');
  }
  if (typeof source.revision !== 'string' || !REVISION.test(source.revision)) throw invalidRun('invalid source revision');
  const overrideAttempts = sanitizeOverrideAttempts(source.overrideAttempts);
  return { run: { runId: run.runId, workDir, repoDir }, source: { repoDir, revision: source.revision, overrideAttempts } };
}

function evidenceRootFor(label: string, deps: ScanActivityDeps, run: AuditRun): string {
  if (typeof deps.evidenceRoot !== 'string' || !path.isAbsolute(deps.evidenceRoot)) {
    throw storeFailure(label, 'evidence root must be an absolute path', true);
  }
  const root = path.resolve(deps.evidenceRoot);
  if (isInside(run.workDir, root) || isInside(root, run.workDir)) {
    throw storeFailure(label, 'evidence root must not overlap the work dir', true);
  }
  return root;
}

function evidenceStoreFor(scanner: ScannerId, deps: ScanActivityDeps, run: AuditRun): EvidenceStore {
  return createEvidenceStore(evidenceRootFor(scanner, deps, run), run.runId);
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
      overrideAttempts: trusted.source.overrideAttempts ?? [],
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

function sealFailure(error: unknown): ApplicationFailure {
  const message = error instanceof Error ? error.message : '';
  return message.startsWith(SEAL_PREFIX)
    ? ApplicationFailure.create({ type: 'EvidenceSealError', message, nonRetryable: true })
    : ApplicationFailure.create({ type: 'EvidenceSealError', message: 'evidence seal: bundle could not be sealed', nonRetryable: false });
}

function sealResult(result: SealEvidenceResult): SealEvidenceResult {
  return {
    bundlePath: result.bundlePath,
    rootHash: result.rootHash,
    recordCount: result.recordCount,
    artifactCount: result.artifactCount,
    abandonedCount: result.abandonedCount,
    selfVerified: result.selfVerified,
  };
}

async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function signatureRequired(deps: ScanActivityDeps): Promise<boolean> {
  if (deps.requireSignature === true) return true;
  return typeof deps.signingKeyPath === 'string' && deps.signingKeyPath.length > 0 && (await exists(path.resolve(deps.signingKeyPath)));
}

function sealActivity(deps: ScanActivityDeps): SealEvidenceActivity {
  const seal = sealBundleActivity(deps);
  return async (input) => {
    const result = await seal(input);
    return { ...result, signatureRequired: await signatureRequired(deps) };
  };
}

function sealBundleActivity(deps: ScanActivityDeps): (input: SealEvidenceActivityInput) => Promise<SealEvidenceResult> {
  return async (input) => {
    const run = trustedRunOnly(input?.run, deps.tmpRoot);
    validateRepoUrl(input.repoUrl);
    const revision = input.source === null || input.source === undefined ? null : input.source.revision;
    if (revision !== null && (typeof revision !== 'string' || !REVISION.test(revision))) throw invalidRun('invalid source revision');
    if (!Array.isArray(input.usedRecordIds) || !input.usedRecordIds.every((id) => typeof id === 'string' && RECORD_ID.test(id) && !id.includes('..'))) {
      throw invalidRun('invalid used record ids');
    }
    const workflowId = Context.current().info.workflowExecution?.workflowId ?? input.workflowId;
    if (typeof workflowId !== 'string' || !WORKFLOW_ID.test(workflowId)) throw invalidRun('invalid workflowId');
    const root = evidenceRootFor('seal', deps, run);
    const bundleDir = path.join(root, run.runId);
    try {
      await mkdir(root, { recursive: true, mode: 0o700 });
      await mkdir(bundleDir, { mode: 0o700 }).catch((err: unknown) => {
        if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
      });
      if (await exists(path.join(bundleDir, 'manifest.json'))) return sealResult(await openSealedBundle(bundleDir, run.runId));
      try {
        return sealResult(
          await sealEvidenceBundle({
            bundleDir,
            runId: run.runId,
            workflowId,
            temporalRunId: run.runId,
            source: { repoUrl: input.repoUrl, revision },
            frameworkVersion: deps.frameworkVersion,
            usedRecordIds: [...new Set(input.usedRecordIds)],
            clock: deps.clock,
          }),
        );
      } catch (error) {
        if (error instanceof Error && error.message.includes('already sealed')) return sealResult(await openSealedBundle(bundleDir, run.runId));
        throw error;
      }
    } catch (error) {
      throw sealFailure(error);
    }
  };
}

function unsignedResult(required: boolean, detail?: string): SignEvidenceResult {
  return detail === undefined ? { signed: false, required, level: 0 } : { signed: false, required, level: 0, detail };
}

function signFailureDetail(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  return message.startsWith(SIGN_PREFIX) ? message : 'evidence sign: the bundle could not be signed';
}

function signActivity(deps: ScanActivityDeps): SignEvidenceActivity {
  return async (input) => {
    const run = trustedRunOnly(input?.run, deps.tmpRoot);
    if (typeof input.rootHash !== 'string' || !HEX64.test(input.rootHash)) throw invalidRun('invalid root hash');
    const bundleDir = path.join(evidenceRootFor('sign', deps, run), run.runId);
    const configured = typeof deps.signingKeyPath === 'string' && deps.signingKeyPath.length > 0 ? path.resolve(deps.signingKeyPath) : null;
    const keyPresent = configured !== null && (await exists(configured));
    if (configured === null || !keyPresent) {
      return deps.requireSignature === true ? unsignedResult(true, 'no signing key is configured') : unsignedResult(false);
    }
    try {
      if (!(await exists(path.join(bundleDir, 'signature.json')))) {
        await signEvidenceBundle({ bundleDir, keyPath: configured, evidenceRoot: deps.evidenceRoot, clock: deps.clock });
      }
      const hashes = await verifyEvidenceBundle(bundleDir, { expectRootHash: input.rootHash });
      const sig = await verifyBundleSignature(bundleDir, { trustedKeys: [`${configured}.pub`] });
      const level = computeAssuranceLevel(hashes.hashesOk, sig);
      const result: SignEvidenceResult = { signed: sig.status !== 'unsigned', required: true, level };
      if (sig.keyId !== null) result.keyId = sig.keyId;
      if (sig.signedAt !== null) result.signedAt = sig.signedAt;
      if (level !== 1) result.detail = hashes.hashesOk ? `signature ${sig.status} against ${configured}.pub` : 'evidence bundle does not verify';
      return result;
    } catch (error) {
      return unsignedResult(true, signFailureDetail(error));
    }
  };
}

export function createScanActivities(deps: ScanActivityDeps): ScanActivities {
  return {
    runGitleaks: scanActivity('gitleaks', runGitleaksScan, deps),
    runSemgrep: scanActivity('semgrep', runSemgrepScan, deps),
    runNpmAudit: scanActivity('npm-audit', runNpmAuditScan, deps),
    runLicenseCheck: scanActivity('license-check', runLicenseScan, deps),
    sealEvidence: sealActivity(deps),
    signEvidence: signActivity(deps),
  };
}
