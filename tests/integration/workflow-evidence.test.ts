import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { RetryState } from '@temporalio/common';
import { ActivityFailure, ApplicationFailure } from '@temporalio/workflow';
import type { AuditRun, FetchedSource } from '../../src/scan/lifecycle';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../src/scan/tool-types';
import type { AuditInput, AuditResult } from '../../src/types';
import type { EvidenceManifest } from '../../src/evidence/types';

type Fn = (...args: unknown[]) => unknown;

const harness = vi.hoisted(() => ({ activities: {} as Record<string, Fn> }));

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
              const impl = harness.activities[name];
              if (impl === undefined) throw new Error(`unexpected activity ${name}`);
              return impl(...args);
            },
        },
      ),
    workflowInfo: () => ({ workflowId: 'wf-evidence', runId: 'run-evidence' }),
    setHandler: () => undefined,
    condition: async (fn: () => boolean) => fn(),
  };
});

vi.mock('@temporalio/activity', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@temporalio/activity')>();
  return { ...actual, Context: { current: () => ({ info: { attempt: 1 } }) } };
});

const { applicationAudit } = await import('../../src/workflows/index');
const { createScanActivities } = await import('../../src/scan/activities');
const lifecycle = await import('../../src/scan/lifecycle');
const { createEvidenceStore } = await import('../../src/evidence/store');
const { verifyEvidenceBundle } = await import('../../src/evidence/verify');
const { generateReport } = await import('../../src/activities/index');
const { generateSigningKey } = await import('../../src/evidence/sign');

const T0 = new Date('2026-01-01T00:00:00.000Z');
const REPO_URL = 'https://github.com/acme/app';
const REVISION = 'c'.repeat(40);
const RUN_ID = 'run-evidence';
const INPUT: AuditInput = { repoUrl: REPO_URL, skipApproval: true };
const FIXTURES = path.resolve(__dirname, '../fixtures/tools');

function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return { exitCode: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutTruncated: false, timedOut: false, startedAt: T0, endedAt: T0, ...partial };
}

async function fixture(name: string): Promise<ProcessOutcome> {
  const f = JSON.parse(await readFile(path.join(FIXTURES, name), 'utf8')) as { exitCode: number; stdout: string; stderr: string };
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

let tmpRoot: string;
let evidenceRoot: string;
let outDir: string;
let cloneFails: boolean;

async function runner(): Promise<ProcessRunner> {
  const tools: Record<string, ProcessOutcome> = {
    gitleaks: await fixture('gitleaks-leak.json'),
    semgrep: await fixture('semgrep-clean.json'),
    npm: await fixture('npm-audit-clean.json'),
  };
  return async (req: ProcessRequest) => {
    if (req.args.length === 1 && (req.args[0] === 'version' || req.args[0] === '--version')) return outcome({ stdout: Buffer.from('1.2.3\n') });
    if (req.file === 'git' && req.args.includes('clone')) {
      if (cloneFails) return outcome({ exitCode: 128, stderr: Buffer.from("fatal: repository 'https://github.com/acme/app/' not found\n") });
      const repoDir = req.args[req.args.length - 1];
      await mkdir(repoDir, { recursive: true, mode: 0o700 });
      await writeFile(path.join(repoDir, 'package.json'), '{"name":"app","version":"1.0.0"}');
      await writeFile(
        path.join(repoDir, 'package-lock.json'),
        JSON.stringify({ name: 'app', lockfileVersion: 3, packages: { '': { name: 'app', version: '1.0.0' }, 'node_modules/left-pad': { version: '1.3.0', license: 'MIT' } } }),
      );
      return outcome();
    }
    if (req.file === 'git' && req.args.includes('rev-parse')) return outcome({ stdout: Buffer.from(`${REVISION}\n`) });
    const result = tools[req.file];
    if (result === undefined) throw new Error(`unexpected tool ${req.file}`);
    return result;
  };
}

async function wire(signingKeyPath?: string): Promise<void> {
  const run = await runner();
  const scans = createScanActivities({
    signingKeyPath,
    runner: run,
    clock: () => T0,
    evidenceRoot,
    tmpRoot,
    frameworkVersion: '0.0.0-it',
    workerEnv: { PATH: '/usr/bin' },
    configDir: '/opt/tessera/config/scanners',
  });
  harness.activities = {
    initAuditRun: async () => lifecycle.initAuditRun({ workflowId: 'wf-evidence', temporalRunId: RUN_ID, tmpRoot }),
    fetchSource: async (auditRun: unknown, repoUrl: unknown): Promise<FetchedSource> => {
      try {
        return await lifecycle.fetchSource(auditRun as AuditRun, repoUrl as string, {
          runner: run,
          store: createEvidenceStore(evidenceRoot, RUN_ID),
          clock: () => T0,
          frameworkVersion: '0.0.0-it',
          tmpRoot,
        });
      } catch (error) {
        if (error instanceof lifecycle.SourceFetchFailure) {
          throw new ActivityFailure(
            'Activity task failed',
            'fetchSource',
            '1',
            RetryState.NON_RETRYABLE_FAILURE,
            'worker',
            ApplicationFailure.create({
              type: 'SourceUnavailableError',
              message: error.message,
              nonRetryable: true,
              details: [{ evidenceRecordIds: error.evidenceRecordIds }],
            }),
          );
        }
        throw error;
      }
    },
    detectTechStack: async () => ({ language: 'nodejs', frameworks: ['Express'], hasPayments: false, hasPII: false, packageManager: 'npm' }),
    generateScopeDocument: async () => ({ repoUrl: REPO_URL, techStack: {}, securityLevel: 1, frameworks: ['OWASP-ASVS'], inScope: [], outOfScope: [], createdAt: new Date(0) }),
    runGitleaks: scans.runGitleaks as Fn,
    runSemgrep: scans.runSemgrep as Fn,
    runNpmAudit: scans.runNpmAudit as Fn,
    runLicenseCheck: scans.runLicenseCheck as Fn,
    reviewCriticalPaths: async () => [],
    mapToCompliance: async () => [],
    crossValidate: async () => ({ falsePositives: [], severityCorrections: [], missingFindings: [], reviewNotes: '' }),
    generateReport: (async (input: Parameters<typeof generateReport>[0]) => generateReport({ ...input, outputDir: outDir })) as Fn,
    cleanupRun: async (auditRun: unknown) => lifecycle.cleanupRun(auditRun as AuditRun, tmpRoot),
    sealEvidence: scans.sealEvidence as Fn,
    signEvidence: scans.signEvidence as Fn,
  };
}

const bundle = (): string => path.join(evidenceRoot, RUN_ID);
const manifestOf = async (): Promise<EvidenceManifest> => JSON.parse(await readFile(path.join(bundle(), 'manifest.json'), 'utf8')) as EvidenceManifest;

beforeEach(async () => {
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-wfe-'));
  evidenceRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-wfe-ev-'));
  outDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-wfe-out-'));
  cloneFails = false;
  await wire();
});

afterEach(async () => {
  await chmod(bundle(), 0o700).catch(() => undefined);
  for (const dir of [tmpRoot, evidenceRoot, outDir]) await rm(dir, { recursive: true, force: true });
});

describe('applicationAudit with real evidence activities (FR-009, FR-015, FR-017)', () => {
  it('seals one bundle with source and scan evidence, returns the root hash and prints it in the report', async () => {
    const result: AuditResult = await applicationAudit(INPUT);

    expect(result.evidence?.bundlePath).toBe(bundle());
    expect(result.evidence?.rootHash).toMatch(/^[0-9a-f]{64}$/);
    const rootHash = result.evidence?.rootHash as string;
    const report = await verifyEvidenceBundle(bundle(), { expectRootHash: rootHash });
    expect(report.issues).toEqual([]);
    expect(report.ok).toBe(true);

    const m = await manifestOf();
    const records = m.entries.filter((e) => e.kind === 'record');
    expect(result.evidence?.recordCount).toBe(records.length);
    expect(records.map((e) => e.recordId)).toEqual(
      expect.arrayContaining(['source.clone.a1', 'source.revision.a1', 'scan.gitleaks.a1', 'scan.semgrep.a1', 'scan.npm-audit.a1']),
    );
    expect(records.every((e) => e.used)).toBe(true);
    expect(m.source).toEqual({ repoUrl: REPO_URL, revision: REVISION });
    for (const r of records) {
      expect(JSON.parse(await readFile(path.join(bundle(), r.path), 'utf8')).runId).toBe(RUN_ID);
    }

    const text = await readFile(result.reportPath, 'utf8');
    const lines = text.split('\n');
    const revisionAt = lines.indexOf(`Source revision: ${REVISION}`);
    expect(revisionAt).toBeGreaterThan(-1);
    expect(lines.indexOf(`Evidence bundle: ${bundle()}`)).toBeGreaterThan(revisionAt);
    expect(lines).toContain(`Evidence root hash: ${rootHash}`);
    expect(lines).toContain(`Verify: npm run evidence:verify -- ${bundle()} --expect-root ${rootHash}`);
    expect(lines).toContain('Integrity: hashes only; the manifest is not signed');
    expect(lines).toContain('Signature: none');
    expect(lines).toContain('Assurance level: 0');
    expect(result.signature).toEqual({ signed: false, level: 0 });
    expect(text).toContain('`sha256sum -c SHA256SUMS`');
  });

  it('keeps an audit without a required signature complete and says Signature: none when the signing activity throws', async () => {
    harness.activities.signEvidence = async () => {
      throw new Error('worker lost');
    };

    const result: AuditResult = await applicationAudit(INPUT);

    expect(result.outcome).toBe('complete');
    expect(result.signature).toEqual({ signed: false, level: 0 });
    const lines = (await readFile(result.reportPath, 'utf8')).split('\n');
    expect(lines).toContain('Signature: none');
    expect(lines).toContain('Assurance level: 0');
    expect(lines[0]).toBe('Audit outcome: COMPLETE');
  });

  it('TS-036 ends incomplete when a signing key is configured but the signing activity throws', async () => {
    const keyDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-wfe-key-'));
    try {
      const keyPath = path.join(keyDir, 'signing', 'ed25519.pem');
      await generateSigningKey(keyPath);
      await wire(keyPath);
      harness.activities.signEvidence = async () => {
        throw new Error('worker lost');
      };

      const result: AuditResult = await applicationAudit(INPUT);

      expect(result.outcome).toBe('incomplete');
      expect(result.notPerformed).toEqual([expect.objectContaining({ scanner: 'evidence', status: 'unavailable', cause: 'unsigned' })]);
      expect(result.signature).toEqual({ signed: false, level: 0 });
      const lines = (await readFile(result.reportPath, 'utf8')).split('\n');
      expect(lines[0]).toBe('Audit outcome: INCOMPLETE');
      expect(lines).toContain('Signature: none');
      expect(lines).toContain('Assurance level: 0');
    } finally {
      await rm(keyDir, { recursive: true, force: true });
    }
  });

  it('TS-031 TS-034 signs the sealed bundle with a configured key, verifies with the public key and states the limits in the report', async () => {
    const keyDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-wfe-key-'));
    try {
      const keyPath = path.join(keyDir, 'signing', 'ed25519.pem');
      const { keyId } = await generateSigningKey(keyPath);
      await wire(keyPath);

      const result: AuditResult = await applicationAudit(INPUT);

      expect(result.outcome).toBe('complete');
      expect(result.signature).toEqual({ signed: true, keyId, signedAt: T0.toISOString(), level: 1 });
      const verified = await verifyEvidenceBundle(bundle(), { expectRootHash: result.evidence?.rootHash, trustedKeys: [`${keyPath}.pub`] });
      expect(verified.ok).toBe(true);
      expect(verified.signature).toEqual({ status: 'valid', keyId, signedAt: T0.toISOString(), timeAttested: false });
      const lines = (await readFile(result.reportPath, 'utf8')).split('\n');
      expect(lines).toContain('Integrity: hashes and a signed manifest');
      expect(lines).not.toContain('Integrity: hashes only; the manifest is not signed');
      expect(lines).toContain(`Signature: valid, key ${keyId}, signed ${T0.toISOString()} (signing time is not independently attested)`);
      expect(lines).toContain('Assurance level: 1');
      const body = (await readFile(keyPath, 'utf8')).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      expect(lines.join('\n')).not.toContain(body);
    } finally {
      await rm(keyDir, { recursive: true, force: true });
    }
  });

  it('leaves a sealed, verifiable bundle after a source failure and names it in the failure details', async () => {
    cloneFails = true;
    await wire();

    const error = await applicationAudit(INPUT).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(ApplicationFailure);
    const failure = error as ApplicationFailure;
    expect(failure.type).toBe('SourceUnavailableError');
    const details = failure.details?.[0] as { outcome: string; evidence: { bundlePath: string; rootHash: string } };
    expect(details.outcome).toBe('incomplete');
    expect(details.evidence.bundlePath).toBe(bundle());
    const report = await verifyEvidenceBundle(details.evidence.bundlePath, { expectRootHash: details.evidence.rootHash });
    expect(report.ok).toBe(true);
    const m = await manifestOf();
    expect(m.source.revision).toBeNull();
    expect(m.entries.filter((e) => e.kind === 'record').map((e) => [e.recordId, e.used])).toEqual([['source.clone.a1', true]]);
  });
});
