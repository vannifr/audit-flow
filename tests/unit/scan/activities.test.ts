import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ApplicationFailure } from '@temporalio/activity';
import { createScanActivities } from '../../../src/scan/activities';
import type { ScanActivityDeps } from '../../../src/scan/activities';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../../src/scan/tool-types';
import type { AuditRun, FetchedSource } from '../../../src/scan/lifecycle';
import { chmod, symlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { verifyEvidenceBundle } from '../../../src/evidence/verify';
import { generateSigningKey } from '../../../src/evidence/sign';
import type { EvidenceManifest } from '../../../src/evidence/types';

const attempt = vi.hoisted(() => ({ value: 1 }));

vi.mock('@temporalio/activity', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@temporalio/activity')>();
  return { ...actual, Context: { current: () => ({ info: { attempt: attempt.value } }) } };
});

const T0 = new Date('2026-01-01T00:00:00.000Z');
const REPO_URL = 'https://github.com/acme/app';
const REVISION = 'a'.repeat(40);
const RUN_ID = 'run-0001';
const PLANTED = 'AKIAZZPLANTEDSECRET99';
const FIXTURES = path.resolve(__dirname, '../../fixtures/tools');

interface Fixture {
  exitCode: number;
  stdout: string;
  stderr: string;
}

async function fixture(name: string): Promise<ProcessOutcome> {
  const f = JSON.parse(await readFile(path.join(FIXTURES, name), 'utf8')) as Fixture;
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    stdoutTruncated: false,
    timedOut: false,
    startedAt: T0,
    endedAt: T0,
    ...partial,
  };
}

let tmpRoot: string;
let evidenceRoot: string;
let run: AuditRun;
let source: FetchedSource;
let requests: ProcessRequest[];

function runnerFor(main: ProcessOutcome | ((req: ProcessRequest) => ProcessOutcome)): ProcessRunner {
  return async (req) => {
    requests.push(req);
    if (req.args.length === 1 && (req.args[0] === 'version' || req.args[0] === '--version')) {
      return outcome({ stdout: Buffer.from('1.2.3\n') });
    }
    return typeof main === 'function' ? main(req) : main;
  };
}

function deps(runner: ProcessRunner, overrides: Partial<ScanActivityDeps> = {}): ScanActivityDeps {
  return {
    runner,
    clock: () => T0,
    evidenceRoot,
    tmpRoot,
    frameworkVersion: '0.0.0-test',
    workerEnv: { PATH: '/usr/bin' },
    configDir: '/opt/tessera/config/scanners',
    ...overrides,
  };
}

async function writeRepo(files: Record<string, string>): Promise<void> {
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(run.repoDir, name), content);
  }
}

function lockfile(): string {
  return JSON.stringify({
    name: 'app',
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/left-pad': { version: '1.3.0', license: 'MIT' },
    },
  });
}

beforeEach(async () => {
  attempt.value = 1;
  requests = [];
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-act-'));
  evidenceRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-evroot-'));
  const workDir = path.join(tmpRoot, `tessera-${RUN_ID}`);
  run = { runId: RUN_ID, workDir, repoDir: path.join(workDir, 'repo') };
  source = { repoDir: run.repoDir, revision: REVISION };
  await mkdir(run.repoDir, { recursive: true, mode: 0o700 });
  await mkdir(path.join(workDir, 'home'), { mode: 0o700 });
  await mkdir(path.join(workDir, 'tmp'), { mode: 0o700 });
});

afterEach(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
  await rm(evidenceRoot, { recursive: true, force: true });
});

async function expectFailure(promise: Promise<unknown>, type: string, nonRetryable: boolean): Promise<ApplicationFailure> {
  const error = await promise.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(error).toBeInstanceOf(ApplicationFailure);
  const failure = error as ApplicationFailure;
  expect(failure.type).toBe(type);
  expect(failure.nonRetryable).toBe(nonRetryable);
  return failure;
}

describe('createScanActivities', () => {
  it('runs gitleaks with the framework config, records evidence under evidenceRoot/<runId> (0700) and uses the activity attempt', async () => {
    attempt.value = 3;
    const acts = createScanActivities(deps(runnerFor(await fixture('gitleaks-clean.json'))));
    const result = await acts.runGitleaks(run, source, REPO_URL);

    expect(result.scanner).toBe('gitleaks');
    expect(result.status.status).toBe('completed');
    expect(result.status.required).toBe(true);
    expect(result.status.evidenceRecordIds).toEqual(['scan.gitleaks.a3']);
    expect(result.evidence.recordId).toBe('scan.gitleaks.a3');
    const main = requests.find((r) => r.args.includes('dir'));
    expect(main?.args).toContain('/opt/tessera/config/scanners/gitleaks.toml');
    expect(main?.cwd).toBe(run.repoDir);

    const bundle = path.join(evidenceRoot, RUN_ID);
    expect((await stat(bundle)).mode & 0o777).toBe(0o700);
    expect(await readdir(path.join(bundle, 'records'))).toContain('scan.gitleaks.a3.json');
  });

  it('reports exit-because-issues-found as completed with findings that point at the step record (TS-004, FR-004, FR-007)', async () => {
    const acts = createScanActivities(deps(runnerFor(await fixture('gitleaks-leak.json'))));
    const result = await acts.runGitleaks(run, source, REPO_URL);

    expect(result.status.status).toBe('completed');
    expect(result.status.cause).toBe('issues-found');
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(result.status.evidenceRecordIds).toContain(finding.evidenceRef?.recordId);
    }
  });

  it('returns unavailable instead of throwing when the scanner is not installed (TS-001)', async () => {
    const missing = outcome({ exitCode: null, spawnErrorCode: 'ENOENT' });
    const acts = createScanActivities(deps(async (req) => {
      requests.push(req);
      return missing;
    }));
    const result = await acts.runSemgrep(run, source, REPO_URL);
    expect(result.scanner).toBe('semgrep');
    expect(result.status.status).toBe('unavailable');
    expect(result.status.required).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('returns failed instead of throwing when semgrep crashes (TS-002)', async () => {
    const acts = createScanActivities(deps(runnerFor(await fixture('semgrep-crash.json'))));
    const result = await acts.runSemgrep(run, source, REPO_URL);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBeDefined();
  });

  it('runs npm audit in the isolated directory and links every finding to its record', async () => {
    await writeRepo({ 'package.json': '{"name":"app"}', 'package-lock.json': lockfile() });
    const acts = createScanActivities(deps(runnerFor(await fixture('npm-audit-vulnerable.json'))));
    const result = await acts.runNpmAudit(run, source, REPO_URL);
    expect(result.scanner).toBe('npm-audit');
    expect(result.status.status).toBe('completed');
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(result.status.evidenceRecordIds).toContain(finding.evidenceRef?.recordId);
    }
    expect(requests.find((r) => r.args.includes('audit'))?.cwd.startsWith(run.workDir)).toBe(true);
  });

  it('marks npm audit and the license check as not required when the source has no package.json (R4)', async () => {
    await writeRepo({ 'README.md': 'hi' });
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const npm = await acts.runNpmAudit(run, source, REPO_URL);
    const licenses = await acts.runLicenseCheck(run, source, REPO_URL);
    for (const result of [npm, licenses]) {
      expect(result.status.status).toBe('skipped');
      expect(result.status.cause).toBe('not-applicable');
      expect(result.status.required).toBe(false);
    }
  });

  it('keeps the license check required when package.json has no lockfile', async () => {
    await writeRepo({ 'package.json': '{}' });
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const result = await acts.runLicenseCheck(run, source, REPO_URL);
    expect(result.status.status).toBe('skipped');
    expect(result.status.cause).toBe('no-lockfile');
    expect(result.status.required).toBe(true);
  });

  it('checks licenses in-process from the lockfile', async () => {
    await writeRepo({ 'package.json': '{"name":"app"}', 'package-lock.json': lockfile() });
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const result = await acts.runLicenseCheck(run, source, REPO_URL);
    expect(result.scanner).toBe('license-check');
    expect(result.status.status).toBe('completed');
    expect(requests).toEqual([]);
  });

  it('returns only structured, sanitized data: no raw tool output and only known status fields', async () => {
    const leak = JSON.stringify([
      { RuleID: 'aws-access-token', Description: 'AWS', StartLine: 1, EndLine: 1, Match: `key = ${PLANTED}`, Secret: PLANTED, File: 'a.js', Fingerprint: 'a.js:aws:1' },
    ]);
    const acts = createScanActivities(deps(runnerFor(outcome({ exitCode: 42, stdout: Buffer.from(leak), stderr: Buffer.from(`raw ${PLANTED}`) }))));
    const result = await acts.runGitleaks(run, source, REPO_URL);
    expect(result.findings).toHaveLength(1);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(PLANTED);
    expect(Object.keys(result).sort()).toEqual(['evidence', 'findings', 'scanner', 'status']);
    expect(Object.keys(result.status).every((k) =>
      ['scanner', 'required', 'status', 'cause', 'causeDetail', 'heuristic', 'toolVersion', 'findingCount', 'evidenceRecordIds'].includes(k),
    )).toBe(true);
    expect(Object.keys(result.evidence).every((k) => ['recordId', 'recordSha256', 'locator'].includes(k))).toBe(true);
  });

  it('refuses an evidence root inside the work dir (fail closed, non-retryable)', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome()), { evidenceRoot: path.join(run.workDir, 'evidence') }));
    await expectFailure(acts.runGitleaks(run, source, REPO_URL), 'EvidenceStoreError', true);
    expect(requests).toEqual([]);
  });

  it('refuses an evidence root that contains the work dir', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome()), { evidenceRoot: tmpRoot }));
    await expectFailure(acts.runSemgrep(run, source, REPO_URL), 'EvidenceStoreError', true);
    expect(requests).toEqual([]);
  });

  it('refuses a relative evidence root', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome()), { evidenceRoot: 'relative/evidence' }));
    await expectFailure(acts.runLicenseCheck(run, source, REPO_URL), 'EvidenceStoreError', true);
  });

  it('throws a retryable EvidenceStoreError when evidence cannot be written, without echoing tool output', async () => {
    const blocker = path.join(evidenceRoot, 'blocked');
    await writeFile(blocker, 'not a directory');
    const leak = JSON.stringify([{ RuleID: 'x', Description: 'x', StartLine: 1, EndLine: 1, Match: PLANTED, Secret: PLANTED, File: 'a.js', Fingerprint: 'f' }]);
    const acts = createScanActivities(deps(runnerFor(outcome({ exitCode: 42, stdout: Buffer.from(leak) })), { evidenceRoot: blocker }));
    const failure = await expectFailure(acts.runGitleaks(run, source, REPO_URL), 'EvidenceStoreError', false);
    expect(failure.message).not.toContain(PLANTED);
    expect(failure.message).toContain('gitleaks');
  });

  it('does not throw when the runner itself throws: the status carries the problem', async () => {
    const acts = createScanActivities(deps(async () => {
      throw new Error(`boom ${PLANTED}`);
    }));
    const result = await acts.runSemgrep(run, source, REPO_URL);
    expect(result.status.status).not.toBe('completed');
    expect(JSON.stringify(result)).not.toContain(PLANTED);
  });

  it('hides non-store step errors behind a generic message', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome()), {
      clock: () => {
        throw new Error(`boom ${PLANTED}`);
      },
    }));
    const failure = await expectFailure(acts.runSemgrep(run, source, REPO_URL), 'EvidenceStoreError', false);
    expect(failure.message).not.toContain(PLANTED);
    expect(failure.message).toContain('semgrep');
  });

  it.each([
    ['a run id with path characters', () => ({ run: { ...run, runId: '../x' }, source })],
    ['a work dir outside <tmpRoot>/tessera-<runId>', () => ({ run: { ...run, workDir: '/etc' }, source })],
    ['a repo dir outside the work dir', () => ({ run: { ...run, repoDir: '/etc' }, source })],
    ['a source dir that differs from the run repo dir', () => ({ run, source: { ...source, repoDir: tmpRoot } })],
    ['an invalid revision', () => ({ run, source: { ...source, revision: 'HEAD' } })],
  ])('rejects %s as a non-retryable InvalidRunError', async (_label, make) => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const { run: r, source: s } = make();
    await expectFailure(acts.runGitleaks(r, s, REPO_URL), 'InvalidRunError', true);
    expect(requests).toEqual([]);
  });

  it('rejects an invalid repository URL', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    await expectFailure(acts.runNpmAudit(run, source, 'https://evil.example/x;id'), 'InvalidRepoError', false);
  });
});

describe('worker-registered scan activities', () => {
  const saved = process.env.TESSERA_EVIDENCE_ROOT;

  afterEach(() => {
    if (saved === undefined) delete process.env.TESSERA_EVIDENCE_ROOT;
    else process.env.TESSERA_EVIDENCE_ROOT = saved;
  });

  it('exports runLicenseCheck with default deps: os.tmpdir() work dirs and TESSERA_EVIDENCE_ROOT', async () => {
    process.env.TESSERA_EVIDENCE_ROOT = evidenceRoot;
    const realTmp = os.tmpdir();
    const runId = `act-${process.pid}-${Date.now()}`;
    const workDir = path.join(realTmp, `tessera-${runId}`);
    const own: AuditRun = { runId, workDir, repoDir: path.join(workDir, 'repo') };
    await mkdir(own.repoDir, { recursive: true, mode: 0o700 });
    try {
      const activities = await import('../../../src/activities/index');
      const result = await activities.runLicenseCheck(own, { repoDir: own.repoDir, revision: REVISION }, REPO_URL);
      expect(result.status.status).toBe('skipped');
      expect(result.status.required).toBe(false);
      expect((await readdir(path.join(evidenceRoot, runId, 'records'))).filter((f) => f.endsWith('.json'))).toEqual(['license-check.a1.json']);
      expect(typeof activities.runGitleaks).toBe('function');
      expect(typeof activities.runSemgrep).toBe('function');
      expect(typeof activities.runNpmAudit).toBe('function');
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  });
});

describe('sealEvidence activity (FR-009, FR-015, FR-017)', () => {
  const bundle = (): string => path.join(evidenceRoot, RUN_ID);
  const manifestOf = async (): Promise<EvidenceManifest> =>
    JSON.parse(await readFile(path.join(bundle(), 'manifest.json'), 'utf8')) as EvidenceManifest;

  afterEach(async () => {
    await chmod(bundle(), 0o700).catch(() => undefined);
  });

  async function scanned(): Promise<ReturnType<typeof createScanActivities>> {
    const acts = createScanActivities(deps(runnerFor(await fixture('gitleaks-leak.json'))));
    await acts.runGitleaks(run, source, REPO_URL);
    return acts;
  }

  it('seals the run bundle under evidenceRoot/<runId>, verifies itself and marks used records', async () => {
    const acts = await scanned();
    const result = await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: ['scan.gitleaks.a1'], workflowId: 'wf-seal' });
    expect(result).toMatchObject({ bundlePath: bundle(), recordCount: 1, artifactCount: 2, abandonedCount: 0, selfVerified: true });
    expect(Object.keys(result).sort()).toEqual(['abandonedCount', 'artifactCount', 'bundlePath', 'recordCount', 'rootHash', 'selfVerified', 'signatureRequired']);
    expect(result.signatureRequired).toBe(false);
    const m = await manifestOf();
    expect(m.runId).toBe(RUN_ID);
    expect(m.temporalRunId).toBe(RUN_ID);
    expect(m.workflowId).toBe('wf-seal');
    expect(m.source).toEqual({ repoUrl: REPO_URL, revision: REVISION });
    expect(m.framework.version).toBe('0.0.0-test');
    expect(m.sealedAt).toBe(T0.toISOString());
    expect(m.rootHash).toBe(result.rootHash);
    expect(m.entries.every((e) => e.used)).toBe(true);
    const report = await verifyEvidenceBundle(bundle(), { expectRootHash: result.rootHash });
    expect(report.ok).toBe(true);
    expect((await stat(bundle())).mode & 0o777).toBe(0o500);
  });

  it('marks records the workflow did not use as used=false', async () => {
    const acts = await scanned();
    await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' });
    const m = await manifestOf();
    expect(m.entries.length).toBeGreaterThan(0);
    expect(m.entries.every((e) => e.used === false)).toBe(true);
  });

  it('is idempotent on a retry: the same result and a byte-identical manifest', async () => {
    const acts = await scanned();
    const first = await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: ['scan.gitleaks.a1'], workflowId: 'wf-seal' });
    const before = await readFile(path.join(bundle(), 'manifest.json'));
    const later = createScanActivities(deps(runnerFor(outcome()), { clock: () => new Date('2027-06-01T00:00:00.000Z') }));
    const second = await later.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: ['scan.gitleaks.a1'], workflowId: 'wf-seal' });
    expect(second).toEqual(first);
    expect((await readFile(path.join(bundle(), 'manifest.json'))).equals(before)).toBe(true);
  });

  it('finishes an interrupted seal: a leftover partial manifest is removed and the directory is locked', async () => {
    const acts = await scanned();
    const first = await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' });
    await chmod(bundle(), 0o700);
    await writeFile(path.join(bundle(), '.manifest.json.partial'), 'partial');
    const second = await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' });
    expect(second).toEqual(first);
    expect(await readdir(bundle())).not.toContain('.manifest.json.partial');
    expect((await stat(bundle())).mode & 0o777).toBe(0o500);
  });

  it('refuses a retry when the existing sealed bundle no longer verifies (non-retryable)', async () => {
    const acts = await scanned();
    await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' });
    await chmod(path.join(bundle(), 'records'), 0o700);
    const file = path.join(bundle(), 'records', 'scan.gitleaks.a1.json');
    await chmod(file, 0o600);
    await writeFile(file, '{"tampered":true}');
    const failure = await expectFailure(
      acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' }),
      'EvidenceSealError',
      true,
    );
    expect(failure.message).toMatch(/does not verify/);
  });

  it('seals a run without any evidence yet as an empty bundle whose root is the genesis hash', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const result = await acts.sealEvidence({ run, source: null, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' });
    expect(result.recordCount).toBe(0);
    expect(result.rootHash).toBe(createHash('sha256').update(`tessera:${RUN_ID}`).digest('hex'));
    expect((await manifestOf()).source).toEqual({ repoUrl: REPO_URL, revision: null });
  });

  it('refuses to seal when a used record is not in the bundle (non-retryable)', async () => {
    const acts = await scanned();
    const failure = await expectFailure(
      acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: ['scan.semgrep.a1'], workflowId: 'wf-seal' }),
      'EvidenceSealError',
      true,
    );
    expect(failure.message).toMatch(/scan\.semgrep\.a1/);
    await expect(stat(path.join(bundle(), 'manifest.json'))).rejects.toThrow();
  });

  it('refuses a bundle with a symlink (non-retryable) and writes no manifest', async () => {
    const acts = await scanned();
    await symlink('/etc/hostname', path.join(bundle(), 'artifacts', 'evil.txt'));
    await expectFailure(acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' }), 'EvidenceSealError', true);
    await expect(stat(path.join(bundle(), 'manifest.json'))).rejects.toThrow();
  });

  it.each([
    ['an invalid used record id', { usedRecordIds: ['../x'] }],
    ['a forged source revision', { source: { repoDir: '/x', revision: 'nope' } }],
    ['a missing workflow id', { workflowId: undefined }],
    ['a workflow id with path characters', { workflowId: 'a/b' }],
  ])('rejects %s as InvalidRunError', async (_name, override) => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const input = { run, source, repoUrl: REPO_URL, usedRecordIds: [] as string[], workflowId: 'wf-seal', ...override } as Parameters<typeof acts.sealEvidence>[0];
    await expectFailure(acts.sealEvidence(input), 'InvalidRunError', true);
  });

  it('rejects a run whose paths do not match the tmp root', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const forged = { ...run, workDir: '/etc' };
    await expectFailure(acts.sealEvidence({ run: forged, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' }), 'InvalidRunError', true);
  });

  it('refuses an evidence root that overlaps the work dir', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome()), { evidenceRoot: path.join(run.workDir, 'evidence') }));
    await expectFailure(acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' }), 'EvidenceStoreError', true);
  });

  it('maps an unexpected I/O problem to a retryable EvidenceSealError without echoing it', async () => {
    const blocker = path.join(evidenceRoot, 'file');
    await writeFile(blocker, 'x');
    const acts = createScanActivities(deps(runnerFor(outcome()), { evidenceRoot: path.join(blocker, 'sub') }));
    const failure = await expectFailure(acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-seal' }), 'EvidenceSealError', false);
    expect(failure.message).toBe('evidence seal: bundle could not be sealed');
  });
});

describe('signEvidence activity (FR-018, FR-020, TS-035, TS-036)', () => {
  const bundle = (): string => path.join(evidenceRoot, RUN_ID);
  let keyRoot: string;

  beforeEach(async () => {
    keyRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-signkey-'));
  });

  afterEach(async () => {
    await chmod(bundle(), 0o700).catch(() => undefined);
    await rm(keyRoot, { recursive: true, force: true });
  });

  async function sealed(overrides: Partial<ScanActivityDeps> = {}): Promise<{ acts: ReturnType<typeof createScanActivities>; rootHash: string }> {
    const acts = createScanActivities(deps(runnerFor(await fixture('gitleaks-leak.json')), overrides));
    await acts.runGitleaks(run, source, REPO_URL);
    const sealResult = await acts.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: ['scan.gitleaks.a1'], workflowId: 'wf-sign' });
    return { acts, rootHash: sealResult.rootHash };
  }

  it('signs the sealed bundle with the configured key and computes level 1 from a real verification', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    const { keyId } = await generateSigningKey(keyPath);
    const { acts, rootHash } = await sealed({ signingKeyPath: keyPath });
    const result = await acts.signEvidence({ run, rootHash });
    expect(result).toEqual({ signed: true, required: true, keyId, signedAt: T0.toISOString(), level: 1 });
    expect((await stat(path.join(bundle(), 'signature.json'))).mode & 0o777).toBe(0o400);
    expect((await stat(bundle())).mode & 0o777).toBe(0o500);
    const report = await verifyEvidenceBundle(bundle(), { expectRootHash: rootHash, trustedKeys: [`${keyPath}.pub`] });
    expect(report.ok).toBe(true);
    expect(report.signature.status).toBe('valid');
  });

  it('is idempotent on a retry after the signature was written', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    await generateSigningKey(keyPath);
    const { acts, rootHash } = await sealed({ signingKeyPath: keyPath });
    const first = await acts.signEvidence({ run, rootHash });
    const before = await readFile(path.join(bundle(), 'signature.json'));
    const later = createScanActivities(deps(runnerFor(outcome()), { signingKeyPath: keyPath, clock: () => new Date('2027-01-01T00:00:00.000Z') }));
    expect(await later.signEvidence({ run, rootHash })).toEqual(first);
    expect((await readFile(path.join(bundle(), 'signature.json'))).equals(before)).toBe(true);
  });

  it('gives an unsigned level 0 result when no key exists and no signature is required', async () => {
    const { acts, rootHash } = await sealed({ signingKeyPath: path.join(keyRoot, 'absent.pem') });
    expect(await acts.signEvidence({ run, rootHash })).toEqual({ signed: false, required: false, level: 0 });
    expect(await readdir(bundle())).not.toContain('signature.json');
    const none = await sealedAgain();
    expect(none).toEqual({ signed: false, required: false, level: 0 });
  });

  async function sealedAgain(): Promise<unknown> {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    const report = await verifyEvidenceBundle(bundle());
    return acts.signEvidence({ run, rootHash: report.rootHash as string });
  }

  it('TS-036 reports a required but missing signature with level 0', async () => {
    const { acts, rootHash } = await sealed({ signingKeyPath: path.join(keyRoot, 'absent.pem'), requireSignature: true });
    const result = await acts.signEvidence({ run, rootHash });
    expect(result).toMatchObject({ signed: false, required: true, level: 0 });
    expect(result.detail).toMatch(/no signing key/);
  });

  it('TS-035 refuses a key inside the evidence root with a clear cause and writes no signature', async () => {
    const inside = path.join(evidenceRoot, 'keys', 'ed25519.pem');
    await generateSigningKey(inside);
    const { acts, rootHash } = await sealed({ signingKeyPath: inside });
    const result = await acts.signEvidence({ run, rootHash });
    expect(result).toMatchObject({ signed: false, required: true, level: 0 });
    expect(result.detail).toMatch(/^evidence sign: refusing a signing key inside the evidence folder/);
    expect(await readdir(bundle())).not.toContain('signature.json');
    const body = (await readFile(inside, 'utf8')).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    expect(JSON.stringify(result)).not.toContain(body);
  });

  it('refuses a key file that group or others can read', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    await generateSigningKey(keyPath);
    await chmod(keyPath, 0o640);
    const { acts, rootHash } = await sealed({ signingKeyPath: keyPath });
    const result = await acts.signEvidence({ run, rootHash });
    expect(result).toMatchObject({ signed: false, required: true, level: 0 });
    expect(result.detail).toMatch(/group or others/);
  });

  it('gives level 0 when the published public key does not belong to the signing key', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    await generateSigningKey(keyPath);
    const other = path.join(keyRoot, 'other', 'k.pem');
    await generateSigningKey(other);
    await chmod(`${keyPath}.pub`, 0o600);
    await writeFile(`${keyPath}.pub`, await readFile(`${other}.pub`));
    const { acts, rootHash } = await sealed({ signingKeyPath: keyPath });
    const result = await acts.signEvidence({ run, rootHash });
    expect(result.signed).toBe(true);
    expect(result.level).toBe(0);
    expect(result.detail).toMatch(/unknown-key/);
  });

  it('gives level 0 when the bundle does not match the expected root hash', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    await generateSigningKey(keyPath);
    const { acts } = await sealed({ signingKeyPath: keyPath });
    const result = await acts.signEvidence({ run, rootHash: 'e'.repeat(64) });
    expect(result.level).toBe(0);
    expect(result.detail).toMatch(/does not verify/);
  });

  it('tells the workflow at seal time whether a signature is required', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    expect((await sealed({ signingKeyPath: path.join(keyRoot, 'absent.pem') })).acts).toBeDefined();
    const plain = createScanActivities(deps(runnerFor(outcome()), { signingKeyPath: path.join(keyRoot, 'absent.pem') }));
    expect((await plain.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-sign' })).signatureRequired).toBe(false);
    const demanded = createScanActivities(deps(runnerFor(outcome()), { signingKeyPath: path.join(keyRoot, 'absent.pem'), requireSignature: true }));
    expect((await demanded.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-sign' })).signatureRequired).toBe(true);
    await generateSigningKey(keyPath);
    const keyed = createScanActivities(deps(runnerFor(outcome()), { signingKeyPath: keyPath }));
    expect((await keyed.sealEvidence({ run, source, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-sign' })).signatureRequired).toBe(true);
  });

  it('refuses an invalid root hash as non-retryable input', async () => {
    const acts = createScanActivities(deps(runnerFor(outcome())));
    await expectFailure(acts.signEvidence({ run, rootHash: 'not-a-hash' }), 'InvalidRunError', true);
  });

  it('turns an unexpected signing error into a generic cause without internals', async () => {
    const keyPath = path.join(keyRoot, 'signing', 'ed25519.pem');
    await generateSigningKey(keyPath);
    const acts = createScanActivities(deps(runnerFor(outcome()), { signingKeyPath: keyPath }));
    const result = await acts.signEvidence({ run, rootHash: 'f'.repeat(64) });
    expect(result).toMatchObject({ signed: false, required: true, level: 0 });
    expect(result.detail).toMatch(/^evidence sign:/);
  });
});

describe('worker-registered signEvidence', () => {
  const saved = { root: process.env.TESSERA_EVIDENCE_ROOT, key: process.env.TESSERA_SIGNING_KEY, req: process.env.TESSERA_REQUIRE_SIGNATURE };
  let keyRoot: string;

  beforeEach(async () => {
    keyRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-wsign-'));
  });

  afterEach(async () => {
    for (const [name, value] of [['TESSERA_EVIDENCE_ROOT', saved.root], ['TESSERA_SIGNING_KEY', saved.key], ['TESSERA_REQUIRE_SIGNATURE', saved.req]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(keyRoot, { recursive: true, force: true });
  });

  async function sealedOwnRun(): Promise<{ own: AuditRun; workDir: string; rootHash: string; activities: typeof import('../../../src/activities/index') }> {
    process.env.TESSERA_EVIDENCE_ROOT = evidenceRoot;
    const runId = `sign-${process.pid}-${Date.now()}`;
    const workDir = path.join(os.tmpdir(), `tessera-${runId}`);
    const own: AuditRun = { runId, workDir, repoDir: path.join(workDir, 'repo') };
    const activities = await import('../../../src/activities/index');
    const sealResult = await activities.sealEvidence({ run: own, source: null, repoUrl: REPO_URL, usedRecordIds: [], workflowId: 'wf-sign' });
    return { own, workDir, rootHash: sealResult.rootHash, activities };
  }

  it('signs with TESSERA_SIGNING_KEY and reports level 1', async () => {
    const keyPath = path.join(keyRoot, 'ed25519.pem');
    const { keyId } = await generateSigningKey(keyPath);
    process.env.TESSERA_SIGNING_KEY = keyPath;
    delete process.env.TESSERA_REQUIRE_SIGNATURE;
    const { own, workDir, rootHash, activities } = await sealedOwnRun();
    try {
      const result = await activities.signEvidence({ run: own, rootHash });
      expect(result).toMatchObject({ signed: true, required: true, keyId, level: 1 });
    } finally {
      await chmod(path.join(evidenceRoot, own.runId), 0o700).catch(() => undefined);
      await rm(workDir, { recursive: true, force: true });
    }
  });

  it('honours TESSERA_REQUIRE_SIGNATURE=1 when the key is missing', async () => {
    process.env.TESSERA_SIGNING_KEY = path.join(keyRoot, 'missing.pem');
    process.env.TESSERA_REQUIRE_SIGNATURE = '1';
    const { own, workDir, rootHash, activities } = await sealedOwnRun();
    try {
      expect(await activities.signEvidence({ run: own, rootHash })).toMatchObject({ signed: false, required: true, level: 0 });
    } finally {
      await chmod(path.join(evidenceRoot, own.runId), 0o700).catch(() => undefined);
      await rm(workDir, { recursive: true, force: true });
    }
  });
});
