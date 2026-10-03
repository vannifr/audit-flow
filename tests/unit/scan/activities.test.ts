import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ApplicationFailure } from '@temporalio/activity';
import { createScanActivities } from '../../../src/scan/activities';
import type { ScanActivityDeps } from '../../../src/scan/activities';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../../src/scan/tool-types';
import type { AuditRun, FetchedSource } from '../../../src/scan/lifecycle';

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
