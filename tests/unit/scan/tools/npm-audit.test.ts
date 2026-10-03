import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { npmAuditPolicy, runNpmAuditScan } from '../../../../src/scan/tools/npm-audit';
import type { ScanContext } from '../../../../src/scan/scan-types';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../../../src/scan/tool-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../../src/evidence/types';

const T0 = new Date('2026-01-01T00:00:00.000Z');
const FIXTURES = path.resolve(__dirname, '../../../fixtures/tools');

function sha(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class FakeStore implements EvidenceStore {
  readonly bundleDir = '/tmp/bundle';
  records: EvidenceRecord[] = [];
  artifacts: { recordId: string; suffix: string; bytes: Buffer }[] = [];
  async writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    this.artifacts.push({ recordId, suffix, bytes });
    return { ...meta, path: `${recordId}.${suffix}`, bytes: bytes.length, sha256: sha(bytes) };
  }
  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    this.records.push(record);
    return { recordId: record.id, recordSha256: sha(JSON.stringify(record)) };
  }
}

interface Fixture {
  exitCode: number;
  stdout: string;
  stderr: string;
}

async function fixture(name: string): Promise<Fixture> {
  return JSON.parse(await readFile(path.join(FIXTURES, name), 'utf8')) as Fixture;
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

function fromFixture(f: Fixture): ProcessOutcome {
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

function fakeRunner(main: ProcessOutcome) {
  const requests: ProcessRequest[] = [];
  const snapshots: string[][] = [];
  const runner: ProcessRunner = async (req) => {
    requests.push(req);
    if (req.args.length === 1 && req.args[0] === '--version') return outcome({ stdout: Buffer.from('10.9.2\n') });
    snapshots.push((await readdir(req.cwd)).sort());
    return main;
  };
  return { runner, requests, snapshots };
}

let root: string;
let repoDir: string;
let workDir: string;
let store: FakeStore;

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'npm-audit-test-'));
  workDir = path.join(root, 'tessera-run1');
  repoDir = path.join(workDir, 'repo');
  await mkdir(repoDir, { recursive: true });
  store = new FakeStore();
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function ctx(runner: ProcessRunner, overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    run: { runId: 'run1', workDir, repoDir },
    source: { repoDir, revision: 'abc123' },
    repoUrl: 'https://example.com/org/repo.git',
    attempt: 1,
    deps: { runner, store, clock: () => T0, frameworkVersion: '0.0.0-test' },
    workerEnv: {},
    configDir: '/unused',
    ...overrides,
  };
}

async function withManifest(lockName: string | null = 'package-lock.json', lock = '{"lock":true}') {
  await writeFile(path.join(repoDir, 'package.json'), '{"name":"x"}');
  if (lockName !== null) await writeFile(path.join(repoDir, lockName), lock);
}

describe('npmAuditPolicy', () => {
  it('declares npm with the npm-audit scanner and version probe', () => {
    expect(npmAuditPolicy.tool).toBe('npm');
    expect(npmAuditPolicy.scanner).toBe('npm-audit');
    expect(npmAuditPolicy.versionArgs).toEqual(['--version']);
  });

  it('parses reports, error objects and rejects everything else', () => {
    expect(npmAuditPolicy.parse(Buffer.from('{"vulnerabilities":{},"metadata":{}}')).ok).toBe(true);
    expect(npmAuditPolicy.parse(Buffer.from('{"error":{"code":"EX"}}')).ok).toBe(true);
    expect(npmAuditPolicy.parse(Buffer.from('')).ok).toBe(false);
    expect(npmAuditPolicy.parse(Buffer.from('  \n')).ok).toBe(false);
    expect(npmAuditPolicy.parse(Buffer.from('not json')).ok).toBe(false);
    expect(npmAuditPolicy.parse(Buffer.from('[]')).ok).toBe(false);
    expect(npmAuditPolicy.parse(Buffer.from('{"foo":1}')).ok).toBe(false);
  });

  it('classifies exit codes', () => {
    const ok = npmAuditPolicy.parse(Buffer.from('{"vulnerabilities":{},"metadata":{}}'));
    expect(npmAuditPolicy.classify(outcome({ exitCode: 0 }), ok)).toEqual({ status: 'completed', exitClass: 'success' });
    expect(npmAuditPolicy.classify(outcome({ exitCode: 1 }), ok)).toEqual({
      status: 'completed',
      exitClass: 'issues-found',
      cause: 'issues-found',
    });
    const bad = npmAuditPolicy.classify(outcome({ exitCode: 2 }), ok);
    expect(bad.status).toBe('failed');
    expect(bad.cause).toBe('tool-error');
    const unparsed = npmAuditPolicy.classify(outcome({ exitCode: 1 }), npmAuditPolicy.parse(Buffer.from('')));
    expect(unparsed).toMatchObject({ status: 'failed', cause: 'parse-error' });
  });

  it('classifies npm error objects', () => {
    const lock = npmAuditPolicy.parse(Buffer.from('{"error":{"code":"ENOLOCK"}}'));
    expect(npmAuditPolicy.classify(outcome({ exitCode: 1 }), lock)).toMatchObject({ status: 'skipped', cause: 'no-lockfile' });
    const other = npmAuditPolicy.parse(Buffer.from('{"error":{"code":"E503","summary":"down"}}'));
    const c = npmAuditPolicy.classify(outcome({ exitCode: 1 }), other);
    expect(c).toMatchObject({ status: 'failed', cause: 'tool-error' });
    expect(c.causeDetail).toContain('E503');
    expect(c.causeDetail).toContain('down');
    const noCode = npmAuditPolicy.parse(Buffer.from('{"error":{}}'));
    expect(npmAuditPolicy.classify(outcome({ exitCode: 1 }), noCode).causeDetail).toContain('unknown');
  });

  it('sanitizes by parse result', () => {
    const bytes = Buffer.from('x');
    expect(npmAuditPolicy.sanitize(bytes, { ok: true }).mediaType).toBe('application/json');
    expect(npmAuditPolicy.sanitize(bytes, { ok: false }).mediaType).toBe('text/plain');
  });
});

describe('runNpmAuditScan applicability', () => {
  it('skips as not-applicable without package.json', async () => {
    const f = fakeRunner(outcome());
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.findings).toEqual([]);
    expect(result.status).toMatchObject({ scanner: 'npm-audit', status: 'skipped', cause: 'not-applicable', required: false, heuristic: false });
    expect(f.requests).toHaveLength(0);
    expect(store.records[0]).toMatchObject({ stepId: 'scan.npm-audit', kind: 'in-process', status: 'skipped', cause: 'not-applicable' });
    expect(result.evidence.recordId).toBe('scan.npm-audit.a1');
  });

  it('skips as no-lockfile and stays required', async () => {
    await withManifest(null);
    const f = fakeRunner(outcome());
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'skipped', cause: 'no-lockfile', required: true, findingCount: 0 });
    expect(result.status.evidenceRecordIds).toEqual(['scan.npm-audit.a1']);
    expect(f.requests).toHaveLength(0);
  });

  it.each(['yarn.lock', 'pnpm-lock.yaml'])('skips as unsupported-lockfile for %s', async (name) => {
    await withManifest(name, 'x');
    const f = fakeRunner(outcome());
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'skipped', cause: 'unsupported-lockfile', required: true });
    expect(f.requests).toHaveLength(0);
  });

  it('prefers an npm lockfile over yarn.lock', async () => {
    await withManifest('yarn.lock', 'x');
    await writeFile(path.join(repoDir, 'package-lock.json'), '{}');
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status.status).toBe('completed');
  });

  it('ignores a symlinked package.json', async () => {
    await writeFile(path.join(root, 'secret.json'), '{}');
    await symlink(path.join(root, 'secret.json'), path.join(repoDir, 'package.json'));
    await writeFile(path.join(repoDir, 'package-lock.json'), '{}');
    const f = fakeRunner(outcome());
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status.cause).toBe('not-applicable');
    expect(f.requests).toHaveLength(0);
  });

  it('fails when the manifest cannot be read', async ({ skip }) => {
    if (process.getuid?.() === 0) skip();
    await withManifest();
    await chmod(path.join(repoDir, 'package.json'), 0o000);
    const f = fakeRunner(outcome());
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'tool-error', required: true });
    expect(f.requests).toHaveLength(0);
  });
});

describe('runNpmAuditScan isolation and invocation', () => {
  it('copies only package.json and the lockfile, never .npmrc', async () => {
    await withManifest('package-lock.json', '{"lock":1}');
    await writeFile(path.join(repoDir, '.npmrc'), 'registry=http://127.0.0.1:9/\naudit=false\n');
    await writeFile(path.join(repoDir, 'yarn.lock'), 'x');
    await writeFile(path.join(repoDir, 'index.js'), 'x');
    await mkdir(path.join(workDir, 'npm-audit'), { recursive: true });
    await writeFile(path.join(workDir, 'npm-audit', 'stale.txt'), 'old');
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    await runNpmAuditScan(ctx(f.runner));
    expect(f.snapshots).toEqual([['package-lock.json', 'package.json']]);
    const dir = path.join(workDir, 'npm-audit');
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect(await readFile(path.join(dir, 'package-lock.json'), 'utf8')).toBe('{"lock":1}');
    expect(await readFile(path.join(dir, 'package.json'), 'utf8')).toBe('{"name":"x"}');
  });

  it('copies npm-shrinkwrap.json when that is the lockfile', async () => {
    await withManifest('npm-shrinkwrap.json', '{"s":1}');
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    await runNpmAuditScan(ctx(f.runner));
    expect(f.snapshots).toEqual([['npm-shrinkwrap.json', 'package.json']]);
  });

  it('runs npm audit --json in the isolated directory with exact args and inputs', async () => {
    await withManifest('package-lock.json', '{"lock":1}');
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    const main = f.requests.find((r) => r.args[0] === 'audit');
    expect(main?.file).toBe('npm');
    expect(main?.args).toEqual(['audit', '--json']);
    expect(main?.cwd).toBe(path.join(workDir, 'npm-audit'));
    expect(main?.timeoutMs).toBeGreaterThan(0);
    expect(store.records[0].action.inputs).toEqual({ lockfileSha256: sha('{"lock":1}') });
    expect(store.records[0].action.cwd).toBe('<WORK>/npm-audit');
    expect(result.status.toolVersion).toBe('10.9.2');
  });
});

describe('runNpmAuditScan results', () => {
  it('maps the vulnerable fixture to findings with severities', async () => {
    await withManifest();
    const f = fakeRunner(fromFixture(await fixture('npm-audit-vulnerable.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({
      scanner: 'npm-audit',
      required: true,
      heuristic: false,
      status: 'completed',
      cause: 'issues-found',
      findingCount: 9,
    });
    expect(result.findings).toHaveLength(9);
    const count = (s: string) => result.findings.filter((x) => x.severity === s).length;
    expect(count('P0')).toBe(1);
    expect(count('P1')).toBe(5);
    expect(count('P2')).toBe(0);
    expect(count('P3')).toBe(3);
    const ids = result.findings.map((x) => x.id);
    expect(ids).toEqual(ids.map((_, i) => `DEP-${i + 1}`));
    expect(store.records[0].findingIds).toEqual(ids);
    const minimist = result.findings.find((x) => x.title.startsWith('minimist:'));
    expect(minimist?.severity).toBe('P0');
    expect(minimist?.title).toBe('minimist: Prototype Pollution in minimist');
    expect(minimist?.category).toBe('security-dependencies');
    expect(minimist?.scanner).toBe('npm-audit');
    expect(minimist?.heuristic).toBe(false);
    expect(minimist?.evidenceRef).toEqual({ ...result.evidence, locator: 'vulnerabilities.minimist' });
    expect(minimist?.remediation).toEqual({ description: 'Update minimist to 1.2.8', effort: 'hours', priority: 'immediate' });
    expect(minimist?.evidence[0]).toMatchObject({ type: 'scan-output', file: 'package.json', tool: 'npm', timestamp: T0 });
    const body = JSON.parse(minimist!.evidence[0].content) as Record<string, unknown>;
    expect(body).toMatchObject({ package: 'minimist', range: '1.0.0 - 1.2.5', fixAvailable: expect.objectContaining({ version: '1.2.8' }) });
    expect(JSON.stringify(body.via)).toContain('https://github.com/advisories/');
    const serve = result.findings.find((x) => x.title.startsWith('serve-static:'));
    expect(serve?.severity).toBe('P3');
    expect(serve?.remediation).toMatchObject({ description: 'Update serve-static to latest', priority: 'short-term' });
    const lodash = result.findings.find((x) => x.title.startsWith('lodash:'));
    expect(lodash?.severity).toBe('P1');
  });

  it('includes string via entries (transitive) in the evidence', async () => {
    await withManifest();
    const f = fakeRunner(fromFixture(await fixture('npm-audit-vulnerable.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    const serve = result.findings.find((x) => x.title.startsWith('serve-static:'));
    const body = JSON.parse(serve!.evidence[0].content) as { via: string[] };
    expect(body.via).toContain('send');
    expect(serve?.description).toContain('send');
  });

  it('maps moderate to P2 and unknown severities to P3 and tolerates odd shapes', async () => {
    await withManifest();
    const report = {
      vulnerabilities: {
        a: { severity: 'moderate', via: [{ title: 'Mod issue' }], range: '<1' },
        b: { severity: 'weird', via: [{ url: 'u' }, 5, {}] },
        c: { via: 'oops', fixAvailable: true },
        d: 'not-an-object',
        e: { severity: 'CRITICAL', via: [{ title: 'x'.repeat(300) }] },
      },
      metadata: {},
    };
    const f = fakeRunner(outcome({ exitCode: 1, stdout: Buffer.from(JSON.stringify(report)) }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.findings.map((x) => [x.title.split(':')[0], x.severity])).toEqual([
      ['a', 'P2'],
      ['b', 'P3'],
      ['c', 'P3'],
      ['e', 'P0'],
    ]);
    expect(result.findings[0].title).toBe('a: Mod issue');
    expect(result.findings[1].title).toBe('b: known vulnerability');
    expect(result.findings[3].title).toHaveLength(3 + 120);
  });

  it('reports clean runs as completed without findings', async () => {
    await withManifest();
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.findings).toEqual([]);
    expect(result.status).toMatchObject({ status: 'completed', findingCount: 0 });
    expect(result.status.cause).toBeUndefined();
  });

  it('turns an ENOLOCK report into skipped/no-lockfile', async () => {
    await withManifest();
    const f = fakeRunner(fromFixture(await fixture('npm-audit-enolock.json')));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'skipped', cause: 'no-lockfile', required: true });
    expect(result.findings).toEqual([]);
  });

  it('fails on other npm error objects', async () => {
    await withManifest();
    const stdout = JSON.stringify({ error: { code: 'EAUDITNOLOCK', summary: 'nope' } });
    const f = fakeRunner(outcome({ exitCode: 1, stdout: Buffer.from(stdout) }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'tool-error' });
    expect(result.findings).toEqual([]);
  });

  it('fails with parse-error on empty stdout with exit 1', async () => {
    await withManifest();
    const f = fakeRunner(outcome({ exitCode: 1, stderr: Buffer.from('npm error double-loading config') }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'parse-error' });
    expect(result.findings).toEqual([]);
  });

  it('fails with parse-error on non-JSON output', async () => {
    await withManifest();
    const f = fakeRunner(outcome({ exitCode: 0, stdout: Buffer.from('<html>502</html>') }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'parse-error' });
    expect(store.artifacts[0].suffix).toBe('stdout.txt');
  });

  it('fails on an unexpected exit code with valid JSON', async () => {
    await withManifest();
    const f = fakeRunner(outcome({ exitCode: 2, stdout: Buffer.from('{"vulnerabilities":{},"metadata":{}}') }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'tool-error' });
  });

  it('reports a missing npm as unavailable', async () => {
    await withManifest();
    const f = fakeRunner(outcome({ exitCode: null, spawnErrorCode: 'ENOENT' }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'unavailable', cause: 'not-installed', required: true, findingCount: 0 });
  });

  it('reports a timeout as failed', async () => {
    await withManifest();
    const f = fakeRunner(outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.status).toMatchObject({ status: 'failed', cause: 'timeout' });
    expect(result.findings).toEqual([]);
  });

  it('marks the status partial when more than 2000 vulnerabilities are reported', async () => {
    await withManifest();
    const vulnerabilities: Record<string, unknown> = {};
    for (let i = 0; i < 2005; i++) vulnerabilities[`pkg-${i}`] = { severity: 'low', via: [] };
    const f = fakeRunner(outcome({ exitCode: 1, stdout: Buffer.from(JSON.stringify({ vulnerabilities, metadata: {} })) }));
    const result = await runNpmAuditScan(ctx(f.runner));
    expect(result.findings).toHaveLength(2000);
    expect(result.status).toMatchObject({ status: 'partial', cause: 'findings-truncated', findingCount: 2000 });
    expect(store.records[0].findingIds).toHaveLength(2000);
  });
});

describe('runNpmAuditScan override attempts (FR-014)', () => {
  it('puts the dependency steering attempts in its evidence record', async () => {
    await withManifest('package-lock.json', '{"lock":1}');
    const attempts = [
      { kind: 'project-config' as const, path: '.npmrc', detail: 'npm configuration, kept', sha256: 'c'.repeat(64), neutralizedBy: 'isolated-working-dir' as const },
      { kind: 'control-file' as const, path: '.gitleaksignore', detail: 'gitleaks ignore list, removed', neutralizedBy: 'removed-from-working-copy' as const },
      { kind: 'project-config' as const, path: '.snyk', detail: 'snyk policy, removed', neutralizedBy: 'removed-from-working-copy' as const },
    ];
    const f = fakeRunner(fromFixture(await fixture('npm-audit-clean.json')));
    await runNpmAuditScan(ctx(f.runner, { overrideAttempts: attempts }));
    expect(store.records[0].overrideAttempts).toEqual([attempts[0], attempts[2]]);
  });
});
