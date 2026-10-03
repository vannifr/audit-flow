import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, rm, stat, mkdir, access, symlink, writeFile, chmod, lstat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
vi.mock('node:fs/promises', async (importOriginal) => {
  const orig = await importOriginal<typeof import('node:fs/promises')>();
  return { ...orig, lstat: vi.fn(orig.lstat) };
});

import { initAuditRun, fetchSource, cleanupRun } from '../../../src/scan/lifecycle';
import type { AuditRun } from '../../../src/scan/lifecycle';
import { validateRepoUrl } from '../../../src/activities/index';
import type { ProcessOutcome, ProcessRequest, ProcessRunner, RunToolDeps } from '../../../src/scan/tool-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../src/evidence/types';

const T0 = new Date('2026-01-01T00:00:00.000Z');
const REV = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';

class FakeStore implements EvidenceStore {
  readonly bundleDir = '/tmp/bundle';
  records: EvidenceRecord[] = [];

  async writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    return { ...meta, path: `${recordId}.${suffix}`, bytes: bytes.length, sha256: 'f'.repeat(64) };
  }

  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    this.records.push(record);
    return { recordId: record.id, recordSha256: 'e'.repeat(64) };
  }
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

interface Fake {
  deps: RunToolDeps;
  requests: ProcessRequest[];
}

function fake(cloneResult: ProcessOutcome = outcome(), revision = REV): Fake {
  const requests: ProcessRequest[] = [];
  const runner: ProcessRunner = async (req) => {
    requests.push(req);
    if (req.args.includes('--version')) return outcome({ stdout: Buffer.from('git version 2.43.0\n') });
    if (req.args.includes('clone')) {
      if (cloneResult.exitCode === 0) await mkdir(req.args[req.args.length - 1], { recursive: true });
      return cloneResult;
    }
    if (req.args.includes('rev-parse')) return outcome({ stdout: Buffer.from(`${revision}\n`) });
    return outcome();
  };
  const deps: RunToolDeps = { runner, store: new FakeStore(), clock: () => T0, frameworkVersion: '0.0.0-test' };
  return { deps, requests };
}

const cloneFailure = (stderr: string): ProcessOutcome =>
  outcome({ exitCode: 128, stderr: Buffer.from(stderr) });

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

describe('audit run lifecycle', () => {
  let tmpRoot: string;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(join(tmpdir(), 'lifecycle-test-'));
  });

  afterEach(async () => {
    await rm(tmpRoot, { recursive: true, force: true });
  });

  describe('initAuditRun', () => {
    it('creates <tmp>/tessera-<runId> with mode 0700', async () => {
      const run = await initAuditRun({ workflowId: 'audit-123', temporalRunId: 'run-abc', tmpRoot });
      expect(run.runId).toBe('run-abc');
      expect(run.workDir).toBe(join(tmpRoot, 'tessera-run-abc'));
      expect(run.repoDir.startsWith(run.workDir)).toBe(true);
      const st = await stat(run.workDir);
      expect(st.isDirectory()).toBe(true);
      expect(st.mode & 0o777).toBe(0o700);
    });

    it.each(['a/b', '../x', 'a.b', 'a;id', 'a b', '$(id)', 'a\\b'])(
      'rejects workflowId %s',
      async (workflowId) => {
        await expect(initAuditRun({ workflowId, temporalRunId: 'run-abc', tmpRoot })).rejects.toThrow(
          /workflowId/i,
        );
        expect(await exists(join(tmpRoot, 'tessera-run-abc'))).toBe(false);
      },
    );

    it('gives two runs with different runIds different directories (TS-018)', async () => {
      const a = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-a', tmpRoot });
      const b = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-b', tmpRoot });
      expect(a.workDir).not.toBe(b.workDir);
      expect(await exists(a.workDir)).toBe(true);
      expect(await exists(b.workDir)).toBe(true);
    });
  });

  describe('fetchSource', () => {
    const run: AuditRun = { runId: 'run-abc', workDir: '/tmp/tessera-run-abc', repoDir: '/tmp/tessera-run-abc/repo' };
    const url = 'https://github.com/owner/repo';

    afterEach(async () => {
      await rm(run.workDir, { recursive: true, force: true });
    });

    function hostileClone(files: Record<string, string>): Fake {
      const f = fake();
      const inner = f.deps.runner;
      f.deps.runner = async (req) => {
        const result = await inner(req);
        if (req.args.includes('clone')) {
          const target = req.args[req.args.length - 1];
          for (const [rel, content] of Object.entries(files)) {
            await mkdir(join(target, rel, '..'), { recursive: true });
            await writeFile(join(target, rel), content);
          }
        }
        return result;
      };
      return f;
    }

    it('probes the clone after rev-parse, removes steering files and records a source.probe record (TS-029, FR-014)', async () => {
      const own = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-probe', tmpRoot });
      const f = hostileClone({
        '.gitleaksignore': 'src/a.js:generic-api-key:1\n',
        'sub/.semgrepignore': 'src/\n',
        '.npmrc': 'registry=http://127.0.0.1:9/\n',
        'src/a.js': 'const k = 1; // gitleaks:allow\n',
      });
      const result = await fetchSource(own, url, { ...f.deps, tmpRoot });
      expect(await exists(join(own.repoDir, '.gitleaksignore'))).toBe(false);
      expect(await exists(join(own.repoDir, 'sub/.semgrepignore'))).toBe(false);
      expect(await exists(join(own.repoDir, 'src/a.js'))).toBe(true);
      const records = (f.deps.store as FakeStore).records;
      expect(records.map((r) => r.stepId)).toEqual(['source.clone', 'source.revision', 'source.probe']);
      const probe = records[2];
      expect(probe).toMatchObject({
        id: 'source.probe.a1',
        kind: 'source-probe',
        status: 'completed',
        source: { repoUrl: url, revision: REV },
        action: { command: null, args: [], inputs: expect.objectContaining({ controlFiles: '3', inlineMarkers: '1', truncated: 'false' }) },
      });
      expect(probe.scanner).toBeUndefined();
      expect(probe.causeDetail).toContain('3 control files');
      expect(probe.causeDetail).toContain('1 inline marker');
      expect(probe.overrideAttempts.map((a) => [a.kind, a.path, a.neutralizedBy])).toEqual([
        ['control-file', '.gitleaksignore', 'removed-from-working-copy'],
        ['project-config', '.npmrc', 'isolated-working-dir'],
        ['control-file', 'sub/.semgrepignore', 'removed-from-working-copy'],
        ['inline-marker', 'src/a.js', 'framework-flag'],
      ]);
      expect(result.overrideAttempts).toEqual(probe.overrideAttempts);
      expect(result.evidenceRecordIds).toEqual(['source.clone.a1', 'source.revision.a1', 'source.probe.a1']);
    });

    it('records a clean probe with no attempts for a source without steering files', async () => {
      const own = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-clean', tmpRoot });
      const f = hostileClone({ 'src/a.js': 'x\n' });
      const result = await fetchSource(own, url, { ...f.deps, tmpRoot, attempt: 2 });
      expect(result.overrideAttempts).toEqual([]);
      const probe = (f.deps.store as FakeStore).records.find((r) => r.stepId === 'source.probe');
      expect(probe).toMatchObject({ id: 'source.probe.a2', status: 'completed', overrideAttempts: [] });
    });

    it('fails closed with a recorded failed probe when the clone dir cannot be probed', async () => {
      const own = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-noprobe', tmpRoot });
      const f = fake();
      const inner = f.deps.runner;
      f.deps.runner = async (req) => {
        const result = await inner(req);
        if (req.args.includes('clone')) {
          const target = req.args[req.args.length - 1];
          await rm(target, { recursive: true, force: true });
          await symlink(tmpRoot, target);
        }
        return result;
      };
      const error = await fetchSource(own, url, { ...f.deps, tmpRoot }).then(() => undefined, (e: unknown) => e);
      expect(error).toMatchObject({ kind: 'source-unavailable', retryable: false });
      expect((error as { evidenceRecordIds: string[] }).evidenceRecordIds).toEqual(['source.clone.a1', 'source.revision.a1', 'source.probe.a1']);
      const probe = (f.deps.store as FakeStore).records.find((r) => r.stepId === 'source.probe');
      expect(probe).toMatchObject({ kind: 'source-probe', status: 'failed', result: { exitClass: 'tool-error' } });
      expect(probe?.causeDetail).toMatch(/source probe/);
    });

    it('clones shallow with the url after -- and returns the 40-hex revision (TS-014)', async () => {
      const { deps, requests } = fake();
      const result = await fetchSource(run, url, deps);
      const clone = requests.find((r) => r.args.includes('clone'));
      expect(clone).toBeDefined();
      expect(clone?.args).toContain('--depth');
      expect(clone?.args).toContain('1');
      const sep = clone?.args.indexOf('--') ?? -1;
      expect(sep).toBeGreaterThan(-1);
      expect(clone?.args[sep + 1]).toBe(url);
      const revParse = requests.find((r) => r.args.includes('rev-parse'));
      expect(revParse?.args).toContain('HEAD');
      expect(result.revision).toMatch(/^[0-9a-f]{40}$/);
      expect(result.revision).toBe(REV);
      expect(result.repoDir).toBe(run.repoDir);
    });

    it('classifies an unresolvable host as a retryable network error (TS-011)', async () => {
      const { deps } = fake(cloneFailure("fatal: unable to access 'https://github.com/o/r/': Could not resolve host: github.com\n"));
      await expect(fetchSource(run, url, deps)).rejects.toMatchObject({ kind: 'network', retryable: true });
    });

    it('classifies a missing repository as a non-retryable source-unavailable error (TS-011)', async () => {
      const { deps } = fake(cloneFailure("remote: Repository not found.\nfatal: repository 'https://github.com/o/r/' not found\n"));
      await expect(fetchSource(run, url, deps)).rejects.toMatchObject({
        kind: 'source-unavailable',
        retryable: false,
      });
    });

    it('rejects a malformed revision from rev-parse', async () => {
      const { deps } = fake(outcome(), 'not-a-revision');
      await expect(fetchSource(run, url, deps)).rejects.toThrow(/revision/i);
    });

    it.each(['file:///x', 'https://github.com/a/b;id'])('rejects %s without invoking the runner', async (badUrl) => {
      const { deps, requests } = fake();
      await expect(fetchSource(run, badUrl, deps)).rejects.toMatchObject({ code: 'invalid-repo-url' });
      expect(requests).toHaveLength(0);
    });

    it.each([
      ['workDir outside the tessera-<runId> naming', { runId: 'run-abc', workDir: '/etc', repoDir: '/etc/repo' }],
      ['relative workDir', { runId: 'run-abc', workDir: 'tessera-run-abc', repoDir: 'tessera-run-abc/repo' }],
      ['non-normalized workDir', { runId: 'run-abc', workDir: '/tmp/x/../tessera-run-abc', repoDir: '/tmp/x/../tessera-run-abc/repo' }],
      ['repoDir not under workDir', { runId: 'run-abc', workDir: '/tmp/tessera-run-abc', repoDir: '/etc/repo' }],
      ['invalid runId', { runId: '../x', workDir: '/tmp/tessera-../x', repoDir: '/tmp/tessera-../x/repo' }],
      ['missing workDir and repoDir', { runId: 'run-abc' }],
      ['missing runId', { workDir: '/tmp/tessera-run-abc', repoDir: '/tmp/tessera-run-abc/repo' }],
      ['empty object', {}],
    ])('rejects a forged AuditRun: %s', async (_name, forged) => {
      const { deps, requests } = fake();
      await expect(fetchSource(forged as unknown as AuditRun, url, deps)).rejects.toMatchObject({ code: 'invalid-run' });
      expect(requests).toHaveLength(0);
    });

    it('classifies a timed out clone (timedOut true) as a retryable network error', async () => {
      const { deps } = fake(outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true }));
      await expect(fetchSource(run, url, deps)).rejects.toMatchObject({ kind: 'network', retryable: true });
    });

    it('classifies exit 128 with "timed out" in stderr as a retryable network error', async () => {
      const { deps } = fake(cloneFailure('fatal: unable to access: Connection timed out after 300000 milliseconds\n'));
      await expect(fetchSource(run, url, deps)).rejects.toMatchObject({ kind: 'network', retryable: true });
    });

    it('rejects a forged AuditRun whose valid tessera-<runId> workDir lies outside tmpRoot', async () => {
      const outside = await mkdtemp(join(tmpdir(), 'lifecycle-outside-'));
      try {
        const workDir = join(outside, 'tessera-run-abc');
        const marker = join(workDir, 'repo', 'keep.txt');
        await mkdir(join(workDir, 'repo'), { recursive: true });
        await writeFile(marker, 'keep');
        const forged: AuditRun = { runId: 'run-abc', workDir, repoDir: join(workDir, 'repo') };
        const { deps, requests } = fake();
        await expect(fetchSource(forged, url, { ...deps, tmpRoot })).rejects.toMatchObject({ code: 'invalid-run' });
        expect(requests).toHaveLength(0);
        expect(await exists(marker)).toBe(true);
      } finally {
        await rm(outside, { recursive: true, force: true });
      }
    });
  });

  describe('cleanupRun hardening', () => {
    afterEach(() => {
      vi.unstubAllEnvs();
      vi.mocked(lstat).mockReset();
    });

    it('refuses a workDir that is a symlink to a directory and leaves the target intact', async () => {
      const target = join(tmpRoot, 'victim');
      await mkdir(target);
      await writeFile(join(target, 'keep.txt'), 'data');
      const workDir = join(tmpRoot, 'tessera-run-link');
      await symlink(target, workDir);
      const run: AuditRun = { runId: 'run-link', workDir, repoDir: join(workDir, 'repo') };
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/symlink/i);
      expect(await exists(join(target, 'keep.txt'))).toBe(true);
      expect((await lstat(workDir)).isSymbolicLink()).toBe(true);
    });

    it('refuses a directory not owned by the current uid (lstat mocked to report another uid)', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-uid', tmpRoot });
      const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
      vi.mocked(lstat).mockImplementation(async (p: Parameters<typeof actual.lstat>[0]) => {
        const st = await actual.lstat(p);
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: st.uid + 1 });
      });
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/not owned/i);
      vi.mocked(lstat).mockReset();
      vi.mocked(lstat).mockImplementation(actual.lstat);
      expect(await exists(run.workDir)).toBe(true);
    });

    it('refuses a workDir under TESSERA_EVIDENCE_ROOT and keeps it', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-ev', tmpRoot });
      vi.stubEnv('TESSERA_EVIDENCE_ROOT', tmpRoot);
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/evidence root/i);
      expect(await exists(run.workDir)).toBe(true);
    });

    it('refuses a workDir equal to TESSERA_EVIDENCE_ROOT', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-ev2', tmpRoot });
      vi.stubEnv('TESSERA_EVIDENCE_ROOT', run.workDir);
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/evidence root/i);
      expect(await exists(run.workDir)).toBe(true);
    });

    it('removes the workDir when TESSERA_EVIDENCE_ROOT is elsewhere', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-ev3', tmpRoot });
      const other = await mkdtemp(join(tmpdir(), 'lifecycle-evidence-'));
      try {
        vi.stubEnv('TESSERA_EVIDENCE_ROOT', other);
        await cleanupRun(run, tmpRoot);
        expect(await exists(run.workDir)).toBe(false);
      } finally {
        await rm(other, { recursive: true, force: true });
      }
    });
  });

  describe('initAuditRun idempotence and symlinks', () => {
    it('is idempotent on an existing directory and restores mode 0700', async () => {
      const a = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-idem', tmpRoot });
      await chmod(a.workDir, 0o755);
      const b = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-idem', tmpRoot });
      expect(b).toEqual(a);
      expect((await stat(b.workDir)).mode & 0o777).toBe(0o700);
      expect((await stat(join(b.workDir, 'home'))).mode & 0o777).toBe(0o700);
      expect((await stat(join(b.workDir, 'tmp'))).mode & 0o777).toBe(0o700);
    });

    it('refuses when the workDir is a symlink and does not touch the target', async () => {
      const target = join(tmpRoot, 'victim');
      await mkdir(target);
      await symlink(target, join(tmpRoot, 'tessera-run-sym'));
      await expect(initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-sym', tmpRoot })).rejects.toThrow(/symlink/i);
      expect(await readdir(target)).toEqual([]);
    });

    it('refuses when home inside an existing workDir is a symlink', async () => {
      const a = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-sym2', tmpRoot });
      const target = join(tmpRoot, 'victim2');
      await mkdir(target);
      await rm(join(a.workDir, 'home'), { recursive: true });
      await symlink(target, join(a.workDir, 'home'));
      await expect(initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-sym2', tmpRoot })).rejects.toThrow(/symlink/i);
      expect(await readdir(target)).toEqual([]);
    });

    it('refuses when the workDir exists as a regular file', async () => {
      await writeFile(join(tmpRoot, 'tessera-run-file'), 'x');
      await expect(initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-file', tmpRoot })).rejects.toThrow(/not a directory/i);
    });
  });

  describe('cleanupRun', () => {
    it('removes the work dir on success', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-ok', tmpRoot });
      await mkdir(run.repoDir, { recursive: true });
      await cleanupRun(run, tmpRoot);
      expect(await exists(run.workDir)).toBe(false);
    });

    it('removes the work dir after a failure path', async () => {
      const run = await initAuditRun({ workflowId: 'audit-1', temporalRunId: 'run-fail', tmpRoot });
      const { deps } = fake(cloneFailure('remote: Repository not found.\n'));
      try {
        await fetchSource(run, 'https://github.com/o/r', deps);
      } catch {
        expect(await exists(run.workDir)).toBe(true);
      } finally {
        await cleanupRun(run, tmpRoot);
      }
      expect(await exists(run.workDir)).toBe(false);
    });

    it('refuses a path outside <tmp>/tessera-*', async () => {
      const run: AuditRun = { runId: 'x', workDir: '/etc', repoDir: '/etc/repo' };
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/outside|refus/i);
      expect(await exists('/etc')).toBe(true);
    });

    it('refuses a sibling directory that is not tessera-*', async () => {
      const sibling = join(tmpRoot, 'other');
      await mkdir(sibling, { recursive: true });
      const run: AuditRun = { runId: 'x', workDir: sibling, repoDir: join(sibling, 'repo') };
      await expect(cleanupRun(run, tmpRoot)).rejects.toThrow(/outside|refus/i);
      expect(await exists(sibling)).toBe(true);
    });
  });

  describe('validateRepoUrl reuse', () => {
    it.each(['file:///x', '--upload-pack=x', 'https://github.com/a/b;id'])('still rejects %s', (url) => {
      expect(() => validateRepoUrl(url)).toThrow();
    });
  });
});
