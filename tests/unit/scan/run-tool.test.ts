import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, symlink, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runTool } from '../../../src/scan/run-tool';
import type {
  ParseResult,
  ProcessOutcome,
  ProcessRequest,
  ProcessRunner,
  RunToolDeps,
  ToolInvocation,
  ToolPolicy,
} from '../../../src/scan/tool-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../src/evidence/types';

const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const T0 = new Date('2026-01-01T00:00:00.000Z');
const T1 = new Date('2026-01-01T00:00:01.000Z');

function sha(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class FakeStore implements EvidenceStore {
  readonly bundleDir = '/tmp/bundle';
  records: EvidenceRecord[] = [];
  artifacts: { recordId: string; suffix: string; bytes: Buffer }[] = [];
  failWrites = false;

  async writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    if (this.failWrites) throw new Error('disk full');
    this.artifacts.push({ recordId, suffix, bytes });
    return { ...meta, path: `${recordId}.${suffix}`, bytes: bytes.length, sha256: sha(bytes) };
  }

  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    if (this.failWrites) throw new Error('disk full');
    this.records.push(record);
    return { recordId: record.id, recordSha256: sha(Buffer.from(JSON.stringify(record))) };
  }
}

function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: Buffer.from('{"ok":true}'),
    stderr: Buffer.alloc(0),
    stdoutTruncated: false,
    timedOut: false,
    startedAt: T0,
    endedAt: T1,
    ...partial,
  };
}

interface FakeRunner {
  runner: ProcessRunner;
  requests: ProcessRequest[];
}

function fakeRunner(main: ProcessOutcome, version = 'faketool 1.2.3\n'): FakeRunner {
  const requests: ProcessRequest[] = [];
  const runner: ProcessRunner = async (req) => {
    requests.push(req);
    if (req.args.length === 1 && req.args[0] === '--version') {
      return outcome({ stdout: Buffer.from(version) });
    }
    return main;
  };
  return { runner, requests };
}

const policy: ToolPolicy<unknown> = {
  tool: 'npm',
  scanner: 'npm-audit',
  versionArgs: ['--version'],
  parse(output: Buffer): ParseResult<unknown> {
    if (output.length === 0) return { ok: true, value: null };
    try {
      return { ok: true, value: JSON.parse(output.toString('utf8')) };
    } catch {
      return { ok: false, error: 'not json' };
    }
  },
  classify() {
    return { status: 'completed', exitClass: 'success' };
  },
  sanitize(output: Buffer) {
    return { bytes: output, redactions: 0, mediaType: 'application/json' };
  },
};

function invocation(overrides: Partial<ToolInvocation> = {}): ToolInvocation {
  return {
    stepId: 'audit',
    attempt: 1,
    runId: 'run-1',
    source: { repoUrl: 'https://example.invalid/repo.git', revision: 'a'.repeat(40) },
    args: ['audit', '--json', '--', 'pkg; rm -rf /'],
    cwd: '/tmp/tessera-abc/src',
    timeoutMs: 1000,
    outputFrom: 'stdout',
    pathTokens: { '/tmp/tessera-abc': '<WORK>' },
    ...overrides,
  };
}

function deps(runner: ProcessRunner, store: FakeStore): RunToolDeps {
  return { runner, store, clock: () => T1, frameworkVersion: '0.0.0-test' };
}

describe('runTool', () => {
  it('writes exactly one record per call on success and returns completed', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome());
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('completed');
    expect(result.record).toEqual(store.records[0]);
    expect(result.evidence.recordId).toBe(store.records[0].id);
    expect(result.record.tool.name).toBe('npm');
    expect(result.record.runId).toBe('run-1');
    expect(result.record.stepId).toBe('audit');
    expect(result.record.recordedBy).toEqual({ framework: 'tessera', version: '0.0.0-test' });
  });

  it('records the tool version from the version probe', async () => {
    const store = new FakeStore();
    const { runner, requests } = fakeRunner(outcome());
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(requests.some((r) => r.args.length === 1 && r.args[0] === '--version')).toBe(true);
    expect(result.toolVersion).toContain('1.2.3');
    expect(result.record.tool.version).toContain('1.2.3');
  });

  it('records ENOENT as unavailable with cause not-installed and still writes one record', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(
      outcome({ exitCode: null, stdout: Buffer.alloc(0), spawnErrorCode: 'ENOENT' }),
    );
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('unavailable');
    expect(result.classification.cause).toBe('not-installed');
    expect(store.records[0].status).toBe('unavailable');
    expect(store.records[0].cause).toBe('not-installed');
    expect(store.records[0].result.exitClass).toBe('not-installed');
    expect(store.records[0].result.spawnErrorCode).toBe('ENOENT');
  });

  it('records a timeout as failed with cause timeout and still writes one record', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(
      outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true, stdout: Buffer.alloc(0) }),
    );
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('failed');
    expect(result.classification.cause).toBe('timeout');
    expect(store.records[0].result.timedOut).toBe(true);
    expect(store.records[0].result.exitClass).toBe('timeout');
  });

  it('records truncated stdout as partial with cause output-truncated', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome({ stdoutTruncated: true, stdout: Buffer.from('{"a":') }));
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('partial');
    expect(result.classification.cause).toBe('output-truncated');
    expect(store.records[0].result.exitClass).toBe('output-truncated');
    expect(store.records[0].output?.truncated).toBe(true);
  });

  it('treats success with empty output as completed and records the empty-output hash', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('completed');
    expect(store.records[0].output).not.toBeNull();
    expect(store.records[0].output?.rawSha256).toBe(EMPTY_SHA);
    expect(store.records[0].output?.sha256).toBe(EMPTY_SHA);
    expect(store.records[0].output?.rawBytes).toBe(0);
  });

  it('records non-parseable output as failed with cause parse-error', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome({ stdout: Buffer.from('<html>not json</html>') }));
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.parsed.ok).toBe(false);
    expect(result.classification.status).toBe('failed');
    expect(result.classification.cause).toBe('parse-error');
    expect(store.records[0].status).toBe('failed');
    expect(store.records[0].cause).toBe('parse-error');
  });

  it('passes file and args to the runner as separate values and never a shell string', async () => {
    const store = new FakeStore();
    const { runner, requests } = fakeRunner(outcome());
    const inv = invocation();
    await runTool(inv, policy, deps(runner, store));
    const main = requests.find((r) => r.args[0] === 'audit');
    expect(main).toBeDefined();
    expect(main?.file).toBe('npm');
    expect(main?.args).toEqual(['audit', '--json', '--', 'pkg; rm -rf /']);
    expect(Array.isArray(main?.args)).toBe(true);
    expect(main?.file).not.toMatch(/\s/);
    expect(main?.cwd).toBe(inv.cwd);
    expect(main?.timeoutMs).toBe(1000);
  });

  it('runs the tool with a complete allowlisted environment, not process.env', async () => {
    const store = new FakeStore();
    const { runner, requests } = fakeRunner(outcome());
    await runTool(invocation(), policy, deps(runner, store));
    const main = requests.find((r) => r.args[0] === 'audit');
    expect(main?.env.NO_COLOR).toBe('1');
    expect(Object.keys(main?.env ?? {})).not.toContain('NODE_OPTIONS');
    expect(Object.keys(main?.env ?? {})).not.toContain('GITHUB_TOKEN');
  });

  it('throws when the evidence store fails (fail closed)', async () => {
    const store = new FakeStore();
    store.failWrites = true;
    const { runner } = fakeRunner(outcome());
    await expect(runTool(invocation(), policy, deps(runner, store))).rejects.toThrow('disk full');
    expect(store.records).toHaveLength(0);
  });

  it('writes one record per call across repeated calls', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome());
    await runTool(invocation({ attempt: 1 }), policy, deps(runner, store));
    await runTool(invocation({ attempt: 2 }), policy, deps(runner, store));
    expect(store.records).toHaveLength(2);
    expect(store.records[0].id).not.toBe(store.records[1].id);
    expect(store.records.map((r) => r.attempt)).toEqual([1, 2]);
  });

  it('links finding ids from findingIdsFor into the record', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome());
    await runTool(invocation(), policy, deps(runner, store), () => ['f-1', 'f-2']);
    expect(store.records[0].findingIds).toEqual(['f-1', 'f-2']);
  });

  it('rejects when only writeRecord fails and the artifact write succeeds', async () => {
    const store = new FakeStore();
    store.writeRecord = async () => {
      throw new Error('record write failed');
    };
    const { runner } = fakeRunner(outcome());
    await expect(runTool(invocation(), policy, deps(runner, store))).rejects.toThrow('record write failed');
    expect(store.records).toHaveLength(0);
  });

  it('runs the version probe in the work dir, not in the source cwd', async () => {
    const store = new FakeStore();
    const { runner, requests } = fakeRunner(outcome());
    const inv = invocation();
    await runTool(inv, policy, deps(runner, store));
    const probe = requests.find((r) => r.args.length === 1 && r.args[0] === '--version');
    const main = requests.find((r) => r.args[0] === 'audit');
    expect(probe?.cwd).toBe('/tmp/tessera-abc');
    expect(probe?.cwd).not.toBe(inv.cwd);
    expect(main?.cwd).toBe('/tmp/tessera-abc/src');
  });

  it('stores no absolute work paths in the record and uses the <WORK> token', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(outcome());
    const inv = invocation({
      args: ['audit', '--json', '--prefix', '/tmp/tessera-abc/src/sub'],
      inputs: { lockfile: '/tmp/tessera-abc/src/package-lock.json' },
    });
    await runTool(inv, policy, deps(runner, store));
    const record = store.records[0];
    expect(record.action.args).toEqual(['audit', '--json', '--prefix', '<WORK>/src/sub']);
    expect(record.action.cwd).toBe('<WORK>/src');
    expect(record.action.inputs.lockfile).toBe('<WORK>/src/package-lock.json');
    expect(JSON.stringify(record)).not.toContain('/tmp/tessera-abc');
  });

  it('tokenizes work paths in stored output and stderr', async () => {
    const store = new FakeStore();
    const { runner } = fakeRunner(
      outcome({ stdout: Buffer.from('{"p":"/tmp/tessera-abc/src/x"}'), stderr: Buffer.from('failed at /tmp/tessera-abc/src/y') }),
    );
    await runTool(invocation(), policy, deps(runner, store));
    for (const artifact of store.artifacts) {
      expect(artifact.bytes.toString('utf8')).not.toContain('/tmp/tessera-abc');
      expect(artifact.bytes.toString('utf8')).toContain('<WORK>');
    }
    expect(store.artifacts).toHaveLength(2);
  });

  it('still writes exactly one record when the runner itself rejects', async () => {
    const store = new FakeStore();
    const runner: ProcessRunner = async () => {
      throw new Error('runner exploded');
    };
    const result = await runTool(invocation(), policy, deps(runner, store));
    expect(store.records).toHaveLength(1);
    expect(result.classification.status).toBe('failed');
    expect(store.records[0].result.spawnErrorCode).toBeDefined();
  });

  describe('with real environment variables', () => {
    beforeEach(() => {
      vi.stubEnv('NODE_OPTIONS', '--require /evil.js');
      vi.stubEnv('GITHUB_TOKEN', 'ghp_fake');
      vi.stubEnv('SEMGREP_APP_TOKEN', 'fake');
      vi.stubEnv('npm_config_registry', 'https://evil.example');
    });

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it('does not hand denied process.env variables to the runner for any request', async () => {
      const store = new FakeStore();
      const { runner, requests } = fakeRunner(outcome());
      await runTool(invocation(), policy, deps(runner, store));
      expect(requests.length).toBeGreaterThanOrEqual(2);
      for (const req of requests) {
        const keys = Object.keys(req.env);
        expect(keys).not.toContain('NODE_OPTIONS');
        expect(keys).not.toContain('GITHUB_TOKEN');
        expect(keys).not.toContain('SEMGREP_APP_TOKEN');
        expect(keys).not.toContain('npm_config_registry');
        expect(Object.values(req.env)).not.toContain('ghp_fake');
      }
      expect(JSON.stringify(store.records[0])).not.toContain('ghp_fake');
    });
  });

  describe('outputFrom file', () => {
    let base: string;
    let work: string;
    let outside: string;

    beforeEach(async () => {
      base = await realpath(await mkdtemp(path.join(tmpdir(), 'tessera-rt-')));
      work = path.join(base, 'work');
      outside = path.join(base, 'outside');
      await mkdir(path.join(work, 'src'), { recursive: true });
      await mkdir(outside, { recursive: true });
    });

    afterEach(async () => {
      await rm(base, { recursive: true, force: true });
    });

    function fileInvocation(file: string): ToolInvocation {
      return invocation({
        cwd: path.join(work, 'src'),
        outputFrom: { file },
        pathTokens: { [work]: '<WORK>' },
      });
    }

    it('reads a report inside the work dir', async () => {
      await writeFile(path.join(work, 'src', 'report.json'), '{"inside":true}');
      const store = new FakeStore();
      const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
      const result = await runTool(fileInvocation('report.json'), policy, deps(runner, store));
      expect(result.classification.status).toBe('completed');
      expect(store.artifacts.map((a) => a.bytes.toString('utf8'))).toContain('{"inside":true}');
    });

    it('rejects a report path that escapes the work dir via ..', async () => {
      await writeFile(path.join(outside, 'secret.json'), '{"secret":"outside-content"}');
      const store = new FakeStore();
      const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
      const result = await runTool(fileInvocation('../../outside/secret.json'), policy, deps(runner, store));
      expect(store.records).toHaveLength(1);
      expect(result.classification.status).toBe('failed');
      expect(store.records[0].status).toBe('failed');
      expect(store.records[0].output).toBeNull();
      expect(JSON.stringify(store.artifacts.map((a) => a.bytes.toString('utf8')))).not.toContain('outside-content');
      expect(JSON.stringify(store.records[0])).not.toContain('outside-content');
    });

    it('rejects an escaping .. report path as rejected, not as missing, even when the target does not exist', async () => {
      const store = new FakeStore();
      const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
      const result = await runTool(fileInvocation('../../outside/absent.json'), policy, deps(runner, store));
      expect(result.classification.status).toBe('failed');
      expect(result.parsed.error).toBe('report path rejected');
      expect(store.records[0].output).toBeNull();
    });

    it('rejects a report that is a symlink to a file outside the work dir', async () => {
      await writeFile(path.join(outside, 'secret.json'), '{"secret":"outside-content"}');
      await symlink(path.join(outside, 'secret.json'), path.join(work, 'src', 'report.json'));
      const store = new FakeStore();
      const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
      const result = await runTool(fileInvocation('report.json'), policy, deps(runner, store));
      expect(store.records).toHaveLength(1);
      expect(result.classification.status).toBe('failed');
      expect(store.records[0].output).toBeNull();
      expect(JSON.stringify(store.artifacts.map((a) => a.bytes.toString('utf8')))).not.toContain('outside-content');
    });

    it('rejects a report reached through a symlinked directory pointing outside the work dir', async () => {
      await writeFile(path.join(outside, 'secret.json'), '{"secret":"outside-content"}');
      await symlink(outside, path.join(work, 'src', 'linkdir'));
      const store = new FakeStore();
      const { runner } = fakeRunner(outcome({ stdout: Buffer.alloc(0) }));
      const result = await runTool(fileInvocation('linkdir/secret.json'), policy, deps(runner, store));
      expect(result.classification.status).toBe('failed');
      expect(store.records[0].output).toBeNull();
      expect(JSON.stringify(store.artifacts.map((a) => a.bytes.toString('utf8')))).not.toContain('outside-content');
    });
  });
});
