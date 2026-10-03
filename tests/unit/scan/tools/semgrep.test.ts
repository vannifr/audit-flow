import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { runSemgrepScan, semgrepPolicy } from '../../../../src/scan/tools/semgrep';
import type { ScanContext } from '../../../../src/scan/scan-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../../src/evidence/types';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../../../src/scan/tool-types';

const T0 = new Date('2026-01-01T00:00:00.000Z');
const T1 = new Date('2026-01-01T00:00:01.000Z');
const WORK = '/tmp/tessera-abc';
const REPO = `${WORK}/repo`;
const FIXTURES = path.resolve(__dirname, '../../../fixtures/tools');

const EXPECTED_ARGS = [
  '--metrics=off',
  '--config',
  'p/javascript',
  '--config',
  'p/nodejs',
  '--disable-nosem',
  '--disable-version-check',
  '--json',
  '--quiet',
  '.',
];

interface Fixture {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function fixture(name: string): Fixture {
  return JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8')) as Fixture;
}

function sha(bytes: Buffer): string {
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
    return { recordId: record.id, recordSha256: sha(Buffer.from(JSON.stringify(record))) };
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
    endedAt: T1,
    ...partial,
  };
}

function fromFixture(f: Fixture): ProcessOutcome {
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

function setup(main: ProcessOutcome, overrides: Partial<ScanContext> = {}) {
  const requests: ProcessRequest[] = [];
  const runner: ProcessRunner = async (req) => {
    requests.push(req);
    if (req.args.length === 1 && req.args[0] === '--version') {
      return outcome({ stdout: Buffer.from('1.178.0\n') });
    }
    return main;
  };
  const store = new FakeStore();
  const ctx: ScanContext = {
    run: { runId: 'run-1', workDir: WORK, repoDir: REPO },
    source: { repoDir: REPO, revision: 'a'.repeat(40) },
    repoUrl: 'https://example.invalid/repo.git',
    attempt: 1,
    deps: { runner, store, clock: () => T1, frameworkVersion: '0.0.0-test' },
    workerEnv: {},
    configDir: '/tmp/config',
    ...overrides,
  };
  return { ctx, store, requests };
}

function semgrepJson(results: unknown[], errors: unknown[] = []): Buffer {
  return Buffer.from(JSON.stringify({ version: '1.178.0', results, errors, paths: { scanned: ['a.js'] } }));
}

function result(overrides: Record<string, unknown> = {}) {
  return {
    check_id: 'javascript.express.security.injection.raw-html-format',
    path: 'src/server.js',
    start: { line: 15, col: 1 },
    end: { line: 15, col: 9 },
    extra: { message: 'Unsafe HTML', severity: 'WARNING', lines: 'requires login' },
    ...overrides,
  };
}

describe('runSemgrepScan', () => {
  it('reports a clean scan as completed without cause', async () => {
    const { ctx } = setup(fromFixture(fixture('semgrep-clean.json')));
    const res = await runSemgrepScan(ctx);
    expect(res.scanner).toBe('semgrep');
    expect(res.status).toMatchObject({
      scanner: 'semgrep',
      required: true,
      heuristic: false,
      status: 'completed',
      findingCount: 0,
      toolVersion: '1.178.0',
    });
    expect(res.status.cause).toBeUndefined();
    expect(res.findings).toEqual([]);
  });

  it('turns demo results into findings with issues-found', async () => {
    const { ctx, store } = setup(fromFixture(fixture('semgrep-results.json')));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('completed');
    expect(res.status.cause).toBe('issues-found');
    expect(res.status.findingCount).toBe(4);
    expect(res.findings.map((f) => f.id)).toEqual(['SAST-1', 'SAST-2', 'SAST-3', 'SAST-4']);
    const first = res.findings[0]!;
    expect(first.title).toBe('raw-html-format');
    expect(first.category).toBe('security-injection');
    expect(first.verified).toBe(false);
    expect(first.createdAt).toEqual(T1);
    expect(first.scanner).toBe('semgrep');
    expect(first.evidenceRef).toEqual(res.evidence);
    expect(first.evidence).toHaveLength(1);
    expect(first.evidence[0]).toMatchObject({ type: 'scan-output', file: 'src/server.js', line: 15, tool: 'semgrep', timestamp: T1 });
    expect(first.evidence[0]!.content.startsWith('src/server.js:15 ')).toBe(true);
    const lines = res.findings.map((f) => `${f.evidence[0]!.file}:${f.evidence[0]!.line}`);
    expect(lines).toContain('src/server.js:15');
    expect(lines).toContain('src/server.js:19');
    expect(res.findings.map((f) => f.severity)).toEqual(['P1', 'P1', 'P1', 'P0']);
    expect(store.records).toHaveLength(1);
    expect(store.records[0]!.findingIds).toEqual(['SAST-1', 'SAST-2', 'SAST-3', 'SAST-4']);
    expect(res.status.evidenceRecordIds).toEqual([store.records[0]!.id]);
  });

  it('never uses source lines as content', async () => {
    const { ctx } = setup(fromFixture(fixture('semgrep-results.json')));
    const res = await runSemgrepScan(ctx);
    for (const f of res.findings) {
      expect(f.evidence[0]!.content).not.toContain('requires login');
      expect(f.description).not.toContain('requires login');
    }
  });

  it('does not store lines in the evidence artifact', async () => {
    const { ctx, store } = setup(fromFixture(fixture('semgrep-results.json')));
    await runSemgrepScan(ctx);
    const stored = store.artifacts[0]!.bytes.toString('utf8');
    expect(stored).not.toContain('requires login');
    expect(stored).toContain('raw-html-format');
  });

  it('marks the crash fixture as failed tool-error', async () => {
    const { ctx } = setup(fromFixture(fixture('semgrep-crash.json')));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('tool-error');
    expect(res.findings).toEqual([]);
  });

  it('marks results with tool errors as partial tool-reported-errors', async () => {
    const stdout = semgrepJson([result()], [{ code: 3, level: 'warn', type: 'PartialParsing', message: 'broken file' }]);
    const { ctx } = setup(outcome({ exitCode: 0, stdout }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('tool-reported-errors');
    expect(res.findings).toHaveLength(1);
  });

  it('marks errors without results as partial too', async () => {
    const stdout = semgrepJson([], [{ code: 3, level: 'warn', type: 'X', message: 'broken file' }]);
    const { ctx } = setup(outcome({ exitCode: 1, stdout }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('tool-reported-errors');
  });

  it('accepts exit 1 with results as completed', async () => {
    const { ctx } = setup(outcome({ exitCode: 1, stdout: semgrepJson([result()]) }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('completed');
    expect(res.status.cause).toBe('issues-found');
  });

  it('marks exit 2 with results as partial tool-error', async () => {
    const { ctx } = setup(outcome({ exitCode: 2, stdout: semgrepJson([result()]) }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('tool-error');
    expect(res.findings).toHaveLength(1);
  });

  it('marks non-JSON output as failed parse-error', async () => {
    const { ctx } = setup(outcome({ exitCode: 0, stdout: Buffer.from('Traceback: boom') }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('parse-error');
    expect(res.findings).toEqual([]);
  });

  it('marks JSON without a results array as failed parse-error', async () => {
    for (const body of ['[]', 'null', '{"errors":[]}', '{"results":{}}']) {
      const { ctx } = setup(outcome({ exitCode: 0, stdout: Buffer.from(body) }));
      const res = await runSemgrepScan(ctx);
      expect(res.status.status).toBe('failed');
      expect(res.status.cause).toBe('parse-error');
    }
  });

  it('marks a missing binary as unavailable not-installed', async () => {
    const { ctx } = setup(outcome({ exitCode: null, spawnErrorCode: 'ENOENT' }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('unavailable');
    expect(res.status.cause).toBe('not-installed');
    expect(res.findings).toEqual([]);
  });

  it('marks a timeout as failed timeout', async () => {
    const { ctx } = setup(outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('timeout');
  });

  it('marks truncated output as partial output-truncated', async () => {
    const { ctx } = setup(outcome({ exitCode: 0, stdout: Buffer.from('{"results":['), stdoutTruncated: true }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('output-truncated');
  });

  it('caps findings at 2000 and reports findings-truncated', async () => {
    const many = Array.from({ length: 2005 }, (_, i) => result({ path: `src/f${i}.js` }));
    const { ctx, store } = setup(outcome({ exitCode: 1, stdout: semgrepJson(many) }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings).toHaveLength(2000);
    expect(res.status.findingCount).toBe(2000);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('findings-truncated');
    expect(res.findings[1999]!.id).toBe('SAST-2000');
    expect(store.records[0]!.findingIds).toHaveLength(2000);
  });

  it('keeps exactly 2000 findings completed', async () => {
    const many = Array.from({ length: 2000 }, (_, i) => result({ path: `src/f${i}.js` }));
    const { ctx } = setup(outcome({ exitCode: 1, stdout: semgrepJson(many) }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings).toHaveLength(2000);
    expect(res.status.status).toBe('completed');
  });

  it('keeps an earlier partial cause when findings overflow', async () => {
    const many = Array.from({ length: 2001 }, (_, i) => result({ path: `src/f${i}.js` }));
    const { ctx } = setup(outcome({ exitCode: 2, stdout: semgrepJson(many) }));
    const res = await runSemgrepScan(ctx);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('tool-error');
    expect(res.findings).toHaveLength(2000);
  });

  it('deduplicates identical check, path and line', async () => {
    const dup = [
      result(),
      result(),
      result({ start: { line: 16 } }),
      result({ path: 'src/other.js' }),
      result({ check_id: 'other.rule.name' }),
    ];
    const { ctx } = setup(outcome({ exitCode: 1, stdout: semgrepJson(dup) }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings).toHaveLength(4);
    expect(res.findings.map((f) => f.id)).toEqual(['SAST-1', 'SAST-2', 'SAST-3', 'SAST-4']);
    expect(res.status.findingCount).toBe(4);
  });

  it('invokes semgrep with the exact fixed arguments and no auto config', async () => {
    const { ctx, requests } = setup(fromFixture(fixture('semgrep-clean.json')));
    await runSemgrepScan(ctx);
    const main = requests.find((r) => r.args.length > 1)!;
    expect(main.file).toBe('semgrep');
    expect(main.args).toEqual(EXPECTED_ARGS);
    expect(main.args).toContain('--metrics=off');
    expect(main.args).toContain('--disable-nosem');
    expect(main.args.join(' ')).not.toContain('auto');
    expect(main.args.join(' ')).not.toContain('/tmp');
    expect(main.cwd).toBe(REPO);
  });

  it('records stepId, packs and args in the evidence record', async () => {
    const { ctx, store } = setup(fromFixture(fixture('semgrep-clean.json')));
    await runSemgrepScan(ctx);
    const rec = store.records[0]!;
    expect(rec.stepId).toBe('scan.semgrep');
    expect(rec.id).toBe('scan.semgrep.a1');
    expect(rec.scanner).toBe('semgrep');
    expect(rec.runId).toBe('run-1');
    expect(rec.action.args).toEqual(EXPECTED_ARGS);
    expect(rec.action.inputs.configs).toBe('p/javascript,p/nodejs');
    expect(rec.source).toEqual({ repoUrl: 'https://example.invalid/repo.git', revision: 'a'.repeat(40) });
    expect(store.artifacts[0]!.suffix).toBe('stdout.json');
  });

  it('applies the old severity mapping and falls back to defaults', async () => {
    const stdout = semgrepJson([
      result({ path: 'a.js', extra: { message: 'm', severity: 'ERROR' } }),
      result({ path: 'b.js', extra: { message: 'm', severity: 'WARNING' } }),
      result({ path: 'c.js', extra: { message: 'm', severity: 'INFO' } }),
      result({ path: 'd.js', extra: { message: 'm', severity: 'weird' } }),
      result({ path: 'e.js', extra: { message: 'm' } }),
    ]);
    const { ctx } = setup(outcome({ exitCode: 1, stdout }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings.map((f) => f.severity)).toEqual(['P0', 'P1', 'P2', 'P3', 'P3']);
  });

  it('tolerates sparse results', async () => {
    const stdout = semgrepJson([
      { check_id: 'a.b.c', path: './src/x.js', extra: {} },
      { start: { line: 'x' } },
      42,
    ]);
    const { ctx } = setup(outcome({ exitCode: 1, stdout }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings).toHaveLength(2);
    const [a, b] = res.findings;
    expect(a!.evidence[0]!.file).toBe('src/x.js');
    expect(a!.evidence[0]!.line).toBeUndefined();
    expect(a!.description).toBe('Security issue detected');
    expect(a!.evidence[0]!.content).toBe('src/x.js Security issue detected');
    expect(b!.title).toBe('unknown-rule');
  });

  it('redacts secrets from messages', async () => {
    const stdout = semgrepJson([
      result({ extra: { message: 'password = "hunter2hunter2hunter2hunter2"', severity: 'ERROR' } }),
    ]);
    const { ctx, store } = setup(outcome({ exitCode: 1, stdout }));
    const res = await runSemgrepScan(ctx);
    expect(res.findings[0]!.evidence[0]!.content).not.toContain('hunter2');
    expect(res.findings[0]!.description).not.toContain('hunter2');
    expect(store.artifacts[0]!.bytes.toString('utf8')).not.toContain('hunter2');
  });
});

describe('semgrepPolicy', () => {
  it('declares tool, scanner and version args', () => {
    expect(semgrepPolicy.tool).toBe('semgrep');
    expect(semgrepPolicy.scanner).toBe('semgrep');
    expect(semgrepPolicy.versionArgs).toEqual(['--version']);
  });

  it('parses valid reports and rejects the rest', () => {
    expect(semgrepPolicy.parse(semgrepJson([result()])).ok).toBe(true);
    expect(semgrepPolicy.parse(Buffer.from('{"results":[]}')).ok).toBe(true);
    expect(semgrepPolicy.parse(Buffer.from('nope')).ok).toBe(false);
    expect(semgrepPolicy.parse(Buffer.from('[1]')).ok).toBe(false);
    expect(semgrepPolicy.parse(Buffer.from('{"results":[],"errors":"x"}')).ok).toBe(false);
  });

  it('classifies by exit code and content', () => {
    const clean = semgrepPolicy.parse(semgrepJson([]));
    const hits = semgrepPolicy.parse(semgrepJson([result()]));
    const errs = semgrepPolicy.parse(semgrepJson([result()], [{ message: 'x' }]));
    const bad = semgrepPolicy.parse(Buffer.from('x'));
    const o = (exitCode: number | null) => outcome({ exitCode });
    expect(semgrepPolicy.classify(o(0), clean)).toEqual({ status: 'completed', exitClass: 'success' });
    expect(semgrepPolicy.classify(o(0), hits)).toEqual({ status: 'completed', exitClass: 'issues-found', cause: 'issues-found' });
    expect(semgrepPolicy.classify(o(1), errs)).toMatchObject({ status: 'partial', cause: 'tool-reported-errors' });
    expect(semgrepPolicy.classify(o(2), hits)).toMatchObject({ status: 'partial', exitClass: 'tool-error', cause: 'tool-error' });
    expect(semgrepPolicy.classify(o(2), clean)).toMatchObject({ status: 'failed', exitClass: 'tool-error', cause: 'tool-error' });
    expect(semgrepPolicy.classify(o(7), clean)).toMatchObject({ status: 'failed', cause: 'tool-error' });
    expect(semgrepPolicy.classify(o(null), clean)).toMatchObject({ status: 'failed', cause: 'tool-error' });
    expect(semgrepPolicy.classify(o(0), bad)).toMatchObject({ status: 'failed', cause: 'parse-error' });
  });

  it('sanitizes to a whitelist without lines, fix or metavars', () => {
    const raw = semgrepJson([
      result({
        extra: {
          message: 'm',
          severity: 'ERROR',
          lines: 'SECRET LINE',
          fix: 'SECRET FIX',
          metavars: { $A: 'SECRET' },
          metadata: { cwe: ['CWE-79'] },
        },
      }),
    ]);
    const parsed = semgrepPolicy.parse(raw);
    const out = semgrepPolicy.sanitize(raw, parsed);
    const text = out.bytes.toString('utf8');
    expect(out.mediaType).toBe('application/json');
    expect(text).not.toContain('SECRET');
    expect(text).toContain('CWE-79');
    expect(JSON.parse(text).results[0].check_id).toContain('raw-html-format');
    expect(JSON.parse(text).paths.scanned).toEqual(['a.js']);
  });

  it('sanitizes unparsable output as redacted text', () => {
    const raw = Buffer.from('token = "abcdefghijklmnopqrstuvwxyz0123456789"');
    const out = semgrepPolicy.sanitize(raw, semgrepPolicy.parse(raw));
    expect(out.mediaType).toBe('text/plain');
    expect(out.bytes.toString('utf8')).not.toContain('abcdefghijklmnopqrstuvwxyz0123456789');
  });

  it('sanitizes sparse reports', () => {
    const raw = Buffer.from(JSON.stringify({ results: [7, { extra: 'x' }], errors: [3, { message: 'e' }] }));
    const out = semgrepPolicy.sanitize(raw, semgrepPolicy.parse(raw));
    const body = JSON.parse(out.bytes.toString('utf8'));
    expect(body.results).toHaveLength(1);
    expect(body.errors).toHaveLength(1);
  });
});

describe('runSemgrepScan override attempts (TS-029, TS-030, FR-014)', () => {
  it('puts the semgrep steering attempts in its evidence record and keeps --disable-nosem on', async () => {
    const attempts = [
      { kind: 'control-file' as const, path: '.gitleaksignore', detail: 'gitleaks ignore list, removed', neutralizedBy: 'removed-from-working-copy' as const },
      { kind: 'control-file' as const, path: 'src/.semgrepignore', detail: 'semgrep ignore list, removed', sha256: 'b'.repeat(64), neutralizedBy: 'removed-from-working-copy' as const },
      { kind: 'project-config' as const, path: '.semgrep.yml', detail: 'semgrep configuration, removed', neutralizedBy: 'removed-from-working-copy' as const },
      { kind: 'inline-marker' as const, path: 'src/a.js', detail: 'inline marker "gitleaks:allow" x2', neutralizedBy: 'framework-flag' as const },
      { kind: 'inline-marker' as const, path: 'src/a.js', detail: 'inline marker "nosemgrep" x1', neutralizedBy: 'framework-flag' as const },
    ];
    const { ctx, store, requests } = setup(outcome({ stdout: semgrepJson([]) }), { overrideAttempts: attempts });
    await runSemgrepScan(ctx);
    expect(store.records[0].overrideAttempts).toEqual([attempts[1], attempts[2], attempts[4]]);
    const main = requests.find((r) => r.args.includes('--json'));
    expect(main?.args).toContain('--disable-nosem');
  });
});
