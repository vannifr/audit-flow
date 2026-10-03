import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { gitleaksPolicy, runGitleaksScan } from '../../../../src/scan/tools/gitleaks';
import type { GitleaksLeak } from '../../../../src/scan/tools/gitleaks';
import { MAX_FINDINGS_PER_STEP } from '../../../../src/scan/scan-types';
import type { ScanContext } from '../../../../src/scan/scan-types';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../../../src/scan/tool-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../../src/evidence/types';

const T0 = new Date('2026-01-01T00:00:00.000Z');
const T1 = new Date('2026-01-01T00:00:01.000Z');
const WORK = '/tmp/tessera-abc';
const REPO = '/tmp/tessera-abc/src';
const CONFIG_DIR = '/opt/tessera/config/scanners';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const PLAIN_SECRET = 'zq-plain-secret-value-9f3a7c1d';

interface Fixture {
  args: string[];
  exitCode: number;
  stdout: string;
  stderr: string;
}

function fixture(name: string): Fixture {
  return JSON.parse(readFileSync(path.join(__dirname, '../../../fixtures/tools', name), 'utf8')) as Fixture;
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

  everything(): string {
    return JSON.stringify(this.records) + this.artifacts.map((a) => a.bytes.toString('utf8')).join('\n');
  }
}

function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: Buffer.from('[]\n'),
    stderr: Buffer.alloc(0),
    stdoutTruncated: false,
    timedOut: false,
    startedAt: T0,
    endedAt: T1,
    ...partial,
  };
}

function fromFixture(name: string): ProcessOutcome {
  const f = fixture(name);
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

function setup(main: ProcessOutcome, overrides: Partial<ScanContext> = {}) {
  const requests: ProcessRequest[] = [];
  const runner: ProcessRunner = async (req) => {
    requests.push(req);
    if (req.args.length === 1 && req.args[0] === 'version') {
      return outcome({ stdout: Buffer.from('8.30.1\n') });
    }
    return main;
  };
  const store = new FakeStore();
  const ctx: ScanContext = {
    run: { runId: 'run-1', workDir: WORK, repoDir: REPO },
    source: { repoDir: REPO, revision: 'a'.repeat(40) },
    repoUrl: 'https://example.invalid/repo.git',
    attempt: 2,
    deps: { runner, store, clock: () => T1, frameworkVersion: '0.0.0-test' },
    workerEnv: {},
    configDir: CONFIG_DIR,
    ...overrides,
  };
  return { ctx, store, requests };
}

function leakJson(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    RuleID: 'generic-api-key',
    Description: 'Detected a Generic API Key',
    StartLine: 4,
    EndLine: 4,
    Match: "internalApiKey: 'REDACTED'",
    Secret: 'REDACTED',
    File: 'src/config.js',
    Fingerprint: 'src/config.js:generic-api-key:4',
    ...overrides,
  };
}

function manyLeaks(n: number): Buffer {
  return Buffer.from(JSON.stringify(Array.from({ length: n }, (_, i) => leakJson({ StartLine: i + 1, Fingerprint: `f${i}` }))));
}

describe('runGitleaksScan', () => {
  it('reports a clean scan as completed without cause', async () => {
    const { ctx, store } = setup(fromFixture('gitleaks-clean.json'));
    const result = await runGitleaksScan(ctx);
    expect(result.scanner).toBe('gitleaks');
    expect(result.findings).toEqual([]);
    expect(result.status).toEqual({
      scanner: 'gitleaks',
      required: true,
      status: 'completed',
      heuristic: false,
      toolVersion: '8.30.1',
      findingCount: 0,
      evidenceRecordIds: ['scan.gitleaks.a2'],
    });
    expect(result.evidence.recordId).toBe('scan.gitleaks.a2');
    expect(store.records).toHaveLength(1);
    expect(store.records[0].result.exitClass).toBe('success');
  });

  it('turns a leak with exit 42 into one finding and completed/issues-found', async () => {
    const { ctx, store } = setup(fromFixture('gitleaks-leak.json'));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('completed');
    expect(result.status.cause).toBe('issues-found');
    expect(result.status.findingCount).toBe(1);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toEqual({
      id: 'LEAK-1',
      title: 'Secret detected: generic-api-key',
      description: 'Hardcoded secret found in src/config.js',
      severity: 'P0',
      category: 'security-data',
      evidence: [
        {
          type: 'scan-output',
          file: 'src/config.js',
          line: 4,
          content: "internalApiKey: '[REDACTED]'",
          tool: 'gitleaks',
          timestamp: T1,
        },
      ],
      remediation: {
        description: 'Remove secret from code and rotate immediately. Move to environment variables or secrets manager.',
        effort: 'hours',
        priority: 'immediate',
      },
      verified: false,
      createdAt: T1,
      evidenceRef: result.evidence,
      scanner: 'gitleaks',
    });
    expect(result.evidence.recordId).toBe('scan.gitleaks.a2');
    expect(result.evidence.recordSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(store.records[0].result.exitClass).toBe('issues-found');
    expect(store.records[0].findingIds).toEqual(['LEAK-1']);
  });

  it('never leaks the secret value into findings, records or artifacts', async () => {
    const stdout = Buffer.from(
      JSON.stringify([
        leakJson({ Secret: AWS_KEY, Match: `aws_key = ${AWS_KEY}`, Description: `key ${AWS_KEY}` }),
        leakJson({ Secret: PLAIN_SECRET, Match: `value: ${PLAIN_SECRET}`, RuleID: 'custom', StartLine: 9, Fingerprint: `x:${PLAIN_SECRET}` }),
      ]),
    );
    const { ctx, store } = setup(outcome({ exitCode: 42, stdout, stderr: Buffer.from(`leak ${AWS_KEY}`) }));
    const result = await runGitleaksScan(ctx);
    expect(result.findings).toHaveLength(2);
    for (const secret of [AWS_KEY, PLAIN_SECRET]) {
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(store.everything()).not.toContain(secret);
    }
    const stored = store.artifacts.find((a) => a.suffix === 'stdout.json');
    expect(stored).toBeDefined();
    const parsed = JSON.parse(stored!.bytes.toString('utf8')) as Record<string, string>[];
    expect(parsed.map((p) => p.Secret)).toEqual(['[REDACTED]', '[REDACTED]']);
    expect(parsed.map((p) => p.Match)).toEqual(['[REDACTED]', '[REDACTED]']);
  });

  it('classifies exit 1 with an empty report as failed/tool-error', async () => {
    const { ctx, store } = setup(fromFixture('gitleaks-error.json'));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBe('tool-error');
    expect(result.status.causeDetail).toContain('code 1');
    expect(result.findings).toEqual([]);
    expect(store.records[0].result.exitClass).toBe('tool-error');
  });

  it('classifies other exit codes as failed/tool-error', async () => {
    const { ctx } = setup(outcome({ exitCode: 2, stdout: Buffer.from('[]') }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBe('tool-error');
    expect(result.findings).toEqual([]);
  });

  it('reports a missing binary as unavailable/not-installed', async () => {
    const { ctx } = setup(outcome({ exitCode: null, stdout: Buffer.alloc(0), spawnErrorCode: 'ENOENT' }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('unavailable');
    expect(result.status.cause).toBe('not-installed');
    expect(result.status.findingCount).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it('reports a timeout as failed/timeout', async () => {
    const { ctx } = setup(outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true, stdout: Buffer.from('[') }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBe('timeout');
    expect(result.findings).toEqual([]);
  });

  it('reports truncated output as partial/output-truncated', async () => {
    const { ctx } = setup(outcome({ exitCode: 42, stdout: Buffer.from('[{"RuleID":"a"'), stdoutTruncated: true }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('partial');
    expect(result.status.cause).toBe('output-truncated');
  });

  it('reports non-JSON output as failed/parse-error', async () => {
    const { ctx } = setup(outcome({ exitCode: 42, stdout: Buffer.from('not json at all') }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBe('parse-error');
    expect(result.findings).toEqual([]);
  });

  it('treats a success exit with empty output as failed, never as clean', async () => {
    const { ctx } = setup(outcome({ exitCode: 0, stdout: Buffer.alloc(0) }));
    const result = await runGitleaksScan(ctx);
    expect(result.status.status).toBe('failed');
    expect(result.status.cause).toBe('parse-error');
  });

  it('caps findings at the step maximum and marks the step partial', async () => {
    const { ctx, store } = setup(outcome({ exitCode: 42, stdout: manyLeaks(MAX_FINDINGS_PER_STEP + 1) }));
    const result = await runGitleaksScan(ctx);
    expect(result.findings).toHaveLength(MAX_FINDINGS_PER_STEP);
    expect(result.findings[MAX_FINDINGS_PER_STEP - 1].id).toBe(`LEAK-${MAX_FINDINGS_PER_STEP}`);
    expect(result.status.status).toBe('partial');
    expect(result.status.cause).toBe('findings-truncated');
    expect(result.status.findingCount).toBe(MAX_FINDINGS_PER_STEP);
    expect(store.records[0].findingIds).toHaveLength(MAX_FINDINGS_PER_STEP);
    expect(store.records[0].status).toBe('partial');
  });

  it('does not truncate at exactly the maximum', async () => {
    const { ctx } = setup(outcome({ exitCode: 42, stdout: manyLeaks(MAX_FINDINGS_PER_STEP) }));
    const result = await runGitleaksScan(ctx);
    expect(result.findings).toHaveLength(MAX_FINDINGS_PER_STEP);
    expect(result.status.status).toBe('completed');
    expect(result.status.cause).toBe('issues-found');
  });

  it('invokes gitleaks without a shell and with the exact hardened arguments', async () => {
    const { ctx, requests } = setup(fromFixture('gitleaks-clean.json'));
    await runGitleaksScan(ctx);
    const main = requests.find((r) => r.args[0] === 'dir');
    expect(main).toBeDefined();
    expect(main!.file).toBe('gitleaks');
    expect(main!.cwd).toBe(REPO);
    expect(main!.args).toEqual([
      'dir',
      '--no-banner',
      '--redact=100',
      '--exit-code',
      '42',
      '--report-format',
      'json',
      '--report-path',
      '-',
      '--config',
      '/opt/tessera/config/scanners/gitleaks.toml',
      '--ignore-gitleaks-allow',
      '.',
    ]);
    expect(requests.some((r) => r.file === 'gitleaks' && r.args.length === 1 && r.args[0] === 'version')).toBe(true);
    expect(requests.some((r) => r.file === 'sh' || r.file === 'bash')).toBe(false);
  });

  it('takes the config path from ctx.configDir', async () => {
    const { ctx, requests } = setup(fromFixture('gitleaks-clean.json'), { configDir: '/srv/other' });
    await runGitleaksScan(ctx);
    const main = requests.find((r) => r.args[0] === 'dir')!;
    expect(main.args[main.args.indexOf('--config') + 1]).toBe('/srv/other/gitleaks.toml');
  });

  it('tokenizes work and source paths in the stored record', async () => {
    const { ctx, store } = setup(fromFixture('gitleaks-clean.json'));
    await runGitleaksScan(ctx);
    expect(store.records[0].action.cwd).toBe('<SRC>');
    expect(store.records[0].attempt).toBe(2);
    expect(store.records[0].stepId).toBe('scan.gitleaks');
    expect(store.records[0].action.command).toBe('gitleaks');
  });

  it('relativizes absolute file paths inside the repo and keeps outside ones', async () => {
    const stdout = Buffer.from(
      JSON.stringify([leakJson({ File: `${REPO}/a/b.js` }), leakJson({ File: '/elsewhere/c.js' })]),
    );
    const { ctx } = setup(outcome({ exitCode: 42, stdout }));
    const result = await runGitleaksScan(ctx);
    expect(result.findings[0].evidence[0].file).toBe('a/b.js');
    expect(result.findings[1].evidence[0].file).toBe('/elsewhere/c.js');
  });
});

describe('gitleaksPolicy', () => {
  const run = (partial: Partial<ProcessOutcome>) => outcome(partial);

  it('declares tool, scanner and version args', () => {
    expect(gitleaksPolicy.tool).toBe('gitleaks');
    expect(gitleaksPolicy.scanner).toBe('gitleaks');
    expect(gitleaksPolicy.versionArgs).toEqual(['version']);
  });

  it('parses an array of leaks and an empty array', () => {
    expect(gitleaksPolicy.parse(Buffer.from('[]\n'))).toEqual({ ok: true, value: [] });
    const parsed = gitleaksPolicy.parse(Buffer.from(JSON.stringify([leakJson()])));
    expect(parsed.ok).toBe(true);
    expect(parsed.value).toEqual([
      {
        RuleID: 'generic-api-key',
        Description: 'Detected a Generic API Key',
        File: 'src/config.js',
        StartLine: 4,
        EndLine: 4,
        Fingerprint: 'src/config.js:generic-api-key:4',
        Match: "internalApiKey: 'REDACTED'",
        Secret: 'REDACTED',
      },
    ]);
  });

  it('defaults missing optional fields', () => {
    const parsed = gitleaksPolicy.parse(Buffer.from('[{"RuleID":"r","File":"f","StartLine":"x"}]'));
    expect(parsed.value).toEqual([
      { RuleID: 'r', Description: '', File: 'f', StartLine: 0, EndLine: 0, Fingerprint: '', Match: '', Secret: '' },
    ]);
  });

  it('parses empty output as no leaks', () => {
    expect(gitleaksPolicy.parse(Buffer.from('  \n'))).toEqual({ ok: true, value: [] });
  });

  it('rejects non-JSON, non-array and malformed entries', () => {
    expect(gitleaksPolicy.parse(Buffer.from('nope')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('{"a":1}')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('[1]')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('[null]')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('[[]]')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('[{"File":"f"}]')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('[{"RuleID":"r"}]')).ok).toBe(false);
    expect(gitleaksPolicy.parse(Buffer.from('nope')).error).toContain('JSON');
  });

  it('classifies exit codes per R3', () => {
    const ok = { ok: true, value: [] as GitleaksLeak[] };
    expect(gitleaksPolicy.classify(run({ exitCode: 0 }), ok)).toEqual({ status: 'completed', exitClass: 'success' });
    expect(gitleaksPolicy.classify(run({ exitCode: 42 }), ok)).toEqual({
      status: 'completed',
      exitClass: 'issues-found',
      cause: 'issues-found',
    });
    const one = gitleaksPolicy.classify(run({ exitCode: 1 }), ok);
    expect(one).toMatchObject({ status: 'failed', exitClass: 'tool-error', cause: 'tool-error' });
    expect(gitleaksPolicy.classify(run({ exitCode: 3 }), ok).status).toBe('failed');
    const none = gitleaksPolicy.classify(run({ exitCode: null }), ok);
    expect(none).toMatchObject({ status: 'failed', cause: 'tool-error' });
    expect(none.causeDetail).toContain('no exit code');
  });

  it('classifies an empty report on a success exit as parse-error', () => {
    const result = gitleaksPolicy.classify(run({ exitCode: 0, stdout: Buffer.alloc(0) }), { ok: true, value: [] });
    expect(result).toMatchObject({ status: 'failed', cause: 'parse-error' });
  });

  it('classifies more than the cap as partial/findings-truncated', () => {
    const leaks = Array.from({ length: MAX_FINDINGS_PER_STEP + 1 }, () => ({}) as GitleaksLeak);
    const result = gitleaksPolicy.classify(run({ exitCode: 42 }), { ok: true, value: leaks });
    expect(result).toMatchObject({ status: 'partial', exitClass: 'issues-found', cause: 'findings-truncated' });
    expect(result.causeDetail).toContain(String(MAX_FINDINGS_PER_STEP + 1));
  });

  it('classifies an unparsed non-empty report by exit code only', () => {
    const result = gitleaksPolicy.classify(run({ exitCode: 42, stdout: Buffer.from('x') }), { ok: false, error: 'bad' });
    expect(result.status).toBe('completed');
  });

  it('sanitizes parsed output: Secret and Match always [REDACTED], whitelist only', () => {
    const raw = Buffer.from(JSON.stringify([leakJson({ Secret: PLAIN_SECRET, Match: PLAIN_SECRET, Author: 'someone' })]));
    const parsed = gitleaksPolicy.parse(raw);
    const out = gitleaksPolicy.sanitize(raw, parsed);
    expect(out.mediaType).toBe('application/json');
    expect(out.bytes.toString('utf8')).not.toContain(PLAIN_SECRET);
    expect(out.bytes.toString('utf8')).not.toContain('someone');
    expect(out.redactions).toBeGreaterThanOrEqual(1);
    expect(JSON.parse(out.bytes.toString('utf8'))).toEqual([
      {
        RuleID: 'generic-api-key',
        Description: 'Detected a Generic API Key',
        File: 'src/config.js',
        StartLine: 4,
        EndLine: 4,
        Fingerprint: 'src/config.js:generic-api-key:4',
        Match: '[REDACTED]',
        Secret: '[REDACTED]',
      },
    ]);
  });

  it('counts no redactions for leaks without secret or match', () => {
    const raw = Buffer.from(JSON.stringify([leakJson({ Secret: '', Match: '' })]));
    expect(gitleaksPolicy.sanitize(raw, gitleaksPolicy.parse(raw)).redactions).toBe(0);
  });

  it('sanitizes unparsed output as redacted text', () => {
    const raw = Buffer.from(`oops ${AWS_KEY}`);
    const out = gitleaksPolicy.sanitize(raw, { ok: false, error: 'bad' });
    expect(out.mediaType).toBe('text/plain');
    expect(out.bytes.toString('utf8')).not.toContain(AWS_KEY);
    expect(out.redactions).toBeGreaterThan(0);
  });
});
