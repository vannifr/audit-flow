import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, chmodSync } from 'node:fs';
import { mkdtemp, rm, readFile, readdir, stat, symlink, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import type { ArtifactRef, EvidenceRecord } from '../../../src/evidence/types';

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

function makeRecord(stepId: string, attempt: number, runId: string, extra: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    schema: 'tessera.evidence/v1',
    id: `${stepId}.a${attempt}`,
    runId,
    stepId,
    attempt,
    kind: 'tool-run',
    scanner: 'npm-audit',
    action: { command: 'npm', args: ['audit', '--json'], cwd: '<SOURCE>', envOverrides: {}, envPassthrough: [], inputs: {} },
    tool: { name: 'npm', version: '10.0.0' },
    source: { repoUrl: 'https://example.invalid/repo.git', revision: 'a'.repeat(40) },
    startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:00:01.000Z',
    durationMs: 1000,
    result: { exitCode: 0, signal: null, exitClass: 'success', timedOut: false },
    status: 'completed',
    output: null,
    stderr: null,
    findingIds: [],
    overrideAttempts: [],
    recordedBy: { framework: 'tessera', version: '0.0.0' },
    ...extra,
  };
}

const mode = async (p: string): Promise<number> => (await stat(p)).mode & 0o777;

describe('evidence store', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-evstore-'));
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('TS-013 returns an evidence ref whose recordId is <stepId>.a<attempt> and publishes records/<id>.json', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const record = makeRecord('scan.npm-audit', 2, 'run-1');
    const ref = await store.writeRecord(record);
    expect(ref.recordId).toBe('scan.npm-audit.a2');
    const file = path.join(store.bundleDir, 'records', 'scan.npm-audit.a2.json');
    const bytes = await readFile(file);
    expect(JSON.parse(bytes.toString('utf8'))).toEqual(record);
    expect(ref.recordSha256).toBe(sha(bytes));
  });

  it('TS-013 records a failed step with its own record next to a successful one', async () => {
    const store = createEvidenceStore(root, 'run-1');
    await store.writeRecord(makeRecord('scan.gitleaks', 1, 'run-1', { status: 'failed', result: { exitCode: null, signal: null, exitClass: 'spawn-error', timedOut: false, spawnErrorCode: 'ENOENT' } }));
    await store.writeRecord(makeRecord('scan.semgrep', 1, 'run-1'));
    const names = (await readdir(path.join(store.bundleDir, 'records'))).filter((n) => !n.startsWith('.')).sort();
    expect(names).toEqual(['scan.gitleaks.a1.json', 'scan.semgrep.a1.json']);
  });

  it('TS-015 stores action, tool, times, result and the raw output fingerprint in the record', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const raw = Buffer.from('{"raw":true}');
    const stored = Buffer.from('{"raw":"[REDACTED]"}');
    const artifact = await store.writeArtifact('scan.npm-audit.a1', 'stdout.json', stored, {
      mediaType: 'application/json',
      rawBytes: raw.length,
      rawSha256: sha(raw),
      redactions: 1,
      truncated: false,
    });
    await store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1', { output: artifact }));
    const parsed = JSON.parse(await readFile(path.join(store.bundleDir, 'records', 'scan.npm-audit.a1.json'), 'utf8')) as EvidenceRecord;
    expect(parsed.action.command).toBe('npm');
    expect(parsed.tool).toEqual({ name: 'npm', version: '10.0.0' });
    expect(parsed.startedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(parsed.endedAt).toBe('2026-01-01T00:00:01.000Z');
    expect(parsed.result.exitCode).toBe(0);
    expect(parsed.output?.rawSha256).toBe(sha(raw));
  });

  it('R10 keeps the stored hash and the raw hash as two separate fields', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const raw = Buffer.from('password=hunter2');
    const stored = Buffer.from('password=[REDACTED:secret]');
    const ref: ArtifactRef = await store.writeArtifact('scan.gitleaks.a1', 'stdout.json', stored, {
      mediaType: 'text/plain',
      rawBytes: raw.length,
      rawSha256: sha(raw),
      redactions: 1,
      truncated: false,
    });
    expect(ref.sha256).toBe(sha(stored));
    expect(ref.rawSha256).toBe(sha(raw));
    expect(ref.sha256).not.toBe(ref.rawSha256);
    expect(ref.bytes).toBe(stored.length);
    expect(ref.rawBytes).toBe(raw.length);
    expect(ref.path).toBe('artifacts/scan.gitleaks.a1.stdout.json');
    const onDisk = await readFile(path.join(store.bundleDir, ref.path));
    expect(onDisk.equals(stored)).toBe(true);
  });

  it('TS-017 a second publish with the same id leaves the original bytes unchanged and returns the existing hash', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const first = makeRecord('scan.npm-audit', 1, 'run-1');
    const firstRef = await store.writeRecord(first);
    const file = path.join(store.bundleDir, 'records', 'scan.npm-audit.a1.json');
    const original = await readFile(file);
    const second = makeRecord('scan.npm-audit', 1, 'run-1', { status: 'failed', durationMs: 5 });
    const secondRef = await store.writeRecord(second);
    const after = await readFile(file);
    expect(after.equals(original)).toBe(true);
    expect(secondRef.recordSha256).toBe(firstRef.recordSha256);
    expect(secondRef.recordSha256).toBe(sha(original));
    expect(JSON.parse(after.toString('utf8')).status).toBe('completed');
  });

  it('TS-017 published record files are mode 0400 and the bundle folders are 0700', async () => {
    const store = createEvidenceStore(root, 'run-1');
    await store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'));
    const artifact = await store.writeArtifact('scan.npm-audit.a1', 'stdout.json', Buffer.from('{}'), {
      mediaType: 'application/json',
      rawBytes: 2,
      rawSha256: sha('{}'),
      redactions: 0,
      truncated: false,
    });
    expect(await mode(path.join(store.bundleDir, 'records', 'scan.npm-audit.a1.json'))).toBe(0o400);
    expect(await mode(path.join(store.bundleDir, artifact.path))).toBe(0o400);
    expect(await mode(store.bundleDir)).toBe(0o700);
    expect(await mode(path.join(store.bundleDir, 'records'))).toBe(0o700);
    expect(await mode(path.join(store.bundleDir, 'artifacts'))).toBe(0o700);
  });

  it('TS-017 does not overwrite an existing artifact with the same name', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const meta = { mediaType: 'text/plain' as const, rawBytes: 1, rawSha256: sha('a'), redactions: 0, truncated: false };
    const first = await store.writeArtifact('scan.npm-audit.a1', 'stderr.txt', Buffer.from('first'), meta);
    await store.writeArtifact('scan.npm-audit.a1', 'stderr.txt', Buffer.from('second'), meta).catch(() => undefined);
    expect((await readFile(path.join(store.bundleDir, first.path), 'utf8'))).toBe('first');
  });

  it('FR-011 staging leftovers are not published as records', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const staging = path.join(store.bundleDir, 'records', '.staging');
    await mkdir(staging, { recursive: true });
    await writeFile(path.join(staging, 'scan.semgrep.a1.json'), '{"partial":');
    await store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'));
    const published = (await readdir(path.join(store.bundleDir, 'records'))).filter((n) => n.endsWith('.json'));
    expect(published).toEqual(['scan.npm-audit.a1.json']);
  });

  it('FR-011 leaves no staging file behind after a successful publish', async () => {
    const store = createEvidenceStore(root, 'run-1');
    await store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'));
    const left = await readdir(path.join(store.bundleDir, 'records', '.staging'));
    expect(left).toEqual([]);
  });

  it('TS-018 two stores with different runIds never share files', async () => {
    const a = createEvidenceStore(root, 'run-a');
    const b = createEvidenceStore(root, 'run-b');
    expect(a.bundleDir).not.toBe(b.bundleDir);
    await a.writeRecord(makeRecord('scan.npm-audit', 1, 'run-a'));
    await b.writeRecord(makeRecord('scan.gitleaks', 1, 'run-b'));
    const inA = (await readdir(path.join(a.bundleDir, 'records'))).filter((n) => n.endsWith('.json'));
    const inB = (await readdir(path.join(b.bundleDir, 'records'))).filter((n) => n.endsWith('.json'));
    expect(inA).toEqual(['scan.npm-audit.a1.json']);
    expect(inB).toEqual(['scan.gitleaks.a1.json']);
  });

  it('TS-018 the same record id in two runs is stored separately with each run id', async () => {
    const a = createEvidenceStore(root, 'run-a');
    const b = createEvidenceStore(root, 'run-b');
    await a.writeRecord(makeRecord('scan.npm-audit', 1, 'run-a'));
    await b.writeRecord(makeRecord('scan.npm-audit', 1, 'run-b'));
    const ra = JSON.parse(await readFile(path.join(a.bundleDir, 'records', 'scan.npm-audit.a1.json'), 'utf8')) as EvidenceRecord;
    const rb = JSON.parse(await readFile(path.join(b.bundleDir, 'records', 'scan.npm-audit.a1.json'), 'utf8')) as EvidenceRecord;
    expect(ra.runId).toBe('run-a');
    expect(rb.runId).toBe('run-b');
  });

  it('TS-019 a resumed run republishing the same record id creates no duplicate', async () => {
    const first = createEvidenceStore(root, 'run-1');
    const record = makeRecord('source.clone', 1, 'run-1');
    const firstRef = await first.writeRecord(record);
    const resumed = createEvidenceStore(root, 'run-1');
    const resumedRef = await resumed.writeRecord(record);
    expect(resumed.bundleDir).toBe(first.bundleDir);
    expect(resumedRef).toEqual(firstRef);
    const names = (await readdir(path.join(first.bundleDir, 'records'))).filter((n) => n.endsWith('.json'));
    expect(names).toEqual(['source.clone.a1.json']);
  });

  it('TS-019 a retry attempt gets its own record id and keeps the earlier record', async () => {
    const store = createEvidenceStore(root, 'run-1');
    await store.writeRecord(makeRecord('source.clone', 1, 'run-1', { status: 'failed' }));
    await store.writeRecord(makeRecord('source.clone', 2, 'run-1'));
    const names = (await readdir(path.join(store.bundleDir, 'records'))).filter((n) => n.endsWith('.json')).sort();
    expect(names).toEqual(['source.clone.a1.json', 'source.clone.a2.json']);
  });

  it('refuses a symlink at the record path inside the bundle', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const outside = path.join(root, 'outside.json');
    await writeFile(outside, 'untouched');
    await mkdir(path.join(store.bundleDir, 'records'), { recursive: true });
    await symlink(outside, path.join(store.bundleDir, 'records', 'scan.npm-audit.a1.json'));
    await expect(store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'))).rejects.toThrow(/symlink/i);
    expect(await readFile(outside, 'utf8')).toBe('untouched');
  });

  it('refuses a symlinked artifacts directory inside the bundle', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const elsewhere = path.join(root, 'elsewhere');
    await mkdir(elsewhere);
    await mkdir(store.bundleDir, { recursive: true });
    await symlink(elsewhere, path.join(store.bundleDir, 'artifacts'));
    await expect(
      store.writeArtifact('scan.npm-audit.a1', 'stdout.json', Buffer.from('{}'), {
        mediaType: 'application/json',
        rawBytes: 2,
        rawSha256: sha('{}'),
        redactions: 0,
        truncated: false,
      }),
    ).rejects.toThrow(/symlink/i);
    expect(await readdir(elsewhere)).toEqual([]);
  });

  it('tightens a pre-existing bundle folder and records folder from 0755 to 0700', async () => {
    const bundle = path.join(root, 'run-1');
    mkdirSync(bundle);
    chmodSync(bundle, 0o755);
    mkdirSync(path.join(bundle, 'records'));
    chmodSync(path.join(bundle, 'records'), 0o755);
    const store = createEvidenceStore(root, 'run-1');
    await store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'));
    expect(await mode(bundle)).toBe(0o700);
    expect(await mode(path.join(bundle, 'records'))).toBe(0o700);
    expect(await mode(path.join(bundle, 'records', '.staging'))).toBe(0o700);
  });

  it('rejects unsafe record and artifact identifiers and creates nothing', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const meta = { mediaType: 'text/plain' as const, rawBytes: 1, rawSha256: sha('a'), redactions: 0, truncated: false };
    for (const stepId of ['..', 'a/b', '', '../../evil']) {
      await expect(store.writeRecord(makeRecord(stepId, 1, 'run-1'))).rejects.toThrow(/invalid/i);
    }
    for (const recordId of ['..', 'a/b', '']) {
      await expect(store.writeArtifact(recordId, 'stdout.json', Buffer.from('x'), meta)).rejects.toThrow(/invalid/i);
    }
    await expect(store.writeArtifact('scan.npm-audit.a1', '../../evil', Buffer.from('x'), meta)).rejects.toThrow(/invalid/i);
    expect(existsSync(store.bundleDir)).toBe(false);
    expect(existsSync(path.join(root, '..', 'evil'))).toBe(false);
    expect(existsSync(path.join(root, 'evil'))).toBe(false);
  });

  it('rejects a runId that would escape the evidence root and creates nothing outside it', async () => {
    const sibling = path.join(root, '..', 'up');
    for (const runId of ['..', '../up']) {
      expect(() => createEvidenceStore(root, runId)).toThrow(/invalid runId/i);
    }
    expect(existsSync(sibling)).toBe(false);
    expect(await readdir(root)).toEqual([]);
  });

  it('fails closed when the evidence root is not writable and leaves no record behind', async () => {
    if (process.getuid?.() === 0) return;
    chmodSync(root, 0o500);
    try {
      const store = createEvidenceStore(root, 'run-1');
      await expect(store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'))).rejects.toThrow();
      await expect(
        store.writeArtifact('scan.npm-audit.a1', 'stdout.json', Buffer.from('{}'), {
          mediaType: 'application/json',
          rawBytes: 2,
          rawSha256: sha('{}'),
          redactions: 0,
          truncated: false,
        }),
      ).rejects.toThrow();
      expect(existsSync(path.join(root, 'run-1'))).toBe(false);
    } finally {
      chmodSync(root, 0o700);
    }
  });

  it('fails closed when a staging file already blocks the write and publishes no record', async () => {
    const store = createEvidenceStore(root, 'run-1');
    const staging = path.join(store.bundleDir, 'records', '.staging');
    await mkdir(staging, { recursive: true });
    await writeFile(path.join(staging, 'scan.npm-audit.a1.json'), 'blocker');
    await expect(store.writeRecord(makeRecord('scan.npm-audit', 1, 'run-1'))).rejects.toThrow(/staging/i);
    const published = (await readdir(path.join(store.bundleDir, 'records'))).filter((n) => n.endsWith('.json'));
    expect(published).toEqual([]);
  });
});
