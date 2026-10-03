import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { recordInProcessStep } from '../../../../src/scan/tools/in-process';
import type { ScanContext } from '../../../../src/scan/scan-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../../src/evidence/types';
import type { ProcessRunner } from '../../../../src/scan/tool-types';

const T0 = new Date('2026-01-01T00:00:00.000Z');
const T1 = new Date('2026-01-01T00:00:02.500Z');

function sha(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class FakeStore implements EvidenceStore {
  readonly bundleDir = '/tmp/bundle';
  records: EvidenceRecord[] = [];
  artifacts: { recordId: string; suffix: string; bytes: Buffer; meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'> }[] = [];
  failArtifact = false;
  failRecord = false;

  async writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    if (this.failArtifact) throw new Error('disk full');
    this.artifacts.push({ recordId, suffix, bytes, meta });
    return { ...meta, path: `records/${recordId}.${suffix}`, bytes: bytes.length, sha256: sha(bytes) };
  }

  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    if (this.failRecord) throw new Error('disk full');
    this.records.push(record);
    return { recordId: record.id, recordSha256: sha(JSON.stringify(record)) };
  }
}

const runnerCalls: unknown[] = [];
const runner: ProcessRunner = async (req) => {
  runnerCalls.push(req);
  throw new Error('no process may run');
};

function ctx(store: FakeStore, attempt = 1): ScanContext {
  const times = [T0, T1];
  let i = 0;
  return {
    run: { runId: 'run-ip', workDir: '/tmp/tessera-secretdir', repoDir: '/tmp/tessera-secretdir/repo' },
    source: { repoDir: '/tmp/tessera-secretdir/repo', revision: 'b'.repeat(40) },
    repoUrl: 'https://example.invalid/r.git',
    attempt,
    deps: {
      runner,
      store,
      clock: () => times[Math.min(i++, times.length - 1)],
      frameworkVersion: '9.9.9-test',
    },
    workerEnv: {},
    configDir: '/opt/tessera/config',
  };
}

describe('recordInProcessStep', () => {
  it('writes an in-process record with id <stepId>.a<attempt> and success for completed', async () => {
    const store = new FakeStore();
    const { record, evidence } = await recordInProcessStep(ctx(store, 3), {
      stepId: 'license-check',
      scanner: 'license-check',
      toolName: 'tessera-license-check',
      status: 'completed',
      inputs: { lockfileName: 'package-lock.json' },
      findingIds: ['LIC-1', 'LIC-2'],
    });
    expect(record.id).toBe('license-check.a3');
    expect(record.stepId).toBe('license-check');
    expect(record.attempt).toBe(3);
    expect(record.kind).toBe('in-process');
    expect(record.scanner).toBe('license-check');
    expect(record.schema).toBe('tessera.evidence/v1');
    expect(record.runId).toBe('run-ip');
    expect(record.tool).toEqual({ name: 'tessera-license-check', version: null });
    expect(record.action).toEqual({
      command: null,
      args: [],
      cwd: '<WORK>',
      envOverrides: {},
      envPassthrough: [],
      inputs: { lockfileName: 'package-lock.json' },
    });
    expect(record.source).toEqual({ repoUrl: 'https://example.invalid/r.git', revision: 'b'.repeat(40) });
    expect(record.result).toEqual({ exitCode: null, signal: null, exitClass: 'success', timedOut: false });
    expect(record.status).toBe('completed');
    expect(record.output).toBeNull();
    expect(record.stderr).toBeNull();
    expect(record.findingIds).toEqual(['LIC-1', 'LIC-2']);
    expect(record.overrideAttempts).toEqual([]);
    expect(record.recordedBy).toEqual({ framework: 'tessera', version: '9.9.9-test' });
    expect(record.startedAt).toBe(T0.toISOString());
    expect(record.endedAt).toBe(T1.toISOString());
    expect(record.durationMs).toBe(2500);
    expect(store.records).toEqual([record]);
    expect(store.artifacts).toHaveLength(0);
    expect(evidence.recordId).toBe('license-check.a3');
    expect(evidence.recordSha256).toBe(sha(JSON.stringify(record)));
    expect(runnerCalls).toHaveLength(0);
  });

  it.each(['partial', 'failed', 'skipped', 'unavailable'] as const)('marks %s as not-run and keeps cause', async (status) => {
    const store = new FakeStore();
    const { record } = await recordInProcessStep(ctx(store), {
      stepId: 's',
      scanner: 'license-check',
      toolName: 't',
      status,
      cause: 'no-lockfile',
      causeDetail: 'no lockfile found',
    });
    expect(record.result.exitClass).toBe('not-run');
    expect(record.status).toBe(status);
    expect(record.cause).toBe('no-lockfile');
    expect(record.causeDetail).toBe('no lockfile found');
    expect(record.findingIds).toEqual([]);
    expect(record.action.inputs).toEqual({});
  });

  it('stores redacted output with the raw fingerprint and redaction count', async () => {
    const store = new FakeStore();
    const raw = Buffer.from('{"note":"password=hunter2hunter2hunter2","pkg":"left-pad"}', 'utf8');
    const { record } = await recordInProcessStep(ctx(store), {
      stepId: 'license-check',
      scanner: 'license-check',
      toolName: 't',
      status: 'completed',
      output: { bytes: raw, mediaType: 'application/json', suffix: 'summary.json' },
    });
    expect(store.artifacts).toHaveLength(1);
    const art = store.artifacts[0];
    expect(art.recordId).toBe('license-check.a1');
    expect(art.suffix).toBe('summary.json');
    expect(art.bytes.toString('utf8')).not.toContain('hunter2');
    expect(art.bytes.toString('utf8')).toContain('left-pad');
    expect(art.meta.rawSha256).toBe(sha(raw));
    expect(art.meta.rawBytes).toBe(raw.length);
    expect(art.meta.redactions).toBeGreaterThan(0);
    expect(art.meta.truncated).toBe(false);
    expect(art.meta.mediaType).toBe('application/json');
    expect(record.output).not.toBeNull();
    expect(record.output?.sha256).toBe(sha(art.bytes));
    expect(record.output?.rawSha256).toBe(sha(raw));
    expect(record.output?.redactions).toBe(art.meta.redactions);
  });

  it('keeps clean output byte-identical with zero redactions', async () => {
    const store = new FakeStore();
    const raw = Buffer.from('plain summary', 'utf8');
    const { record } = await recordInProcessStep(ctx(store), {
      stepId: 'x',
      scanner: 'license-check',
      toolName: 't',
      status: 'completed',
      output: { bytes: raw, mediaType: 'text/plain', suffix: 'txt' },
    });
    expect(store.artifacts[0].bytes.equals(raw)).toBe(true);
    expect(record.output?.redactions).toBe(0);
    expect(record.output?.sha256).toBe(record.output?.rawSha256);
  });

  it('never puts absolute work paths into the record', async () => {
    const store = new FakeStore();
    const { record } = await recordInProcessStep(ctx(store), {
      stepId: 'x',
      scanner: 'license-check',
      toolName: 't',
      status: 'completed',
      output: { bytes: Buffer.from('{}'), mediaType: 'application/json', suffix: 'json' },
    });
    const text = JSON.stringify(record);
    expect(text).not.toContain('/tmp/tessera-secretdir');
    expect(text).not.toContain('/opt/tessera');
  });

  it('rejects when the artifact write fails and writes no record', async () => {
    const store = new FakeStore();
    store.failArtifact = true;
    await expect(
      recordInProcessStep(ctx(store), {
        stepId: 'x',
        scanner: 'license-check',
        toolName: 't',
        status: 'completed',
        output: { bytes: Buffer.from('{}'), mediaType: 'application/json', suffix: 'json' },
      }),
    ).rejects.toThrow('disk full');
    expect(store.records).toHaveLength(0);
  });

  it('rejects when the record write fails', async () => {
    const store = new FakeStore();
    store.failRecord = true;
    await expect(
      recordInProcessStep(ctx(store), { stepId: 'x', scanner: 'license-check', toolName: 't', status: 'failed' }),
    ).rejects.toThrow('disk full');
  });
});
