import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, readdir, readFile, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import { traceEvidence, verifyEvidenceBundle } from '../../../src/evidence/verify';
import type { ArtifactRef, EvidenceRecord } from '../../../src/evidence/types';

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const RUN = 'run-1';

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

async function walk(dir: string, base = ''): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(path.join(dir, base), { withFileTypes: true })) {
    const rel = base ? `${base}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await walk(dir, rel)));
    else out.push(rel);
  }
  return out;
}

async function unlockAll(dir: string): Promise<void> {
  const st = await lstat(dir);
  if (st.isSymbolicLink()) return;
  if (st.isDirectory()) {
    await chmod(dir, 0o700);
    for (const e of await readdir(dir)) await unlockAll(path.join(dir, e));
  } else {
    await chmod(dir, 0o600);
  }
}

async function lockAll(dir: string): Promise<void> {
  const st = await lstat(dir);
  if (st.isSymbolicLink()) return;
  if (st.isDirectory()) {
    for (const e of await readdir(dir)) await lockAll(path.join(dir, e));
    await chmod(dir, 0o500);
  } else {
    await chmod(dir, 0o400);
  }
}

interface Sealed {
  dir: string;
  runId: string;
  rootHash: string;
  recordIds: string[];
  manifest: Record<string, any>;
}

async function buildSealedBundle(
  root: string,
  opts: { runId?: string; steps?: number; mutate?: (dir: string) => Promise<void> } = {},
): Promise<Sealed> {
  const runId = opts.runId ?? RUN;
  const store = createEvidenceStore(root, runId);
  const recordIds: string[] = [];
  const steps = opts.steps ?? 2;
  for (let i = 0; i < steps; i++) {
    const stepId = i === 0 ? 'scan.npm-audit' : i === 1 ? 'scan.gitleaks' : `scan.step-${i}`;
    const id = `${stepId}.a1`;
    let output: ArtifactRef | null = null;
    let stderr: ArtifactRef | null = null;
    if (i === 0) {
      output = await store.writeArtifact(id, 'json', Buffer.from('{"sanitized":true}\n'), {
        mediaType: 'application/json',
        rawBytes: 40,
        rawSha256: sha('raw-output-' + id),
        redactions: 1,
        truncated: false,
      });
      stderr = await store.writeArtifact(id, 'txt', Buffer.from('warn\n'), {
        mediaType: 'text/plain',
        rawBytes: 5,
        rawSha256: sha('raw-stderr-' + id),
        redactions: 0,
        truncated: false,
      });
    }
    await store.writeRecord(makeRecord(stepId, 1, runId, { output, stderr }));
    recordIds.push(id);
  }
  const dir = store.bundleDir;
  await unlockAll(dir);
  if (opts.mutate) await opts.mutate(dir);

  const files = (await walk(dir)).filter((f) => !f.startsWith('records/.staging/') && (f.startsWith('records/') || f.startsWith('artifacts/')));
  files.sort();
  const genesis = sha('tessera:' + runId);
  let prev = genesis;
  const entries = [];
  const sums: string[] = [];
  let seq = 0;
  for (const f of files) {
    seq += 1;
    const bytes = await readFile(path.join(dir, f));
    const h = sha(bytes);
    const chainHash = sha(`${prev}\n${seq}\n${f}\n${h}`);
    const base = path.posix.basename(f);
    const recordId = f.startsWith('records/') ? base.replace(/\.json$/, '') : base.replace(/\.[^.]+$/, '');
    entries.push({ seq, path: f, kind: f.startsWith('records/') ? 'record' : 'artifact', recordId, bytes: bytes.length, sha256: h, chainHash, used: true });
    sums.push(`${h}  ${f}`);
    prev = chainHash;
  }
  const manifest = {
    schema: 'tessera.manifest/v1',
    runId,
    workflowId: 'wf',
    temporalRunId: '11111111-1111-4111-8111-111111111111',
    source: { repoUrl: 'https://example.invalid/repo.git', revision: 'a'.repeat(40) },
    sealedAt: '2026-01-01T00:00:10.000Z',
    retainUntil: '2027-01-01T00:00:10.000Z',
    framework: { name: 'tessera', version: '0.0.0' },
    hashAlgorithm: 'sha256',
    entries,
    abandoned: [],
    chain: { algorithm: 'tessera-chain/v1', genesis, head: prev },
    rootHash: prev,
  };
  await writeFile(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  await writeFile(path.join(dir, 'SHA256SUMS'), sums.join('\n') + '\n');
  await lockAll(dir);
  return { dir, runId, rootHash: prev, recordIds, manifest };
}

async function rewriteManifest(dir: string, edit: (m: Record<string, any>) => void): Promise<void> {
  await unlockAll(dir);
  const file = path.join(dir, 'manifest.json');
  const m = JSON.parse(await readFile(file, 'utf8'));
  edit(m);
  await writeFile(file, JSON.stringify(m, null, 2) + '\n');
}

async function removeTree(dir: string): Promise<void> {
  await unlockAll(dir).catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
}

async function snapshot(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const visit = async (p: string, rel: string): Promise<void> => {
    const st = await lstat(p);
    if (st.isDirectory()) {
      out[rel || '.'] = `dir ${st.mode & 0o777} ${st.mtimeMs}`;
      for (const e of await readdir(p)) await visit(path.join(p, e), rel ? `${rel}/${e}` : e);
    } else {
      out[rel] = `file ${st.mode & 0o777} ${st.mtimeMs} ${sha(await readFile(p))}`;
    }
  };
  await visit(dir, '');
  return out;
}

describe('verifyEvidenceBundle', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-verify-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('TS-024: an unmodified bundle is ok and the root matches the expected anchor', async () => {
    const b = await buildSealedBundle(root);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
    expect(report.issues).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.rootMatches).toBe(true);
    expect(report.runId).toBe(RUN);
    expect(report.rootHash).toBe(b.rootHash);
    expect(report.manifestRootHash).toBe(b.rootHash);
    expect(report.checkedEntries).toBe(b.manifest.entries.length);
    expect(report.bundlePath).toBe(b.dir);
  });

  it('rootMatches is null without expectRootHash', async () => {
    const b = await buildSealedBundle(root);
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(true);
    expect(report.rootMatches).toBeNull();
  });

  it('a wrong expectRootHash fails with rootMatches false and no file issues', async () => {
    const b = await buildSealedBundle(root);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: 'f'.repeat(64) });
    expect(report.ok).toBe(false);
    expect(report.rootMatches).toBe(false);
    expect(report.issues).toEqual([]);
    expect(report.rootHash).toBe(b.rootHash);
  });

  const changes: { name: string; problem: 'modified' | 'missing' | 'extra'; target: string; apply: (dir: string) => Promise<void> }[] = [
    {
      name: 'a modified record',
      problem: 'modified',
      target: 'records/scan.gitleaks.a1.json',
      apply: async (dir) => {
        const file = path.join(dir, 'records/scan.gitleaks.a1.json');
        const rec = JSON.parse(await readFile(file, 'utf8'));
        rec.durationMs = 999999;
        await writeFile(file, JSON.stringify(rec, null, 2) + '\n');
      },
    },
    {
      name: 'a modified artifact',
      problem: 'modified',
      target: 'artifacts/scan.npm-audit.a1.json',
      apply: async (dir) => {
        await writeFile(path.join(dir, 'artifacts/scan.npm-audit.a1.json'), '{"sanitized":false}\n');
      },
    },
    {
      name: 'a deleted record',
      problem: 'missing',
      target: 'records/scan.gitleaks.a1.json',
      apply: async (dir) => {
        await unlink(path.join(dir, 'records/scan.gitleaks.a1.json'));
      },
    },
    {
      name: 'a deleted artifact',
      problem: 'missing',
      target: 'artifacts/scan.npm-audit.a1.txt',
      apply: async (dir) => {
        await unlink(path.join(dir, 'artifacts/scan.npm-audit.a1.txt'));
      },
    },
    {
      name: 'an added file in records/',
      problem: 'extra',
      target: 'records/injected.json',
      apply: async (dir) => {
        await writeFile(path.join(dir, 'records/injected.json'), '{}\n');
      },
    },
    {
      name: 'an added file in artifacts/',
      problem: 'extra',
      target: 'artifacts/injected.bin',
      apply: async (dir) => {
        await writeFile(path.join(dir, 'artifacts/injected.bin'), 'x');
      },
    },
    {
      name: 'an added file in the bundle root',
      problem: 'extra',
      target: 'notes.txt',
      apply: async (dir) => {
        await writeFile(path.join(dir, 'notes.txt'), 'hello');
      },
    },
  ];

  it.each(changes)('TS-025: $name gives ok false with exactly one $problem issue', async ({ problem, target, apply }) => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await apply(b.dir);
    await lockAll(b.dir);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem, path: target });
  });

  it('a modified file reports expected and actual hashes', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'artifacts/scan.npm-audit.a1.json'), 'changed');
    const report = await verifyEvidenceBundle(b.dir);
    const entry = b.manifest.entries.find((e: { path: string }) => e.path === 'artifacts/scan.npm-audit.a1.json');
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0].expected).toBe(entry.sha256);
    expect(report.issues[0].actual).toBe(sha('changed'));
  });

  it('issues are sorted by path and each file is reported once', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'records/zzz.json'), '{}');
    await writeFile(path.join(b.dir, 'artifacts/aaa.bin'), 'x');
    await unlink(path.join(b.dir, 'records/scan.gitleaks.a1.json'));
    const report = await verifyEvidenceBundle(b.dir);
    const paths = report.issues.map((i) => i.path);
    expect(paths).toEqual(['artifacts/aaa.bin', 'records/scan.gitleaks.a1.json', 'records/zzz.json']);
  });

  it('TS-026: repeated verification of an unmodified bundle never fails', async () => {
    const b = await buildSealedBundle(root, { steps: 20 });
    for (let i = 0; i < 25; i++) {
      const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
      expect(report.ok).toBe(true);
      expect(report.issues).toEqual([]);
    }
  });

  it('a missing manifest.json gives one invalid-record issue on manifest.json', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await unlink(path.join(b.dir, 'manifest.json'));
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem: 'invalid-record', path: 'manifest.json' });
    expect(report.rootHash).toBeNull();
    expect(report.runId).toBeNull();
  });

  it.each([
    ['not json', 'this is not json'],
    ['wrong schema', JSON.stringify({ schema: 'something/else', runId: RUN })],
    ['empty object', '{}'],
  ])('an invalid manifest.json (%s) gives one invalid-record issue', async (_name, content) => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'manifest.json'), content);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem: 'invalid-record', path: 'manifest.json' });
  });

  it('a record with another runId gives run-mismatch on that record', async () => {
    const b = await buildSealedBundle(root, {
      mutate: async (dir) => {
        const rec = makeRecord('scan.foreign', 1, 'other-run');
        await writeFile(path.join(dir, 'records/scan.foreign.a1.json'), JSON.stringify(rec, null, 2) + '\n');
      },
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem: 'run-mismatch', path: 'records/scan.foreign.a1.json', expected: RUN, actual: 'other-run' });
  });

  it('a sealed record that is not valid JSON or has a wrong schema gives invalid-record', async () => {
    const b = await buildSealedBundle(root, {
      mutate: async (dir) => {
        await writeFile(path.join(dir, 'records/broken.a1.json'), 'not json');
        await writeFile(path.join(dir, 'records/schema.a1.json'), JSON.stringify({ schema: 'x', runId: RUN }));
      },
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([
      ['invalid-record', 'records/broken.a1.json'],
      ['invalid-record', 'records/schema.a1.json'],
    ]);
  });

  it('a manually changed chainHash gives chain-broken on that entry', async () => {
    const b = await buildSealedBundle(root);
    const target = b.manifest.entries[1].path as string;
    await rewriteManifest(b.dir, (m) => {
      m.entries[1].chainHash = 'e'.repeat(64);
    });
    await lockAll(b.dir);
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    const broken = report.issues.filter((i) => i.problem === 'chain-broken');
    expect(broken.length).toBeGreaterThanOrEqual(1);
    expect(broken[0].path).toBe(target);
    expect(report.issues.every((i) => i.problem === 'chain-broken')).toBe(true);
  });

  it('a manually changed chain.head gives chain-broken', async () => {
    const b = await buildSealedBundle(root);
    await rewriteManifest(b.dir, (m) => {
      m.chain.head = 'd'.repeat(64);
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.problem === 'chain-broken')).toBe(true);
    expect(report.rootHash).toBe(b.rootHash);
  });

  it('a symlink inside the bundle counts as extra and is not followed', async () => {
    const outside = path.join(root, 'outside.json');
    await writeFile(outside, '{"secret":true}');
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await symlink(outside, path.join(b.dir, 'records/link.json'));
    await symlink(path.join(b.dir, 'records'), path.join(b.dir, 'artifacts/dirlink'));
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([
      ['extra', 'artifacts/dirlink'],
      ['extra', 'records/link.json'],
    ]);
  });

  it('a symlink replacing a listed file is reported and not followed', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    const file = path.join(b.dir, 'artifacts/scan.npm-audit.a1.txt');
    const original = await readFile(file);
    await unlink(file);
    const copy = path.join(root, 'copy.txt');
    await writeFile(copy, original);
    await symlink(copy, file);
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.length).toBeGreaterThanOrEqual(1);
    expect(report.issues.every((i) => i.path === 'artifacts/scan.npm-audit.a1.txt')).toBe(true);
  });

  it('does not modify the bundle (content, modes, mtimes)', async () => {
    const b = await buildSealedBundle(root);
    const before = await snapshot(b.dir);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
    expect(report.ok).toBe(true);
    const after = await snapshot(b.dir);
    expect(after).toEqual(before);
    expect(Object.keys(before).length).toBeGreaterThan(5);
    expect((await stat(path.join(b.dir, 'manifest.json'))).mode & 0o777).toBe(0o400);
  });
});

describe('traceEvidence', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-trace-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('TS-020: returns the record, artifact hashes, source revision and root hash', async () => {
    const b = await buildSealedBundle(root);
    const trace = await traceEvidence(b.dir, 'scan.npm-audit.a1');
    const record = JSON.parse(await readFile(path.join(b.dir, 'records/scan.npm-audit.a1.json'), 'utf8'));
    expect(trace.recordId).toBe('scan.npm-audit.a1');
    expect(trace.record).toEqual(record);
    expect(trace.rootHash).toBe(b.rootHash);
    expect(trace.source).toEqual({ repoUrl: 'https://example.invalid/repo.git', revision: 'a'.repeat(40) });
    expect(trace.artifacts).toHaveLength(2);
    expect(trace.artifacts).toEqual(
      expect.arrayContaining([
        { path: 'artifacts/scan.npm-audit.a1.json', sha256: sha('{"sanitized":true}\n'), rawSha256: sha('raw-output-scan.npm-audit.a1') },
        { path: 'artifacts/scan.npm-audit.a1.txt', sha256: sha('warn\n'), rawSha256: sha('raw-stderr-scan.npm-audit.a1') },
      ]),
    );
  });

  it('a record without artifacts traces to an empty artifact list', async () => {
    const b = await buildSealedBundle(root);
    const trace = await traceEvidence(b.dir, 'scan.gitleaks.a1');
    expect(trace.recordId).toBe('scan.gitleaks.a1');
    expect(trace.artifacts).toEqual([]);
    expect(trace.rootHash).toBe(b.rootHash);
  });

  it('an unknown recordId rejects with a not-found style error', async () => {
    const b = await buildSealedBundle(root);
    await expect(traceEvidence(b.dir, 'scan.nope.a1')).rejects.toThrow(/unknown|not found|no such/i);
  });

  it('a recordId with path traversal rejects with a not-found style error', async () => {
    const b = await buildSealedBundle(root);
    await expect(traceEvidence(b.dir, '../manifest')).rejects.toThrow(/unknown|not found|invalid|no such/i);
  });
});

describe('verifyEvidenceBundle: manifest and side-file tampering', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-verify-extra-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('a forged manifest rootHash gives chain-broken on manifest.json while the recomputed root stays the real one', async () => {
    const b = await buildSealedBundle(root);
    await rewriteManifest(b.dir, (m) => {
      m.rootHash = 'a'.repeat(64);
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues).toEqual([{ path: 'manifest.json', problem: 'chain-broken', expected: b.rootHash, actual: 'a'.repeat(64) }]);
    expect(report.rootHash).toBe(b.rootHash);
    expect(report.manifestRootHash).toBe('a'.repeat(64));
  });

  it('a forged chain genesis gives chain-broken on manifest.json', async () => {
    const b = await buildSealedBundle(root);
    await rewriteManifest(b.dir, (m) => {
      m.chain.genesis = 'b'.repeat(64);
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['chain-broken', 'manifest.json']]);
  });

  it('a renumbered entry gives chain-broken on that entry', async () => {
    const b = await buildSealedBundle(root);
    const target = b.manifest.entries[1].path as string;
    await rewriteManifest(b.dir, (m) => {
      m.entries[1].seq = 7;
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['chain-broken', target]]);
  });

  it('a manifest byte count that does not match the file gives modified on that file', async () => {
    const b = await buildSealedBundle(root);
    const target = b.manifest.entries[0].path as string;
    await rewriteManifest(b.dir, (m) => {
      m.entries[0].bytes += 1;
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem: 'modified', path: target });
  });

  it('a modified SHA256SUMS gives one modified issue on SHA256SUMS', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'SHA256SUMS'), `${'0'.repeat(64)}  records/scan.gitleaks.a1.json\n`);
    const report = await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash });
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['modified', 'SHA256SUMS']]);
  });

  it('a deleted SHA256SUMS gives one missing issue on SHA256SUMS', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await unlink(path.join(b.dir, 'SHA256SUMS'));
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['missing', 'SHA256SUMS']]);
  });

  it('checks abandoned staging files: listed and intact is ok, changed is modified, deleted is missing', async () => {
    const staged = Buffer.from('partial write');
    const b = await buildSealedBundle(root, {
      mutate: async (dir) => {
        await writeFile(path.join(dir, 'records/.staging/scan.x.a1.json'), staged);
      },
    });
    await rewriteManifest(b.dir, (m) => {
      m.abandoned = [{ path: 'records/.staging/scan.x.a1.json', bytes: staged.length, sha256: sha(staged) }];
    });
    await lockAll(b.dir);
    expect((await verifyEvidenceBundle(b.dir, { expectRootHash: b.rootHash })).ok).toBe(true);

    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'records/.staging/scan.x.a1.json'), 'other');
    let report = await verifyEvidenceBundle(b.dir);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['modified', 'records/.staging/scan.x.a1.json']]);

    await unlink(path.join(b.dir, 'records/.staging/scan.x.a1.json'));
    report = await verifyEvidenceBundle(b.dir);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['missing', 'records/.staging/scan.x.a1.json']]);
  });

  it('an unlisted file in records/.staging is extra', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'records/.staging/late.json'), 'x');
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['extra', 'records/.staging/late.json']]);
  });

  it('a sealed record whose id does not match its file name gives invalid-record', async () => {
    const b = await buildSealedBundle(root, {
      mutate: async (dir) => {
        await writeFile(path.join(dir, 'records/scan.alias.a1.json'), JSON.stringify(makeRecord('scan.other', 1, RUN), null, 2) + '\n');
      },
    });
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([['invalid-record', 'records/scan.alias.a1.json']]);
  });

  it.each([
    ['an entry path with traversal', (m: Record<string, any>) => (m.entries[0].path = 'records/../../etc/passwd')],
    ['entries out of byte order', (m: Record<string, any>) => m.entries.reverse()],
    ['an artifact entry whose recordId is not its name prefix', (m: Record<string, any>) => {
      const art = m.entries.find((e: { kind: string }) => e.kind === 'artifact');
      art.recordId = 'scan.gitleaks.a1';
    }],
    ['a record entry under artifacts/', (m: Record<string, any>) => (m.entries.find((e: { kind: string }) => e.kind === 'artifact').kind = 'record')],
    ['a non-boolean used flag', (m: Record<string, any>) => (m.entries[0].used = 'yes')],
  ])('a structurally invalid manifest (%s) gives one invalid-record issue', async (_name, edit) => {
    const b = await buildSealedBundle(root);
    await rewriteManifest(b.dir, edit);
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.ok).toBe(false);
    expect(report.issues).toEqual([{ path: 'manifest.json', problem: 'invalid-record' }]);
  });

  it('a symlinked manifest.json is not followed and is invalid', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    const copy = path.join(root, 'manifest-copy.json');
    await writeFile(copy, await readFile(path.join(b.dir, 'manifest.json')));
    await unlink(path.join(b.dir, 'manifest.json'));
    await symlink(copy, path.join(b.dir, 'manifest.json'));
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.issues).toEqual([{ path: 'manifest.json', problem: 'invalid-record' }]);
  });

  it('an added directory is reported, with its files, as extra', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(path.join(b.dir, 'records/sub'));
    await writeFile(path.join(b.dir, 'records/sub/x.json'), '{}');
    await mkdir(path.join(b.dir, 'empty'));
    const report = await verifyEvidenceBundle(b.dir);
    expect(report.issues.map((i) => [i.problem, i.path])).toEqual([
      ['extra', 'empty'],
      ['extra', 'records/sub/x.json'],
    ]);
  });

  it('a path that is not a bundle directory rejects', async () => {
    await expect(verifyEvidenceBundle(path.join(root, 'nope'))).rejects.toThrow();
    const file = path.join(root, 'file');
    await writeFile(file, 'x');
    await expect(verifyEvidenceBundle(file)).rejects.toThrow(/not a bundle directory/);
  });
});

describe('traceEvidence integrity', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-trace-extra-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('refuses to trace a record that no longer matches the manifest', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    const file = path.join(b.dir, 'records/scan.gitleaks.a1.json');
    const rec = JSON.parse(await readFile(file, 'utf8'));
    rec.tool.version = '9.9.9';
    await writeFile(file, JSON.stringify(rec, null, 2) + '\n');
    await expect(traceEvidence(b.dir, 'scan.gitleaks.a1')).rejects.toThrow(/does not match the manifest/);
  });

  it('refuses to trace when an artifact hash in the record differs from the manifest', async () => {
    const b = await buildSealedBundle(root);
    await rewriteManifest(b.dir, (m) => {
      const art = m.entries.find((e: { path: string }) => e.path === 'artifacts/scan.npm-audit.a1.json');
      art.sha256 = 'f'.repeat(64);
    });
    await expect(traceEvidence(b.dir, 'scan.npm-audit.a1')).rejects.toThrow(/does not match the manifest/);
  });

  it('refuses to trace without a valid manifest', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'manifest.json'), 'broken');
    await expect(traceEvidence(b.dir, 'scan.npm-audit.a1')).rejects.toThrow(/manifest/);
  });
});
