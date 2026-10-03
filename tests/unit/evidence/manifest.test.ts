import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import type { EvidenceManifest } from '../../../src/evidence/types';
import type { EvidenceRecord } from '../../../src/evidence/types';
import { sealEvidenceBundle, type SealOptions } from '../../../src/evidence/manifest';
import { vi } from 'vitest';

const verifyControl = vi.hoisted(() => ({ fail: false }));

vi.mock('../../../src/evidence/verify', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/evidence/verify')>();
  return {
    ...actual,
    verifyEvidenceBundle: async (...args: Parameters<typeof actual.verifyEvidenceBundle>) => {
      const report = await actual.verifyEvidenceBundle(...args);
      return verifyControl.fail ? { ...report, ok: false, issues: [{ path: 'records/x.json', problem: 'modified' as const }] } : report;
    },
  };
});

const RUN = 'run-1';
const NOW = new Date('2026-03-01T12:00:00.000Z');
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const mode = async (p: string): Promise<number> => (await stat(p)).mode & 0o777;

function makeRecord(stepId: string, attempt: number, runId: string): EvidenceRecord {
  return {
    schema: 'tessera.evidence/v1',
    id: `${stepId}.a${attempt}`,
    runId,
    stepId,
    attempt,
    kind: 'tool-run',
    scanner: 'npm-audit',
    action: { command: 'npm', args: ['audit'], cwd: '<SOURCE>', envOverrides: {}, envPassthrough: [], inputs: {} },
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
  };
}

interface OracleFile {
  path: string;
  bytes: Buffer;
}

async function listFiles(bundle: string): Promise<OracleFile[]> {
  const out: OracleFile[] = [];
  for (const dir of ['records', 'artifacts']) {
    let names: string[] = [];
    try {
      names = await readdir(path.join(bundle, dir));
    } catch {
      continue;
    }
    for (const name of names) {
      if (name.startsWith('.')) continue;
      const rel = `${dir}/${name}`;
      out.push({ path: rel, bytes: await readFile(path.join(bundle, rel)) });
    }
  }
  return out.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
}

function oracle(runId: string, files: OracleFile[]) {
  const genesis = sha(`tessera:${runId}`);
  let prev = genesis;
  const entries = files.map((f, i) => {
    const seq = i + 1;
    const fileSha = sha(f.bytes);
    const chainHash = sha(`${prev}\n${seq}\n${f.path}\n${fileSha}`);
    prev = chainHash;
    return { seq, path: f.path, sha256: fileSha, bytes: f.bytes.length, chainHash };
  });
  return { genesis, head: prev, entries };
}

describe('sealEvidenceBundle', () => {
  let root: string;
  let bundle: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-seal-'));
    bundle = path.join(root, RUN);
  });

  afterEach(async () => {
    await chmod(bundle, 0o700).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  });

  const opts = (extra: Partial<SealOptions> = {}): SealOptions => ({
    bundleDir: bundle,
    runId: RUN,
    workflowId: 'wf-1',
    temporalRunId: 'temporal-1',
    source: { repoUrl: 'https://example.invalid/repo.git', revision: 'b'.repeat(40) },
    frameworkVersion: '1.2.3',
    usedRecordIds: ['scan.npm-audit.a1', 'scan.semgrep.a1'],
    clock: () => NOW,
    ...extra,
  });

  async function populate(): Promise<void> {
    const store = createEvidenceStore(root, RUN);
    const out = Buffer.from('{"ok":true}');
    await store.writeArtifact('scan.npm-audit.a1', 'stdout.json', out, {
      mediaType: 'application/json',
      rawBytes: out.length,
      rawSha256: sha(out),
      redactions: 0,
      truncated: false,
    });
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    await store.writeRecord(makeRecord('scan.semgrep', 1, RUN));
    await store.writeRecord(makeRecord('scan.semgrep', 2, RUN));
  }

  const readManifest = async (): Promise<EvidenceManifest> =>
    JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8')) as EvidenceManifest;

  it('TS-016 writes a manifest with identity, source revision, retention and framework fields', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const m = await readManifest();
    expect(m.schema).toBe('tessera.manifest/v1');
    expect(m.runId).toBe(RUN);
    expect(m.workflowId).toBe('wf-1');
    expect(m.temporalRunId).toBe('temporal-1');
    expect(m.source.revision).toBe('b'.repeat(40));
    expect(m.sealedAt).toBe(NOW.toISOString());
    expect(m.retainUntil).toBe(new Date(NOW.getTime() + 365 * 86400000).toISOString());
    expect(m.framework).toEqual({ name: 'tessera', version: '1.2.3' });
    expect(m.hashAlgorithm).toBe('sha256');
  });

  it('TS-016 lists every record and artifact as an entry matching the independent hash chain oracle', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const m = await readManifest();
    const expected = oracle(RUN, await listFiles(bundle));
    expect(expected.entries).toHaveLength(4);
    expect(m.chain).toEqual({ algorithm: 'tessera-chain/v1', genesis: expected.genesis, head: expected.head });
    expect(m.rootHash).toBe(expected.head);
    expect(m.entries.map((e) => ({ seq: e.seq, path: e.path, sha256: e.sha256, bytes: e.bytes, chainHash: e.chainHash }))).toEqual(
      expected.entries,
    );
  });

  it('TS-016 marks kind and recordId per entry and used=false for attempts the workflow did not use', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const m = await readManifest();
    const by = Object.fromEntries(m.entries.map((e) => [e.path, e]));
    expect(by['artifacts/scan.npm-audit.a1.stdout.json']).toMatchObject({ kind: 'artifact', recordId: 'scan.npm-audit.a1' });
    expect(by['records/scan.npm-audit.a1.json']).toMatchObject({ kind: 'record', recordId: 'scan.npm-audit.a1', used: true });
    expect(by['records/scan.semgrep.a1.json']).toMatchObject({ kind: 'record', recordId: 'scan.semgrep.a1', used: true });
    expect(by['records/scan.semgrep.a2.json']).toMatchObject({ kind: 'record', recordId: 'scan.semgrep.a2', used: false });
  });

  it('TS-016 sorts entries by path in byte order with seq starting at 1', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const m = await readManifest();
    const paths = m.entries.map((e) => e.path);
    expect(paths).toEqual([...paths].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
    expect(m.entries.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
  });

  it('TS-016 lists files in records/.staging as abandoned and not as entries', async () => {
    await populate();
    const staged = Buffer.from('partial');
    await writeFile(path.join(bundle, 'records', '.staging', 'scan.x.a1.json'), staged);
    const result = await sealEvidenceBundle(opts());
    const m = await readManifest();
    expect(m.abandoned).toEqual([{ path: 'records/.staging/scan.x.a1.json', bytes: staged.length, sha256: sha(staged) }]);
    expect(m.entries.some((e) => e.path.includes('.staging'))).toBe(false);
    expect(result.abandonedCount).toBe(1);
  });

  it('TS-016 writes SHA256SUMS in coreutils format, sorted, with correct hashes', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const text = await readFile(path.join(bundle, 'SHA256SUMS'), 'utf8');
    const files = await listFiles(bundle);
    expect(text).toBe(files.map((f) => `${sha(f.bytes)}  ${f.path}\n`).join(''));
  });

  it('TS-017 makes manifest.json and SHA256SUMS 0400 and the bundle directory 0500', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    expect(await mode(path.join(bundle, 'manifest.json'))).toBe(0o400);
    expect(await mode(path.join(bundle, 'SHA256SUMS'))).toBe(0o400);
    expect(await mode(bundle)).toBe(0o500);
  });

  it('TS-017 keeps every record and artifact 0400', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    for (const f of await listFiles(bundle)) expect(await mode(path.join(bundle, f.path))).toBe(0o400);
  });

  it('TS-020 rejects a second seal with already sealed and leaves manifest.json byte-identical', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const before = await readFile(path.join(bundle, 'manifest.json'));
    await expect(sealEvidenceBundle(opts({ clock: () => new Date('2027-01-01T00:00:00.000Z') }))).rejects.toThrow(/already sealed/);
    expect((await readFile(path.join(bundle, 'manifest.json'))).equals(before)).toBe(true);
  });

  it('seals a bundle without records with head equal to genesis and recordCount 0', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.tmp', 1, RUN));
    await chmod(path.join(bundle, 'records', 'scan.tmp.a1.json'), 0o600);
    await rm(path.join(bundle, 'records', 'scan.tmp.a1.json'));
    const result = await sealEvidenceBundle(opts({ usedRecordIds: [] }));
    const m = await readManifest();
    const genesis = sha(`tessera:${RUN}`);
    expect(m.entries).toEqual([]);
    expect(m.chain.head).toBe(genesis);
    expect(m.rootHash).toBe(genesis);
    expect(result.rootHash).toBe(genesis);
    expect(result.recordCount).toBe(0);
    expect(result.artifactCount).toBe(0);
  });

  it('rejects the seal when a record belongs to another runId', async () => {
    await populate();
    const foreign = path.join(bundle, 'records', 'scan.other.a1.json');
    await writeFile(foreign, JSON.stringify(makeRecord('scan.other', 1, 'other-run')), { mode: 0o400 });
    await expect(sealEvidenceBundle(opts())).rejects.toThrow(/mismatch/i);
    await expect(stat(path.join(bundle, 'manifest.json'))).rejects.toThrow();
  });

  it('rejects the seal when the bundle contains a symlink', async () => {
    await populate();
    await symlink('/etc/hostname', path.join(bundle, 'artifacts', 'evil.txt'));
    await expect(sealEvidenceBundle(opts())).rejects.toThrow(/symlink/i);
    await expect(stat(path.join(bundle, 'manifest.json'))).rejects.toThrow();
  });

  it('returns bundlePath, rootHash, counts and selfVerified', async () => {
    await populate();
    const result = await sealEvidenceBundle(opts());
    const expected = oracle(RUN, await listFiles(bundle));
    expect(result).toEqual({
      bundlePath: bundle,
      rootHash: expected.head,
      recordCount: 3,
      artifactCount: 1,
      abandonedCount: 0,
      selfVerified: true,
    });
  });

  it('is deterministic: same bundle and clock give a byte-identical manifest', async () => {
    await populate();
    await sealEvidenceBundle(opts());
    const first = await readFile(path.join(bundle, 'manifest.json'));
    await chmod(bundle, 0o700);
    await chmod(path.join(bundle, 'manifest.json'), 0o600);
    await rm(path.join(bundle, 'manifest.json'));
    await rm(path.join(bundle, 'SHA256SUMS'));
    await sealEvidenceBundle(opts());
    expect((await readFile(path.join(bundle, 'manifest.json'))).equals(first)).toBe(true);
  });

  it('does not change any existing record while sealing', async () => {
    await populate();
    const before = await listFiles(bundle);
    await sealEvidenceBundle(opts());
    const after = await listFiles(bundle);
    expect(after.map((f) => [f.path, sha(f.bytes)])).toEqual(before.map((f) => [f.path, sha(f.bytes)]));
  });
});

describe('sealEvidenceBundle: self-verification, byte order and refusals', () => {
  let root: string;
  let bundle: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-seal-extra-'));
    bundle = path.join(root, RUN);
  });

  afterEach(async () => {
    verifyControl.fail = false;
    await chmod(bundle, 0o700).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  });

  const opts = (extra: Partial<SealOptions> = {}): SealOptions => ({
    bundleDir: bundle,
    runId: RUN,
    workflowId: 'wf-1',
    temporalRunId: 'temporal-1',
    source: { repoUrl: 'https://example.invalid/repo.git', revision: null },
    frameworkVersion: '1.2.3',
    usedRecordIds: [],
    clock: () => NOW,
    ...extra,
  });

  it('rejects the seal when its own verification fails', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    verifyControl.fail = true;
    await expect(sealEvidenceBundle(opts())).rejects.toThrow(/self-verification failed: modified records\/x\.json/);
  });

  it('orders entries by bytes, not by locale: upper case before lower case', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.a', 1, RUN));
    await store.writeRecord(makeRecord('scan.B', 1, RUN));
    await store.writeRecord(makeRecord('scan.Z', 1, RUN));
    await sealEvidenceBundle(opts());
    const m = JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8')) as EvidenceManifest;
    expect(m.entries.map((e) => e.path)).toEqual(['records/scan.B.a1.json', 'records/scan.Z.a1.json', 'records/scan.a.a1.json']);
  });

  it('refuses a used record id that is not in the bundle and writes no manifest', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    await expect(sealEvidenceBundle(opts({ usedRecordIds: ['scan.semgrep.a1'] }))).rejects.toThrow(/scan\.semgrep\.a1 is not in the bundle/);
    await expect(stat(path.join(bundle, 'manifest.json'))).rejects.toThrow();
  });

  it.each([
    ['an unexpected file in the bundle root', async () => writeFile(path.join(bundle, 'notes.txt'), 'x')],
    ['a record that is not JSON', async () => writeFile(path.join(bundle, 'records', 'scan.bad.a1.json'), 'nope')],
    ['a record with another schema', async () => writeFile(path.join(bundle, 'records', 'scan.bad.a1.json'), JSON.stringify({ schema: 'x', runId: RUN }))],
    ['a record whose id does not match its name', async () => writeFile(path.join(bundle, 'records', 'scan.alias.a1.json'), JSON.stringify(makeRecord('scan.other', 1, RUN)))],
    ['a non-JSON file in records/', async () => writeFile(path.join(bundle, 'records', 'scan.txt'), 'x')],
  ])('refuses %s and writes no manifest', async (_name, plant) => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    await plant();
    await expect(sealEvidenceBundle(opts())).rejects.toThrow(/evidence seal:/);
    await expect(stat(path.join(bundle, 'manifest.json'))).rejects.toThrow();
  });

  it('refuses a bundle directory that is a symlink', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    const alias = path.join(root, 'alias');
    await symlink(bundle, alias);
    await expect(sealEvidenceBundle(opts({ bundleDir: alias }))).rejects.toThrow(/symlink/);
  });

  it('replaces a stale SHA256SUMS from an interrupted seal', async () => {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1, RUN));
    await writeFile(path.join(bundle, 'SHA256SUMS'), 'stale\n');
    const result = await sealEvidenceBundle(opts());
    expect(result.selfVerified).toBe(true);
    expect(await readFile(path.join(bundle, 'SHA256SUMS'), 'utf8')).not.toContain('stale');
  });

  it('derives the artifact recordId from the record that references it', async () => {
    const store = createEvidenceStore(root, RUN);
    const out = Buffer.from('x');
    const ref = await store.writeArtifact('scan.npm-audit.a1', 'stdout.json', out, {
      mediaType: 'application/json',
      rawBytes: 1,
      rawSha256: sha(out),
      redactions: 0,
      truncated: false,
    });
    await store.writeRecord({ ...makeRecord('scan.npm-audit', 1, RUN), output: ref });
    await store.writeArtifact('orphan.a2', 'txt', out, { mediaType: 'text/plain', rawBytes: 1, rawSha256: sha(out), redactions: 0, truncated: false });
    await sealEvidenceBundle(opts({ usedRecordIds: ['scan.npm-audit.a1'] }));
    const m = JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8')) as EvidenceManifest;
    const by = Object.fromEntries(m.entries.map((e) => [e.path, e]));
    expect(by['artifacts/scan.npm-audit.a1.stdout.json']).toMatchObject({ recordId: 'scan.npm-audit.a1', used: true });
    expect(by['artifacts/orphan.a2.txt']).toMatchObject({ recordId: 'orphan.a2', used: false });
  });

  it.each([
    ['a relative bundleDir', { bundleDir: 'relative/dir' }],
    ['a missing bundle directory', { bundleDir: '/nonexistent-tessera-bundle' }],
    ['non-string used ids', { usedRecordIds: [1 as unknown as string] }],
  ])('rejects %s', async (_name, extra) => {
    await expect(sealEvidenceBundle(opts(extra as Partial<SealOptions>))).rejects.toThrow(/evidence seal:/);
  });
});

describe('sealEvidenceBundle: record references and seal summaries', () => {
  let root: string;
  let bundle: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-seal-refs-'));
    bundle = path.join(root, RUN);
  });

  afterEach(async () => {
    const { readdir: list } = await import('node:fs/promises');
    await chmod(bundle, 0o700).catch(() => undefined);
    for (const sub of ['artifacts', 'records']) {
      await chmod(path.join(bundle, sub), 0o700).catch(() => undefined);
      for (const f of await list(path.join(bundle, sub)).catch(() => [] as string[])) await chmod(path.join(bundle, sub, f), 0o600).catch(() => undefined);
    }
    await rm(root, { recursive: true, force: true });
  });

  async function writeRaw(files: Record<string, string>): Promise<void> {
    const { mkdir } = await import('node:fs/promises');
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(bundle, rel)), { recursive: true });
      await writeFile(path.join(bundle, rel), content);
    }
  }

  const rec = (id: string, output?: string): string => JSON.stringify({ schema: 'tessera.evidence/v1', runId: RUN, id, ...(output ? { output: { path: output } } : {}) });

  const opts = (): SealOptions => ({
    bundleDir: bundle,
    runId: RUN,
    workflowId: 'wf-1',
    temporalRunId: 'temporal-1',
    source: { repoUrl: 'https://example.invalid/repo.git', revision: null },
    frameworkVersion: '1.2.3',
    usedRecordIds: [],
    clock: () => NOW,
  });

  it('attributes an artifact to the first record, in byte order, that references it', async () => {
    await writeRaw({
      'records/x.json': rec('x', 'artifacts/x.a1.out'),
      'records/x.a1.json': rec('x.a1', 'artifacts/x.a1.out'),
      'artifacts/x.a1.out': 'out',
    });
    await sealEvidenceBundle(opts());
    const manifest = JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8')) as EvidenceManifest;
    expect(manifest.entries.find((e) => e.path === 'artifacts/x.a1.out')?.recordId).toBe('x.a1');
  });

  it('lists at most five problems when an existing seal does not verify', async () => {
    const files: Record<string, string> = { 'records/r.json': rec('r') };
    for (let i = 1; i <= 7; i++) files[`artifacts/r.${i}`] = `v${i}`;
    await writeRaw(files);
    await sealEvidenceBundle(opts());
    await chmod(bundle, 0o700);
    await chmod(path.join(bundle, 'artifacts'), 0o700);
    for (let i = 1; i <= 7; i++) {
      await chmod(path.join(bundle, `artifacts/r.${i}`), 0o600);
      await writeFile(path.join(bundle, `artifacts/r.${i}`), `changed${i}`);
    }
    const { openSealedBundle } = await import('../../../src/evidence/manifest');
    await expect(openSealedBundle(bundle, RUN)).rejects.toThrow(
      'evidence seal: existing seal does not verify: modified artifacts/r.1, modified artifacts/r.2, modified artifacts/r.3, modified artifacts/r.4, modified artifacts/r.5',
    );
    await expect(openSealedBundle(bundle, RUN)).rejects.not.toThrow('artifacts/r.6');
  });
});
