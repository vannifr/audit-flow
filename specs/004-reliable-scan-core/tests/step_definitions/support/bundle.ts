import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { ProcessOutcome, ProcessRequest } from '../../../../../src/scan/tool-types';
import type { EvidenceManifest, EvidenceRecord, ManifestEntry } from '../../../../../src/evidence/types';
import { sealEvidenceBundle } from '../../../../../src/evidence/manifest';
import { createEvidenceStore } from '../../../../../src/evidence/store';
import { runVerifyCli } from '../../../../../src/cli/verify-evidence';
import { T0, crashingTool, fixture, outcome } from './harness';
import type { ScanWorld } from './harness';

export const sha256 = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');

export function useGitSource(world: ScanWorld, revision: string = world.source.revision): void {
  world.source = { repoDir: world.source.repoDir, revision };
  world.sourceBehaviour = async (req: ProcessRequest): Promise<ProcessOutcome> => {
    if (req.args.length === 1) return outcome({ stdout: Buffer.from('git version 2.40.0\n') });
    if (req.args.includes('clone')) {
      const repoDir = req.args[req.args.length - 1];
      await mkdir(repoDir, { recursive: true, mode: 0o700 });
      for (const [name, content] of Object.entries(world.repoFiles)) await writeFile(path.join(repoDir, name), content);
      return outcome();
    }
    if (req.args.includes('rev-parse')) return outcome({ stdout: Buffer.from(`${revision}\n`) });
    throw new Error(`unexpected git call: ${req.args.join(' ')}`);
  };
}

export const bundleDirOf = (world: ScanWorld): string => path.join(world.evidenceRoot, world.runId);

export async function readManifest(dir: string): Promise<EvidenceManifest> {
  return JSON.parse(await readFile(path.join(dir, 'manifest.json'), 'utf8')) as EvidenceManifest;
}

export interface StoredRecord {
  entry: ManifestEntry;
  record: EvidenceRecord;
  bytes: Buffer;
}

export async function readRecords(dir: string): Promise<StoredRecord[]> {
  const manifest = await readManifest(dir);
  const out: StoredRecord[] = [];
  for (const entry of manifest.entries.filter((e) => e.kind === 'record')) {
    const bytes = await readFile(path.join(dir, entry.path));
    out.push({ entry, record: JSON.parse(bytes.toString('utf8')) as EvidenceRecord, bytes });
  }
  return out;
}

export async function recordById(dir: string, id: string): Promise<StoredRecord> {
  const found = (await readRecords(dir)).find((r) => r.record.id === id);
  assert.ok(found, `no evidence record ${id}`);
  return found;
}

export async function listFiles(dir: string, base = ''): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(path.join(dir, base), { withFileTypes: true })) {
    const rel = base === '' ? e.name : `${base}/${e.name}`;
    if (e.isDirectory()) out.push(...(await listFiles(dir, rel)));
    else out.push(rel);
  }
  return out.sort();
}

export async function fingerprintTree(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const f of await listFiles(dir)) out[f] = sha256(await readFile(path.join(dir, f)));
  return out;
}

async function modesOf(dir: string, rel = ''): Promise<Map<string, number>> {
  const modes = new Map<string, number>();
  const full = path.join(dir, rel);
  modes.set(rel, (await lstat(full)).mode & 0o777);
  if ((await lstat(full)).isDirectory()) {
    await chmod(full, 0o700);
    for (const name of await readdir(full)) {
      for (const [k, v] of await modesOf(dir, rel === '' ? name : `${rel}/${name}`)) modes.set(k, v);
    }
  } else {
    await chmod(full, 0o600);
  }
  return modes;
}

export async function withOpenBundle<T>(dir: string, change: () => Promise<T>): Promise<T> {
  const modes = await modesOf(dir);
  try {
    return await change();
  } finally {
    const rels = [...modes.keys()].sort((a, b) => b.length - a.length);
    for (const rel of rels) {
      await chmod(path.join(dir, rel), modes.get(rel) as number).catch(() => undefined);
    }
    for (const f of await listFiles(dir)) {
      if (!modes.has(f)) await chmod(path.join(dir, f), 0o400);
    }
  }
}

export interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

export async function cli(argv: string[]): Promise<CliRun> {
  let stdout = '';
  let stderr = '';
  const code = await runVerifyCli(argv, { stdout: (s) => (stdout += s), stderr: (s) => (stderr += s) });
  return { code, stdout, stderr };
}

export interface RawOutput {
  stdout: Buffer;
  stderr: Buffer;
}

const rawByWorld = new WeakMap<ScanWorld, Record<string, RawOutput>>();

export function rawOutputs(world: ScanWorld): Record<string, RawOutput> {
  const raw = rawByWorld.get(world);
  assert.ok(raw, 'the audit was not prepared through prepareAudit');
  return raw;
}

export async function prepareAudit(world: ScanWorld, revision?: string): Promise<void> {
  useGitSource(world, revision);
  const leak = await fixture('gitleaks-leak.json');
  const clean = await fixture('semgrep-clean.json');
  const crash = crashingTool();
  world.setTool('gitleaks', () => leak);
  world.setTool('semgrep', () => clean);
  world.setTool('npm-audit', () => crash);
  rawByWorld.set(world, {
    'source.clone': { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) },
    'source.revision': { stdout: Buffer.from(`${world.source.revision}\n`), stderr: Buffer.alloc(0) },
    'scan.gitleaks': { stdout: leak.stdout, stderr: leak.stderr },
    'scan.semgrep': { stdout: clean.stdout, stderr: clean.stderr },
    'scan.npm-audit': { stdout: crash.stdout, stderr: crash.stderr },
  });
}

export async function completedAudit(world: ScanWorld): Promise<void> {
  await prepareAudit(world);
  await world.runAudit();
  assert.equal(world.error, undefined, `audit failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.result?.evidence, 'the audit sealed no evidence');
  assert.equal(world.result.evidence.bundlePath, bundleDirOf(world));
}

export async function sealedBundleWithRecords(world: ScanWorld, runId: string, count: number): Promise<string> {
  const template = (await recordById(bundleDirOf(world), 'scan.semgrep.a1')).record;
  assert.ok(template.output, 'the template record has no output artifact');
  const raw = rawOutputs(world)['scan.semgrep'].stdout;
  const store = createEvidenceStore(world.evidenceRoot, runId);
  const ids: string[] = [];
  for (let i = 0; i < count; i++) {
    const stepId = `scan.bulk-${i}`;
    const id = `${stepId}.a1`;
    const output = await store.writeArtifact(id, 'stdout.json', Buffer.from(`{"step":${i}}\n`), {
      mediaType: 'application/json',
      rawBytes: raw.length,
      rawSha256: sha256(raw),
      redactions: 0,
      truncated: false,
    });
    await store.writeRecord({ ...template, id, runId, stepId, attempt: 1, output });
    ids.push(id);
  }
  const result = await sealEvidenceBundle({
    bundleDir: store.bundleDir,
    runId,
    workflowId: 'wf-bdd',
    temporalRunId: runId,
    source: template.source,
    frameworkVersion: '0.0.0-bdd',
    usedRecordIds: ids,
    clock: () => T0,
  });
  assert.equal(result.recordCount, count);
  return store.bundleDir;
}

export async function rewriteRecordAndRecompute(dir: string, recordPath: string, change: (bytes: Buffer) => Buffer): Promise<void> {
  await withOpenBundle(dir, async () => {
    const manifest = await readManifest(dir);
    const target = manifest.entries.find((e) => e.path === recordPath);
    assert.ok(target, `no manifest entry for ${recordPath}`);
    const changed = change(await readFile(path.join(dir, recordPath)));
    await writeFile(path.join(dir, recordPath), changed);
    target.sha256 = sha256(changed);
    target.bytes = changed.length;
    let previous = sha256(`tessera:${manifest.runId}`);
    for (const [index, entry] of manifest.entries.entries()) {
      entry.seq = index + 1;
      entry.chainHash = sha256(`${previous}\n${entry.seq}\n${entry.path}\n${entry.sha256}`);
      previous = entry.chainHash;
    }
    manifest.chain.head = previous;
    manifest.rootHash = previous;
    await writeFile(path.join(dir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    await writeFile(path.join(dir, 'SHA256SUMS'), manifest.entries.map((e) => `${e.sha256}  ${e.path}\n`).join(''));
  });
}
