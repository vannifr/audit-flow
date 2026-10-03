import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { lstat, open, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { sha256Hex } from './hash';
import type { EvidenceManifest, EvidenceRecord, ManifestEntry, Sha256Hex } from './types';
import { SIGNATURE_FILE, verifyBundleSignature } from './sign';
import type { SignatureReport } from './sign';

export interface VerifyOptions {
  expectRootHash?: string;
  trustedKeys?: string[];
}

export interface VerifyIssue {
  path: string;
  problem: 'modified' | 'missing' | 'extra' | 'run-mismatch' | 'invalid-record' | 'chain-broken';
  expected?: string;
  actual?: string;
}

export type VerifyVerdict = 'verified' | 'hashes-ok' | 'failed';

export interface VerifyReport {
  ok: HashesOkUnlessKeysGiven;
  verdict: VerifyVerdict;
  bundlePath: string;
  runId: string | null;
  rootHash: string | null;
  manifestRootHash: string | null;
  rootMatches: boolean | null;
  checkedEntries: number;
  issues: VerifyIssue[];
  hashesOk: boolean;
  signature: SignatureReport;
}

export type HashesOkUnlessKeysGiven = boolean;

export interface EvidenceTrace {
  recordId: string;
  record: EvidenceRecord;
  artifacts: { path: string; sha256: Sha256Hex; rawSha256: Sha256Hex }[];
  source: { repoUrl: string; revision: string | null };
  rootHash: Sha256Hex;
}

export const MANIFEST_FILE = 'manifest.json';
export const SUMS_FILE = 'SHA256SUMS';
export const MAX_RECORD_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$/;
const RECORD_PATH = /^records\/([^/]+)\.json$/;
const ARTIFACT_PATH = /^artifacts\/([^/]+)$/;
const ABANDONED_PATH = /^records\/\.staging\/([^/]+)$/;
const ALLOWED_DIRS: ReadonlySet<string> = new Set(['records', 'artifacts', 'records/.staging']);
const READ_CHUNK = 64 * 1024;
const PRIORITY: Record<VerifyIssue['problem'], number> = {
  missing: 0,
  extra: 0,
  modified: 1,
  'chain-broken': 2,
  'run-mismatch': 3,
  'invalid-record': 4,
};

export function isSafeName(name: string): boolean {
  return SAFE_NAME.test(name) && !name.includes('..');
}

export function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export function chainGenesis(runId: string): Sha256Hex {
  return sha256Hex(`tessera:${runId}`);
}

export function chainLink(prev: Sha256Hex, seq: number, entryPath: string, sha256: Sha256Hex): Sha256Hex {
  return sha256Hex(`${prev}\n${seq}\n${entryPath}\n${sha256}`);
}

export function renderSums(entries: readonly { path: string; sha256: string }[]): string {
  return entries.map((e) => `${e.sha256}  ${e.path}\n`).join('');
}

function isErrno(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code;
}

export type OpenResult = { fh: FileHandle; stat: Stats } | { problem: 'missing' | 'symlink' | 'not-regular' };

export async function openRegular(file: string): Promise<OpenResult> {
  let st: Stats;
  try {
    st = await lstat(file);
  } catch (err) {
    if (isErrno(err, 'ENOENT') || isErrno(err, 'ENOTDIR')) return { problem: 'missing' };
    throw err;
  }
  if (st.isSymbolicLink()) return { problem: 'symlink' };
  if (!st.isFile()) return { problem: 'not-regular' };
  let fh: FileHandle;
  try {
    fh = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    if (isErrno(err, 'ELOOP')) return { problem: 'symlink' };
    if (isErrno(err, 'ENOENT')) return { problem: 'missing' };
    throw err;
  }
  const fst = await fh.stat();
  if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) {
    await fh.close();
    return { problem: 'not-regular' };
  }
  return { fh, stat: fst };
}

export interface HashedContent {
  sha256: Sha256Hex;
  bytes: number;
  content: Buffer | null;
}

export async function hashHandle(fh: FileHandle, keepUpTo: number): Promise<HashedContent> {
  const hash = createHash('sha256');
  const buf = Buffer.allocUnsafe(READ_CHUNK);
  const kept: Buffer[] = [];
  let keep = keepUpTo > 0;
  let pos = 0;
  for (;;) {
    const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
    if (bytesRead === 0) break;
    const chunk = buf.subarray(0, bytesRead);
    hash.update(chunk);
    pos += bytesRead;
    if (keep) {
      if (pos > keepUpTo) {
        keep = false;
        kept.length = 0;
      } else {
        kept.push(Buffer.from(chunk));
      }
    }
  }
  return { sha256: hash.digest('hex'), bytes: pos, content: keep ? Buffer.concat(kept) : null };
}

async function readRegular(file: string, keepUpTo: number): Promise<HashedContent | { problem: 'missing' | 'symlink' | 'not-regular' }> {
  const opened = await openRegular(file);
  if ('problem' in opened) return opened;
  try {
    return await hashHandle(opened.fh, keepUpTo);
  } finally {
    await opened.fh.close();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isHex(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function validEntry(value: unknown): value is ManifestEntry {
  if (!isRecord(value)) return false;
  const { seq, path: p, kind, recordId, bytes, sha256, chainHash, used } = value;
  if (!isCount(seq) || !isCount(bytes) || !isHex(sha256) || !isHex(chainHash) || typeof used !== 'boolean') return false;
  if (typeof p !== 'string' || typeof recordId !== 'string' || !isSafeName(recordId)) return false;
  if (kind === 'record') {
    const m = RECORD_PATH.exec(p);
    return m !== null && isSafeName(`${m[1]}.json`) && m[1] === recordId;
  }
  if (kind === 'artifact') {
    const m = ARTIFACT_PATH.exec(p);
    return m !== null && isSafeName(m[1]) && (m[1] === recordId || m[1].startsWith(`${recordId}.`));
  }
  return false;
}

function validAbandoned(value: unknown): value is { path: string; bytes: number; sha256: string } {
  if (!isRecord(value)) return false;
  if (typeof value.path !== 'string' || !isCount(value.bytes) || !isHex(value.sha256)) return false;
  const m = ABANDONED_PATH.exec(value.path);
  return m !== null && isSafeName(m[1]);
}

export function parseManifest(content: Buffer | null): EvidenceManifest | null {
  if (content === null) return null;
  let m: unknown;
  try {
    m = JSON.parse(content.toString('utf8'));
  } catch {
    return null;
  }
  if (!isRecord(m) || m.schema !== 'tessera.manifest/v1' || m.hashAlgorithm !== 'sha256') return null;
  if (typeof m.runId !== 'string' || m.runId.length === 0) return null;
  for (const key of ['workflowId', 'temporalRunId', 'sealedAt', 'retainUntil'] as const) {
    if (typeof m[key] !== 'string') return null;
  }
  const source = m.source;
  if (!isRecord(source) || typeof source.repoUrl !== 'string' || (source.revision !== null && typeof source.revision !== 'string')) return null;
  if (!isRecord(m.framework) || m.framework.name !== 'tessera' || typeof m.framework.version !== 'string') return null;
  const chain = m.chain;
  if (!isRecord(chain) || chain.algorithm !== 'tessera-chain/v1' || !isHex(chain.genesis) || !isHex(chain.head)) return null;
  if (!isHex(m.rootHash)) return null;
  if (!Array.isArray(m.entries) || !m.entries.every(validEntry)) return null;
  if (!Array.isArray(m.abandoned) || !m.abandoned.every(validAbandoned)) return null;
  const entries = m.entries as ManifestEntry[];
  for (let i = 1; i < entries.length; i++) {
    if (compareBytes(entries[i - 1].path, entries[i].path) >= 0) return null;
  }
  const seen = new Set(entries.map((e) => e.path));
  for (const a of m.abandoned as { path: string }[]) {
    if (seen.has(a.path)) return null;
    seen.add(a.path);
  }
  return m as unknown as EvidenceManifest;
}

export async function readManifest(bundleDir: string): Promise<EvidenceManifest | null> {
  const read = await readRegular(path.join(bundleDir, MANIFEST_FILE), MAX_MANIFEST_BYTES);
  if ('problem' in read) return null;
  return parseManifest(read.content);
}

type NodeKind = 'file' | 'symlink' | 'dir' | 'other';

async function walkBundle(bundleDir: string): Promise<{ nodes: Map<string, NodeKind>; emptyDirs: string[] }> {
  const nodes = new Map<string, NodeKind>();
  const emptyDirs: string[] = [];
  const visit = async (rel: string): Promise<void> => {
    const dirents = await readdir(rel === '' ? bundleDir : path.join(bundleDir, rel), { withFileTypes: true });
    if (dirents.length === 0 && rel !== '') emptyDirs.push(rel);
    for (const d of dirents) {
      const child = rel === '' ? d.name : `${rel}/${d.name}`;
      if (d.isSymbolicLink()) nodes.set(child, 'symlink');
      else if (d.isDirectory()) {
        nodes.set(child, 'dir');
        await visit(child);
      } else if (d.isFile()) nodes.set(child, 'file');
      else nodes.set(child, 'other');
    }
  };
  await visit('');
  return { nodes, emptyDirs };
}

async function assertBundleDir(bundleDir: string): Promise<void> {
  const st = await lstat(bundleDir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`evidence verify: not a bundle directory: ${bundleDir}`);
}

function recordProblem(content: Buffer | null, entry: ManifestEntry, runId: string): VerifyIssue | null {
  if (content === null) return { path: entry.path, problem: 'invalid-record', actual: 'record too large' };
  let rec: unknown;
  try {
    rec = JSON.parse(content.toString('utf8'));
  } catch {
    return { path: entry.path, problem: 'invalid-record', actual: 'not valid JSON' };
  }
  if (!isRecord(rec) || rec.schema !== 'tessera.evidence/v1') {
    return { path: entry.path, problem: 'invalid-record', expected: 'tessera.evidence/v1' };
  }
  if (rec.runId !== runId) {
    return { path: entry.path, problem: 'run-mismatch', expected: runId, actual: typeof rec.runId === 'string' ? rec.runId : String(rec.runId) };
  }
  if (rec.id !== entry.recordId) {
    return { path: entry.path, problem: 'invalid-record', expected: entry.recordId, actual: typeof rec.id === 'string' ? rec.id : String(rec.id) };
  }
  return null;
}

function verdictFor(hashesOk: boolean, keysGiven: boolean, signature: SignatureReport): VerifyVerdict {
  if (!hashesOk) return 'failed';
  if (!keysGiven) return 'hashes-ok';
  return signature.status === 'valid' ? 'verified' : 'failed';
}

export async function verifyEvidenceBundle(bundleDir: string, opts: VerifyOptions = {}): Promise<VerifyReport> {
  await assertBundleDir(bundleDir);
  const expectRoot = typeof opts.expectRootHash === 'string' ? opts.expectRootHash.trim().toLowerCase() : undefined;
  const manifest = await readManifest(bundleDir);
  const signature = await verifyBundleSignature(bundleDir, { trustedKeys: Array.isArray(opts.trustedKeys) ? opts.trustedKeys : [] });
  const signatureOk = opts.trustedKeys === undefined || signature.status === 'valid';
  if (manifest === null) {
    return {
      ok: false,
      bundlePath: bundleDir,
      runId: null,
      rootHash: null,
      manifestRootHash: null,
      rootMatches: expectRoot === undefined ? null : false,
      checkedEntries: 0,
      issues: [{ path: MANIFEST_FILE, problem: 'invalid-record' }],
      hashesOk: false,
      signature,
      verdict: 'failed',
    };
  }

  const issues = new Map<string, VerifyIssue>();
  const report = (issue: VerifyIssue): void => {
    const current = issues.get(issue.path);
    if (current === undefined || PRIORITY[issue.problem] < PRIORITY[current.problem]) issues.set(issue.path, issue);
  };

  const { nodes, emptyDirs } = await walkBundle(bundleDir);
  const expected = new Set<string>([MANIFEST_FILE, SUMS_FILE]);
  if (nodes.get(SIGNATURE_FILE) === 'file') expected.add(SIGNATURE_FILE);
  for (const e of manifest.entries) expected.add(e.path);
  for (const a of manifest.abandoned) expected.add(a.path);

  for (const [rel, kind] of nodes) {
    if (kind === 'dir') continue;
    if (!expected.has(rel) || kind !== 'file') report({ path: rel, problem: 'extra' });
  }
  for (const rel of emptyDirs) {
    if (!ALLOWED_DIRS.has(rel)) report({ path: rel, problem: 'extra' });
  }
  const checkFile = async (rel: string, sha256: string, bytes: number, keep: number): Promise<HashedContent | null> => {
    if (nodes.get(rel) !== 'file') {
      if (!nodes.has(rel) || nodes.get(rel) === 'dir') report({ path: rel, problem: 'missing' });
      return null;
    }
    const read = await readRegular(path.join(bundleDir, rel), keep);
    if ('problem' in read) {
      report({ path: rel, problem: read.problem === 'missing' ? 'missing' : 'extra' });
      return null;
    }
    if (read.sha256 !== sha256) {
      report({ path: rel, problem: 'modified', expected: sha256, actual: read.sha256 });
      return null;
    }
    if (read.bytes !== bytes) {
      report({ path: rel, problem: 'modified', expected: `bytes:${bytes}`, actual: `bytes:${read.bytes}` });
      return null;
    }
    return read;
  };

  for (const entry of manifest.entries) {
    const read = await checkFile(entry.path, entry.sha256, entry.bytes, entry.kind === 'record' ? MAX_RECORD_BYTES : 0);
    if (read === null || entry.kind !== 'record') continue;
    const problem = recordProblem(read.content, entry, manifest.runId);
    if (problem !== null) report(problem);
  }
  for (const a of manifest.abandoned) await checkFile(a.path, a.sha256, a.bytes, 0);

  const sums = renderSums(manifest.entries);
  const sumsBytes = Buffer.byteLength(sums, 'utf8');
  const sumsHash = sha256Hex(sums);
  await checkFile(SUMS_FILE, sumsHash, sumsBytes, 0);

  const genesis = chainGenesis(manifest.runId);
  let prev = genesis;
  manifest.entries.forEach((entry, i) => {
    const seq = i + 1;
    const link = chainLink(prev, seq, entry.path, entry.sha256);
    if (entry.seq !== seq) report({ path: entry.path, problem: 'chain-broken', expected: `seq:${seq}`, actual: `seq:${entry.seq}` });
    else if (entry.chainHash !== link) report({ path: entry.path, problem: 'chain-broken', expected: link, actual: entry.chainHash });
    prev = link;
  });
  const head = prev;
  if (manifest.chain.genesis !== genesis) {
    report({ path: MANIFEST_FILE, problem: 'chain-broken', expected: genesis, actual: manifest.chain.genesis });
  } else if (manifest.chain.head !== head) {
    report({ path: MANIFEST_FILE, problem: 'chain-broken', expected: head, actual: manifest.chain.head });
  } else if (manifest.rootHash !== head) {
    report({ path: MANIFEST_FILE, problem: 'chain-broken', expected: head, actual: manifest.rootHash });
  }

  const rootMatches = expectRoot === undefined ? null : expectRoot === head;
  const sorted = [...issues.values()].sort((a, b) => compareBytes(a.path, b.path));
  const hashesOk = sorted.length === 0 && rootMatches !== false;
  return {
    ok: hashesOk && signatureOk,
    bundlePath: bundleDir,
    runId: manifest.runId,
    rootHash: head,
    manifestRootHash: manifest.rootHash,
    rootMatches,
    checkedEntries: manifest.entries.length,
    issues: sorted,
    hashesOk,
    signature,
    verdict: verdictFor(hashesOk, opts.trustedKeys !== undefined, signature),
  };
}

export async function traceEvidence(bundleDir: string, recordId: string): Promise<EvidenceTrace> {
  if (typeof recordId !== 'string' || !isSafeName(recordId)) throw new Error('evidence trace: invalid record id');
  await assertBundleDir(bundleDir);
  const manifest = await readManifest(bundleDir);
  if (manifest === null) throw new Error('evidence trace: manifest.json is missing or invalid');
  const entry = manifest.entries.find((e) => e.kind === 'record' && e.recordId === recordId);
  if (entry === undefined) throw new Error(`evidence trace: unknown record id ${recordId}`);
  const read = await readRegular(path.join(bundleDir, entry.path), MAX_RECORD_BYTES);
  if ('problem' in read) throw new Error(`evidence trace: record ${entry.path} not found as a regular file`);
  if (read.sha256 !== entry.sha256 || read.content === null) throw new Error(`evidence trace: record ${entry.path} does not match the manifest`);
  const record = JSON.parse(read.content.toString('utf8')) as EvidenceRecord;
  if (record.runId !== manifest.runId || record.id !== recordId) throw new Error(`evidence trace: record ${entry.path} does not match the manifest`);
  const byPath = new Map(manifest.entries.map((e) => [e.path, e]));
  const artifacts: EvidenceTrace['artifacts'] = [];
  for (const ref of [record.output, record.stderr]) {
    if (ref === null || ref === undefined) continue;
    const listed = byPath.get(ref.path);
    if (listed === undefined || listed.kind !== 'artifact' || listed.sha256 !== ref.sha256) {
      throw new Error(`evidence trace: artifact ${String(ref.path)} does not match the manifest`);
    }
    artifacts.push({ path: ref.path, sha256: ref.sha256, rawSha256: ref.rawSha256 });
  }
  return { recordId, record, artifacts, source: manifest.source, rootHash: manifest.rootHash };
}
