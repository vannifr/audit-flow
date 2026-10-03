import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import { runVerifyCli } from '../../../src/cli/verify-evidence';
import { generateSigningKey, signEvidenceBundle } from '../../../src/evidence/sign';
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

async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = '';
  let err = '';
  const code = await runVerifyCli(argv, {
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

const ANSI = /\u001b\[/;

describe('runVerifyCli', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-cli-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('an unmodified bundle exits 0 and starts with VERIFIED, runId, root hash and entry count', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir]);
    expect(r.code).toBe(0);
    const words = r.out.trim().split(/\s+/);
    expect(words[0]).toBe('VERIFIED');
    expect(r.out).toContain(RUN);
    expect(r.out).toContain(b.rootHash);
    expect(r.out).toMatch(new RegExp(`\\b${b.manifest.entries.length}\\b`));
    expect(ANSI.test(r.out)).toBe(false);
    expect(ANSI.test(r.err)).toBe(false);
  });

  it('a modified bundle exits 1 and starts with FAILED with one line per issue', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'artifacts/scan.npm-audit.a1.json'), 'changed');
    await writeFile(path.join(b.dir, 'records/injected.json'), '{}');
    await lockAll(b.dir);
    const r = await run([b.dir]);
    expect(r.code).toBe(1);
    expect(r.out.trim().split(/\s+/)[0]).toBe('FAILED');
    const lines = r.out.split('\n').map((l) => l.trim());
    expect(lines).toContain('modified artifacts/scan.npm-audit.a1.json');
    expect(lines).toContain('extra records/injected.json');
    expect(ANSI.test(r.out)).toBe(false);
    expect(ANSI.test(r.err)).toBe(false);
  });

  it('a deleted record is reported as a missing line', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await rm(path.join(b.dir, 'records/scan.gitleaks.a1.json'));
    const r = await run([b.dir]);
    expect(r.code).toBe(1);
    expect(r.out.split('\n').map((l) => l.trim())).toContain('missing records/scan.gitleaks.a1.json');
  });

  it('no arguments exits 2 with a usage message on stderr and nothing on stdout', async () => {
    const r = await run([]);
    expect(r.code).toBe(2);
    expect(r.err.length).toBeGreaterThan(0);
    expect(r.out).toBe('');
  });

  it('an unreadable or nonexistent directory exits 2', async () => {
    const r = await run([path.join(root, 'does-not-exist')]);
    expect(r.code).toBe(2);
    expect(r.err.length).toBeGreaterThan(0);
    expect(r.out.trim().split(/\s+/)[0]).not.toBe('VERIFIED');
  });

  it('an unknown option exits 2', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--bogus']);
    expect(r.code).toBe(2);
  });

  it('--expect-root with the right hash exits 0', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--expect-root', b.rootHash]);
    expect(r.code).toBe(0);
    expect(r.out.trim().split(/\s+/)[0]).toBe('VERIFIED');
  });

  it('--expect-root with a wrong hash exits 1 and reports FAILED', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--expect-root', '0'.repeat(64)]);
    expect(r.code).toBe(1);
    expect(r.out.trim().split(/\s+/)[0]).toBe('FAILED');
  });

  it('--expect-root without a value exits 2', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--expect-root']);
    expect(r.code).toBe(2);
  });

  it('--json prints the VerifyReport as JSON on stdout', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--json', '--expect-root', b.rootHash]);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report).toMatchObject({
      ok: true,
      bundlePath: b.dir,
      runId: RUN,
      rootHash: b.rootHash,
      manifestRootHash: b.rootHash,
      rootMatches: true,
      checkedEntries: b.manifest.entries.length,
      issues: [],
    });
  });

  it('--json on a modified bundle exits 1 and lists the issue', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'artifacts/scan.npm-audit.a1.json'), 'changed');
    const r = await run([b.dir, '--json']);
    expect(r.code).toBe(1);
    const report = JSON.parse(r.out);
    expect(report.ok).toBe(false);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]).toMatchObject({ problem: 'modified', path: 'artifacts/scan.npm-audit.a1.json' });
  });

  it('--trace <recordId> shows record id, raw fingerprint, revision and root hash', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--trace', 'scan.npm-audit.a1']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('scan.npm-audit.a1');
    expect(r.out).toContain(sha('raw-output-scan.npm-audit.a1'));
    expect(r.out).toContain(sha('raw-stderr-scan.npm-audit.a1'));
    expect(r.out).toContain('a'.repeat(40));
    expect(r.out).toContain(b.rootHash);
    expect(ANSI.test(r.out)).toBe(false);
  });

  it('--trace with an unknown recordId exits non-zero with a message and no VERIFIED', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--trace', 'scan.nope.a1']);
    expect(r.code).not.toBe(0);
    expect(r.err.length).toBeGreaterThan(0);
  });
});

describe('runVerifyCli trace on a tampered bundle', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-cli-trace-'));
  });

  afterEach(async () => {
    await removeTree(root);
  });

  it('--trace on a modified bundle exits 1, reports FAILED and prints no trace', async () => {
    const b = await buildSealedBundle(root);
    await unlockAll(b.dir);
    await writeFile(path.join(b.dir, 'artifacts/scan.npm-audit.a1.json'), 'changed');
    const r = await run([b.dir, '--trace', 'scan.npm-audit.a1']);
    expect(r.code).toBe(1);
    expect(r.out.trim().split(/\s+/)[0]).toBe('FAILED');
    expect(r.out).not.toContain(sha('raw-output-scan.npm-audit.a1'));
  });

  it('--trace with --json prints the report and the trace as JSON', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--trace', 'scan.npm-audit.a1', '--json']);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.out);
    expect(parsed.report.ok).toBe(true);
    expect(parsed.trace.recordId).toBe('scan.npm-audit.a1');
    expect(parsed.trace.rootHash).toBe(b.rootHash);
  });

  it.each([
    ['a malformed --expect-root', (dir: string) => [dir, '--expect-root', 'xyz']],
    ['two bundle directories', (dir: string) => [dir, dir]],
    ['--trace without a value', (dir: string) => [dir, '--trace']],
  ])('%s exits 2 with a usage message', async (_name, argv) => {
    const b = await buildSealedBundle(root);
    const r = await run(argv(b.dir));
    expect(r.code).toBe(2);
    expect(r.err).toContain('usage:');
    expect(r.out).toBe('');
  });

  it('accepts an upper-case --expect-root', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--expect-root', b.rootHash.toUpperCase()]);
    expect(r.code).toBe(0);
  });
});

describe('runVerifyCli --pubkey (FR-019, SC-008, TS-031, TS-033)', () => {
  let root: string;
  let keys: string;
  let keyPath: string;
  let keyId: string;
  const SIGNED = new Date('2026-03-01T12:05:00.000Z');

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tessera-cli-sig-'));
    keys = await mkdtemp(path.join(tmpdir(), 'tessera-cli-keys-'));
    keyPath = path.join(keys, 'signer', 'ed25519.pem');
    keyId = (await generateSigningKey(keyPath)).keyId;
  });

  afterEach(async () => {
    await removeTree(root);
    await rm(keys, { recursive: true, force: true });
  });

  async function signed(): Promise<Sealed> {
    const b = await buildSealedBundle(root);
    await signEvidenceBundle({ bundleDir: b.dir, keyPath, evidenceRoot: root, clock: () => SIGNED });
    return b;
  }

  const firstWord = (out: string): string => out.trim().split(/\s+/)[0];
  const signatureLine = (out: string): string | undefined => out.split('\n').find((l) => l.startsWith('Signature:'));

  it('TS-031 a signed bundle with the right public key exits 0 and names the key and the unattested time', async () => {
    const b = await signed();
    const r = await run([b.dir, '--pubkey', `${keyPath}.pub`, '--expect-root', b.rootHash]);
    expect(r.code).toBe(0);
    expect(firstWord(r.out)).toBe('VERIFIED');
    expect(r.out.split('\n')[1]).toBe(`Signature: valid (key ${keyId}, signed ${SIGNED.toISOString()}, time not independently attested)`);
  });

  it('accepts a directory of public keys and repeated --pubkey flags', async () => {
    const b = await signed();
    const other = path.join(keys, 'other', 'k.pem');
    await generateSigningKey(other);
    const r = await run([b.dir, '--pubkey', `${other}.pub`, '--pubkey', path.dirname(keyPath)]);
    expect(r.code).toBe(0);
    expect(signatureLine(r.out)).toMatch(/^Signature: valid/);
  });

  it('TS-033 SC-008 an unsigned bundle with --pubkey exits 1, starts with FAILED and says unsigned', async () => {
    const b = await buildSealedBundle(root);
    const r = await run([b.dir, '--pubkey', `${keyPath}.pub`]);
    expect(r.code).toBe(1);
    expect(firstWord(r.out)).toBe('FAILED');
    expect(r.out).not.toContain('VERIFIED');
    expect(signatureLine(r.out)).toBe('Signature: unsigned');
  });

  it('TS-033 SC-008 a bundle signed by a key the verifier lacks exits 1 with unknown-key', async () => {
    const b = await signed();
    const other = path.join(keys, 'other', 'k.pem');
    await generateSigningKey(other);
    const r = await run([b.dir, '--pubkey', `${other}.pub`]);
    expect(r.code).toBe(1);
    expect(firstWord(r.out)).toBe('FAILED');
    expect(r.out).not.toContain('VERIFIED');
    expect(signatureLine(r.out)).toMatch(/^Signature: unknown-key \(key [0-9a-f]{64} /);
  });

  it('a tampered signature exits 1 with invalid', async () => {
    const b = await signed();
    await chmod(b.dir, 0o700);
    const sigFile = path.join(b.dir, 'signature.json');
    await chmod(sigFile, 0o600);
    const sig = JSON.parse(await readFile(sigFile, 'utf8')) as { signedAt: string };
    await writeFile(sigFile, JSON.stringify({ ...sig, signedAt: '2030-01-01T00:00:00.000Z' }));
    const r = await run([b.dir, '--pubkey', `${keyPath}.pub`]);
    expect(r.code).toBe(1);
    expect(firstWord(r.out)).toBe('FAILED');
    expect(signatureLine(r.out)).toBe('Signature: invalid');
  });

  it('broken hashes fail even with a valid signature', async () => {
    const b = await signed();
    const r = await run([b.dir, '--pubkey', `${keyPath}.pub`, '--expect-root', '0'.repeat(64)]);
    expect(r.code).toBe(1);
    expect(firstWord(r.out)).toBe('FAILED');
  });

  it('without --pubkey a signed bundle verifies by hashes and says the signature was not checked, with no extra issue', async () => {
    const b = await signed();
    const r = await run([b.dir]);
    expect(r.code).toBe(0);
    expect(firstWord(r.out)).toBe('VERIFIED');
    expect(r.out.split('\n')[1]).toBe('Signature: not checked (no --pubkey)');
    expect(r.out).not.toContain('extra');
  });

  it('--json reports the signature status and whether it was checked', async () => {
    const b = await signed();
    const checked = JSON.parse((await run([b.dir, '--json', '--pubkey', `${keyPath}.pub`])).out) as { ok: boolean; signatureChecked: boolean; signature: { status: string; keyId: string } };
    expect(checked).toMatchObject({ ok: true, signatureChecked: true, signature: { status: 'valid', keyId } });
    const unchecked = JSON.parse((await run([b.dir, '--json'])).out) as { ok: boolean; signatureChecked: boolean };
    expect(unchecked).toMatchObject({ ok: true, signatureChecked: false });
  });

  it('--pubkey without a value exits 2', async () => {
    const b = await buildSealedBundle(root);
    expect((await run([b.dir, '--pubkey'])).code).toBe(2);
    expect((await run([b.dir, '--pubkey', '--json'])).code).toBe(2);
  });
});
