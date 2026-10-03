import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import { sealEvidenceBundle } from '../../../src/evidence/manifest';
import { verifyEvidenceBundle } from '../../../src/evidence/verify';
import type { EvidenceRecord } from '../../../src/evidence/types';
import { generateSigningKey, signEvidenceBundle, verifyBundleSignature } from '../../../src/evidence/sign';

const RUN = 'run-h';
const SIGNED = new Date('2026-03-01T12:05:00.000Z');

function record(stepId: string): EvidenceRecord {
  return {
    schema: 'tessera.evidence/v1',
    id: `${stepId}.a1`,
    runId: RUN,
    stepId,
    attempt: 1,
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

const bodyOf = (pem: string): string => pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

describe('evidence signing hardening', () => {
  let tmp: string;
  let root: string;
  let bundle: string;
  let keyPath: string;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(tmpdir(), 'tessera-signh-'));
    root = path.join(tmp, 'evidence');
    bundle = path.join(root, RUN);
    keyPath = path.join(tmp, 'keys', 'ed25519.pem');
    await mkdir(root, { recursive: true });
    await createEvidenceStore(root, RUN).writeRecord(record('scan.npm-audit'));
    await sealEvidenceBundle({
      bundleDir: bundle,
      runId: RUN,
      workflowId: 'wf',
      temporalRunId: 't',
      source: { repoUrl: 'https://example.invalid/repo.git', revision: 'b'.repeat(40) },
      frameworkVersion: '1.0.0',
      usedRecordIds: ['scan.npm-audit.a1'],
      clock: () => new Date('2026-03-01T12:00:00.000Z'),
    });
  });

  afterEach(async () => {
    await chmod(bundle, 0o700).catch(() => undefined);
    await rm(tmp, { recursive: true, force: true });
  });

  const sign = (k = keyPath) => signEvidenceBundle({ bundleDir: bundle, keyPath: k, evidenceRoot: root, clock: () => SIGNED });
  const messageOf = async (p: Promise<unknown>): Promise<string> =>
    p.then(
      () => '',
      (e: unknown) => (e instanceof Error ? e.message : String(e)),
    );

  for (const mode of [0o640, 0o604, 0o660, 0o620]) {
    it(`refuses a private key file with mode ${mode.toString(8)} and does not leak it`, async () => {
      await generateSigningKey(keyPath);
      await chmod(keyPath, mode);
      const message = await messageOf(sign());
      expect(message).toMatch(/group or others/);
      expect(message).not.toContain(bodyOf(await readFile(keyPath, 'utf8')));
      await expect(stat(path.join(bundle, 'signature.json'))).rejects.toThrow();
    });
  }

  it('refuses a file that is not a PEM private key without echoing its content', async () => {
    await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
    await writeFile(keyPath, 'SECRETCONTENTNOTAKEY', { mode: 0o600 });
    const message = await messageOf(sign());
    expect(message).toMatch(/not a valid PEM private key/);
    expect(message).not.toContain('SECRETCONTENTNOTAKEY');
  });

  it('refuses a non-Ed25519 private key', async () => {
    await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    expect(await messageOf(sign())).toMatch(/not an Ed25519 key/);
  });

  it('refuses a key path that is a directory', async () => {
    await mkdir(keyPath, { recursive: true, mode: 0o700 });
    expect(await messageOf(sign())).toMatch(/not a regular file/);
  });

  it('removes a leftover partial signature from an interrupted run and signs, leaving the directory 0500', async () => {
    await generateSigningKey(keyPath);
    await chmod(bundle, 0o700);
    await writeFile(path.join(bundle, '.signature.json.partial'), 'partial');
    await chmod(bundle, 0o500);
    await sign();
    expect(await readdir(bundle)).not.toContain('.signature.json.partial');
    expect((await stat(bundle)).mode & 0o777).toBe(0o500);
    expect((await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] })).status).toBe('valid');
  });

  it('restores the bundle directory to 0500 when writing the signature fails', async () => {
    await generateSigningKey(keyPath);
    await chmod(bundle, 0o700);
    await mkdir(path.join(bundle, '.signature.json.partial'));
    await chmod(bundle, 0o500);
    await expect(sign()).rejects.toThrow();
    expect((await stat(bundle)).mode & 0o777).toBe(0o500);
  });

  it('refuses to sign a bundle whose records no longer verify', async () => {
    await generateSigningKey(keyPath);
    await chmod(bundle, 0o700);
    await chmod(path.join(bundle, 'records'), 0o700);
    const rec = path.join(bundle, 'records', 'scan.npm-audit.a1.json');
    await chmod(rec, 0o600);
    await writeFile(rec, '{}');
    expect(await messageOf(sign())).toMatch(/does not verify/);
  });

  it('refuses a symlinked bundle directory and a relative bundle path', async () => {
    await generateSigningKey(keyPath);
    const link = path.join(tmp, 'link');
    await symlink(bundle, link);
    expect(await messageOf(signEvidenceBundle({ bundleDir: link, keyPath, evidenceRoot: path.join(tmp, 'x'), clock: () => SIGNED }))).toMatch(/not a bundle directory/);
    expect(await messageOf(signEvidenceBundle({ bundleDir: 'relative', keyPath, evidenceRoot: root, clock: () => SIGNED }))).toMatch(/absolute/);
  });

  it('keygen refuses an existing public key file and a group-writable key directory', async () => {
    await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
    await writeFile(`${keyPath}.pub`, 'old');
    await expect(generateSigningKey(keyPath)).rejects.toThrow(/exist/);
    await expect(stat(keyPath)).rejects.toThrow();
    const loose = path.join(tmp, 'loose');
    await mkdir(loose, { mode: 0o700 });
    await chmod(loose, 0o770);
    await expect(generateSigningKey(path.join(loose, 'k.pem'))).rejects.toThrow(/writable by group or others/);
    await expect(generateSigningKey('')).rejects.toThrow(/required/);
  });

  describe('verifyBundleSignature edge cases', () => {
    beforeEach(async () => {
      await generateSigningKey(keyPath);
      await sign();
      await chmod(bundle, 0o700);
    });

    const status = async (trusted: string[] = [`${keyPath}.pub`]) => (await verifyBundleSignature(bundle, { trustedKeys: trusted })).status;

    it('gives invalid for a symlinked signature.json, and verify reports it as extra', async () => {
      const real = path.join(tmp, 'sig.json');
      await writeFile(real, await readFile(path.join(bundle, 'signature.json')));
      await unlink(path.join(bundle, 'signature.json'));
      await symlink(real, path.join(bundle, 'signature.json'));
      expect(await status()).toBe('invalid');
      const report = await verifyEvidenceBundle(bundle);
      expect(report.issues.map((i) => [i.problem, i.path])).toContainEqual(['extra', 'signature.json']);
    });

    it('gives invalid when the manifest is missing', async () => {
      await chmod(path.join(bundle, 'manifest.json'), 0o600);
      await unlink(path.join(bundle, 'manifest.json'));
      expect(await status()).toBe('invalid');
    });

    it('gives invalid for a non-hex keyId, a wrong schema, a wrong alg, a short signature and a bad signedAt', async () => {
      const file = path.join(bundle, 'signature.json');
      await chmod(file, 0o600);
      const sig = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
      for (const patch of [
        { keyId: 'XYZ' },
        { schema: 'tessera.signature/v2' },
        { alg: 'rsa' },
        { signature: Buffer.alloc(32).toString('base64') },
        { signedAt: 'yesterday' },
        { runId: '' },
        { manifestSha256: 'f'.repeat(64) },
      ]) {
        await writeFile(file, JSON.stringify({ ...sig, ...patch }));
        expect(await status()).toBe('invalid');
      }
    });

    it('ignores trusted entries that are missing, not keys or not Ed25519', async () => {
      const dir = path.join(tmp, 'trusted');
      await mkdir(dir);
      await writeFile(path.join(dir, 'junk.pub'), 'not a key');
      const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      await writeFile(path.join(dir, 'ec.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
      await writeFile(path.join(dir, 'private.pub'), await readFile(keyPath));
      expect(await status([dir, path.join(tmp, 'missing'), ''])).toBe('unknown-key');
    });

    it('never throws on nonsense input', async () => {
      expect((await verifyBundleSignature('', { trustedKeys: [] })).status).toBe('invalid');
      expect((await verifyBundleSignature(path.join(tmp, 'none'), { trustedKeys: [] })).status).toBe('unsigned');
    });

    it('verifyEvidenceBundle with trusted keys is ok only for a valid signature, and keeps hashesOk separate', async () => {
      const good = await verifyEvidenceBundle(bundle, { trustedKeys: [`${keyPath}.pub`] });
      expect(good).toMatchObject({ ok: true, hashesOk: true, signature: { status: 'valid' } });
      const unknown = await verifyEvidenceBundle(bundle, { trustedKeys: [] });
      expect(unknown).toMatchObject({ ok: false, hashesOk: true, signature: { status: 'unknown-key' } });
      const unchecked = await verifyEvidenceBundle(bundle);
      expect(unchecked).toMatchObject({ ok: true, hashesOk: true });
      await chmod(path.join(bundle, 'signature.json'), 0o600);
      await unlink(path.join(bundle, 'signature.json'));
      const unsigned = await verifyEvidenceBundle(bundle, { trustedKeys: [`${keyPath}.pub`] });
      expect(unsigned).toMatchObject({ ok: false, hashesOk: true, signature: { status: 'unsigned' } });
    });

    it('reports a stray partial signature file as extra', async () => {
      await writeFile(path.join(bundle, '.signature.json.partial'), 'x');
      const report = await verifyEvidenceBundle(bundle);
      expect(report.ok).toBe(false);
      expect(report.issues.map((i) => i.path)).toContain('.signature.json.partial');
    });
  });
});

describe('evidence signing key hard links', () => {
  it('refuses a private key with a second hard link', async () => {
    const tmp = await mkdtemp(path.join(tmpdir(), 'tessera-signhl-'));
    try {
      const root = path.join(tmp, 'evidence');
      const bundle = path.join(root, RUN);
      await mkdir(root, { recursive: true });
      await createEvidenceStore(root, RUN).writeRecord(record('scan.npm-audit'));
      await sealEvidenceBundle({
        bundleDir: bundle,
        runId: RUN,
        workflowId: 'wf',
        temporalRunId: 't',
        source: { repoUrl: 'https://example.invalid/repo.git', revision: null },
        frameworkVersion: '1.0.0',
        usedRecordIds: [],
        clock: () => SIGNED,
      });
      const keyPath = path.join(tmp, 'keys', 'ed25519.pem');
      await generateSigningKey(keyPath);
      const { link } = await import('node:fs/promises');
      await link(keyPath, path.join(tmp, 'keys', 'copy.pem'));
      await expect(signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => SIGNED })).rejects.toThrow(/hard link/);
      await chmod(bundle, 0o700);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });
});
