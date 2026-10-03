import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store';
import { sealEvidenceBundle } from '../../../src/evidence/manifest';
import type { EvidenceManifest, EvidenceRecord } from '../../../src/evidence/types';
import {
  computeAssuranceLevel,
  generateSigningKey,
  signEvidenceBundle,
  verifyBundleSignature,
  type EvidenceSignature,
  type SignatureReport,
  type SignatureStatus,
} from '../../../src/evidence/sign';

const RUN = 'run-1';
const SEALED = new Date('2026-03-01T12:00:00.000Z');
const SIGNED = new Date('2026-03-01T12:05:00.000Z');
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const mode = async (p: string): Promise<number> => (await stat(p)).mode & 0o777;

function makeRecord(stepId: string, attempt: number): EvidenceRecord {
  return {
    schema: 'tessera.evidence/v1',
    id: `${stepId}.a${attempt}`,
    runId: RUN,
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

function oraclePayload(s: { runId: string; rootHash: string; manifestSha256: string; signedAt: string }): Buffer {
  return Buffer.from(`tessera-sig/v1\n${s.runId}\n${s.rootHash}\n${s.manifestSha256}\n${s.signedAt}`);
}

function oracleChain(runId: string, files: { path: string; bytes: Buffer }[]) {
  let prev = sha(`tessera:${runId}`);
  const entries = files.map((f, i) => {
    const chainHash = sha(`${prev}\n${i + 1}\n${f.path}\n${sha(f.bytes)}`);
    prev = chainHash;
    return { sha256: sha(f.bytes), chainHash };
  });
  return { entries, head: prev };
}

function privateBody(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

async function allFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await allFiles(p)));
    else out.push(p);
  }
  return out;
}

describe('computeAssuranceLevel', () => {
  const statuses: SignatureStatus[] = ['valid', 'invalid', 'unsigned', 'unknown-key'];
  const report = (status: SignatureStatus): SignatureReport => ({ status, keyId: null, signedAt: null, timeAttested: false });
  for (const hashesOk of [true, false]) {
    for (const status of statuses) {
      const expected = hashesOk && status === 'valid' ? 1 : 0;
      it(`hashesOk=${hashesOk} status=${status} gives level ${expected}`, () => {
        expect(computeAssuranceLevel(hashesOk, report(status))).toBe(expected);
      });
    }
  }
});

describe('evidence signing', () => {
  let tmp: string;
  let root: string;
  let bundle: string;
  let keyDir: string;
  let keyPath: string;
  let keyId: string;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(tmpdir(), 'tessera-sign-'));
    root = path.join(tmp, 'evidence');
    keyDir = path.join(tmp, 'keys');
    keyPath = path.join(keyDir, 'ed25519.pem');
    bundle = path.join(root, RUN);
    await mkdir(root, { recursive: true });
  });

  afterEach(async () => {
    await chmod(bundle, 0o700).catch(() => undefined);
    await rm(tmp, { recursive: true, force: true });
  });

  async function populate(): Promise<void> {
    const store = createEvidenceStore(root, RUN);
    await store.writeRecord(makeRecord('scan.npm-audit', 1));
    await store.writeRecord(makeRecord('scan.semgrep', 1));
  }

  async function seal(): Promise<void> {
    await populate();
    await sealEvidenceBundle({
      bundleDir: bundle,
      runId: RUN,
      workflowId: 'wf-1',
      temporalRunId: 'temporal-1',
      source: { repoUrl: 'https://example.invalid/repo.git', revision: 'b'.repeat(40) },
      frameworkVersion: '1.2.3',
      usedRecordIds: ['scan.npm-audit.a1', 'scan.semgrep.a1'],
      clock: () => SEALED,
    });
  }

  async function sealAndSign(): Promise<EvidenceSignature> {
    await seal();
    keyId = (await generateSigningKey(keyPath)).keyId;
    return signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => SIGNED });
  }

  const readSig = async (): Promise<EvidenceSignature> =>
    JSON.parse(await readFile(path.join(bundle, 'signature.json'), 'utf8')) as EvidenceSignature;

  async function openBundle(): Promise<void> {
    await chmod(bundle, 0o700);
    await chmod(path.join(bundle, 'manifest.json'), 0o600);
    await chmod(path.join(bundle, 'SHA256SUMS'), 0o600);
    await chmod(path.join(bundle, 'records'), 0o700);
  }

  async function rewriteManifest(mutate: (m: EvidenceManifest) => void): Promise<void> {
    await openBundle();
    const file = path.join(bundle, 'manifest.json');
    const m = JSON.parse(await readFile(file, 'utf8')) as EvidenceManifest;
    mutate(m);
    await writeFile(file, JSON.stringify(m, null, 2) + '\n');
  }

  describe('generateSigningKey', () => {
    it('creates an Ed25519 key pair with private key 0600 in a 0700 directory and the public key next to it', async () => {
      const res = await generateSigningKey(keyPath);
      expect(await mode(keyDir)).toBe(0o700);
      expect(await mode(keyPath)).toBe(0o600);
      expect(res.publicKeyPath).toBe(`${keyPath}.pub`);
      const pub = createPublicKey(await readFile(res.publicKeyPath));
      expect(pub.asymmetricKeyType).toBe('ed25519');
      expect(res.keyId).toBe(sha(pub.export({ type: 'spki', format: 'der' })));
      expect(res.keyId).toMatch(/^[0-9a-f]{64}$/);
    });

    it('does not put the private key into the public key file', async () => {
      const res = await generateSigningKey(keyPath);
      const body = privateBody(await readFile(keyPath, 'utf8'));
      expect(await readFile(res.publicKeyPath, 'utf8')).not.toContain(body);
      expect(await readFile(res.publicKeyPath, 'utf8')).not.toContain('PRIVATE');
    });

    it('refuses to overwrite an existing key and leaves it untouched', async () => {
      await generateSigningKey(keyPath);
      const before = await readFile(keyPath, 'utf8');
      await expect(generateSigningKey(keyPath)).rejects.toThrow(/exist/i);
      expect(await readFile(keyPath, 'utf8')).toBe(before);
    });
  });

  describe('signEvidenceBundle', () => {
    it('writes signature.json with the contract fields and a signature that the independent oracle accepts', async () => {
      const sig = await sealAndSign();
      const onDisk = await readSig();
      expect(onDisk).toEqual(sig);
      const manifest = await readFile(path.join(bundle, 'manifest.json'));
      const parsed = JSON.parse(manifest.toString('utf8')) as EvidenceManifest;
      expect(sig.schema).toBe('tessera.signature/v1');
      expect(sig.alg).toBe('ed25519');
      expect(sig.keyId).toBe(keyId);
      expect(sig.runId).toBe(RUN);
      expect(sig.rootHash).toBe(parsed.rootHash);
      expect(sig.manifestSha256).toBe(sha(manifest));
      expect(sig.signedAt).toBe(SIGNED.toISOString());
      const pub = createPublicKey(await readFile(`${keyPath}.pub`));
      expect(cryptoVerify(null, oraclePayload(sig), pub, Buffer.from(sig.signature, 'base64'))).toBe(true);
      expect(cryptoVerify(null, oraclePayload({ ...sig, signedAt: '2026-03-01T12:05:01.000Z' }), pub, Buffer.from(sig.signature, 'base64'))).toBe(false);
    });

    it('makes signature.json read-only 0400', async () => {
      await sealAndSign();
      expect(await mode(path.join(bundle, 'signature.json'))).toBe(0o400);
    });

    it('TS-035 refuses a key path inside the evidence root and writes no signature', async () => {
      await seal();
      const inside = path.join(root, 'keys', 'ed25519.pem');
      await generateSigningKey(inside);
      await expect(signEvidenceBundle({ bundleDir: bundle, keyPath: inside, evidenceRoot: root, clock: () => SIGNED })).rejects.toThrow();
      await expect(stat(path.join(bundle, 'signature.json'))).rejects.toThrow();
    });

    it('TS-035 refuses a key path inside the bundle directory', async () => {
      await seal();
      await generateSigningKey(path.join(tmp, 'elsewhere', 'ed25519.pem'));
      await chmod(bundle, 0o700);
      const bundleKey = path.join(bundle, 'key.pem');
      await writeFile(bundleKey, await readFile(path.join(tmp, 'elsewhere', 'ed25519.pem')), { mode: 0o600 });
      await expect(
        signEvidenceBundle({ bundleDir: bundle, keyPath: bundleKey, evidenceRoot: path.join(tmp, 'other-root'), clock: () => SIGNED }),
      ).rejects.toThrow();
    });

    it('TS-035 refuses a key path outside the root that is a symlink into the root', async () => {
      await seal();
      const inside = path.join(root, 'keys', 'ed25519.pem');
      await generateSigningKey(inside);
      await mkdir(keyDir, { recursive: true });
      await symlink(inside, keyPath);
      await expect(signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => SIGNED })).rejects.toThrow();
      await expect(stat(path.join(bundle, 'signature.json'))).rejects.toThrow();
    });

    it('refuses a bundle that is not sealed', async () => {
      await populate();
      await generateSigningKey(keyPath);
      await expect(signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => SIGNED })).rejects.toThrow();
      await expect(stat(path.join(bundle, 'signature.json'))).rejects.toThrow();
    });

    it('refuses a second signature and keeps the first untouched', async () => {
      await sealAndSign();
      const before = await readFile(path.join(bundle, 'signature.json'), 'utf8');
      await expect(
        signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => new Date('2027-01-01T00:00:00.000Z') }),
      ).rejects.toThrow(/exist|already/i);
      expect(await readFile(path.join(bundle, 'signature.json'), 'utf8')).toBe(before);
    });

    it('does not leak the private key into signature.json, any bundle file or an error message', async () => {
      await sealAndSign();
      const body = privateBody(await readFile(keyPath, 'utf8'));
      for (const f of await allFiles(bundle)) {
        expect((await readFile(f)).toString('latin1')).not.toContain(body);
      }
      let message = '';
      try {
        await signEvidenceBundle({ bundleDir: bundle, keyPath, evidenceRoot: root, clock: () => SIGNED });
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
      expect(message.length).toBeGreaterThan(0);
      expect(message).not.toContain(body);
      let missing = '';
      try {
        await signEvidenceBundle({ bundleDir: bundle, keyPath: path.join(keyDir, 'missing.pem'), evidenceRoot: root, clock: () => SIGNED });
      } catch (e) {
        missing = e instanceof Error ? e.message : String(e);
      }
      expect(missing.length).toBeGreaterThan(0);
      expect(missing).not.toContain(body);
    });
  });

  describe('verifyBundleSignature', () => {
    it('TS-031 gives valid with keyId, signedAt and timeAttested false for a trusted key (file)', async () => {
      await sealAndSign();
      const r = await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] });
      expect(r).toEqual({ status: 'valid', keyId, signedAt: SIGNED.toISOString(), timeAttested: false });
    });

    it('TS-031 accepts a trusted directory containing .pub files, including old keys after rotation', async () => {
      await sealAndSign();
      const trusted = path.join(tmp, 'trusted');
      await mkdir(trusted);
      await generateSigningKey(path.join(tmp, 'other', 'k.pem'));
      await writeFile(path.join(trusted, 'a.pub'), await readFile(path.join(tmp, 'other', 'k.pem.pub')));
      await writeFile(path.join(trusted, 'b.pub'), await readFile(`${keyPath}.pub`));
      await writeFile(path.join(trusted, 'notes.txt'), 'ignored');
      const r = await verifyBundleSignature(bundle, { trustedKeys: [trusted] });
      expect(r.status).toBe('valid');
      expect(r.keyId).toBe(keyId);
    });

    it('TS-032 SC-007 gives invalid when a record is changed and the manifest and SHA256SUMS are recomputed by hand', async () => {
      await sealAndSign();
      await openBundle();
      const recPath = path.join(bundle, 'records', 'scan.npm-audit.a1.json');
      await chmod(recPath, 0o600);
      const rec = JSON.parse(await readFile(recPath, 'utf8')) as EvidenceRecord;
      rec.result.exitCode = 1;
      await writeFile(recPath, JSON.stringify(rec));
      const files = await Promise.all(
        ['records/scan.npm-audit.a1.json', 'records/scan.semgrep.a1.json'].map(async (p) => ({ path: p, bytes: await readFile(path.join(bundle, p)) })),
      );
      const o = oracleChain(RUN, files);
      const m = JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8')) as EvidenceManifest;
      m.entries.forEach((e, i) => {
        e.sha256 = o.entries[i]!.sha256;
        e.chainHash = o.entries[i]!.chainHash;
        e.bytes = files[i]!.bytes.length;
      });
      m.chain.head = o.head;
      m.rootHash = o.head;
      await writeFile(path.join(bundle, 'manifest.json'), JSON.stringify(m, null, 2) + '\n');
      await writeFile(path.join(bundle, 'SHA256SUMS'), files.map((f) => `${sha(f.bytes)}  ${f.path}\n`).join(''));
      const r = await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] });
      expect(r.status).toBe('invalid');
      expect(r.timeAttested).toBe(false);
    });

    for (const field of ['used', 'source.revision', 'sealedAt']) {
      it(`gives invalid when only the manifest field ${field} outside the chain is changed`, async () => {
        await sealAndSign();
        await rewriteManifest((m) => {
          if (field === 'used') m.entries[0]!.used = !m.entries[0]!.used;
          else if (field === 'source.revision') m.source.revision = 'c'.repeat(40);
          else m.sealedAt = '2026-03-02T00:00:00.000Z';
        });
        const r = await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] });
        expect(r.status).toBe('invalid');
      });
    }

    it('gives invalid when signature.json has a different runId than the manifest', async () => {
      await sealAndSign();
      const s = await readSig();
      await chmod(path.join(bundle, 'signature.json'), 0o600);
      await chmod(bundle, 0o700);
      await writeFile(path.join(bundle, 'signature.json'), JSON.stringify({ ...s, runId: 'run-2' }));
      expect((await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] })).status).toBe('invalid');
    });

    it('gives invalid when signature.json has a different rootHash than the manifest', async () => {
      await sealAndSign();
      const s = await readSig();
      await chmod(bundle, 0o700);
      await chmod(path.join(bundle, 'signature.json'), 0o600);
      await writeFile(path.join(bundle, 'signature.json'), JSON.stringify({ ...s, rootHash: 'd'.repeat(64) }));
      expect((await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] })).status).toBe('invalid');
    });

    for (const [name, mutate] of [
      ['broken JSON', () => '{not json'],
      ['broken base64', (s: EvidenceSignature) => JSON.stringify({ ...s, signature: '!!!not-base64!!!' })],
      ['empty signature', (s: EvidenceSignature) => JSON.stringify({ ...s, signature: '' })],
      ['array instead of object', () => '[]'],
    ] as const) {
      it(`gives invalid without throwing for ${name}`, async () => {
        const s = await sealAndSign();
        await chmod(bundle, 0o700);
        await chmod(path.join(bundle, 'signature.json'), 0o600);
        await writeFile(path.join(bundle, 'signature.json'), mutate(s));
        const r = await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] });
        expect(r.status).toBe('invalid');
        expect(r.timeAttested).toBe(false);
      });
    }

    it('TS-033 SC-008 gives unsigned with null keyId and signedAt when signature.json is missing', async () => {
      await seal();
      await generateSigningKey(keyPath);
      const r = await verifyBundleSignature(bundle, { trustedKeys: [`${keyPath}.pub`] });
      expect(r).toEqual({ status: 'unsigned', keyId: null, signedAt: null, timeAttested: false });
    });

    const untrusted: [string, (ctx: { keyPath: string; tmp: string }) => Promise<string[]>][] = [
      [
        'a trusted key with a different keyId',
        async (c) => {
          const other = path.join(c.tmp, 'other', 'k.pem');
          await generateSigningKey(other);
          return [`${other}.pub`];
        },
      ],
      ['an empty trusted key list', async () => []],
      [
        'an empty trusted directory',
        async (c) => {
          const d = path.join(c.tmp, 'empty-trusted');
          await mkdir(d);
          return [d];
        },
      ],
    ];
    for (const [name, trustedFor] of untrusted) {
      it(`TS-033 SC-008 gives unknown-key for ${name}`, async () => {
        await sealAndSign();
        const trustedKeys = await trustedFor({ keyPath, tmp });
        const r = await verifyBundleSignature(bundle, { trustedKeys });
        expect(r.status).toBe('unknown-key');
        expect(r.keyId).toBe(keyId);
        expect(r.timeAttested).toBe(false);
      });
    }
  });
});
