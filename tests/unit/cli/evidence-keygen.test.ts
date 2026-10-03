import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash, createPublicKey } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runKeygenCli } from '../../../src/cli/evidence-keygen';

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { stdout: (s: string) => void out.push(s), stderr: (s: string) => void err.push(s) } };
}

describe('runKeygenCli', () => {
  let dir: string;
  let keyPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'tessera-keygen-'));
    keyPath = path.join(dir, 'signing', 'ed25519.pem');
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('creates the key, prints keyId and public key path, never the private key, exit 0', async () => {
    const c = capture();
    const code = await runKeygenCli([keyPath], c.io);
    expect(code).toBe(0);
    const pub = await readFile(`${keyPath}.pub`);
    const keyId = createHash('sha256').update(createPublicKey(pub).export({ type: 'spki', format: 'der' })).digest('hex');
    const text = c.out.join('');
    expect(text).toContain(keyId);
    expect(text).toContain(`${keyPath}.pub`);
    const privatePem = await readFile(keyPath, 'utf8');
    const body = privatePem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    expect(body.length).toBeGreaterThan(20);
    expect(text + c.err.join('')).not.toContain(body);
    expect(text + c.err.join('')).not.toContain('PRIVATE KEY');
    expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
  });

  it('refuses an existing key with exit 1 and leaves it untouched', async () => {
    expect(await runKeygenCli([keyPath], capture().io)).toBe(0);
    const before = await readFile(keyPath, 'utf8');
    const c = capture();
    expect(await runKeygenCli([keyPath], c.io)).toBe(1);
    expect(c.err.join('').length).toBeGreaterThan(0);
    expect(await readFile(keyPath, 'utf8')).toBe(before);
  });

  it('refuses when only a leftover file exists at the key path', async () => {
    await writeFile(path.join(dir, 'x.pem'), 'x');
    const c = capture();
    expect(await runKeygenCli([path.join(dir, 'x.pem')], c.io)).toBe(1);
    expect(await readFile(path.join(dir, 'x.pem'), 'utf8')).toBe('x');
  });

  it('exits 2 with usage and creates nothing when no argument is given', async () => {
    const c = capture();
    expect(await runKeygenCli([], c.io)).toBe(2);
    expect(c.err.join('')).toMatch(/usage/i);
  });
});
