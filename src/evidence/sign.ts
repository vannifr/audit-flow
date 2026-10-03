import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { FileHandle } from 'node:fs/promises';
import { chmod, link, lstat, mkdir, open, readdir, realpath, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { Sha256Hex } from './types';
import { MANIFEST_FILE, hashHandle, openRegular, parseManifest, verifyEvidenceBundle } from './verify';

export interface EvidenceSignature {
  schema: 'tessera.signature/v1';
  alg: 'ed25519';
  keyId: Sha256Hex;
  runId: string;
  rootHash: Sha256Hex;
  manifestSha256: Sha256Hex;
  signedAt: string;
  signature: string;
}

export type SignatureStatus = 'valid' | 'invalid' | 'unsigned' | 'unknown-key';

export interface SignatureReport {
  status: SignatureStatus;
  keyId: string | null;
  signedAt: string | null;
  timeAttested: false;
}

export type AssuranceLevel = 0 | 1;

export interface SignOptions {
  keyPath: string;
}

export interface VerifySignatureOptions {
  trustedKeys: string[];
}

export const SIGNATURE_FILE = 'signature.json';
export const SIGNATURE_PARTIAL_FILE = '.signature.json.partial';
const PAYLOAD_PREFIX = 'tessera-sig/v1';
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_KEY_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;
const SIGNATURE_MODE = 0o400;
const SEALED_DIR_MODE = 0o500;
const OPEN_DIR_MODE = 0o700;

export function computeAssuranceLevel(hashesOk: boolean, sig: SignatureReport): AssuranceLevel {
  return hashesOk && sig.status === 'valid' ? 1 : 0;
}

function fail(scope: 'sign' | 'keygen', message: string): never {
  throw new Error(`evidence ${scope}: ${message}`);
}

function errnoCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null ? (err as NodeJS.ErrnoException).code : undefined;
}

async function lstatOrNull(p: string): Promise<Stats | null> {
  try {
    return await lstat(p);
  } catch (err) {
    if (errnoCode(err) === 'ENOENT') return null;
    throw err;
  }
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

async function realOrResolved(p: string): Promise<string> {
  try {
    return await realpath(p);
  } catch {
    return path.resolve(p);
  }
}

function sha256(bytes: Buffer | string): Sha256Hex {
  return createHash('sha256').update(bytes).digest('hex');
}

export function publicKeyId(key: KeyObject): Sha256Hex {
  return sha256(key.export({ type: 'spki', format: 'der' }));
}

export function signaturePayload(s: { runId: string; rootHash: string; manifestSha256: string; signedAt: string }): Buffer {
  return Buffer.from(`${PAYLOAD_PREFIX}\n${s.runId}\n${s.rootHash}\n${s.manifestSha256}\n${s.signedAt}`, 'utf8');
}

function tempName(base: string): string {
  return `.${base}.${randomBytes(8).toString('hex')}.tmp`;
}

async function writeExclusive(file: string, content: string | Buffer, mode: number): Promise<void> {
  const fh = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try {
    await fh.writeFile(content);
    await fh.sync();
  } finally {
    await fh.close();
  }
}

async function syncDir(dir: string): Promise<void> {
  const fh = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

async function publishNoClobber(scope: 'sign' | 'keygen', dir: string, target: string, content: string, mode: number): Promise<void> {
  const tmp = path.join(dir, tempName(path.basename(target)));
  await writeExclusive(tmp, content, mode);
  try {
    await link(tmp, target);
  } catch (err) {
    if (errnoCode(err) === 'EEXIST') fail(scope, `refusing to overwrite: ${target} already exists`);
    throw err;
  } finally {
    await unlink(tmp).catch(() => undefined);
  }
}

async function prepareKeyDir(dir: string): Promise<void> {
  const existing = await lstatOrNull(dir);
  if (existing === null) {
    await mkdir(dir, { recursive: true, mode: OPEN_DIR_MODE });
    await chmod(dir, OPEN_DIR_MODE);
    return;
  }
  if (existing.isSymbolicLink() || !existing.isDirectory()) fail('keygen', `key directory is not a plain directory: ${dir}`);
  const uid = process.getuid?.();
  if (uid !== undefined && existing.uid !== uid) fail('keygen', `key directory is not owned by the current user: ${dir}`);
  if ((existing.mode & 0o022) !== 0) fail('keygen', `key directory is writable by group or others: ${dir}`);
}

export async function generateSigningKey(keyPath: string): Promise<{ keyId: string; publicKeyPath: string }> {
  if (typeof keyPath !== 'string' || keyPath.length === 0) fail('keygen', 'a key path is required');
  const target = path.resolve(keyPath);
  const publicKeyPath = `${target}.pub`;
  const dir = path.dirname(target);
  for (const p of [target, publicKeyPath]) {
    if ((await lstatOrNull(p)) !== null) fail('keygen', `refusing to overwrite: ${p} already exists`);
  }
  await prepareKeyDir(dir);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  await publishNoClobber('keygen', dir, target, privatePem, 0o600);
  try {
    await publishNoClobber('keygen', dir, publicKeyPath, publicPem, 0o644);
  } catch (err) {
    await unlink(target).catch(() => undefined);
    throw err;
  }
  await syncDir(dir);
  return { keyId: publicKeyId(publicKey), publicKeyPath };
}

async function loadPrivateKey(realKey: string): Promise<KeyObject> {
  let fh: FileHandle;
  try {
    fh = await open(realKey, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    const code = errnoCode(err);
    if (code === 'ELOOP') fail('sign', `signing key must not be a symlink: ${realKey}`);
    if (code === 'ENOENT') fail('sign', `signing key not found: ${realKey}`);
    fail('sign', `signing key cannot be opened (${code ?? 'unknown error'}): ${realKey}`);
  }
  let bytes: Buffer | null = null;
  try {
    const st = await fh.stat();
    if (!st.isFile()) fail('sign', `signing key is not a regular file: ${realKey}`);
    if (st.nlink !== 1) fail('sign', `signing key has more than one hard link: ${realKey}`);
    const uid = process.getuid?.();
    if (uid !== undefined && st.uid !== uid) fail('sign', `signing key is not owned by the current user: ${realKey}`);
    if ((st.mode & 0o077) !== 0) fail('sign', `signing key is accessible to group or others, expected mode 0600: ${realKey}`);
    if (st.size > MAX_KEY_BYTES) fail('sign', `signing key file is too large: ${realKey}`);
    const read = await hashHandle(fh, MAX_KEY_BYTES);
    if (read.content === null) fail('sign', `signing key file is too large: ${realKey}`);
    bytes = read.content;
    let key: KeyObject;
    try {
      key = createPrivateKey({ key: bytes, format: 'pem' });
    } catch {
      fail('sign', `signing key is not a valid PEM private key: ${realKey}`);
    }
    if (key.asymmetricKeyType !== 'ed25519') fail('sign', `signing key is not an Ed25519 key: ${realKey}`);
    return key;
  } finally {
    if (bytes !== null) bytes.fill(0);
    await fh.close();
  }
}

async function readSealedManifest(bundleDir: string): Promise<Buffer> {
  const opened = await openRegular(path.join(bundleDir, MANIFEST_FILE));
  if ('problem' in opened) fail('sign', `bundle is not sealed (manifest.json ${opened.problem}): ${bundleDir}`);
  try {
    const read = await hashHandle(opened.fh, MAX_MANIFEST_BYTES);
    if (read.content === null) fail('sign', 'manifest.json is too large');
    return read.content;
  } finally {
    await opened.fh.close();
  }
}

async function removeStalePartial(bundleDir: string): Promise<void> {
  const file = path.join(bundleDir, SIGNATURE_PARTIAL_FILE);
  const st = await lstatOrNull(file);
  if (st === null) return;
  if (!st.isFile() || st.isSymbolicLink()) fail('sign', `unexpected entry ${SIGNATURE_PARTIAL_FILE} in the bundle`);
  await unlink(file);
}

async function writeSignatureFile(bundleDir: string, content: string): Promise<void> {
  await chmod(bundleDir, OPEN_DIR_MODE);
  try {
    await removeStalePartial(bundleDir);
    const partial = path.join(bundleDir, SIGNATURE_PARTIAL_FILE);
    await writeExclusive(partial, content, SIGNATURE_MODE);
    try {
      await link(partial, path.join(bundleDir, SIGNATURE_FILE));
    } catch (err) {
      if (errnoCode(err) === 'EEXIST') fail('sign', `signature already exists: ${path.join(bundleDir, SIGNATURE_FILE)}`);
      throw err;
    } finally {
      await unlink(partial).catch(() => undefined);
    }
    await syncDir(bundleDir);
  } finally {
    await chmod(bundleDir, SEALED_DIR_MODE);
  }
}

async function assertSigningPreconditions(opts: {
  bundleDir: string;
  keyPath: string;
  evidenceRoot: string;
  clock: () => Date;
}): Promise<{ bundleDir: string; realKey: string }> {
  if (typeof opts?.bundleDir !== 'string' || !path.isAbsolute(opts.bundleDir)) fail('sign', 'bundleDir must be an absolute path');
  if (typeof opts.keyPath !== 'string' || opts.keyPath.length === 0) fail('sign', 'a signing key path is required');
  if (typeof opts.evidenceRoot !== 'string' || opts.evidenceRoot.length === 0) fail('sign', 'evidenceRoot is required');
  if (typeof opts.clock !== 'function') fail('sign', 'clock is required');
  const bundleDir = path.resolve(opts.bundleDir);
  const dirStat = await lstatOrNull(bundleDir);
  if (dirStat === null || dirStat.isSymbolicLink() || !dirStat.isDirectory()) fail('sign', `not a bundle directory: ${bundleDir}`);
  const uid = process.getuid?.();
  if (uid !== undefined && dirStat.uid !== uid) fail('sign', `${bundleDir} is not owned by the current user`);

  const keyPath = path.resolve(opts.keyPath);
  let realKey: string;
  try {
    realKey = await realpath(keyPath);
  } catch (err) {
    fail('sign', `signing key not found (${errnoCode(err) ?? 'unknown error'}): ${keyPath}`);
  }
  const roots = [path.resolve(opts.evidenceRoot), await realOrResolved(opts.evidenceRoot), bundleDir, await realOrResolved(bundleDir)];
  for (const root of roots) {
    if (isInside(root, realKey) || isInside(root, keyPath)) fail('sign', `refusing a signing key inside the evidence folder: ${keyPath}`);
  }
  return { bundleDir, realKey };
}

async function clearSignatureLeftovers(bundleDir: string): Promise<void> {
  if ((await lstatOrNull(path.join(bundleDir, SIGNATURE_FILE))) !== null) {
    fail('sign', `signature already exists: ${path.join(bundleDir, SIGNATURE_FILE)}`);
  }
  if ((await lstatOrNull(path.join(bundleDir, SIGNATURE_PARTIAL_FILE))) !== null) {
    await chmod(bundleDir, OPEN_DIR_MODE);
    try {
      await removeStalePartial(bundleDir);
    } finally {
      await chmod(bundleDir, SEALED_DIR_MODE);
    }
  }
}

export async function signEvidenceBundle(opts: {
  bundleDir: string;
  keyPath: string;
  evidenceRoot: string;
  clock: () => Date;
}): Promise<EvidenceSignature> {
  const { bundleDir, realKey } = await assertSigningPreconditions(opts);
  await clearSignatureLeftovers(bundleDir);
  const manifestBytes = await readSealedManifest(bundleDir);
  const manifest = parseManifest(manifestBytes);
  if (manifest === null || manifest.runId.includes('\n')) fail('sign', 'manifest.json is not a valid tessera manifest');
  const report = await verifyEvidenceBundle(bundleDir);
  if (!report.ok || report.runId !== manifest.runId || report.rootHash !== manifest.rootHash) {
    fail('sign', 'bundle does not verify; refusing to sign');
  }
  const current = await readSealedManifest(bundleDir);
  if (!current.equals(manifestBytes)) fail('sign', 'manifest.json changed while signing');

  const privateKey = await loadPrivateKey(realKey);
  const keyId = publicKeyId(createPublicKey(privateKey));
  const fields = {
    runId: manifest.runId,
    rootHash: manifest.rootHash,
    manifestSha256: sha256(manifestBytes),
    signedAt: opts.clock().toISOString(),
  };
  const signature: EvidenceSignature = {
    schema: 'tessera.signature/v1',
    alg: 'ed25519',
    keyId,
    runId: fields.runId,
    rootHash: fields.rootHash,
    manifestSha256: fields.manifestSha256,
    signedAt: fields.signedAt,
    signature: cryptoSign(null, signaturePayload(fields), privateKey).toString('base64'),
  };
  await writeSignatureFile(bundleDir, `${JSON.stringify(signature, null, 2)}\n`);
  return signature;
}

function compareCodeUnits(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readCapped(file: string, cap: number): Promise<Buffer | 'missing' | 'unreadable'> {
  const opened = await openRegular(file);
  if ('problem' in opened) return opened.problem === 'missing' ? 'missing' : 'unreadable';
  try {
    const read = await hashHandle(opened.fh, cap);
    return read.content ?? 'unreadable';
  } finally {
    await opened.fh.close();
  }
}

async function readPublicKey(file: string): Promise<KeyObject | null> {
  try {
    const st = await stat(file);
    if (!st.isFile() || st.size > MAX_KEY_BYTES) return null;
    const fh = await open(file, constants.O_RDONLY | constants.O_NONBLOCK);
    let read: { content: Buffer | null };
    try {
      read = await hashHandle(fh, MAX_KEY_BYTES);
    } finally {
      await fh.close();
    }
    if (read.content === null || read.content.includes('PRIVATE KEY')) return null;
    const key = createPublicKey({ key: read.content, format: 'pem' });
    return key.type === 'public' && key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

async function loadTrustedKeys(entries: readonly string[]): Promise<Map<string, KeyObject>> {
  const keys = new Map<string, KeyObject>();
  const add = (key: KeyObject | null): void => {
    if (key !== null) keys.set(publicKeyId(key), key);
  };
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (typeof entry !== 'string' || entry.length === 0) continue;
    let st: Stats;
    try {
      st = await stat(entry);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      let names: string[];
      try {
        names = await readdir(entry);
      } catch {
        continue;
      }
      for (const name of names.filter((n) => n.endsWith('.pub')).sort(compareCodeUnits)) add(await readPublicKey(path.join(entry, name)));
    } else if (st.isFile()) {
      add(await readPublicKey(entry));
    }
  }
  return keys;
}

function parseSignature(content: Buffer): EvidenceSignature | null {
  let value: unknown;
  try {
    value = JSON.parse(content.toString('utf8'));
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const { schema, alg, keyId, runId, rootHash, manifestSha256, signedAt, signature } = value;
  if (schema !== 'tessera.signature/v1' || alg !== 'ed25519') return null;
  if (typeof keyId !== 'string' || !HEX64.test(keyId)) return null;
  if (typeof runId !== 'string' || runId.length === 0 || runId.includes('\n')) return null;
  if (typeof rootHash !== 'string' || !HEX64.test(rootHash)) return null;
  if (typeof manifestSha256 !== 'string' || !HEX64.test(manifestSha256)) return null;
  if (typeof signedAt !== 'string' || signedAt.includes('\n') || !Number.isFinite(Date.parse(signedAt))) return null;
  if (typeof signature !== 'string' || !BASE64.test(signature)) return null;
  return { schema, alg, keyId, runId, rootHash, manifestSha256, signedAt, signature };
}

function sigReport(status: SignatureStatus, keyId: string | null = null, signedAt: string | null = null): SignatureReport {
  return { status, keyId, signedAt, timeAttested: false };
}

async function checkSignature(bundleDir: string, trustedKeys: readonly string[]): Promise<SignatureReport> {
  const raw = await readCapped(path.join(bundleDir, SIGNATURE_FILE), MAX_SIGNATURE_BYTES);
  if (raw === 'missing') return sigReport('unsigned');
  if (raw === 'unreadable') return sigReport('invalid');
  const sig = parseSignature(raw);
  if (sig === null) return sigReport('invalid');
  const invalid = sigReport('invalid', sig.keyId, sig.signedAt);
  const sigBytes = Buffer.from(sig.signature, 'base64');
  if (sigBytes.length !== 64) return invalid;
  const manifestBytes = await readCapped(path.join(bundleDir, MANIFEST_FILE), MAX_MANIFEST_BYTES);
  if (typeof manifestBytes === 'string') return invalid;
  const manifest = parseManifest(manifestBytes);
  if (manifest === null) return invalid;
  if (sha256(manifestBytes) !== sig.manifestSha256) return invalid;
  if (manifest.runId !== sig.runId || manifest.rootHash !== sig.rootHash) return invalid;
  const key = (await loadTrustedKeys(trustedKeys)).get(sig.keyId);
  if (key === undefined) return sigReport('unknown-key', sig.keyId, sig.signedAt);
  const payload = signaturePayload({ runId: manifest.runId, rootHash: manifest.rootHash, manifestSha256: sha256(manifestBytes), signedAt: sig.signedAt });
  return cryptoVerify(null, payload, key, sigBytes) ? sigReport('valid', sig.keyId, sig.signedAt) : invalid;
}

export async function verifyBundleSignature(bundleDir: string, opts: VerifySignatureOptions): Promise<SignatureReport> {
  try {
    if (typeof bundleDir !== 'string' || bundleDir.length === 0) return sigReport('invalid');
    return await checkSignature(path.resolve(bundleDir), opts?.trustedKeys ?? []);
  } catch {
    return sigReport('invalid');
  }
}
