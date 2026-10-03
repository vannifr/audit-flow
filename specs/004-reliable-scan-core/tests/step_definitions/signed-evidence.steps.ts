import assert from 'node:assert/strict';
import { createPublicKey, createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { After, Given, Then, When } from '@cucumber/cucumber';
import { signEvidenceBundle, verifyBundleSignature } from '../../../../src/evidence/sign';
import type { SignatureReport } from '../../../../src/evidence/sign';
import { verifyEvidenceBundle } from '../../../../src/evidence/verify';
import { bundleDirOf, cli, completedAudit, listFiles, readManifest, rewriteRecordAndRecompute } from './support/bundle';
import { T0 } from './support/harness';
import type { ScanWorld } from './support/harness';
import { state } from './evidence-verification.steps';

interface Key {
  keyPath: string;
  publicKeyPath: string;
  keyId: string;
}

interface SignedCtx {
  signer: Key | undefined;
  verifier: Key | undefined;
  sig: SignatureReport | undefined;
  reportDir: string;
  reportText: string;
  condition: string | undefined;
}

const contexts = new WeakMap<ScanWorld, SignedCtx>();

function ctx(world: ScanWorld): SignedCtx {
  let c = contexts.get(world);
  if (c === undefined) {
    c = { signer: undefined, verifier: undefined, sig: undefined, reportDir: '', reportText: '', condition: undefined };
    contexts.set(world, c);
  }
  return c;
}

After(async function (this: ScanWorld) {
  const c = contexts.get(this);
  if (c !== undefined && c.reportDir !== '') await rm(c.reportDir, { recursive: true, force: true });
});

async function independentKeyId(publicKeyPath: string): Promise<string> {
  const der = createPublicKey(await readFile(publicKeyPath)).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

async function signedAudit(world: ScanWorld): Promise<Key> {
  const key = await world.provisionKey();
  assert.equal(key.keyId, await independentKeyId(key.publicKeyPath));
  world.signingKeyPath = key.keyPath;
  await completedAudit(world);
  const s = state(world);
  s.dir = bundleDirOf(world);
  ctx(world).signer = key;
  return key;
}

async function exists(file: string): Promise<boolean> {
  return lstat(file).then(
    () => true,
    () => false,
  );
}

function signer(world: ScanWorld): Key {
  const key = ctx(world).signer;
  assert.ok(key, 'the audit was not signed');
  return key;
}

async function readReport(world: ScanWorld): Promise<string> {
  assert.equal(world.error, undefined, `audit failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.reportInput, 'no report was generated');
  const { generateReport } = await import('../../../../src/activities/index');
  const c = ctx(world);
  c.reportDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-bdd-signed-report-'));
  const written = await generateReport({ ...(world.reportInput as Parameters<typeof generateReport>[0]), outputDir: c.reportDir });
  c.reportText = await readFile(written.reportPath, 'utf8');
  return c.reportText;
}

Given('a completed audit', async function (this: ScanWorld) {
  await signedAudit(this);
});

When('verification runs with the published public key', async function (this: ScanWorld) {
  const s = state(this);
  const key = signer(this);
  s.trustedKeys = [key.publicKeyPath];
  s.report = await verifyEvidenceBundle(s.dir, { trustedKeys: s.trustedKeys });
  s.run = await cli(['--pubkey', key.publicKeyPath, s.dir]);
  ctx(this).sig = await verifyBundleSignature(s.dir, { trustedKeys: s.trustedKeys });
});

Then('it reports the signature as valid', function (this: ScanWorld) {
  const s = state(this);
  const sig = ctx(this).sig;
  assert.ok(s.report && s.run && sig);
  assert.equal(sig.status, 'valid');
  assert.equal(s.report.signature.status, 'valid');
  assert.deepEqual(s.report.issues, []);
  assert.equal(s.report.ok, true);
  assert.equal(s.run.code, 0, s.run.stdout + s.run.stderr);
  const lines = s.run.stdout.split('\n');
  assert.equal(lines[0], 'VERIFIED');
  assert.ok(
    lines.some((l) => l.startsWith('Signature: valid (')),
    `no "Signature: valid" line in: ${s.run.stdout}`,
  );
});

Then('it names the key', async function (this: ScanWorld) {
  const s = state(this);
  const sig = ctx(this).sig;
  assert.ok(s.report && s.run && sig);
  const keyId = await independentKeyId(signer(this).publicKeyPath);
  assert.equal(sig.keyId, keyId);
  assert.equal(s.report.signature.keyId, keyId);
  const stored = JSON.parse(await readFile(path.join(s.dir, 'signature.json'), 'utf8')) as { keyId: string };
  assert.equal(stored.keyId, keyId);
  const line = s.run.stdout.split('\n').find((l) => l.startsWith('Signature: valid'));
  assert.ok(line?.includes(`key ${keyId}`), `the CLI does not name key ${keyId}: ${line}`);
});

Given('evidence where a record was changed and the manifest recomputed by hand', async function (this: ScanWorld) {
  const key = await signedAudit(this);
  const s = state(this);
  s.trustedKeys = [key.publicKeyPath];
  const before = await verifyEvidenceBundle(s.dir, { trustedKeys: s.trustedKeys });
  assert.equal(before.ok, true, 'the evidence was not valid before the change');
  const manifest = await readManifest(s.dir);
  const target = manifest.entries.find((e) => e.kind === 'record');
  assert.ok(target);
  await rewriteRecordAndRecompute(s.dir, target.path, (bytes) => Buffer.concat([bytes, Buffer.from('\n')]));
  const after = await verifyEvidenceBundle(s.dir);
  assert.deepEqual(after.issues, [], 'the hand-made manifest does not hold together');
  assert.equal(after.hashesOk, true);
  assert.notEqual((await readManifest(s.dir)).rootHash, manifest.rootHash, 'the manifest was not recomputed');
});

Then('it reports the signature as invalid', function (this: ScanWorld) {
  const s = state(this);
  assert.ok(s.report && s.run);
  assert.equal(s.report.hashesOk, true, 'the recomputed hashes should be consistent; only the signature can catch this');
  assert.equal(s.report.signature.status, 'invalid');
  assert.equal(s.report.ok, false);
  assert.equal(s.run.code, 1, s.run.stdout);
  const lines = s.run.stdout.split('\n');
  assert.equal(lines[0], 'FAILED');
  assert.ok(lines.includes('Signature: invalid'), `no "Signature: invalid" line in: ${s.run.stdout}`);
});

Given('evidence that is {string}', async function (this: ScanWorld, condition: string) {
  const c = ctx(this);
  c.condition = condition;
  const s = state(this);
  if (condition === 'unsigned') {
    await completedAudit(this);
    s.dir = bundleDirOf(this);
    c.verifier = await this.provisionKey();
    assert.equal(await exists(path.join(s.dir, 'signature.json')), false, 'the evidence was signed');
  } else if (condition === 'signed by a key the verifier lacks') {
    const signerKey = await signedAudit(this);
    c.verifier = await this.provisionKey();
    assert.notEqual(c.verifier.keyId, signerKey.keyId);
    assert.equal(await exists(path.join(s.dir, 'signature.json')), true, 'the evidence was not signed');
  } else {
    assert.fail(`unknown condition ${condition}`);
  }
  s.trustedKeys = [(c.verifier as Key).publicKeyPath];
});

Then('it reports {string}', function (this: ScanWorld, outcome: string) {
  const s = state(this);
  assert.ok(s.report && s.run);
  assert.equal(s.report.signature.status, outcome);
  const line = s.run.stdout.split('\n').find((l) => l.startsWith('Signature:'));
  assert.ok(line?.startsWith(`Signature: ${outcome}`), `CLI signature line was "${line}"`);
  const c = ctx(this);
  if (outcome === 'unknown-key') {
    assert.equal(s.report.signature.keyId, signer(this).keyId);
    assert.notEqual(s.report.signature.keyId, c.verifier?.keyId);
  }
});

Then('it does not report the evidence as verified', function (this: ScanWorld) {
  const s = state(this);
  assert.ok(s.report && s.run);
  assert.equal(s.report.ok, false);
  assert.notEqual(s.report.signature.status, 'valid');
  assert.equal(s.run.code, 1, s.run.stdout);
  const lines = s.run.stdout.split('\n');
  assert.equal(lines[0], 'FAILED');
  assert.ok(!lines.includes('VERIFIED'));
});

Given('a signed audit', async function (this: ScanWorld) {
  await signedAudit(this);
});

When('a reviewer reads the report', async function (this: ScanWorld) {
  await readReport(this);
});

Then('the report states what was signed and by which key', async function (this: ScanWorld) {
  const text = ctx(this).reportText;
  const key = signer(this);
  const dir = bundleDirOf(this);
  const manifest = await readManifest(dir);
  const stored = JSON.parse(await readFile(path.join(dir, 'signature.json'), 'utf8')) as { keyId: string; signedAt: string; rootHash: string };
  assert.equal(stored.rootHash, manifest.rootHash);
  const lines = text.split('\n');
  assert.ok(lines.some((l) => l.startsWith('Signed: manifest.json') && l.includes('root hash')), 'the report does not say what was signed');
  assert.ok(lines.includes(`Evidence root hash: ${manifest.rootHash}`), 'the report does not show the signed root hash');
  assert.ok(
    lines.some((l) => l.startsWith(`Signature: valid, key ${key.keyId}`) && l.includes(`signed ${stored.signedAt}`)),
    'the report does not name the signing key and time',
  );
  assert.equal(stored.keyId, key.keyId);
});

Then('states that the signing time is not independently attested', function (this: ScanWorld) {
  const line = ctx(this).reportText.split('\n').find((l) => l.startsWith('Signature:'));
  assert.ok(line, 'no signature line in the report');
  assert.ok(line.includes('not independently attested'), `the signature line lacks the time limit: ${line}`);
});

Then('shows the computed assurance level', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const key = signer(this);
  const sig = await verifyBundleSignature(dir, { trustedKeys: [key.publicKeyPath] });
  const hashes = await verifyEvidenceBundle(dir);
  const expected = hashes.hashesOk && sig.status === 'valid' ? 1 : 0;
  assert.equal(expected, 1);
  const lines = ctx(this).reportText.split('\n');
  assert.ok(lines.includes(`Assurance level: ${expected}`), 'the report does not show the computed assurance level');
  assert.ok(!lines.includes('Assurance level: 0'));
});

Given('the signing key is located inside the evidence folder', async function (this: ScanWorld) {
  const keyPath = path.join(this.evidenceRoot, 'keys', 'signing.pem');
  const key = await this.provisionKey(keyPath);
  assert.ok(key.keyPath.startsWith(this.evidenceRoot + path.sep));
  this.signingKeyPath = key.keyPath;
  ctx(this).signer = key;
  await completedAudit(this);
  state(this).dir = bundleDirOf(this);
});

Then('signing is refused with a clear cause', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const key = signer(this);
  assert.equal(await exists(path.join(dir, 'signature.json')), false, 'a signature was written');
  const files = await listFiles(dir);
  assert.ok(!files.some((f) => f.includes('signature')), `signature files present: ${files.join(', ')}`);
  assert.equal((await verifyBundleSignature(dir, { trustedKeys: [key.publicKeyPath] })).status, 'unsigned');
  assert.ok(this.result);
  assert.equal(this.result.signature?.signed, false);
  assert.equal(this.result.signature?.level, 0);
  const entry = this.result.notPerformed.find((n) => n.scanner === 'evidence' && n.cause === 'unsigned');
  assert.ok(entry, `no unsigned entry in ${JSON.stringify(this.result.notPerformed)}`);
  assert.ok(entry.summary.includes('refusing a signing key inside the evidence folder'), `unclear cause: ${entry.summary}`);
  await assert.rejects(
    signEvidenceBundle({ bundleDir: dir, keyPath: key.keyPath, evidenceRoot: this.evidenceRoot, clock: () => T0 }),
    /refusing a signing key inside the evidence folder/,
  );
  assert.equal(await exists(path.join(dir, 'signature.json')), false);
});

Given('no signing key is configured and a signature is required', function (this: ScanWorld) {
  this.signingKeyPath = null;
  this.requireSignature = true;
});

Then('the computed assurance level is {int}', async function (this: ScanWorld, level: number) {
  assert.equal(level, 0);
  assert.ok(this.result);
  assert.equal(this.result.outcome, 'incomplete');
  const entry = this.result.notPerformed.find((n) => n.scanner === 'evidence' && n.cause === 'unsigned');
  assert.ok(entry, `no unsigned entry in ${JSON.stringify(this.result.notPerformed)}`);
  assert.equal(this.result.signature?.level, level);
  assert.equal(await exists(path.join(bundleDirOf(this), 'signature.json')), false);
  const text = await readReport(this);
  const lines = text.split('\n');
  assert.ok(lines[0].startsWith('Audit outcome: INCOMPLETE'), `first line was "${lines[0]}"`);
  assert.ok(lines.includes(`Assurance level: ${level}`), 'the report does not show the assurance level');
  assert.ok(!lines.includes('Assurance level: 1'));
});
