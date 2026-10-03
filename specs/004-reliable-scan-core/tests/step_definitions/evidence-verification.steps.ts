import assert from 'node:assert/strict';
import { readFile, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Given, Then, When } from '@cucumber/cucumber';
import { verifyEvidenceBundle } from '../../../../src/evidence/verify';
import type { VerifyReport } from '../../../../src/evidence/verify';
import {
  bundleDirOf,
  cli,
  completedAudit,
  fingerprintTree,
  recordById,
  readManifest,
  sealedBundleWithRecords,
  withOpenBundle,
} from './support/bundle';
import type { CliRun } from './support/bundle';
import type { ScanWorld } from './support/harness';

type Change = 'modified' | 'deleted' | 'added';

interface VerifyState {
  dir: string;
  rootHash: string;
  report: VerifyReport | undefined;
  run: CliRun | undefined;
  change: Change | undefined;
  recordPath: string | undefined;
  reports: VerifyReport[];
  runs: CliRun[];
  before: Record<string, string> | undefined;
  trustedKeys: string[] | undefined;
}

const states = new WeakMap<ScanWorld, VerifyState>();

export function state(world: ScanWorld): VerifyState {
  let s = states.get(world);
  if (s === undefined) {
    s = { dir: '', rootHash: '', report: undefined, run: undefined, change: undefined, recordPath: undefined, reports: [], runs: [], before: undefined, trustedKeys: undefined };
    states.set(world, s);
  }
  return s;
}

const EXPECTED_PROBLEM: Record<Change, string> = { modified: 'modified', deleted: 'missing', added: 'extra' };
const TARGET_RECORD = 'scan.semgrep.a1';

Given('an unmodified sealed evidence set', async function (this: ScanWorld) {
  await completedAudit(this);
  const s = state(this);
  s.dir = bundleDirOf(this);
  s.rootHash = (await readManifest(s.dir)).rootHash;
});

Given('a sealed evidence set where one record is {string}', async function (this: ScanWorld, change: string) {
  assert.ok(change === 'modified' || change === 'deleted' || change === 'added', `unknown change ${change}`);
  await completedAudit(this);
  const s = state(this);
  s.dir = bundleDirOf(this);
  s.change = change;
  const manifest = await readManifest(s.dir);
  assert.equal((await verifyEvidenceBundle(s.dir, { expectRootHash: manifest.rootHash })).ok, true, 'the set was not intact before the change');
  const target = await recordById(s.dir, TARGET_RECORD);
  const file = path.join(s.dir, target.entry.path);
  if (change === 'modified') {
    s.recordPath = target.entry.path;
    await withOpenBundle(s.dir, () => writeFile(file, Buffer.concat([target.bytes, Buffer.from(' ')])));
  } else if (change === 'deleted') {
    s.recordPath = target.entry.path;
    await withOpenBundle(s.dir, () => unlink(file));
  } else {
    s.recordPath = 'records/scan.injected.a1.json';
    const forged = { ...target.record, id: 'scan.injected.a1', stepId: 'scan.injected' };
    await withOpenBundle(s.dir, () => writeFile(path.join(s.dir, s.recordPath as string), `${JSON.stringify(forged, null, 2)}\n`));
  }
});

Given('an unmodified sealed evidence set with many records', async function (this: ScanWorld) {
  await completedAudit(this);
  const s = state(this);
  s.dir = await sealedBundleWithRecords(this, 'run-bdd-many', 60);
  s.rootHash = (await readManifest(s.dir)).rootHash;
  s.before = await fingerprintTree(s.dir);
});

When('verification runs', async function (this: ScanWorld) {
  const s = state(this);
  const keys = s.trustedKeys ?? [];
  s.report = await verifyEvidenceBundle(s.dir, s.trustedKeys === undefined ? {} : { trustedKeys: keys });
  s.run = await cli([...keys.flatMap((k) => ['--pubkey', k]), s.dir]);
});

When('verification runs repeatedly', async function (this: ScanWorld) {
  const s = state(this);
  for (let i = 0; i < 25; i++) {
    s.reports.push(await verifyEvidenceBundle(s.dir, { expectRootHash: s.rootHash }));
    if (i % 5 === 0) s.runs.push(await cli([s.dir, '--expect-root', s.rootHash]));
  }
  const parallel = await Promise.all(Array.from({ length: 8 }, () => verifyEvidenceBundle(s.dir)));
  s.reports.push(...parallel);
});

Then('it reports success', async function (this: ScanWorld) {
  const s = state(this);
  assert.ok(s.report && s.run);
  assert.deepEqual(s.report.issues, []);
  assert.equal(s.report.ok, true);
  assert.equal(s.report.runId, this.runId);
  assert.equal(s.report.rootHash, s.rootHash);
  assert.ok(s.report.checkedEntries > 0);
  assert.equal(s.run.code, 0, s.run.stderr);
  const lines = s.run.stdout.split('\n');
  assert.equal(lines[0], 'VERIFIED');
  assert.ok(lines.includes(`root hash: ${s.rootHash}`));
  assert.ok(lines.includes(`checked entries: ${s.report.checkedEntries}`));
  const withRoot = await cli([s.dir, '--expect-root', s.rootHash]);
  assert.equal(withRoot.code, 0);
  assert.ok(withRoot.stdout.includes('expected root: matches'));
});

Then('it reports a failure naming that record', function (this: ScanWorld) {
  const s = state(this);
  assert.ok(s.report && s.run && s.change && s.recordPath);
  const problem = EXPECTED_PROBLEM[s.change];
  assert.equal(s.report.ok, false);
  assert.ok(
    s.report.issues.some((i) => i.problem === problem && i.path === s.recordPath),
    `no ${problem} issue for ${s.recordPath}: ${JSON.stringify(s.report.issues)}`,
  );
  assert.equal(s.run.code, 1, s.run.stdout);
  const lines = s.run.stdout.split('\n');
  assert.equal(lines[0], 'FAILED');
  assert.ok(lines.includes(`${problem} ${s.recordPath}`), `CLI output lacks "${problem} ${s.recordPath}": ${s.run.stdout}`);
  for (const issue of s.report.issues) assert.ok(issue.path === s.recordPath || issue.problem !== 'extra');
});

Then('it never reports a failure', async function (this: ScanWorld) {
  const s = state(this);
  assert.equal(s.reports.length, 33);
  for (const report of s.reports) {
    assert.deepEqual(report.issues, []);
    assert.equal(report.ok, true);
    assert.ok(report.checkedEntries >= 120);
  }
  assert.equal(s.runs.length, 5);
  for (const run of s.runs) {
    assert.equal(run.code, 0, run.stdout);
    assert.ok(run.stdout.startsWith('VERIFIED\n'));
  }
  assert.deepEqual(await fingerprintTree(s.dir), s.before, 'verification changed the evidence');
  assert.equal(JSON.parse(await readFile(path.join(s.dir, 'manifest.json'), 'utf8')).rootHash, s.rootHash);
});
