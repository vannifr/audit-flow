import assert from 'node:assert/strict';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { After, Given, Then, When } from '@cucumber/cucumber';
import { createEvidenceStore } from '../../../../src/evidence/store';
import type { EvidenceRecord, FindingEvidenceExtension } from '../../../../src/evidence/types';
import { traceEvidence, verifyEvidenceBundle } from '../../../../src/evidence/verify';
import {
  bundleDirOf,
  cli,
  completedAudit,
  fingerprintTree,
  listFiles,
  prepareAudit,
  rawOutputs,
  readManifest,
  readRecords,
  recordById,
  sha256,
} from './support/bundle';
import type { StoredRecord } from './support/bundle';
import { ScanWorld, T0 } from './support/harness';

type Finding = FindingEvidenceExtension & { id: string };
type Fn = (...args: unknown[]) => unknown;

const DAY_MS = 24 * 60 * 60 * 1000;
const STEP_BY_ACTIVITY: Record<string, string> = {
  runGitleaks: 'scan.gitleaks',
  runSemgrep: 'scan.semgrep',
  runNpmAudit: 'scan.npm-audit',
  runLicenseCheck: 'license-check',
};

interface WriteOnce {
  rejected: string;
  fileBefore: string;
  fileWriteFailed: boolean;
  scratchBefore: string;
  scratchAfter: string;
  scratchRefSha: string;
  originalSha: string;
}

interface Replay {
  executions: Record<string, number>;
  firstRecord: Record<string, { recordId: string; refSha: string; fileSha: string }>;
  secondRef: Record<string, { recordId: string; recordSha256: string }>;
}

interface Ctx {
  others: ScanWorld[];
  opened: StoredRecord | undefined;
  finding: Finding | undefined;
  recordsListed: StoredRecord[];
  writeOnce: WriteOnce | undefined;
  resumed: ScanWorld | undefined;
  replay: Replay;
  trace: Awaited<ReturnType<typeof traceEvidence>> | undefined;
}

const contexts = new WeakMap<ScanWorld, Ctx>();

function ctx(world: ScanWorld): Ctx {
  let c = contexts.get(world);
  if (c === undefined) {
    c = { others: [], opened: undefined, finding: undefined, recordsListed: [], writeOnce: undefined, resumed: undefined, replay: { executions: {}, firstRecord: {}, secondRef: {} }, trace: undefined };
    contexts.set(world, c);
  }
  return c;
}

function findingsOf(world: ScanWorld): Finding[] {
  assert.ok(world.result, 'the audit produced no result');
  assert.ok(world.result.findings.length > 0, 'the audit produced no finding');
  return world.result.findings as unknown as Finding[];
}

function executedSteps(world: ScanWorld): string[] {
  const steps: string[] = [];
  if (world.runnerCalls.some((r) => r.file === 'git' && r.args.includes('clone'))) steps.push('source.clone');
  if (world.runnerCalls.some((r) => r.file === 'git' && r.args.includes('rev-parse'))) steps.push('source.revision', 'source.probe');
  for (const [activity, step] of Object.entries(STEP_BY_ACTIVITY)) {
    if (world.called(activity)) steps.push(step);
  }
  return steps;
}

async function readdirTop(root: string): Promise<string[]> {
  return (await readdir(root)).sort();
}

async function artifactBytes(dir: string, ref: { path: string }): Promise<Buffer> {
  return readFile(path.join(dir, ref.path));
}

After(async function (this: ScanWorld) {
  for (const other of ctx(this).others) await other.dispose();
});

Given('a completed audit of a source repository', async function (this: ScanWorld) {
  await completedAudit(this);
});

When('a reviewer opens any finding', function (this: ScanWorld) {
  ctx(this).finding = findingsOf(this)[0];
});

Then('the finding references an evidence record', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  for (const finding of findingsOf(this)) {
    assert.ok(finding.evidenceRef, `finding ${finding.id} has no evidenceRef`);
    const stored = await recordById(dir, finding.evidenceRef.recordId);
    assert.equal(sha256(stored.bytes), finding.evidenceRef.recordSha256);
    assert.equal(stored.entry.sha256, finding.evidenceRef.recordSha256);
    assert.equal(stored.entry.used, true);
  }
});

Then('that record belongs to the step that produced the finding', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  for (const finding of findingsOf(this)) {
    assert.ok(finding.evidenceRef && finding.scanner);
    const { record } = await recordById(dir, finding.evidenceRef.recordId);
    assert.equal(record.scanner, finding.scanner);
    assert.equal(record.stepId, `scan.${finding.scanner}`);
    assert.equal(record.id, finding.evidenceRef.recordId);
    assert.ok(record.findingIds.includes(finding.id), `record ${record.id} does not list finding ${finding.id}`);
    assert.equal(record.runId, this.runId);
  }
});

When('a reviewer lists the evidence', async function (this: ScanWorld) {
  ctx(this).recordsListed = await readRecords(bundleDirOf(this));
});

Then('every executed step has a record', function (this: ScanWorld) {
  const steps = executedSteps(this);
  assert.deepEqual(steps, ['source.clone', 'source.revision', 'source.probe', 'scan.gitleaks', 'scan.semgrep', 'scan.npm-audit', 'license-check']);
  const listed = ctx(this).recordsListed;
  for (const step of steps) {
    const found = listed.filter((r) => r.record.stepId === step);
    assert.equal(found.length, 1, `step ${step} has ${found.length} records`);
    assert.equal(found[0].entry.used, true);
  }
  assert.deepEqual(listed.map((r) => r.record.stepId).sort(), [...steps].sort());
  for (const entry of (this.result?.scanners ?? []).filter((e) => ['gitleaks', 'semgrep', 'npm-audit', 'license-check'].includes(e.scanner))) {
    assert.ok(entry.evidenceRecordIds.length > 0, `${entry.scanner} lists no evidence record`);
    for (const id of entry.evidenceRecordIds) assert.ok(listed.some((r) => r.record.id === id), `${id} is not in the bundle`);
  }
});

Then('steps that found nothing or failed have a record too', function (this: ScanWorld) {
  const listed = ctx(this).recordsListed;
  const semgrep = listed.find((r) => r.record.stepId === 'scan.semgrep');
  assert.ok(semgrep);
  assert.equal(semgrep.record.status, 'completed');
  assert.deepEqual(semgrep.record.findingIds, []);
  assert.equal(this.scannerEntry('semgrep').findingCount, 0);
  const npm = listed.find((r) => r.record.stepId === 'scan.npm-audit');
  assert.ok(npm);
  assert.equal(npm.record.status, 'failed');
  assert.ok(npm.record.cause);
  assert.equal(this.scannerEntry('npm-audit').status, 'failed');
  assert.ok(this.scannerEntry('npm-audit').evidenceRecordIds.includes(npm.record.id));
});

When('the run finishes', function (this: ScanWorld) {
  assert.ok(this.result, 'the run did not finish');
  assert.equal(this.error, undefined);
});

Then('the evidence states the exact source revision that was scanned', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const revision = this.source.revision;
  assert.match(revision, /^[0-9a-f]{40}$/);
  const manifest = await readManifest(dir);
  assert.equal(manifest.source.revision, revision);
  assert.equal(manifest.source.repoUrl, 'https://github.com/acme/app');
  const records = await readRecords(dir);
  const scanRecords = records.filter((r) => !['source.clone', 'source.revision', 'source.probe'].includes(r.record.stepId));
  assert.equal(scanRecords.length, 4);
  for (const r of scanRecords) assert.equal(r.record.source.revision, revision, `${r.record.id} states another revision`);
  const probe = records.find((r) => r.record.stepId === 'source.revision');
  assert.ok(probe?.record.output);
  assert.equal((await artifactBytes(dir, probe.record.output)).toString('utf8').trim(), revision);
  assert.equal(this.result?.evidence?.bundlePath, dir);
});

When('a reviewer opens an evidence record', async function (this: ScanWorld) {
  ctx(this).opened = await recordById(bundleDirOf(this), 'scan.gitleaks.a1');
});

function opened(world: ScanWorld): EvidenceRecord {
  const record = ctx(world).opened?.record;
  assert.ok(record, 'no record opened');
  return record;
}

Then('it contains the action and its inputs', async function (this: ScanWorld) {
  const record = opened(this);
  const call = this.runnerCalls.find((r) => r.file === 'gitleaks' && r.args.length > 1);
  assert.ok(call, 'the scanner was never run');
  assert.equal(record.action.command, 'gitleaks');
  assert.deepEqual(record.action.args, call.args);
  const npm = (await recordById(bundleDirOf(this), 'scan.npm-audit.a1')).record;
  assert.equal(npm.action.inputs.lockfileSha256, sha256(this.repoFiles['package-lock.json']));
  assert.equal(npm.action.inputs.lockfileName ?? 'package-lock.json', 'package-lock.json');
});

Then('the tool identity and version', function (this: ScanWorld) {
  const record = opened(this);
  assert.deepEqual(record.tool, { name: 'gitleaks', version: '1.2.3' });
  assert.equal(record.recordedBy.framework, 'tessera');
  assert.equal(record.recordedBy.version, '0.0.0-bdd');
});

Then('the start and end time', function (this: ScanWorld) {
  const record = opened(this);
  assert.equal(record.startedAt, T0.toISOString());
  assert.equal(record.endedAt, T0.toISOString());
  assert.equal(record.durationMs, Date.parse(record.endedAt) - Date.parse(record.startedAt));
  assert.ok(Date.parse(record.endedAt) >= Date.parse(record.startedAt));
});

Then('the result code', function (this: ScanWorld) {
  const record = opened(this);
  assert.equal(record.result.exitCode, 42);
  assert.equal(record.result.exitClass, 'issues-found');
  assert.equal(record.result.timedOut, false);
  assert.equal(record.status, 'completed');
});

Then('a fingerprint of the raw output', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const manifest = await readManifest(dir);
  for (const { record } of await readRecords(dir)) {
    const raw = rawOutputs(this)[record.stepId];
    if (raw === undefined) continue;
    assert.ok(record.output, `${record.id} has no output artifact`);
    assert.equal(record.output.rawSha256, sha256(raw.stdout), `${record.id} raw output fingerprint is wrong`);
    assert.equal(record.output.rawBytes, raw.stdout.length);
    const bytes = await artifactBytes(dir, record.output);
    assert.equal(sha256(bytes), record.output.sha256);
    assert.equal(bytes.length, record.output.bytes);
    assert.equal(manifest.entries.find((e) => e.path === record.output?.path)?.sha256, record.output.sha256);
    if (record.stderr !== null) {
      assert.equal(record.stderr.rawSha256, sha256(raw.stderr));
      assert.equal(sha256(await artifactBytes(dir, record.stderr)), record.stderr.sha256);
    }
  }
  const license = (await recordById(dir, 'license-check.a1')).record;
  assert.ok(license.output);
  assert.equal(sha256(await artifactBytes(dir, license.output)), license.output.rawSha256);
});

When('the audit is sealed', function (this: ScanWorld) {
  assert.ok(this.result?.evidence, 'the audit did not seal its evidence');
  assert.ok(this.called('sealEvidence'));
});

Then('one folder holds all evidence records and a manifest', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const evidence = this.result?.evidence;
  assert.ok(evidence);
  assert.equal(evidence.bundlePath, dir);
  const files = await listFiles(dir);
  assert.ok(files.includes('manifest.json'));
  for (const f of files) {
    assert.ok(f === 'manifest.json' || f === 'SHA256SUMS' || f.startsWith('records/') || f.startsWith('artifacts/'), `unexpected file ${f}`);
  }
  const recordFiles = files.filter((f) => f.startsWith('records/'));
  assert.equal(recordFiles.length, evidence.recordCount);
  assert.equal(recordFiles.length, executedSteps(this).length);
  assert.deepEqual(await readdirTop(this.evidenceRoot), [this.runId]);
});

Then('the manifest lists every record with its fingerprint', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const manifest = await readManifest(dir);
  const files = (await listFiles(dir)).filter((f) => f.startsWith('records/') || f.startsWith('artifacts/'));
  assert.deepEqual(manifest.entries.map((e) => e.path).sort(), files);
  for (const entry of manifest.entries) {
    const bytes = await readFile(path.join(dir, entry.path));
    assert.equal(entry.sha256, sha256(bytes), `${entry.path} fingerprint does not match`);
    assert.equal(entry.bytes, bytes.length);
  }
  const sums = await readFile(path.join(dir, 'SHA256SUMS'), 'utf8');
  for (const entry of manifest.entries) assert.ok(sums.includes(`${entry.sha256}  ${entry.path}`));
  assert.equal(manifest.rootHash, this.result?.evidence?.rootHash);
  assert.equal(manifest.entries.filter((e) => e.kind === 'record').length, this.result?.evidence?.recordCount);
});

Given('a sealed evidence set', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const manifest = await readManifest(dir);
  assert.ok(manifest.sealedAt);
  const report = await verifyEvidenceBundle(dir, { expectRootHash: manifest.rootHash });
  assert.equal(report.ok, true);
});

When('a second write to an existing record is attempted', async function (this: ScanWorld) {
  const dir = bundleDirOf(this);
  const { record, bytes } = await recordById(dir, 'scan.gitleaks.a1');
  const originalSha = sha256(bytes);
  const forged: EvidenceRecord = { ...record, status: 'failed', findingIds: [], causeDetail: 'rewritten after the fact' };
  let rejected = '';
  await createEvidenceStore(this.evidenceRoot, this.runId)
    .writeRecord(forged)
    .then(
      () => undefined,
      (error: unknown) => {
        rejected = (error as Error).message;
      },
    );
  const file = path.join(dir, 'records', 'scan.gitleaks.a1.json');
  let fileWriteFailed = false;
  await writeFile(file, Buffer.from(JSON.stringify(forged))).catch(() => {
    fileWriteFailed = true;
  });
  const scratch = path.join(this.tmpRoot, 'write-once');
  const store = createEvidenceStore(scratch, this.runId);
  const first = await store.writeRecord(record);
  const scratchFile = path.join(scratch, this.runId, 'records', 'scan.gitleaks.a1.json');
  const scratchBefore = sha256(await readFile(scratchFile));
  const second = await store.writeRecord(forged);
  const scratchAfter = sha256(await readFile(scratchFile));
  assert.equal(second.recordSha256, first.recordSha256);
  ctx(this).writeOnce = { rejected, fileBefore: originalSha, fileWriteFailed, scratchBefore, scratchAfter, scratchRefSha: second.recordSha256, originalSha };
});

Then('the existing record is unchanged', async function (this: ScanWorld) {
  const w = ctx(this).writeOnce;
  assert.ok(w);
  assert.match(w.rejected, /sealed/);
  const dir = bundleDirOf(this);
  const now = await recordById(dir, 'scan.gitleaks.a1');
  assert.equal(sha256(now.bytes), w.originalSha);
  assert.equal(now.entry.sha256, w.originalSha);
  assert.equal(w.scratchBefore, w.scratchAfter);
  assert.equal(w.scratchRefSha, w.scratchBefore);
  assert.equal((await verifyEvidenceBundle(dir)).ok, true);
});

Then('the manifest carries a retention date at least one year ahead', async function (this: ScanWorld) {
  const manifest = await readManifest(bundleDirOf(this));
  const sealed = Date.parse(manifest.sealedAt);
  const retain = Date.parse(manifest.retainUntil);
  assert.ok(Number.isFinite(sealed) && Number.isFinite(retain));
  assert.equal(sealed, T0.getTime());
  assert.ok(retain - sealed >= 365 * DAY_MS, `retention is only ${(retain - sealed) / DAY_MS} days`);
});

function barrier(parties: number): () => Promise<void> {
  let arrived = 0;
  let release: () => void = () => undefined;
  const open = new Promise<void>((resolve) => {
    release = resolve;
  });
  return async () => {
    arrived += 1;
    if (arrived >= parties) release();
    await open;
  };
}

Given('two audits run at the same time', async function (this: ScanWorld) {
  const meet = barrier(2);
  const mk = async (runId: string, revision: string): Promise<ScanWorld> => {
    const world = new ScanWorld();
    await world.prepare({ runId, evidenceRoot: this.evidenceRoot });
    await prepareAudit(world, revision);
    world.activityWrap = (name, impl): Fn =>
      name === 'fetchSource'
        ? async (...args: unknown[]) => {
            await meet();
            return impl(...args);
          }
        : impl;
    return world;
  };
  const c = ctx(this);
  c.others = [await mk('run-bdd-0002', 'b'.repeat(40)), await mk('run-bdd-0003', 'c'.repeat(40))];
});

When('both finish', async function (this: ScanWorld) {
  const [b, c] = ctx(this).others;
  await Promise.all([b.runAudit(), c.runAudit()]);
  for (const w of [b, c]) {
    assert.equal(w.error, undefined, `audit ${w.runId} failed: ${String((w.error as Error | undefined)?.message)}`);
    assert.ok(w.called('fetchSource') && w.called('sealEvidence'));
  }
});

Then('each evidence set contains only records of its own run', async function (this: ScanWorld) {
  const worlds = [this, ...ctx(this).others];
  assert.equal(new Set(worlds.map((w) => w.runId)).size, 3);
  assert.deepEqual(await readdirTop(this.evidenceRoot), worlds.map((w) => w.runId).sort());
  const seen = new Map<string, string>();
  for (const w of worlds) {
    const dir = bundleDirOf(w);
    assert.equal(w.result?.evidence?.bundlePath, dir);
    const files = await listFiles(dir);
    for (const f of files) {
      const abs = path.join(dir, f);
      assert.equal(seen.has(abs), false);
      seen.set(abs, w.runId);
    }
    const manifest = await readManifest(dir);
    assert.equal(manifest.runId, w.runId);
    assert.equal(manifest.source.revision, w.source.revision);
    const records = await readRecords(dir);
    assert.equal(records.length, 7);
    for (const r of records) {
      assert.equal(r.record.runId, w.runId, `${r.entry.path} belongs to another run`);
      if (r.record.stepId !== 'source.clone') assert.ok(r.record.source.revision === w.source.revision || r.record.source.revision === null);
    }
    for (const other of worlds.filter((o) => o !== w)) {
      for (const f of files) {
        assert.equal((await readFile(path.join(dir, f))).includes(other.runId), false, `${f} mentions run ${other.runId}`);
      }
    }
    assert.equal((await verifyEvidenceBundle(dir, { expectRootHash: manifest.rootHash })).ok, true);
  }
});

Given('an audit is interrupted after some steps completed', async function (this: ScanWorld) {
  const world = new ScanWorld();
  await world.prepare({ runId: 'run-bdd-resume', evidenceRoot: this.evidenceRoot });
  await prepareAudit(world);
  const c = ctx(this);
  const replay = c.replay;
  const redelivered = new Set(['fetchSource', 'runGitleaks', 'runSemgrep']);
  world.activityWrap = (name, impl): Fn =>
    !redelivered.has(name)
      ? impl
      : async (...args: unknown[]) => {
          const first = (await impl(...args)) as { evidence?: { recordId: string; recordSha256: string } };
          replay.executions[name] = (replay.executions[name] ?? 0) + 1;
          if (name !== 'fetchSource') {
            assert.ok(first.evidence);
            const file = path.join(world.evidenceRoot, world.runId, 'records', `${first.evidence.recordId}.json`);
            replay.firstRecord[name] = { recordId: first.evidence.recordId, refSha: first.evidence.recordSha256, fileSha: sha256(await readFile(file)) };
          }
          const second = (await impl(...args)) as { evidence?: { recordId: string; recordSha256: string } };
          replay.executions[name] += 1;
          if (second.evidence) replay.secondRef[name] = second.evidence;
          return second;
        };
  c.others.push(world);
  c.resumed = world;
});

When('the audit resumes and finishes', async function (this: ScanWorld) {
  const world = ctx(this).resumed;
  assert.ok(world);
  await world.runAudit();
  assert.equal(world.error, undefined, `audit failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.result?.evidence);
});

Then('evidence of the earlier steps is still valid', async function (this: ScanWorld) {
  const c = ctx(this);
  const world = c.resumed;
  assert.ok(world);
  assert.deepEqual(c.replay.executions, { fetchSource: 2, runGitleaks: 2, runSemgrep: 2 });
  const dir = bundleDirOf(world);
  for (const name of ['runGitleaks', 'runSemgrep']) {
    const first = c.replay.firstRecord[name];
    const stored = await recordById(dir, first.recordId);
    assert.equal(sha256(stored.bytes), first.fileSha, `${first.recordId} changed after the resume`);
    assert.equal(stored.entry.sha256, first.fileSha);
    assert.equal(first.refSha, first.fileSha);
    assert.deepEqual(c.replay.secondRef[name], { recordId: first.recordId, recordSha256: first.fileSha });
  }
  const report = await verifyEvidenceBundle(dir, { expectRootHash: world.result?.evidence?.rootHash });
  assert.deepEqual(report.issues, []);
  assert.equal(report.ok, true);
  assert.equal((await cli([dir])).code, 0);
});

Then('no step has duplicate evidence', async function (this: ScanWorld) {
  const world = ctx(this).resumed;
  assert.ok(world);
  const dir = bundleDirOf(world);
  const manifest = await readManifest(dir);
  const records = await readRecords(dir);
  const stepIds = records.map((r) => r.record.stepId);
  assert.equal(new Set(stepIds).size, stepIds.length, 'a step has more than one record');
  assert.equal(stepIds.length, 7);
  assert.ok(records.every((r) => r.record.attempt === 1));
  assert.equal(new Set(manifest.entries.map((e) => e.path)).size, manifest.entries.length);
  assert.equal(manifest.entries.filter((e) => e.kind === 'artifact').length, 8);
  assert.deepEqual(manifest.abandoned, []);
  assert.deepEqual(await listFiles(dir), [...manifest.entries.map((e) => e.path), 'SHA256SUMS', 'manifest.json'].sort());
});

When('a reviewer traces a finding', async function (this: ScanWorld) {
  const finding = findingsOf(this)[0];
  ctx(this).finding = finding;
  assert.ok(finding.evidenceRef);
  ctx(this).trace = await traceEvidence(bundleDirOf(this), finding.evidenceRef.recordId);
});

Then('the trace shows the evidence record, the raw output fingerprint and the source revision', function (this: ScanWorld) {
  const { trace, finding } = ctx(this);
  assert.ok(trace && finding?.evidenceRef);
  assert.equal(trace.recordId, finding.evidenceRef.recordId);
  assert.equal(trace.record.id, finding.evidenceRef.recordId);
  assert.ok(trace.record.findingIds.includes(finding.id));
  assert.equal(trace.source.revision, this.source.revision);
  const raw = sha256(rawOutputs(this)['scan.gitleaks'].stdout);
  assert.ok(trace.artifacts.some((a) => a.rawSha256 === raw), 'the trace lacks the raw output fingerprint');
  assert.equal(trace.record.output?.rawSha256, raw);
});

Then('the trace is available with one verification command', async function (this: ScanWorld) {
  const { finding } = ctx(this);
  assert.ok(finding?.evidenceRef);
  const dir = bundleDirOf(this);
  const before = await fingerprintTree(dir);
  const run = await cli(['--trace', finding.evidenceRef.recordId, dir]);
  assert.equal(run.code, 0, run.stderr);
  const lines = run.stdout.split('\n');
  assert.equal(lines[0], 'VERIFIED');
  assert.ok(lines.includes(`record: ${finding.evidenceRef.recordId}`));
  assert.ok(lines.includes(`revision: ${this.source.revision}`));
  const raw = sha256(rawOutputs(this)['scan.gitleaks'].stdout);
  assert.ok(lines.some((l) => l.startsWith('artifact: artifacts/scan.gitleaks.a1.stdout.json') && l.includes(`raw sha256 ${raw}`)));
  assert.ok(lines.includes(`root hash: ${(await readManifest(dir)).rootHash}`));
  assert.deepEqual(await fingerprintTree(dir), before);
});
