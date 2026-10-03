import assert from 'node:assert/strict';
import { After, Before, Given, Then, When, setWorldConstructor } from '@cucumber/cucumber';
import { computeOutcome, mayReportClean } from '../../../../src/scan/status';
import type { NotPerformed, ScannerId, ScannerStatusEntry, ScannerStatusValue } from '../../../../src/scan/status';
import {
  SCANNER_BY_LABEL,
  SHA256_EMPTY,
  ScanWorld,
  crashingTool,
  failureOf,
  fixture,
  hangingTool,
  missingTool,
  outcome,
} from './support/harness';

class HonestScanWorld extends ScanWorld {
  expectedStatus: ScannerStatusValue | undefined;
}

setWorldConstructor(HonestScanWorld);

const SCANNER_TOOLS: ScannerId[] = ['gitleaks', 'semgrep', 'npm-audit', 'license-check'];

function scannerFor(label: string): ScannerId {
  const scanner = SCANNER_BY_LABEL[label];
  assert.ok(scanner, `unknown scanner label "${label}"`);
  return scanner;
}

function completed(world: HonestScanWorld) {
  assert.equal(world.error, undefined, `audit unexpectedly failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.result, 'the audit produced no result');
  assert.ok(world.reportInput, 'no report was generated');
  return { result: world.result, report: world.reportInput };
}

function focused(world: HonestScanWorld): ScannerId {
  assert.ok(world.focus, 'no scanner under test');
  return world.focus;
}

function notPerformedFor(world: HonestScanWorld, scanner: ScannerId): NotPerformed | undefined {
  const { result, report } = completed(world);
  const fromResult = result.notPerformed.find((n) => n.scanner === scanner);
  const fromReport = (report.notPerformed as NotPerformed[]).find((n) => n.scanner === scanner);
  assert.deepEqual(fromReport, fromResult, 'report and audit result disagree about what was not performed');
  return fromResult;
}

Before(async function (this: HonestScanWorld) {
  await this.prepare();
});

After(async function (this: HonestScanWorld) {
  await this.dispose();
});

Given('an audit source with known content', function (this: HonestScanWorld) {
  assert.ok(this.repoFiles['package.json']);
  assert.ok(this.repoFiles['package-lock.json']);
  assert.ok(this.repoFiles['index.js']);
});

Given('the secret scanner is not installed', function (this: HonestScanWorld) {
  this.focus = 'gitleaks';
  this.expectedStatus = 'unavailable';
  this.setTool('gitleaks', missingTool);
});

Given('the static analysis scanner crashes during the run', async function (this: HonestScanWorld) {
  const crash = await fixture('semgrep-crash.json');
  this.focus = 'semgrep';
  this.expectedStatus = 'failed';
  this.setTool('semgrep', () => crash);
});

Given('all required scanners complete and find nothing', function (this: HonestScanWorld) {
  this.focus = undefined;
});

Given('a scanner exits with a non-zero code because it found issues', async function (this: HonestScanWorld) {
  const leak = await fixture('gitleaks-leak.json');
  assert.notEqual(leak.exitCode, 0);
  this.focus = 'gitleaks';
  this.setTool('gitleaks', () => leak);
});

Given('the scanner {string} is {string}', function (this: HonestScanWorld, label: string, state: string) {
  const scanner = scannerFor(label);
  assert.ok(state === 'unavailable' || state === 'failed', `unsupported state ${state}`);
  this.focus = scanner;
  this.expectedStatus = state;
  if (scanner === 'license-check') {
    assert.equal(state, 'failed', 'the license check runs in-process and cannot be unavailable');
    this.breakLicenseLockfile();
  } else {
    this.setTool(scanner, state === 'unavailable' ? missingTool : crashingTool);
  }
});

Given('one required scanner did not complete', function (this: HonestScanWorld) {
  this.focus = 'semgrep';
  this.expectedStatus = 'failed';
  this.setTool('semgrep', crashingTool);
});

Given('a scanner produces more output than the size limit', async function (this: HonestScanWorld) {
  const clean = await fixture('semgrep-clean.json');
  this.focus = 'semgrep';
  this.setTool('semgrep', () => ({ ...clean, stdoutTruncated: true }));
});

Given('a scanner returns a success code and no output', function (this: HonestScanWorld) {
  this.directOutcome = outcome({ exitCode: 0 });
});

Given('a scanner does not finish within its time limit', function (this: HonestScanWorld) {
  this.focus = 'semgrep';
  this.setTool('semgrep', hangingTool);
});

Given('the audit source cannot be retrieved', function (this: HonestScanWorld) {
  this.sourceBehaviour = () =>
    outcome({ exitCode: 128, stderr: Buffer.from("fatal: repository 'https://github.com/acme/app/' not found\n") });
});

async function execute(world: HonestScanWorld): Promise<void> {
  if (world.directOutcome !== undefined) {
    await world.runDirectTool();
  } else {
    await world.runAudit();
  }
}

When('an audit runs', async function (this: HonestScanWorld) {
  await execute(this);
});

When('the audit runs', async function (this: HonestScanWorld) {
  await execute(this);
});

When('the audit finishes', async function (this: HonestScanWorld) {
  await execute(this);
});

Then('the report shows the secret scanner as {string}', function (this: HonestScanWorld, status: string) {
  const { result } = completed(this);
  assert.equal(this.scannerEntry('gitleaks').status, status);
  assert.equal(result.scanners.find((s) => s.scanner === 'gitleaks')?.status, status);
});

Then('the audit outcome is {string}', function (this: HonestScanWorld, label: string) {
  const { result, report } = completed(this);
  const expected = label.toLowerCase();
  assert.equal(result.outcome, expected);
  assert.equal(report.outcome, expected);
  const level = (report.signature as { level?: number } | undefined)?.level === 1 ? 1 : 0;
  const decision = computeOutcome({
    scanners: result.scanners,
    untracedFindingIds: [],
    ...(this.requireSignature ? { evidenceSignature: { required: true, level } } : {}),
  });
  assert.equal(decision.outcome, expected);
});

Then('the report does not show a clean result for secret scanning', function (this: HonestScanWorld) {
  const { result, report } = completed(this);
  const entry = this.scannerEntry('gitleaks');
  assert.equal(mayReportClean(entry), false);
  assert.notEqual(entry.status, 'completed');
  const decision = computeOutcome({ scanners: report.scanners as ScannerStatusEntry[], untracedFindingIds: [] });
  assert.ok(!decision.completedScanners.includes('gitleaks'));
  assert.ok(decision.notPerformed.some((n) => n.scanner === 'gitleaks'));
  assert.ok(result.notPerformed.some((n) => n.scanner === 'gitleaks'));
});

Then('the scanner status is {string} and the cause is recorded', async function (this: HonestScanWorld, status: string) {
  completed(this);
  const scanner = focused(this);
  const entry = this.scannerEntry(scanner);
  assert.equal(entry.status, status);
  assert.ok(entry.cause, 'the status carries no cause');
  assert.ok(entry.causeDetail && entry.causeDetail.length > 0, 'the status carries no cause detail');
  const record = await this.evidenceRecord(scanner);
  assert.equal(record.status, status);
  assert.equal(record.cause, entry.cause);
  assert.ok(entry.evidenceRecordIds.includes(record.id));
});

Then('the report states {string}', function (this: HonestScanWorld, text: string) {
  assert.equal(text, 'no findings');
  const { result, report } = completed(this);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(report.findings, []);
  assert.deepEqual(result.notPerformed, []);
  assert.equal(result.outcome, 'complete');
});

Then('the report lists the completed scanners', function (this: HonestScanWorld) {
  const { result, report } = completed(this);
  const decision = computeOutcome({ scanners: report.scanners as ScannerStatusEntry[], untracedFindingIds: [] });
  for (const scanner of SCANNER_TOOLS) {
    assert.ok(decision.completedScanners.includes(scanner), `${scanner} is not listed as completed`);
    assert.equal(this.scannerEntry(scanner).status, 'completed');
    assert.ok(this.scannerEntry(scanner).evidenceRecordIds.length > 0, `${scanner} has no evidence record`);
  }
  assert.deepEqual(report.scanners, result.scanners);
});

Then('the scanner status is {string}', async function (this: HonestScanWorld, status: string) {
  if (this.direct !== undefined) {
    assert.equal(this.direct.classification.status, status);
    assert.equal((await this.directRecord()).status, status);
    return;
  }
  completed(this);
  assert.equal(this.scannerEntry(focused(this)).status, status);
});

Then('the issues are reported as findings', function (this: HonestScanWorld) {
  const { result, report } = completed(this);
  const entry = this.scannerEntry(focused(this));
  assert.equal(entry.cause, 'issues-found');
  assert.ok(result.findings.length > 0);
  assert.equal(result.findings.length, entry.findingCount);
  assert.deepEqual((report.findings as unknown[]).length, result.findings.length);
  for (const finding of result.findings) {
    const ref = (finding as { evidenceRef?: { recordId: string }; scanner?: string });
    assert.equal(ref.scanner, entry.scanner);
    assert.ok(ref.evidenceRef && entry.evidenceRecordIds.includes(ref.evidenceRef.recordId));
  }
  assert.equal(result.outcome, 'complete');
});

Then('the report names {string} as not completed', function (this: HonestScanWorld, label: string) {
  const scanner = scannerFor(label);
  const item = notPerformedFor(this, scanner);
  assert.ok(item, `${scanner} is not named as not performed`);
  assert.equal(item.status, this.expectedStatus);
  assert.ok(item.summary.includes(scanner));
  assert.equal(this.scannerEntry(scanner).status, this.expectedStatus);
  assert.equal(mayReportClean(this.scannerEntry(scanner)), false);
});

Then('the summary lists every check that was not performed', function (this: HonestScanWorld) {
  const { result, report } = completed(this);
  const entries = report.scanners as ScannerStatusEntry[];
  const expected = entries.filter((e) => e.required && e.status !== 'completed').map((e) => e.scanner).sort();
  assert.deepEqual(expected, ['semgrep']);
  assert.deepEqual(result.notPerformed.map((n) => n.scanner).sort(), expected);
  assert.deepEqual(report.notPerformed, result.notPerformed);
  for (const item of result.notPerformed) {
    assert.ok(item.summary.includes(item.scanner));
  }
});

Then('the scanner status is {string} with cause {string}', async function (this: HonestScanWorld, status: string, cause: string) {
  const { result } = completed(this);
  const scanner = focused(this);
  const entry = this.scannerEntry(scanner);
  assert.equal(entry.status, status);
  assert.equal(entry.cause, cause.replace(/ /g, '-'));
  const record = await this.evidenceRecord(scanner);
  assert.equal(record.status, status);
  assert.equal(record.cause, entry.cause);
  assert.equal(result.outcome, 'incomplete');
  assert.ok(result.notPerformed.some((n) => n.scanner === scanner && n.cause === entry.cause));
});

Then('the empty output is recorded with its fingerprint', async function (this: HonestScanWorld) {
  assert.ok(this.direct, 'the tool did not run');
  const record = await this.directRecord();
  assert.equal(record.id, this.direct.evidence.recordId);
  assert.ok(record.output, 'no output artifact recorded for the empty output');
  assert.equal(record.output.rawBytes, 0);
  assert.equal(record.output.rawSha256, SHA256_EMPTY);
  assert.equal(record.result.exitCode, 0);
});

Then('the audit fails early with a clear cause', function (this: HonestScanWorld) {
  assert.equal(this.result, undefined, 'the audit returned a result');
  const failure = failureOf(this.error);
  assert.equal(failure.type, 'SourceUnavailableError');
  assert.equal(failure.nonRetryable, true);
  assert.match(failure.message, /Audit not performed/);
  const detail = failure.details?.[0] as { notPerformed: NotPerformed[] };
  assert.equal(detail.notPerformed[0].scanner, 'source');
  assert.equal(detail.notPerformed[0].cause, 'source-unavailable');
  assert.ok(detail.notPerformed[0].summary.length > 0);
  assert.ok(this.called('fetchSource'));
});

Then('the outcome is {string}', function (this: HonestScanWorld, label: string) {
  const detail = failureOf(this.error).details?.[0] as { outcome: string };
  assert.equal(detail.outcome, label.toLowerCase());
});

Then('no report is produced as if the audit had run', function (this: HonestScanWorld) {
  assert.equal(this.reportInput, undefined);
  assert.equal(this.called('generateReport'), false);
  for (const scanner of SCANNER_TOOLS) assert.equal(this.called(this.activityFor(scanner)), false);
  assert.equal(this.called('detectTechStack'), false);
  assert.equal(this.runnerCalls.some((r) => r.file !== 'git'), false);
});
