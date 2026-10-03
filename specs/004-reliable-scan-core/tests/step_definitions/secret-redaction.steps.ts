import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { After, Given, Then, When } from '@cucumber/cucumber';
import type { EvidenceRecord, OverrideAttempt } from '../../../../src/evidence/types';
import { inlineMarkerDetail } from '../../../../src/scan/source-probe';
import type { ProcessOutcome, ProcessRequest } from '../../../../src/scan/tool-types';
import { bundleDirOf, listFiles, recordById, sha256, useGitSource } from './support/bundle';
import { ScanWorld, capturedLogs, fixture, outcome } from './support/harness';

const DEMO_APP = path.resolve(__dirname, '../../../../demo/vulnerable-app');

interface Planted {
  name: string;
  rule: string;
  file: string;
  line: number;
  value: string;
}

interface Ctx {
  files: Record<string, string>;
  planted: Planted[];
  rawGitleaks: string;
  reportDir: string;
  reportFiles: Record<string, string>;
  treeAtScan: string[] | undefined;
  marker: string;
  markerFile: string;
  neutralized: { toml: string; ignore: string } | undefined;
}

const contexts = new WeakMap<ScanWorld, Ctx>();

function ctx(world: ScanWorld): Ctx {
  let c = contexts.get(world);
  if (c === undefined) {
    c = { files: {}, planted: [], rawGitleaks: '', reportDir: '', reportFiles: {}, treeAtScan: undefined, marker: '', markerFile: '', neutralized: undefined };
    contexts.set(world, c);
  }
  return c;
}

After(async function (this: ScanWorld) {
  const c = contexts.get(this);
  if (c !== undefined && c.reportDir !== '') await rm(c.reportDir, { recursive: true, force: true });
});

async function demo(rel: string): Promise<string> {
  return readFile(path.join(DEMO_APP, rel), 'utf8');
}

function lineOf(source: string, value: string): number {
  return source.split('\n').findIndex((l) => l.includes(value)) + 1;
}

async function plantedSecrets(): Promise<Planted[]> {
  const config = await demo('src/config.js');
  const auth = await demo('src/auth.js');
  const specs: [string, string, string, string, RegExp][] = [
    ['aws access key id', 'aws-access-token', 'src/config.js', config, /awsAccessKeyId:\s*'([^']+)'/],
    ['aws secret access key', 'aws-secret-access-key', 'src/config.js', config, /awsSecretAccessKey:\s*'([^']+)'/],
    ['internal api key', 'generic-api-key', 'src/config.js', config, /internalApiKey:\s*'([^']+)'/],
    ['admin password', 'hardcoded-password', 'src/auth.js', auth, /adminPassword\s*=\s*'([^']+)'/],
  ];
  return specs.map(([name, rule, file, text, pattern]) => {
    const match = pattern.exec(text);
    assert.ok(match, `demo secret ${name} not found in ${file}`);
    return { name, rule, file, line: lineOf(text, match[1]), value: match[1] };
  });
}

function encodings(value: string): string[] {
  const b64 = Buffer.from(value, 'utf8').toString('base64');
  const percent = encodeURIComponent(value);
  return [...new Set([value, b64, b64.replace(/=+$/, ''), b64.replace(/\+/g, '-').replace(/\//g, '_'), percent, percent.toLowerCase(), JSON.stringify(value).slice(1, -1)])];
}

function leakReport(planted: Planted[]): string {
  return JSON.stringify(
    planted.map((p) => ({
      RuleID: p.rule,
      Description: `Detected ${p.name}`,
      StartLine: p.line,
      EndLine: p.line,
      StartColumn: 3,
      EndColumn: 40,
      Match: `${p.name.replace(/ /g, '')}: '${p.value}'`,
      Secret: p.value,
      File: p.file,
      SymlinkFile: '',
      Commit: '',
      Entropy: 4.1,
      Fingerprint: `${p.file}:${p.rule}:${p.line}`,
      Tags: [],
    })),
  );
}

function plantSource(world: ScanWorld, files: Record<string, string>): void {
  useGitSource(world);
  const inner = world.sourceBehaviour;
  assert.ok(inner);
  world.sourceBehaviour = async (req: ProcessRequest): Promise<ProcessOutcome> => {
    if (req.args.includes('clone')) {
      const repoDir = req.args[req.args.length - 1];
      for (const [name, content] of Object.entries(files)) {
        await mkdir(path.dirname(path.join(repoDir, name)), { recursive: true, mode: 0o700 });
        await writeFile(path.join(repoDir, name), content);
      }
    }
    return inner(req);
  };
  ctx(world).files = files;
}

function recordingGitleaks(world: ScanWorld, produce: () => ProcessOutcome | Promise<ProcessOutcome>): void {
  world.setTool('gitleaks', async (req) => {
    if (req.args.length === 1) return outcome();
    const c = ctx(world);
    if (c.treeAtScan === undefined) c.treeAtScan = await listFiles(world.run.repoDir);
    return produce();
  });
}

async function baseSource(): Promise<Record<string, string>> {
  return { 'src/config.js': await demo('src/config.js'), 'src/auth.js': await demo('src/auth.js'), 'src/server.js': await demo('src/server.js') };
}

async function leakFixture(): Promise<{ out: ProcessOutcome; rule: string; file: string; line: number }> {
  const out = await fixture('gitleaks-leak.json');
  const first = (JSON.parse(out.stdout.toString('utf8')) as { RuleID: string; File: string; StartLine: number }[])[0];
  return { out, rule: first.RuleID, file: first.File, line: first.StartLine };
}

async function semgrepFixture(): Promise<{ out: ProcessOutcome; file: string; line: number }> {
  const out = await fixture('semgrep-results.json');
  const first = (JSON.parse(out.stdout.toString('utf8')) as { results: { path: string; start: { line: number } }[] }).results[0];
  return { out, file: first.path, line: first.start.line };
}

function completedAudit(world: ScanWorld): void {
  assert.equal(world.error, undefined, `audit failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.result, 'the audit produced no result');
  assert.ok(world.reportInput, 'no report was generated');
  assert.ok(world.result.evidence, 'the audit sealed no evidence');
}

async function bundleRecord(world: ScanWorld, id: string): Promise<EvidenceRecord> {
  return (await recordById(bundleDirOf(world), id)).record;
}

function attemptsView(attempts: OverrideAttempt[]): string[] {
  return attempts.map((a) => `${a.kind}|${a.path}|${a.neutralizedBy}`);
}

function scanCall(world: ScanWorld, file: string): ProcessRequest {
  const call = world.runnerCalls.find((r) => r.file === file && r.args.length > 1);
  assert.ok(call, `${file} was never run`);
  return call;
}

function leaksOf(world: ScanWorld): { id: string; title: string; evidence: { file?: string; line?: number }[] }[] {
  assert.ok(world.result);
  return world.result.findings.filter((f) => f.id.startsWith('LEAK-')) as never;
}

Given('a source containing a planted secret value', async function (this: ScanWorld) {
  const c = ctx(this);
  c.planted = await plantedSecrets();
  assert.ok(c.planted.every((p) => p.value.length > 0 && p.line > 0));
  plantSource(this, await baseSource());
  const report = leakReport(c.planted);
  c.rawGitleaks = report;
  recordingGitleaks(this, () => outcome({ exitCode: 42, stdout: Buffer.from(report), stderr: Buffer.from(`WRN leaks found: ${c.planted.length} ${c.planted[0].value}\n`) }));
});

When('the audit completes', async function (this: ScanWorld) {
  const c = ctx(this);
  capturedLogs.length = 0;
  await this.runAudit();
  completedAudit(this);
  const { generateReport } = await import('../../../../src/activities/index');
  c.reportDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-bdd-redaction-'));
  await generateReport({ ...(this.reportInput as Parameters<typeof generateReport>[0]), outputDir: c.reportDir });
  for (const f of await listFiles(c.reportDir)) c.reportFiles[f] = await readFile(path.join(c.reportDir, f), 'utf8');
});

function assertAbsent(planted: Planted[], haystacks: [string, string][], label: string): void {
  assert.ok(haystacks.length > 0, `nothing to search in ${label}`);
  for (const p of planted) {
    for (const form of encodings(p.value)) {
      for (const [where, text] of haystacks) {
        assert.ok(!text.includes(form), `${p.name} (${form === p.value ? 'raw' : 'encoded'}) found in ${where}`);
      }
    }
  }
}

Then('the secret value appears in no evidence record', async function (this: ScanWorld) {
  const c = ctx(this);
  for (const p of c.planted) assert.ok(c.rawGitleaks.includes(p.value), `the scanner output never carried ${p.name}`);
  const dir = bundleDirOf(this);
  const files = await listFiles(dir);
  assert.ok(files.some((f) => f.endsWith('records/scan.gitleaks.a1.json')), 'no gitleaks record in the bundle');
  assert.ok(files.some((f) => f.startsWith('artifacts/scan.gitleaks.a1')), 'no gitleaks artifact in the bundle');
  const haystacks: [string, string][] = [];
  for (const f of files) haystacks.push([f, (await readFile(path.join(dir, f))).toString('utf8')]);
  assertAbsent(c.planted, haystacks, 'the evidence bundle');
});

Then('in no report', function (this: ScanWorld) {
  const c = ctx(this);
  assert.ok(Object.keys(c.reportFiles).includes('audit-report.md'), 'the report was not written');
  const haystacks: [string, string][] = Object.entries(c.reportFiles);
  haystacks.push(['workflow result', JSON.stringify(this.result)]);
  haystacks.push(['report input', JSON.stringify(this.reportInput)]);
  assertAbsent(c.planted, haystacks, 'the reports');
});

Then('in no log of the run', function (this: ScanWorld) {
  assert.ok(capturedLogs.length > 0, 'no log line was captured');
  assertAbsent(ctx(this).planted, [['log', capturedLogs.join('')]], 'the logs');
});

Then('the finding states the secret type and its file and line', function (this: ScanWorld) {
  const c = ctx(this);
  const leaks = leaksOf(this);
  assert.equal(leaks.length, c.planted.length);
  for (const p of c.planted) {
    const found = leaks.find((l) => l.title.includes(p.rule));
    assert.ok(found, `no finding for ${p.rule}`);
    assert.equal(found.evidence[0]?.file, p.file);
    assert.equal(found.evidence[0]?.line, p.line);
    assert.ok(c.reportFiles['audit-report.md'].includes(p.rule), `the report does not name ${p.rule}`);
  }
  const evidenceFile = c.reportFiles[`evidence/${leaks[0].id}.json`];
  assert.ok(evidenceFile, 'no evidence file for the first leak');
  const parsed = JSON.parse(evidenceFile) as { file?: string; line?: number };
  assert.equal(parsed.file, leaks[0].evidence[0]?.file);
  assert.equal(parsed.line, leaks[0].evidence[0]?.line);
});

Given('the audited source ships a configuration that allows every secret', async function (this: ScanWorld) {
  const c = ctx(this);
  const leak = await leakFixture();
  const files = await baseSource();
  files['.gitleaks.toml'] = "[allowlist]\nregexes = ['''.*''']\npaths = ['''.*''']\n";
  files['.gitleaksignore'] = `${leak.file}:${leak.rule}:${leak.line}\n`;
  plantSource(this, files);
  recordingGitleaks(this, () => leak.out);
  c.neutralized = { toml: files['.gitleaks.toml'], ignore: files['.gitleaksignore'] };
});

Then('the planted secret is still reported', async function (this: ScanWorld) {
  const c = ctx(this);
  completedAudit(this);
  const leak = await leakFixture();
  const planted = (await plantedSecrets()).find((p) => p.rule === leak.rule && p.file === leak.file);
  assert.ok(planted, 'the fixture leak does not match a planted demo secret');
  const sourceLine = c.files[leak.file].split('\n')[leak.line - 1];
  assert.ok(sourceLine.includes(planted.value), 'the reported line does not hold the planted secret');
  const leaks = leaksOf(this);
  assert.equal(leaks.length, 1);
  assert.ok(leaks[0].title.includes(leak.rule));
  assert.equal(leaks[0].evidence[0]?.file, leak.file);
  assert.equal(leaks[0].evidence[0]?.line, leak.line);
  assert.equal(this.scannerEntry('gitleaks').status, 'completed');
  const tree = c.treeAtScan;
  assert.ok(tree, 'the secret scanner was never run');
  if (c.neutralized !== undefined) {
    for (const name of ['.gitleaks.toml', '.gitleaksignore']) {
      assert.ok(!tree.includes(name), `${name} was still in the working copy when the scanner ran`);
      assert.ok(tree.includes(`${name}.tessera-neutralized`), `${name} was not renamed to .tessera-neutralized`);
    }
    const call = scanCall(this, 'gitleaks');
    const configValue = call.args[call.args.indexOf('--config') + 1];
    assert.ok(!configValue.startsWith(this.run.repoDir), 'the scanner was pointed at a config from the audited source');
  }
});

Then('the attempt to alter the scanner is recorded in the evidence', async function (this: ScanWorld) {
  const c = ctx(this);
  assert.ok(c.neutralized);
  const probe = await bundleRecord(this, 'source.probe.a1');
  const scan = await bundleRecord(this, 'scan.gitleaks.a1');
  assert.equal(probe.overrideAttempts.length, 2);
  assert.deepEqual(attemptsView(probe.overrideAttempts), ['project-config|.gitleaks.toml|removed-from-working-copy', 'control-file|.gitleaksignore|removed-from-working-copy']);
  assert.equal(probe.overrideAttempts[0].sha256, sha256(c.neutralized.toml));
  assert.equal(probe.overrideAttempts[1].sha256, sha256(c.neutralized.ignore));
  assert.deepEqual(scan.overrideAttempts, probe.overrideAttempts);
  assert.match(probe.causeDetail ?? '', /^2 control files neutralized, 0 inline markers counted/);
  const semgrep = await bundleRecord(this, 'scan.semgrep.a1');
  assert.deepEqual(semgrep.overrideAttempts, []);
});

Given('the audited source marks a finding with {string}', async function (this: ScanWorld, marker: string) {
  const c = ctx(this);
  c.marker = marker;
  const files = await baseSource();
  const target = marker === 'gitleaks:allow' ? await leakFixture() : await semgrepFixture();
  const lines = files[target.file].split('\n');
  assert.ok(lines.length >= target.line, `${target.file} has no line ${target.line}`);
  lines[target.line - 1] = `${lines[target.line - 1]} // ${marker}`;
  files[target.file] = lines.join('\n');
  c.markerFile = target.file;
  plantSource(this, files);
  if (marker === 'gitleaks:allow') {
    recordingGitleaks(this, () => (target as Awaited<ReturnType<typeof leakFixture>>).out);
  } else {
    const out = (target as Awaited<ReturnType<typeof semgrepFixture>>).out;
    this.setTool('semgrep', () => out);
  }
});

Then('the finding is still reported', async function (this: ScanWorld) {
  const c = ctx(this);
  completedAudit(this);
  const scanner = c.marker === 'gitleaks:allow' ? 'gitleaks' : 'semgrep';
  const other = scanner === 'gitleaks' ? 'semgrep' : 'gitleaks';
  const expected = [`inline-marker|${c.markerFile}|framework-flag`];
  const probe = await bundleRecord(this, 'source.probe.a1');
  assert.deepEqual(attemptsView(probe.overrideAttempts), expected);
  assert.equal(probe.overrideAttempts[0].detail, inlineMarkerDetail(c.marker as 'gitleaks:allow' | 'nosemgrep', 1));
  assert.match(probe.causeDetail ?? '', /^0 control files neutralized, 1 inline markers counted/);
  assert.equal(probe.action.inputs.inlineMarkers, '1');
  const scan = await bundleRecord(this, `scan.${scanner}.a1`);
  assert.deepEqual(scan.overrideAttempts, probe.overrideAttempts);
  assert.deepEqual((await bundleRecord(this, `scan.${other}.a1`)).overrideAttempts, []);
  assert.ok(scanCall(this, 'gitleaks').args.includes('--ignore-gitleaks-allow'));
  assert.ok(scanCall(this, 'semgrep').args.includes('--disable-nosem'));
  assert.ok(scan.action.args.includes(scanner === 'gitleaks' ? '--ignore-gitleaks-allow' : '--disable-nosem'));
  assert.ok(this.result);
  const hits = this.result.findings.filter((f) => (f as { scanner?: string }).scanner === scanner);
  assert.ok(hits.length >= 1, `the ${scanner} finding was suppressed by the marker`);
  assert.ok(hits.some((f) => f.evidence[0]?.file === c.markerFile));
  assert.equal(this.scannerEntry(scanner).status, 'completed');
});
