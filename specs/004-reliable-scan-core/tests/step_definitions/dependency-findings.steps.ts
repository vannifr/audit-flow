import assert from 'node:assert/strict';
import { Given, Then } from '@cucumber/cucumber';
import { MAX_FINDINGS_PER_STEP } from '../../../../src/scan/scan-types';
import { ScanWorld, fixture, outcome } from './support/harness';

const SEVERITY_BY_NPM: Record<string, string> = { critical: 'P0', high: 'P1', moderate: 'P2', low: 'P3', info: 'P3' };

interface NpmVuln {
  name: string;
  severity: string;
}

async function knownVulnerabilities(): Promise<NpmVuln[]> {
  const raw = await fixture('npm-audit-vulnerable.json');
  const report = JSON.parse(raw.stdout.toString('utf8')) as { vulnerabilities: Record<string, NpmVuln> };
  return Object.values(report.vulnerabilities);
}

function distribution(severities: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const severity of severities) counts[severity] = (counts[severity] ?? 0) + 1;
  return counts;
}

function dependencyFindings(world: ScanWorld) {
  assert.equal(world.error, undefined, `audit unexpectedly failed: ${String((world.error as Error | undefined)?.message)}`);
  assert.ok(world.result, 'the audit produced no result');
  return world.result.findings.filter((f) => (f as { scanner?: string }).scanner === 'npm-audit');
}

function syntheticReport(count: number): Buffer {
  const vulnerabilities: Record<string, unknown> = {};
  for (let i = 1; i <= count; i += 1) {
    const name = `pkg-${i}`;
    vulnerabilities[name] = {
      name,
      severity: 'high',
      isDirect: false,
      via: [{ title: `advisory for ${name}`, url: `https://example.org/advisory/${i}`, severity: 'high' }],
      range: '*',
      fixAvailable: false,
    };
  }
  return Buffer.from(JSON.stringify({ auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: { total: count } } }));
}

Given('a source with known vulnerable dependencies', async function (this: ScanWorld) {
  const vulns = await knownVulnerabilities();
  const counts = distribution(vulns.map((v) => SEVERITY_BY_NPM[v.severity]));
  assert.ok((counts.P0 ?? 0) >= 1, 'the fixture holds no critical vulnerability');
  assert.ok((counts.P1 ?? 0) >= 5, 'the fixture holds fewer than five high vulnerabilities');
  const vulnerable = await fixture('npm-audit-vulnerable.json');
  assert.notEqual(vulnerable.exitCode, 0);
  this.focus = 'npm-audit';
  this.setTool('npm-audit', () => vulnerable);
});

Then('each known vulnerability is reported with severity and affected package', async function (this: ScanWorld) {
  const vulns = await knownVulnerabilities();
  const findings = dependencyFindings(this);
  assert.equal(findings.length, vulns.length);
  const entry = this.scannerEntry('npm-audit');
  assert.equal(entry.status, 'completed');
  assert.equal(entry.cause, 'issues-found');
  assert.equal(entry.findingCount, vulns.length);
  assert.deepEqual(
    distribution(findings.map((f) => f.severity)),
    distribution(vulns.map((v) => SEVERITY_BY_NPM[v.severity])),
  );
  assert.ok(findings.filter((f) => f.severity === 'P0').length >= 1);
  assert.ok(findings.filter((f) => f.severity === 'P1').length >= 5);
  for (const vuln of vulns) {
    const match = findings.find((f) => f.title.startsWith(`${vuln.name}:`));
    assert.ok(match, `no finding for ${vuln.name}`);
    assert.equal(match.severity, SEVERITY_BY_NPM[vuln.severity], `wrong severity for ${vuln.name}`);
    assert.ok(match.evidence.length > 0);
    for (const item of match.evidence) {
      assert.equal(item.file, 'package.json');
      assert.ok(`${match.title} ${item.content}`.includes(vuln.name));
    }
  }
});

Given('a scanner produces very large output', async function (this: ScanWorld) {
  const vulnerable = await fixture('npm-audit-vulnerable.json');
  this.focus = 'npm-audit';
  this.setTool('npm-audit', () => ({ ...vulnerable, stdoutTruncated: true }));
});

Then('no findings are lost to the output size limit', async function (this: ScanWorld) {
  assert.equal(this.error, undefined);
  assert.ok(this.result, 'the audit produced no result');
  const entry = this.scannerEntry('npm-audit');
  assert.notEqual(entry.status, 'completed');
  assert.equal(entry.cause, 'output-truncated');
  assert.equal(this.result.outcome, 'incomplete');
  const item = this.result.notPerformed.find((n) => n.scanner === 'npm-audit');
  assert.ok(item, 'the lost output is not named as not performed');
  assert.equal(item.cause, 'output-truncated');
  assert.equal(dependencyFindings(this).length, entry.findingCount);

  const capped = new ScanWorld();
  await capped.prepare();
  try {
    const raw = syntheticReport(MAX_FINDINGS_PER_STEP + 1);
    capped.setTool('npm-audit', () => outcome({ exitCode: 1, stdout: raw }));
    await capped.runAudit();
    assert.equal(capped.error, undefined);
    const cappedEntry = capped.scannerEntry('npm-audit');
    assert.equal(cappedEntry.status, 'partial');
    assert.equal(cappedEntry.cause, 'findings-truncated');
    assert.equal(cappedEntry.findingCount, MAX_FINDINGS_PER_STEP);
    assert.equal(dependencyFindings(capped).length, MAX_FINDINGS_PER_STEP);
    assert.equal(capped.result?.outcome, 'incomplete');
    assert.ok(capped.result?.notPerformed.some((n) => n.scanner === 'npm-audit' && n.cause === 'findings-truncated'));
  } finally {
    await capped.dispose();
  }
});

Then('truncation is reported as partial', function (this: ScanWorld) {
  const entry = this.scannerEntry('npm-audit');
  assert.equal(entry.status, 'partial');
  assert.ok(entry.causeDetail && entry.causeDetail.length > 0);
  const item = this.result?.notPerformed.find((n) => n.scanner === 'npm-audit');
  assert.equal(item?.status, 'partial');
});
