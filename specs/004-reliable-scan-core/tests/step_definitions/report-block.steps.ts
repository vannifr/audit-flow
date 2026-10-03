import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { After, Then, When, setWorldConstructor } from '@cucumber/cucumber';
import { REVISION, ScanWorld, fixture } from './support/harness';

class ReportBlockWorld extends ScanWorld {
  reportDir = '';
  reportText = '';
}

setWorldConstructor(ReportBlockWorld);

After(async function (this: ReportBlockWorld) {
  if (this.reportDir !== '') await rm(this.reportDir, { recursive: true, force: true });
});

When('an audit finishes', async function (this: ReportBlockWorld) {
  const leak = await fixture('gitleaks-leak.json');
  this.setTool('gitleaks', () => leak);
  await this.runAudit();
  assert.equal(this.error, undefined);
  assert.ok(this.reportInput, 'no report was generated');
  assert.ok(this.result && this.result.findings.length > 0, 'the audit produced no finding');

  const { generateReport } = await import('../../../../src/activities/index');
  this.reportDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-bdd-report-'));
  const written = await generateReport({ ...(this.reportInput as Parameters<typeof generateReport>[0]), outputDir: this.reportDir });
  this.reportText = await readFile(written.reportPath, 'utf8');
});

Then('the first lines of the report show the overall outcome', function (this: ReportBlockWorld) {
  assert.equal(this.result?.outcome, 'complete');
  const lines = this.reportText.split('\n');
  assert.ok(lines[0].startsWith('Audit outcome: COMPLETE'), `first line was "${lines[0]}"`);
  assert.ok(this.reportText.includes(`Source revision: ${REVISION}`), 'the source revision is missing from the report');
});

Then('a scanner status table follows before any finding', function (this: ReportBlockWorld) {
  assert.ok(this.result);
  const header = this.reportText.indexOf('| Scanner | Required | Status |');
  assert.ok(header > 0, 'no scanner status table in the report');
  const findingIds = this.result.findings.map((f) => f.id);
  assert.ok(findingIds.length > 0);
  for (const id of findingIds) {
    const row = this.reportText.indexOf(`| ${id} |`);
    assert.ok(row > 0, `finding ${id} is missing from the report`);
    assert.ok(header < row, `the status table does not precede finding ${id}`);
  }
  assert.ok(header < this.reportText.indexOf('## Findings'), 'the status table does not precede the findings section');
});
