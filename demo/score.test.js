const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { score, summarize, gate } = require('./score');

function expected() {
  const md = fs.readFileSync(path.join(__dirname, 'EXPECTED.md'), 'utf-8');
  return JSON.parse(md.match(/```json\n([\s\S]*?)\n```/)[1])['vulnerable-app'];
}

function finding(id, severity, category, file, line, title) {
  return { id, severity, category, title, description: title, evidence: [{ file, line, content: title }] };
}

test('one finding cannot cover two defects', () => {
  const defects = expected().filter((d) => d.id === 'D02' || d.id === 'D18');
  const rows = score([finding('F1', 'P1', 'security-data', 'src/config.js', 4, 'Secret detected: generic-api-key')], defects);
  const s = summarize(rows);
  assert.equal(s.strict, 1);
  assert.equal(s.broad, 2);
  assert.equal(rows.find((r) => r.id === 'D18').strictFound, true);
  assert.equal(rows.find((r) => r.id === 'D02').strictFound, false);
});

test('line number decides when known and is ignored when absent', () => {
  const d02 = expected().filter((d) => d.id === 'D02');
  assert.equal(summarize(score([finding('F1', 'P0', 'x', 'src/config.js', 3, 'aws secret')], d02)).strict, 1);
  assert.equal(summarize(score([finding('F1', 'P0', 'x', 'src/config.js', 9, 'aws secret')], d02)).strict, 0);
  assert.equal(summarize(score([finding('F1', 'P0', 'x', 'src/config.js', undefined, 'aws secret')], d02)).strict, 1);
});

test('last run gives strict recall 8 of 18', () => {
  const lastRun = path.join(__dirname, 'last-run.json');
  if (!fs.existsSync(lastRun)) return;
  const findings = JSON.parse(fs.readFileSync(lastRun, 'utf-8'))['vulnerable-app'].result.findings;
  const s = summarize(score(findings, expected()));
  assert.equal(s.total, 18);
  assert.equal(s.strict, 8);
  assert.ok(s.broad >= s.strict);
});

test('gate fails on missing dependency defects, low recall, dirty clean app, bad bundle and leak', () => {
  const rows = expected().map((d) => ({ id: d.id, strictFound: false, broadFound: false, strictSeverityOk: false, broadSeverityOk: false }));
  const clean = { outcome: 'complete', findings: [] };
  const verdict = gate({ rows, cleanResult: clean, bundleChecks: [{ name: 'a', exit: 0 }], leaks: [] });
  assert.equal(verdict.pass, false);
  assert.ok(verdict.failures.some((f) => f.startsWith('D05')));
  assert.ok(verdict.failures.some((f) => f.includes('strikte recall')));
  const bad = gate({ rows, cleanResult: { outcome: 'incomplete', findings: [{}] }, bundleChecks: [{ name: 'a', exit: 1 }], leaks: [{ file: 'f' }] });
  assert.ok(bad.failures.some((f) => f.includes('outcome')));
  assert.ok(bad.failures.some((f) => f.includes('bevindingen')));
  assert.ok(bad.failures.some((f) => f.includes('verificatie')));
  assert.ok(bad.failures.some((f) => f.includes('geheime waarde')));
});

test('gate passes when all requirements hold', () => {
  const rows = expected().map((d, i) => ({ id: d.id, strictFound: i < 9, broadFound: i < 9, strictSeverityOk: true, broadSeverityOk: true }));
  const ids = ['D05', 'D06', 'D07'];
  for (const r of rows) if (ids.includes(r.id)) r.strictFound = true;
  const verdict = gate({ rows, cleanResult: { outcome: 'complete', findings: [] }, bundleChecks: [{ name: 'a', exit: 0 }], leaks: [] });
  assert.equal(verdict.pass, true);
});
