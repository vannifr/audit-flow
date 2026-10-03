import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateReport } from '../../src/activities/index';
import type { Finding, TechStack, ScopeDocument, ReviewResult } from '../../src/types';
import type { NotPerformed, ScannerStatusEntry } from '../../src/scan/status';

let out: string;

beforeEach(async () => {
  out = await mkdtemp(path.join(tmpdir(), 'report-'));
});

afterEach(async () => {
  await rm(out, { recursive: true, force: true });
});

const techStack: TechStack = { language: 'nodejs', frameworks: ['Express'], hasPayments: false, hasPII: false, packageManager: 'npm' };
const scope: ScopeDocument = {
  repoUrl: 'https://github.com/o/r',
  techStack,
  securityLevel: 1,
  frameworks: ['OWASP-ASVS'],
  inScope: [],
  outOfScope: [],
  createdAt: new Date(),
};
const reviewResult: ReviewResult = { falsePositives: [], severityCorrections: [], missingFindings: [], reviewNotes: '' };

function finding(id: string, title: string, severity: Finding['severity'] = 'P1'): Finding {
  return {
    id,
    title,
    description: 'd',
    severity,
    category: 'security-code-review',
    evidence: [{ type: 'code-review', file: 'a.js', line: 1, content: 'eval(', tool: 'code-review', timestamp: new Date() }],
    remediation: { description: 'r', effort: 'hours', priority: 'short-term' },
    verified: false,
    createdAt: new Date(),
  };
}

function entry(scanner: ScannerStatusEntry['scanner'], overrides: Partial<ScannerStatusEntry> = {}): ScannerStatusEntry {
  return {
    scanner,
    required: scanner !== 'code-review',
    status: 'completed',
    heuristic: scanner === 'code-review',
    toolVersion: scanner === 'code-review' ? null : '1.2.3',
    findingCount: 0,
    evidenceRecordIds: [],
    ...overrides,
  };
}

const ALL_COMPLETED: ScannerStatusEntry[] = [
  entry('gitleaks'),
  entry('semgrep'),
  entry('npm-audit'),
  entry('license-check'),
  entry('code-review'),
];

async function render(extra: Record<string, unknown>, findings: Finding[] = []): Promise<string> {
  const result = await generateReport({
    repoUrl: 'https://github.com/o/r',
    workflowId: 'wf-1',
    techStack,
    scope,
    findings,
    complianceMaps: [],
    reviewResult,
    outputDir: out,
    ...extra,
  });
  return readFile(result.reportPath, 'utf-8');
}

describe('report outcome block (FR-016, TS-007)', () => {
  it('starts with the plain-text outcome on line 1', async () => {
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(report.split('\n')[0]).toBe('Audit outcome: COMPLETE');
    const incomplete = await render({ outcome: 'incomplete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(incomplete.split('\n')[0]).toBe('Audit outcome: INCOMPLETE');
  });

  it('puts the status block before the first finding', async () => {
    const report = await render(
      { outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED },
      [finding('REVIEW-1', 'eval() usage')],
    );
    const table = report.indexOf('| Scanner | Required | Status | Cause | Heuristic | Findings | Tool version |');
    const first = report.indexOf('REVIEW-1');
    expect(table).toBeGreaterThan(0);
    expect(first).toBeGreaterThan(table);
    expect(report.indexOf('Audit outcome:')).toBeLessThan(table);
  });

  it('lists two not-performed scanners with status and cause when incomplete', async () => {
    const notPerformed: NotPerformed[] = [
      { scanner: 'gitleaks', status: 'unavailable', cause: 'not-installed', summary: 'Required scanner gitleaks was not available (not-installed); its area is not verified.' },
      { scanner: 'semgrep', status: 'failed', cause: 'timeout', summary: 'Required scanner semgrep failed (timeout); its area is not verified.' },
    ];
    const scanners = [
      entry('gitleaks', { status: 'unavailable', cause: 'not-installed', toolVersion: null }),
      entry('semgrep', { status: 'failed', cause: 'timeout' }),
      entry('npm-audit'),
    ];
    const report = await render({ outcome: 'incomplete', notPerformed, scanners });
    expect(report).toContain('Not performed');
    expect(report).toContain('- gitleaks: unavailable, not-installed');
    expect(report).toContain('- semgrep: failed, timeout');
    const notPerformedAt = report.indexOf('Not performed');
    expect(notPerformedAt).toBeGreaterThan(report.indexOf('Audit outcome: INCOMPLETE'));
    expect(notPerformedAt).toBeLessThan(report.indexOf('| Scanner |'));
    expect(report).toContain('| gitleaks | yes | unavailable | not-installed | no | 0 | n/a |');
    expect(report).toContain('| semgrep | yes | failed | timeout | no | 0 | 1.2.3 |');
  });

  it('shows No findings with the completed scanners when complete and empty', async () => {
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(report).toContain('No findings');
    expect(report).toMatch(/Completed scanners: .*gitleaks.*semgrep.*npm-audit.*license-check.*code-review/);
  });

  it('never says No findings when incomplete', async () => {
    const notPerformed: NotPerformed[] = [
      { scanner: 'gitleaks', status: 'failed', cause: 'tool-error', summary: 'x' },
    ];
    const report = await render({
      outcome: 'incomplete',
      notPerformed,
      scanners: [entry('gitleaks', { status: 'failed', cause: 'tool-error' }), entry('semgrep')],
    });
    expect(report.toLowerCase()).not.toContain('no findings');
    expect(report).not.toContain('Risk Level:** LOW');
  });

  it('lists findings and completed scanners when complete with findings, without No findings', async () => {
    const report = await render(
      { outcome: 'complete', notPerformed: [], scanners: [entry('semgrep', { findingCount: 1 }), entry('gitleaks')] },
      [finding('SEM-1', 'sql injection', 'P0')],
    );
    expect(report).not.toContain('No findings');
    expect(report).toContain('Completed scanners: semgrep, gitleaks');
    expect(report).toContain('| SEM-1 | sql injection | P0 |');
  });

  it('marks heuristic scanners as heuristic', async () => {
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(report).toContain('| code-review | no | completed | - | heuristic | 0 | n/a |');
    expect(report).toContain('| gitleaks | yes | completed | - | no | 0 | 1.2.3 |');
  });

  it('shows the source revision when known and omits it otherwise', async () => {
    const known = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, revision: 'a'.repeat(40) });
    expect(known).toContain(`Source revision: ${'a'.repeat(40)}`);
    expect(known.indexOf('Source revision:')).toBeGreaterThan(known.indexOf('| Scanner |'));
    expect(known.indexOf('Source revision:')).toBeLessThan(known.indexOf('# Audit Report'));
    const unknown = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(unknown).not.toContain('Source revision');
  });

  it('falls back to UNKNOWN for callers that pass no status fields', async () => {
    const report = await render({}, [finding('REVIEW-1', 'eval() usage')]);
    expect(report.split('\n')[0]).toBe('Audit outcome: UNKNOWN (scanner status not provided)');
    expect(report).toContain('# Audit Report');
    expect(report).toContain('| REVIEW-1 | eval() usage | P1 |');
    expect(report).not.toContain('| Scanner |');
    expect(report.toLowerCase()).not.toContain('no findings');
  });

  it('does not leak secret values into the report or evidence', async () => {
    const leaky = finding('REVIEW-1', 'Hardcoded password');
    leaky.evidence[0].content = 'password = "admin1234" AKIAIOSFODNN7EXAMPLE';
    const report = await render(
      { outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, repoUrl: 'https://user:hunter2hunter2@github.com/o/r' },
      [leaky],
    );
    const evidence = await readFile(path.join(out, 'evidence', 'REVIEW-1.json'), 'utf-8');
    for (const text of [report, evidence]) {
      expect(text).not.toContain('admin1234');
      expect(text).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(text).not.toContain('hunter2hunter2');
    }
  });

  it('keeps the evidence json consistent with the report', async () => {
    const notPerformed: NotPerformed[] = [{ scanner: 'gitleaks', status: 'unavailable', cause: 'not-installed', summary: 's' }];
    const scanners = [entry('gitleaks', { status: 'unavailable', cause: 'not-installed' })];
    await render({ outcome: 'incomplete', notPerformed, scanners, revision: 'b'.repeat(40) }, [finding('REVIEW-1', 'eval() usage')]);
    const files = await readdir(path.join(out, 'evidence'));
    expect(files).toContain('REVIEW-1.json');
    expect(files).toContain('scanner-status.json');
    const status = JSON.parse(await readFile(path.join(out, 'evidence', 'scanner-status.json'), 'utf-8'));
    expect(status.outcome).toBe('incomplete');
    expect(status.notPerformed).toEqual(notPerformed);
    expect(status.scanners).toEqual(scanners);
    expect(status.revision).toBe('b'.repeat(40));
  });

  it('keeps writing no scanner-status.json for callers without status fields', async () => {
    await render({});
    expect(await readdir(path.join(out, 'evidence'))).not.toContain('scanner-status.json');
  });
});

describe('report evidence section (FR-017, R9)', () => {
  const ROOT = '0123456789abcdef'.repeat(4);
  const BUNDLE = '/var/lib/tessera/evidence/run-1';

  it('shows bundle, root hash, the verify command, the sha256sum limit and the unsigned state after the source revision', async () => {
    const report = await render({
      outcome: 'complete',
      notPerformed: [],
      scanners: ALL_COMPLETED,
      revision: 'a'.repeat(40),
      evidence: { bundlePath: BUNDLE, rootHash: ROOT },
    });
    const lines = report.split('\n');
    const revision = lines.indexOf(`Source revision: ${'a'.repeat(40)}`);
    expect(revision).toBeGreaterThan(0);
    expect(lines.slice(revision + 2, revision + 7)).toEqual([
      `Evidence bundle: ${BUNDLE}`,
      `Evidence root hash: ${ROOT}`,
      `Verify: npm run evidence:verify -- ${BUNDLE} --expect-root ${ROOT} --pubkey <path to the public key>`,
      'Without Tessera, `sha256sum -c SHA256SUMS` in the bundle folder detects only changed or missing files; added files, the hash chain and the root hash need the verify command.',
      'Integrity: hashes only; the manifest is not signed',
    ]);
    expect(report.indexOf('Evidence bundle:')).toBeLessThan(report.indexOf('# Audit Report'));
    expect(report.toLowerCase()).not.toMatch(/assurance level|level [0-9]/);
  });

  it('keeps the evidence section on an incomplete audit', async () => {
    const report = await render({ outcome: 'incomplete', notPerformed: [], scanners: ALL_COMPLETED, evidence: { bundlePath: BUNDLE, rootHash: ROOT } });
    expect(report).toContain(`Evidence root hash: ${ROOT}`);
  });

  it('quotes a bundle path with spaces or quotes in the verify command and strips line breaks', async () => {
    const odd = "/tmp/my evidence/it's\nhere";
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, evidence: { bundlePath: odd, rootHash: ROOT } });
    expect(report).toContain("Evidence bundle: /tmp/my evidence/it's here");
    expect(report).toContain(`Verify: npm run evidence:verify -- '/tmp/my evidence/it'\\''s here' --expect-root ${ROOT} --pubkey <path to the public key>`);
  });

  it('omits the evidence section when no bundle was sealed', async () => {
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED });
    expect(report).not.toContain('Evidence bundle');
    expect(report).not.toContain('Integrity:');
  });
});

describe('report signature and assurance level (FR-020, TS-034)', () => {
  const ROOT = '0123456789abcdef'.repeat(4);
  const BUNDLE = '/var/lib/tessera/evidence/run-1';
  const KEY = 'ab'.repeat(32);
  const AT = '2026-03-01T12:05:00.000Z';
  const base = { outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, evidence: { bundlePath: BUNDLE, rootHash: ROOT } };

  it('states what was signed, by which key, that the time is not attested, and level 1 for a valid signature', async () => {
    const lines = (await render({ ...base, signature: { signed: true, keyId: KEY, signedAt: AT, level: 1 } })).split('\n');
    const integrity = lines.indexOf('Integrity: hashes and a signed manifest');
    expect(integrity).toBeGreaterThan(0);
    expect(lines.slice(integrity + 1, integrity + 4)).toEqual([
      `Signature: valid, key ${KEY}, signed ${AT} (signing time is not independently attested)`,
      'Signed: manifest.json (run id, root hash and the sha256 of the manifest bytes) with Ed25519',
      'Assurance level: 1',
    ]);
    expect(lines).not.toContain('Integrity: hashes only; the manifest is not signed');
  });

  it('says Signature: none and level 0 without a signature', async () => {
    const lines = (await render({ ...base, signature: { signed: false, level: 0 } })).split('\n');
    expect(lines).toContain('Integrity: hashes only; the manifest is not signed');
    expect(lines).toContain('Signature: none');
    expect(lines).toContain('Assurance level: 0');
    expect(lines.join('\n')).not.toMatch(/Assurance level: [1-9]/);
  });

  it('never shows a valid signature or level 1 for an inconsistent claim', async () => {
    for (const signature of [
      { signed: true, keyId: KEY, signedAt: AT, level: 0 },
      { signed: false, keyId: KEY, signedAt: AT, level: 1 },
      { signed: true, signedAt: AT, level: 1 },
      { signed: true, keyId: 'not-hex', signedAt: AT, level: 1 },
      { signed: true, keyId: KEY, level: 1 },
    ]) {
      const text = await render({ ...base, signature });
      expect(text).not.toContain('Signature: valid');
      expect(text).toContain('Assurance level: 0');
      expect(text).toContain('Integrity: hashes only; the manifest is not signed');
    }
    expect(await render({ ...base, signature: { signed: true, keyId: KEY, signedAt: AT, level: 0 } })).toContain(
      'Signature: present but not valid for the signing key',
    );
  });
});

describe('report product name', () => {
  const saved = process.env.TESSERA_PRODUCT_NAME;

  afterEach(() => {
    if (saved === undefined) delete process.env.TESSERA_PRODUCT_NAME;
    else process.env.TESSERA_PRODUCT_NAME = saved;
  });

  it('puts Tessera in the title by default', async () => {
    delete process.env.TESSERA_PRODUCT_NAME;
    expect((await render({})).split('\n')).toContain('# Audit Report (Tessera)');
  });

  it('uses TESSERA_PRODUCT_NAME in the title only and strips markup and line breaks', async () => {
    process.env.TESSERA_PRODUCT_NAME = 'Acme\n# Audit|Kit';
    const report = await render({});
    expect(report.split('\n')).toContain('# Audit Report (Acme Audit Kit)');
    expect(report.match(/Acme/g)).toHaveLength(1);
    process.env.TESSERA_PRODUCT_NAME = '   ';
    expect((await render({})).split('\n')).toContain('# Audit Report (Tessera)');
  });
});

describe('report scanner steering line (FR-014, R5)', () => {
  const ROOT = 'fedcba9876543210'.repeat(4);
  const BUNDLE = '/var/lib/tessera/evidence/run-2';
  const attempts = [
    { kind: 'control-file', path: '.gitleaksignore', detail: 'gitleaks ignore list, removed', neutralizedBy: 'removed-from-working-copy' },
    { kind: 'project-config', path: '.npmrc', detail: 'npm configuration, kept', neutralizedBy: 'isolated-working-dir' },
    { kind: 'inline-marker', path: 'src/a.js', detail: 'inline marker "gitleaks:allow" x2', neutralizedBy: 'framework-flag' },
    { kind: 'inline-marker', path: 'src/b.js', detail: 'inline marker "nosemgrep" x3', neutralizedBy: 'framework-flag' },
  ];

  it('states the neutralized control files and inline markers in the evidence block', async () => {
    const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, evidence: { bundlePath: BUNDLE, rootHash: ROOT }, overrideAttempts: attempts });
    const lines = report.split('\n');
    const at = lines.indexOf('Scanner steering files neutralized: 2 control files, 5 inline markers');
    expect(at).toBeGreaterThan(lines.indexOf(`Evidence root hash: ${ROOT}`));
    expect(at).toBeLessThan(lines.findIndex((l) => l.startsWith('# Audit Report')));
    expect(report).not.toContain('.gitleaksignore');
  });

  it('omits the line when nothing was neutralized or the attempts are malformed', async () => {
    for (const overrideAttempts of [[], undefined, [{ kind: 'bogus' }], 'x']) {
      const report = await render({ outcome: 'complete', notPerformed: [], scanners: ALL_COMPLETED, evidence: { bundlePath: BUNDLE, rootHash: ROOT }, overrideAttempts });
      expect(report).not.toContain('Scanner steering files');
    }
  });
});
