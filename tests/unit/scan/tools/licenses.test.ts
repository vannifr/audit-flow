import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm, chmod, symlink, truncate } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runLicenseScan } from '../../../../src/scan/tools/licenses';
import type { ScanContext } from '../../../../src/scan/scan-types';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore } from '../../../../src/evidence/types';
import type { ProcessRequest, ProcessRunner } from '../../../../src/scan/tool-types';

const childProcessCalls: string[] = [];
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const trap = (name: string) => (...args: unknown[]) => {
    childProcessCalls.push(`${name}:${JSON.stringify(args[0])}`);
    throw new Error(`child_process.${name} is forbidden in the license scan`);
  };
  return {
    ...actual,
    exec: trap('exec'),
    execSync: trap('execSync'),
    execFile: trap('execFile'),
    execFileSync: trap('execFileSync'),
    spawn: trap('spawn'),
    spawnSync: trap('spawnSync'),
    fork: trap('fork'),
  };
});

const T = new Date('2026-01-01T00:00:00.000Z');

function sha(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class FakeStore implements EvidenceStore {
  readonly bundleDir = '/tmp/bundle';
  records: EvidenceRecord[] = [];
  artifacts: { recordId: string; suffix: string; bytes: Buffer }[] = [];

  async writeArtifact(
    recordId: string,
    suffix: string,
    bytes: Buffer,
    meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>,
  ): Promise<ArtifactRef> {
    this.artifacts.push({ recordId, suffix, bytes });
    return { ...meta, path: `records/${recordId}.${suffix}`, bytes: bytes.length, sha256: sha(bytes) };
  }

  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    this.records.push(record);
    return { recordId: record.id, recordSha256: sha(JSON.stringify(record)) };
  }
}

let root: string;
let repo: string;
let store: FakeStore;
let runnerRequests: ProcessRequest[];

const runner: ProcessRunner = async (req) => {
  runnerRequests.push(req);
  throw new Error('no process may run');
};

function ctx(): ScanContext {
  return {
    run: { runId: 'run-lic', workDir: root, repoDir: repo },
    source: { repoDir: repo, revision: 'c'.repeat(40) },
    repoUrl: 'https://example.invalid/app.git',
    attempt: 1,
    deps: { runner, store, clock: () => T, frameworkVersion: '0.0.0-test' },
    workerEnv: {},
    configDir: path.join(root, 'config'),
  };
}

interface Pkg {
  version?: string;
  license?: unknown;
  link?: boolean;
  name?: string;
}

function lock(packages: Record<string, Pkg>, version = 3): string {
  return JSON.stringify({
    name: 'app',
    version: '1.0.0',
    lockfileVersion: version,
    requires: true,
    packages: { '': { name: 'app', version: '1.0.0', license: 'GPL-3.0' }, ...packages },
  });
}

async function writeRepo(files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(repo, rel);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, content);
  }
}

async function scanWith(packages: Record<string, Pkg>, version = 3) {
  await writeRepo({ 'package.json': '{"name":"app"}', 'package-lock.json': lock(packages, version) });
  return runLicenseScan(ctx());
}

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tessera-lic-test-'));
  repo = path.join(root, 'repo');
  await mkdir(repo);
  store = new FakeStore();
  runnerRequests = [];
  childProcessCalls.length = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  expect(runnerRequests).toHaveLength(0);
  expect(childProcessCalls).toEqual([]);
});

describe('runLicenseScan verdicts', () => {
  it('reports nothing for MIT-only dependencies and completes', async () => {
    const res = await scanWith({
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/b': { version: '2.0.0', license: 'ISC' },
      'node_modules/@scope/c': { version: '3.0.0', license: 'Apache-2.0' },
    });
    expect(res.scanner).toBe('license-check');
    expect(res.findings).toEqual([]);
    expect(res.status).toEqual({
      scanner: 'license-check',
      required: true,
      status: 'completed',
      heuristic: false,
      toolVersion: null,
      findingCount: 0,
      evidenceRecordIds: ['license-check.a1'],
    });
  });

  it('flags GPL-3.0 as a P1 compliance finding with evidence', async () => {
    const res = await scanWith({
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/gpl-lib': { version: '4.5.6', license: 'GPL-3.0' },
    });
    expect(res.findings).toHaveLength(1);
    const f = res.findings[0];
    expect(f.id).toBe('LIC-1');
    expect(f.severity).toBe('P1');
    expect(f.category).toBe('compliance');
    expect(f.scanner).toBe('license-check');
    expect(f.title).toContain('gpl-lib');
    expect(f.evidence).toHaveLength(1);
    expect(f.evidence[0].file).toBe('package-lock.json');
    expect(f.evidence[0].content).toBe('gpl-lib@4.5.6: GPL-3.0');
    expect(f.evidence[0].tool).toBe('license-check');
    expect(f.remediation.effort).toBe('hours');
    expect(f.remediation.priority).toBe('short-term');
    expect(f.evidenceRef).toEqual(res.evidence);
    expect(res.status.status).toBe('completed');
    expect(res.status.findingCount).toBe(1);
    expect(store.records[0].findingIds).toEqual(['LIC-1']);
  });

  it.each([
    ['AGPL-3.0', true],
    ['AGPL-3.0-or-later', true],
    ['GPL-2.0-only', true],
    ['GPL-2.0+', true],
    ['GPL', true],
    ['GPLv3', true],
    ['GPL v2', true],
    ['(GPL-2.0 OR AGPL-3.0)', true],
    ['GPL-2.0 WITH Classpath-exception-2.0', true],
    ['{"type":"GPL-3.0"}', true],
    ['GPL-3.0 OR MIT', false],
    ['GPL v3 or MIT license', false],
    ['GPL-3.0 licensed, see COPYING', true],
    ['(MIT OR GPL-3.0)', false],
    ['(GPL-3.0 or MIT)', false],
    ['GPL-2.0 AND MIT', true],
    ['(MIT AND (GPL-3.0 OR BSD-3-Clause))', false],
    ['(MIT AND (GPL-3.0 OR AGPL-3.0))', true],
    ['LGPL-3.0', false],
    ['LGPL-2.1-or-later', false],
    ['LGPL', false],
    ['(LGPL-2.1 OR GPL-3.0)', false],
    ['MIT', false],
    ['BSD-3-Clause', false],
    ['UNLICENSED', false],
    ['SEE LICENSE IN LICENSE.md', false],
  ])('license %s -> violation %s', async (license, violation) => {
    const value = license.startsWith('{') ? JSON.parse(license) : license;
    const res = await scanWith({ 'node_modules/x': { version: '1.0.0', license: value } });
    expect(res.findings.filter((f) => f.severity === 'P1')).toHaveLength(violation ? 1 : 0);
    expect(res.status.status).toBe('completed');
  });

  it('treats a legacy license array as alternatives', async () => {
    const res = await scanWith({
      'node_modules/x': { version: '1.0.0', license: [{ type: 'GPL-2.0' }, { type: 'MIT' }] },
      'node_modules/y': { version: '1.0.0', license: ['GPL-2.0', 'AGPL-3.0'] },
    });
    expect(res.findings.map((f) => f.evidence[0].content)).toEqual(['y@1.0.0: GPL-2.0 OR AGPL-3.0']);
  });

  it('numbers multiple violations, uses the nested package name and skips the root and links', async () => {
    const res = await scanWith({
      'node_modules/a': { version: '1.0.0', license: 'GPL-3.0' },
      'node_modules/a/node_modules/@s/b': { version: '2.0.0', license: 'AGPL-3.0' },
      'node_modules/linked': { link: true },
      'packages/ws': { version: '0.1.0', license: 'MIT' },
    });
    expect(res.findings.map((f) => f.id)).toEqual(['LIC-1', 'LIC-2']);
    expect(res.findings[1].evidence[0].content).toBe('@s/b@2.0.0: AGPL-3.0');
    expect(store.records[0].action.inputs.packages).toBe('3');
  });
});

describe('runLicenseScan missing license data', () => {
  it('adds one P3 summary for packages without a license and states the count', async () => {
    const pkgs: Record<string, Pkg> = { 'node_modules/ok': { version: '1.0.0', license: 'MIT' } };
    for (let i = 0; i < 25; i++) pkgs[`node_modules/nolic-${String(i).padStart(2, '0')}`] = { version: '1.0.0' };
    pkgs['node_modules/empty'] = { version: '1.0.0', license: '' };
    pkgs['node_modules/weird'] = { version: '1.0.0', license: 42 };
    const res = await scanWith(pkgs);
    expect(res.findings).toHaveLength(1);
    const f = res.findings[0];
    expect(f.id).toBe('LIC-1');
    expect(f.severity).toBe('P3');
    expect(f.category).toBe('compliance');
    expect(f.description).toContain('27');
    expect(f.evidence[0].content).toContain('nolic-00');
    expect(f.evidence[0].content).toContain('nolic-17');
    expect(f.evidence[0].content).not.toContain('nolic-24');
    expect(f.evidenceRef).toEqual(res.evidence);
    expect(res.status.status).toBe('completed');
    expect(res.status.causeDetail).toContain('27');
    expect(res.status.findingCount).toBe(1);
  });

  it('puts the P3 summary after the P1 violations', async () => {
    const res = await scanWith({
      'node_modules/g': { version: '1.0.0', license: 'GPL-3.0' },
      'node_modules/n': { version: '1.0.0' },
    });
    expect(res.findings.map((f) => [f.id, f.severity])).toEqual([
      ['LIC-1', 'P1'],
      ['LIC-2', 'P3'],
    ]);
  });
});

describe('runLicenseScan applicability and lockfile handling', () => {
  it('skips as not-applicable without package.json', async () => {
    await writeRepo({ 'README.md': 'hi' });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('skipped');
    expect(res.status.cause).toBe('not-applicable');
    expect(res.status.required).toBe(false);
    expect(res.findings).toEqual([]);
    expect(store.records).toHaveLength(1);
    expect(store.records[0].status).toBe('skipped');
    expect(res.status.evidenceRecordIds).toEqual([store.records[0].id]);
  });

  it('skips with no-lockfile when package.json has no lockfile', async () => {
    await writeRepo({ 'package.json': '{}' });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('skipped');
    expect(res.status.cause).toBe('no-lockfile');
  });

  it.each(['yarn.lock', 'pnpm-lock.yaml'])('skips with unsupported-lockfile for %s only', async (name) => {
    await writeRepo({ 'package.json': '{}', [name]: 'lockfile v1\n' });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('skipped');
    expect(res.status.cause).toBe('unsupported-lockfile');
    expect(res.status.causeDetail).toContain(name);
  });

  it('reports lockfile v1 as partial with unsupported-lockfile', async () => {
    await writeRepo({
      'package.json': '{}',
      'package-lock.json': JSON.stringify({
        lockfileVersion: 1,
        dependencies: { a: { version: '1.0.0' }, b: { version: '1.0.0' } },
      }),
    });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('unsupported-lockfile');
    expect(res.status.causeDetail).toMatch(/lockfileVersion 1/);
    expect(res.status.causeDetail).toMatch(/license/i);
    expect(res.findings).toEqual([]);
  });

  it('fails on an unknown lockfile version', async () => {
    await writeRepo({ 'package.json': '{}', 'package-lock.json': '{"lockfileVersion":7,"packages":{}}' });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('unsupported-lockfile');
  });

  it('fails with parse-error on broken JSON and records the lockfile hash', async () => {
    const broken = '{"lockfileVersion":3,"packages":{';
    await writeRepo({ 'package.json': '{}', 'package-lock.json': broken });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('parse-error');
    expect(res.findings).toEqual([]);
    expect(store.records[0].action.inputs.lockfileSha256).toBe(sha(broken));
    expect(store.records[0].action.inputs.lockfileName).toBe('package-lock.json');
  });

  it.each([
    ['null', 'null'],
    ['array', '[]'],
    ['packages missing', '{"lockfileVersion":3}'],
    ['packages array', '{"lockfileVersion":2,"packages":[]}'],
  ])('fails with parse-error on a %s document', async (_name, body) => {
    await writeRepo({ 'package.json': '{}', 'package-lock.json': body });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('parse-error');
  });

  it('prefers npm-shrinkwrap.json and names it in the evidence', async () => {
    await writeRepo({
      'package.json': '{}',
      'package-lock.json': lock({ 'node_modules/x': { version: '1.0.0', license: 'MIT' } }),
      'npm-shrinkwrap.json': lock({ 'node_modules/x': { version: '1.0.0', license: 'AGPL-3.0' } }),
    });
    const res = await runLicenseScan(ctx());
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].evidence[0].file).toBe('npm-shrinkwrap.json');
    expect(store.records[0].action.inputs.lockfileName).toBe('npm-shrinkwrap.json');
  });

  it('refuses a lockfile larger than 50 MB without reading it', async () => {
    await writeRepo({ 'package.json': '{}', 'package-lock.json': '' });
    await truncate(path.join(repo, 'package-lock.json'), 50 * 1024 * 1024 + 1);
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('tool-error');
    expect(res.status.causeDetail).toMatch(/50 MB/);
    expect(store.records[0].action.inputs.lockfileSha256).toBeUndefined();
  });

  it('accepts a lockfile of exactly 50 MB', async () => {
    const body = lock({ 'node_modules/x': { version: '1.0.0', license: 'GPL-3.0' } });
    await writeRepo({ 'package.json': '{}', 'package-lock.json': body.padEnd(50 * 1024 * 1024, ' ') });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('completed');
    expect(res.findings).toHaveLength(1);
  });

  it('refuses a symlinked lockfile', async () => {
    const outside = path.join(root, 'outside.json');
    await writeFile(outside, lock({ 'node_modules/x': { version: '1.0.0', license: 'MIT' } }));
    await writeRepo({ 'package.json': '{}' });
    await symlink(outside, path.join(repo, 'package-lock.json'));
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('tool-error');
    expect(res.status.causeDetail).toMatch(/symlink|regular file/i);
  });

  it('refuses a lockfile that is a directory', async () => {
    await writeRepo({ 'package.json': '{}' });
    await mkdir(path.join(repo, 'package-lock.json'));
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('failed');
    expect(res.status.cause).toBe('tool-error');
  });

  it('records inputs and a summary artifact without absolute paths', async () => {
    const body = lock({
      'node_modules/a': { version: '1.0.0', license: 'GPL-3.0' },
      'node_modules/b': { version: '1.0.0' },
    });
    await writeRepo({ 'package.json': '{}', 'package-lock.json': body });
    const res = await runLicenseScan(ctx());
    const rec = store.records[0];
    expect(rec.kind).toBe('in-process');
    expect(rec.scanner).toBe('license-check');
    expect(rec.action.inputs).toEqual({ lockfileSha256: sha(body), lockfileName: 'package-lock.json', packages: '2' });
    expect(rec.findingIds).toEqual(['LIC-1', 'LIC-2']);
    expect(store.artifacts).toHaveLength(1);
    const summary = JSON.parse(store.artifacts[0].bytes.toString('utf8'));
    expect(summary.packages).toBe(2);
    expect(summary.violations).toEqual([{ name: 'a', version: '1.0.0', license: 'GPL-3.0' }]);
    expect(summary.missingLicense.count).toBe(1);
    expect(res.evidence.recordId).toBe(rec.id);
    const all = JSON.stringify({ rec, summary, res });
    expect(all).not.toContain(root);
  });
});

describe('runLicenseScan hostile input', () => {
  it('does not pollute prototypes and rejects __proto__/constructor package names', async () => {
    const body =
      '{"lockfileVersion":3,"packages":{' +
      '"node_modules/__proto__":{"version":"1.0.0","license":"GPL-3.0","polluted":"yes"},' +
      '"node_modules/constructor":{"version":"1.0.0","license":"AGPL-3.0"},' +
      '"node_modules/x/node_modules/prototype":{"version":"1.0.0","license":"MIT"},' +
      '"__proto__":{"polluted":"yes"},' +
      '"node_modules/ok":{"version":"1.0.0","license":"MIT"}}}';
    await writeRepo({ 'package.json': '{}', 'package-lock.json': body });
    const res = await runLicenseScan(ctx());
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty('polluted');
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('parse-error');
    expect(res.status.causeDetail).toMatch(/4/);
    expect(res.findings).toEqual([]);
  });

  it('marks malformed package entries as partial', async () => {
    const body = '{"lockfileVersion":3,"packages":{"node_modules/a":null,"node_modules/b":"MIT","node_modules/c":{"version":"1.0.0","license":"MIT"}}}';
    await writeRepo({ 'package.json': '{}', 'package-lock.json': body });
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('parse-error');
    expect(res.status.causeDetail).toMatch(/2/);
  });

  it('never executes repo-local tools such as node_modules/.bin/license-checker', async () => {
    const marker = path.join(root, 'PWNED');
    const script = `#!/bin/sh\necho pwned > '${marker}'\n`;
    await writeRepo({
      'package.json': JSON.stringify({ name: 'evil', scripts: { preinstall: `sh -c "echo x > '${marker}'"` } }),
      'package-lock.json': lock({ 'node_modules/x': { version: '1.0.0', license: 'MIT' } }),
      'node_modules/.bin/license-checker': script,
      'node_modules/.bin/npx': script,
      'node_modules/.bin/npm': script,
      '.npmrc': `script-shell=${path.join(repo, 'node_modules/.bin/npx')}\n`,
    });
    await chmod(path.join(repo, 'node_modules/.bin/license-checker'), 0o755);
    await chmod(path.join(repo, 'node_modules/.bin/npx'), 0o755);
    await chmod(path.join(repo, 'node_modules/.bin/npm'), 0o755);
    const res = await runLicenseScan(ctx());
    expect(res.status.status).toBe('completed');
    expect(existsSync(marker)).toBe(false);
    expect(runnerRequests).toHaveLength(0);
    expect(childProcessCalls).toEqual([]);
  });

  it('caps evidence text and redacts secrets in license strings', async () => {
    const long = `GPL-3.0 AND token=ghp_${'a'.repeat(36)} ${'x'.repeat(1000)}`;
    const res = await scanWith({ 'node_modules/x': { version: '1.0.0', license: long } });
    expect(res.findings).toHaveLength(1);
    const text = JSON.stringify(res.findings[0]);
    expect(text).not.toContain(`ghp_${'a'.repeat(36)}`);
    expect(res.findings[0].evidence[0].content.length).toBeLessThanOrEqual(500);
    expect(res.findings[0].title.length).toBeLessThanOrEqual(300);
  });

  it('caps findings at 2000 and reports partial findings-truncated', async () => {
    const pkgs: Record<string, Pkg> = {};
    for (let i = 0; i < 2005; i++) pkgs[`node_modules/g${i}`] = { version: '1.0.0', license: 'GPL-3.0' };
    pkgs['node_modules/nolic'] = { version: '1.0.0' };
    const res = await scanWith(pkgs);
    expect(res.findings).toHaveLength(2000);
    expect(res.status.status).toBe('partial');
    expect(res.status.cause).toBe('findings-truncated');
    expect(res.status.findingCount).toBe(2000);
    expect(res.status.causeDetail).toMatch(/2006/);
    const summary = JSON.parse(store.artifacts[0].bytes.toString('utf8'));
    expect(summary.violations).toHaveLength(2005);
  });
});
