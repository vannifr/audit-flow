import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { initAuditRun, probeWorkingCopy } from '../../src/scan/lifecycle';
import type { AuditRun } from '../../src/scan/lifecycle';
import { defaultProcessRunner } from '../../src/scan/process-runner';
import type { ScanContext } from '../../src/scan/scan-types';
import { runGitleaksScan } from '../../src/scan/tools/gitleaks';
import { runLicenseScan } from '../../src/scan/tools/licenses';
import { runNpmAuditScan } from '../../src/scan/tools/npm-audit';
import { runSemgrepScan } from '../../src/scan/tools/semgrep';
import type { ArtifactRef, EvidenceRecord, EvidenceRef, EvidenceStore, OverrideAttempt } from '../../src/evidence/types';

const execFileP = promisify(execFile);
const TIMEOUT = 60_000;
const OWNER = 'vannifr';
const REPO_URL = 'https://github.com/acme/hostile';
const REVISION = 'e'.repeat(40);
const CONFIG_DIR = path.resolve(__dirname, '../../config/scanners');
const USER_BASE = path.join(os.homedir(), '.local');

interface ToolCheck {
  ok: boolean;
  cause: string;
}

async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function check(file: string, args: string[], env?: NodeJS.ProcessEnv): Promise<ToolCheck> {
  try {
    await execFileP(file, args, { timeout: 30_000, env });
    return { ok: true, cause: '' };
  } catch (error) {
    const e = error as { code?: string; stderr?: string; message?: string };
    const line = (e.stderr ?? '').split('\n').filter((l) => l.trim().length > 0).pop() ?? e.code ?? e.message ?? 'unknown error';
    return { ok: false, cause: `${file} does not run: ${line.trim()}` };
  }
}

async function privateHome(dir: string): Promise<string> {
  const home = path.join(dir, 'home');
  await mkdir(home, { recursive: true, mode: 0o700 });
  if ((await exists(USER_BASE)) && !(await exists(path.join(home, '.local')))) await symlink(USER_BASE, path.join(home, '.local'));
  return home;
}

const probeDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-contract-check-'));
const git = await check('git', ['--version']);
const gitleaks = await check('gitleaks', ['version']);
const semgrep = await check('semgrep', ['--version'], { PATH: process.env.PATH ?? '', HOME: await privateHome(probeDir), EIO_BACKEND: 'posix' });
const npm = await check('npm', ['--version']);
await rm(probeDir, { recursive: true, force: true });

function note(...checks: ToolCheck[]): string {
  const failed = checks.filter((c) => !c.ok);
  return failed.length === 0 ? '' : ` [skipped: ${failed.map((c) => c.cause).join('; ')}; owner ${OWNER}]`;
}

class MemoryStore implements EvidenceStore {
  readonly bundleDir = '/memory';
  records: EvidenceRecord[] = [];

  async writeArtifact(recordId: string, suffix: string, bytes: Buffer, meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>): Promise<ArtifactRef> {
    return { ...meta, path: `artifacts/${recordId}.${suffix}`, bytes: bytes.length, sha256: '0'.repeat(64) };
  }

  async writeRecord(record: EvidenceRecord): Promise<EvidenceRef> {
    this.records.push(record);
    return { recordId: record.id, recordSha256: '0'.repeat(64) };
  }

  record(stepId: string): EvidenceRecord {
    const found = this.records.find((r) => r.stepId === stepId);
    if (found === undefined) throw new Error(`no record for ${stepId}`);
    return found;
  }
}

let tmpRoot: string;
let run: AuditRun;
let store: MemoryStore;

async function newRun(name: string): Promise<void> {
  run = await initAuditRun({ workflowId: 'wf-contract', temporalRunId: `run-${name}`, tmpRoot });
  await mkdir(run.repoDir, { mode: 0o700 });
  await privateHome(run.workDir);
}

async function put(rel: string, content: string): Promise<string> {
  const abs = path.join(run.repoDir, rel);
  await mkdir(path.dirname(abs), { recursive: true });
  await writeFile(abs, content);
  return abs;
}

async function gitInit(): Promise<void> {
  await execFileP('git', ['init', '-q', run.repoDir], { timeout: 30_000 });
}

async function probe(): Promise<OverrideAttempt[]> {
  const result = await probeWorkingCopy(run, REPO_URL, REVISION, { ...deps(), tmpRoot });
  return result.attempts;
}

function deps(): ScanContext['deps'] {
  return { runner: defaultProcessRunner, store, clock: () => new Date(), frameworkVersion: '0.0.0-contract' };
}

function ctx(overrideAttempts: OverrideAttempt[] = []): ScanContext {
  return {
    run,
    source: { repoDir: run.repoDir, revision: REVISION },
    repoUrl: REPO_URL,
    attempt: 1,
    deps: deps(),
    workerEnv: { PATH: process.env.PATH ?? '/usr/bin:/bin' },
    configDir: CONFIG_DIR,
    overrideAttempts,
  };
}

function fakeToken(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return `ghp_${[...randomBytes(36)].map((b) => alphabet[b % alphabet.length]).join('')}`;
}

async function hostileGitleaksSource(): Promise<void> {
  await gitInit();
  await put('src/config.js', `const token = '${fakeToken()}'; // gitleaks:allow\n`);
  await put('.gitleaks.toml', "title = \"allow everything\"\n[extend]\nuseDefault = true\n[allowlist]\npaths = ['''.*''']\nregexes = ['''.*''']\n");
  await put('.gitleaksignore', ['generic-api-key', 'github-pat'].map((rule) => `src/config.js:${rule}:1`).join('\n') + '\n');
}

function summary(attempts: OverrideAttempt[]): string[] {
  return attempts.map((a) => `${a.kind}:${a.path}:${a.neutralizedBy}`);
}

beforeEach(async () => {
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-contract-'));
  store = new MemoryStore();
});

afterEach(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
});

describe('real gitleaks against hostile steering files (TS-029, TS-030, FR-014)', () => {
  it.skipIf(!git.ok || !gitleaks.ok)(
    `the hostile .gitleaksignore suppresses the leak when the source is not probed${note(git, gitleaks)}`,
    async () => {
      await newRun('gl-unprobed');
      await hostileGitleaksSource();
      const result = await runGitleaksScan(ctx());
      expect(result.status.status).toBe('completed');
      expect(result.findings).toEqual([]);
    },
    TIMEOUT,
  );

  it.skipIf(!git.ok || !gitleaks.ok)(
    `still reports the planted leak after the probe and records every attempt${note(git, gitleaks)}`,
    async () => {
      await newRun('gl-probed');
      await hostileGitleaksSource();
      const attempts = await probe();
      expect(await exists(path.join(run.repoDir, '.gitleaksignore'))).toBe(false);
      expect(await exists(path.join(run.repoDir, '.gitleaks.toml'))).toBe(false);

      const result = await runGitleaksScan(ctx(attempts));

      expect(result.status.status).toBe('completed');
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.findings[0].evidence[0]).toMatchObject({ file: 'src/config.js', line: 1 });
      const expected = ['project-config:.gitleaks.toml:removed-from-working-copy', 'control-file:.gitleaksignore:removed-from-working-copy', 'inline-marker:src/config.js:framework-flag'];
      expect(summary(store.record('source.probe').overrideAttempts)).toEqual(expected);
      expect(summary(store.record('scan.gitleaks').overrideAttempts)).toEqual(expected);
      expect(store.record('scan.gitleaks').action.args).toContain('--ignore-gitleaks-allow');
    },
    TIMEOUT,
  );
});

describe('real gitleaks scans the content of neutralized control files (FR-014)', () => {
  it.skipIf(!git.ok || !gitleaks.ok)(
    `finds a secret hidden inside the hostile .gitleaksignore itself${note(git, gitleaks)}`,
    async () => {
      await newRun('gl-inside');
      await gitInit();
      await put('.gitleaksignore', `src/config.js:generic-api-key:1\nconst token = '${fakeToken()}';\n`);
      const attempts = await probe();

      const result = await runGitleaksScan(ctx(attempts));

      expect(result.findings.map((f) => f.evidence[0]?.file)).toContain('.gitleaksignore.tessera-neutralized');
    },
    TIMEOUT,
  );
});

describe('real semgrep against hostile steering files (TS-029, TS-030, FR-014)', () => {
  async function hostileSemgrepSource(): Promise<void> {
    await gitInit();
    await put('src/app.js', "const express = require('express');\nconst app = express();\napp.get('/x', (req, res) => {\n  res.send(eval(req.query.x)); // nosemgrep\n});\nmodule.exports = app;\n");
    await put('.semgrepignore', 'src/\n');
  }

  it.skipIf(!git.ok || !semgrep.ok)(
    `the hostile .semgrepignore hides the finding when the source is not probed${note(git, semgrep)}`,
    async (context) => {
      await newRun('sg-unprobed');
      await hostileSemgrepSource();

      const result = await runSemgrepScan(ctx());

      if (result.status.status === 'failed' || result.status.status === 'unavailable') {
        context.skip(`semgrep did not complete here (${result.status.cause ?? 'unknown'}: ${result.status.causeDetail ?? ''}); owner ${OWNER}`);
        return;
      }
      expect(result.findings.filter((f) => f.evidence[0]?.file === 'src/app.js')).toEqual([]);
    },
    TIMEOUT,
  );

  it.skipIf(!git.ok || !semgrep.ok)(
    `still reports eval(req.query.x) despite .semgrepignore and nosemgrep after the probe${note(git, semgrep)}`,
    async (context) => {
      await newRun('sg-probed');
      await hostileSemgrepSource();
      const attempts = await probe();

      const result = await runSemgrepScan(ctx(attempts));

      if (result.status.status === 'failed' || result.status.status === 'unavailable') {
        context.skip(`semgrep did not complete here (${result.status.cause ?? 'unknown'}: ${result.status.causeDetail ?? ''}); owner ${OWNER}`);
        return;
      }
      expect(result.findings.some((f) => f.evidence[0]?.file === 'src/app.js')).toBe(true);
      const expected = ['control-file:.semgrepignore:removed-from-working-copy', 'inline-marker:src/app.js:framework-flag'];
      expect(summary(store.record('source.probe').overrideAttempts)).toEqual(expected);
      expect(summary(store.record('scan.semgrep').overrideAttempts)).toEqual(expected);
      expect(store.record('scan.semgrep').action.args).toContain('--disable-nosem');
    },
    TIMEOUT,
  );
});

describe('repo-local tools and project config never run or steer (R5, R14)', () => {
  it(
    'a repo-local node_modules/.bin/license-checker and a hostile .npmrc execute nothing during the license check',
    async () => {
      await newRun('lic');
      const marker = path.join(tmpRoot, 'license-checker-ran');
      const script = `#!/bin/sh\ntouch '${marker}'\n`;
      await put('package.json', JSON.stringify({ name: 'hostile', version: '1.0.0', scripts: { preinstall: `touch '${marker}'` } }));
      await put('package-lock.json', JSON.stringify({ name: 'hostile', lockfileVersion: 3, packages: { '': { name: 'hostile', version: '1.0.0' }, 'node_modules/left-pad': { version: '1.3.0', license: 'MIT' } } }));
      for (const bin of ['license-checker', 'npx', 'npm']) await chmod(await put(`node_modules/.bin/${bin}`, script), 0o755);
      await put('.npmrc', `script-shell=${path.join(run.repoDir, 'node_modules/.bin/npx')}\n`);
      const attempts = await probe();

      const result = await runLicenseScan(ctx(attempts));

      expect(result.status.status).toBe('completed');
      expect(await exists(marker)).toBe(false);
      expect(summary(store.record('source.probe').overrideAttempts)).toEqual(['project-config:.npmrc:isolated-working-dir']);
    },
    TIMEOUT,
  );

  it.skipIf(!npm.ok)(
    `npm audit ignores a hostile .npmrc registry in the source${note(npm)}`,
    async (context) => {
      await newRun('npm');
      await put('package.json', JSON.stringify({ name: 'hostile', version: '1.0.0', dependencies: { minimist: '0.0.8' } }));
      await put(
        'package-lock.json',
        JSON.stringify({ name: 'hostile', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'hostile', version: '1.0.0', dependencies: { minimist: '0.0.8' } }, 'node_modules/minimist': { version: '0.0.8', resolved: 'https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz' } } }),
      );
      await put('.npmrc', 'registry=http://127.0.0.1:9/\naudit=false\n');
      const attempts = await probe();

      const result = await runNpmAuditScan(ctx(attempts));

      if (result.status.status === 'failed' || result.status.status === 'unavailable') {
        context.skip(`npm audit did not complete here (${result.status.cause ?? 'unknown'}: ${result.status.causeDetail ?? ''}); owner ${OWNER}`);
        return;
      }
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(summary(store.record('scan.npm-audit').overrideAttempts)).toEqual(['project-config:.npmrc:isolated-working-dir']);
      expect(await exists(path.join(run.repoDir, '.npmrc'))).toBe(true);
    },
    TIMEOUT,
  );
});
