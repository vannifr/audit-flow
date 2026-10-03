import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { AuditRun, FetchedSource } from '../../src/scan/lifecycle';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from '../../src/scan/tool-types';
import type { AuditInput, AuditResult } from '../../src/types';
import type { EvidenceRecord } from '../../src/evidence/types';

type Fn = (...args: unknown[]) => unknown;

const harness = vi.hoisted(() => ({ activities: {} as Record<string, Fn>, logLines: [] as string[] }));

vi.mock('../../src/logger', async () => {
  const pino = (await import('pino')).default;
  const { Writable } = await import('node:stream');
  const sink = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      harness.logLines.push(chunk.toString('utf8'));
      callback();
    },
  });
  return { default: pino({ level: 'trace' }, sink) };
});

vi.mock('@temporalio/workflow', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@temporalio/workflow')>();
  return {
    ...actual,
    proxyActivities: () =>
      new Proxy(
        {},
        {
          get: (_target, name: string) =>
            (...args: unknown[]) => {
              const impl = harness.activities[name];
              if (impl === undefined) throw new Error(`unexpected activity ${name}`);
              return impl(...args);
            },
        },
      ),
    workflowInfo: () => ({ workflowId: 'wf-sweep', runId: 'run-sweep' }),
    setHandler: () => undefined,
    condition: async (fn: () => boolean) => fn(),
  };
});

vi.mock('@temporalio/activity', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@temporalio/activity')>();
  return {
    ...actual,
    Context: { current: () => ({ info: { attempt: 1, workflowExecution: { workflowId: 'wf-sweep', runId: 'run-sweep' } } }) },
  };
});

const { applicationAudit } = await import('../../src/workflows/index');
const activities = await import('../../src/activities/index');
const { createScanActivities } = await import('../../src/scan/activities');
const lifecycle = await import('../../src/scan/lifecycle');
const { createEvidenceStore } = await import('../../src/evidence/store');
const { verifyEvidenceBundle } = await import('../../src/evidence/verify');

const T0 = new Date('2026-01-01T00:00:00.000Z');
const REPO_URL = 'https://github.com/acme/vulnerable-app';
const REVISION = 'd'.repeat(40);
const RUN_ID = 'run-sweep';
const DEMO_SRC = path.resolve(__dirname, '../../demo/vulnerable-app/src');

interface Planted {
  name: string;
  rule: string;
  file: string;
  line: number;
  value: string;
}

let planted: Planted[];
let tmpRoot: string;
let evidenceRoot: string;
let outDir: string;
let savedEnv: Record<string, string | undefined>;
let gitleaksStdout = '';

function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return { exitCode: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutTruncated: false, timedOut: false, startedAt: T0, endedAt: T0, ...partial };
}

function extract(source: string, pattern: RegExp, label: string): string {
  const match = pattern.exec(source);
  if (match === null) throw new Error(`demo secret ${label} not found`);
  return match[1];
}

function lineOf(source: string, value: string): number {
  return source.split('\n').findIndex((l) => l.includes(value)) + 1;
}

beforeAll(async () => {
  const config = await readFile(path.join(DEMO_SRC, 'config.js'), 'utf8');
  const auth = await readFile(path.join(DEMO_SRC, 'auth.js'), 'utf8');
  const specs: [string, string, string, string, RegExp][] = [
    ['aws access key id', 'aws-access-token', 'src/config.js', config, /awsAccessKeyId:\s*'([^']+)'/],
    ['aws secret access key', 'aws-secret-access-key', 'src/config.js', config, /awsSecretAccessKey:\s*'([^']+)'/],
    ['internal api key', 'generic-api-key', 'src/config.js', config, /internalApiKey:\s*'([^']+)'/],
    ['admin password', 'hardcoded-password', 'src/auth.js', auth, /adminPassword\s*=\s*'([^']+)'/],
  ];
  planted = specs.map(([name, rule, file, text, pattern]) => {
    const value = extract(text, pattern, name);
    return { name, rule, file, line: lineOf(text, value), value };
  });
  expect(planted.map((p) => p.value.length)).toEqual([20, 40, 40, 9]);
});

function gitleaksReport(): string {
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

async function cloneInto(repoDir: string): Promise<void> {
  await mkdir(path.join(repoDir, 'src'), { recursive: true, mode: 0o700 });
  await writeFile(path.join(repoDir, 'package.json'), JSON.stringify({ name: 'vulnerable-app', version: '1.0.0', dependencies: { express: '4.17.1' } }));
  await writeFile(
    path.join(repoDir, 'package-lock.json'),
    JSON.stringify({ name: 'vulnerable-app', lockfileVersion: 3, packages: { '': { name: 'vulnerable-app', version: '1.0.0' }, 'node_modules/express': { version: '4.17.1', license: 'MIT' } } }),
  );
  for (const name of ['config.js', 'auth.js']) {
    const text = await readFile(path.join(DEMO_SRC, name), 'utf8');
    await writeFile(path.join(repoDir, 'src', name), name === 'config.js' ? text.replace(/\n/, ' // gitleaks:allow\n') : text);
  }
  await writeFile(path.join(repoDir, '.gitleaksignore'), planted.map((p) => `${p.file}:${p.rule}:${p.line}`).join('\n'));
  await writeFile(path.join(repoDir, '.gitleaks.toml'), "[allowlist]\nregexes = ['''.*''']\n");
}

function runner(): ProcessRunner {
  return async (req: ProcessRequest) => {
    if (req.args.length === 1 && (req.args[0] === 'version' || req.args[0] === '--version')) return outcome({ stdout: Buffer.from('1.2.3\n') });
    if (req.file === 'git' && req.args.includes('clone')) {
      await cloneInto(req.args[req.args.length - 1]);
      return outcome();
    }
    if (req.file === 'git' && req.args.includes('rev-parse')) return outcome({ stdout: Buffer.from(`${REVISION}\n`) });
    if (req.file === 'gitleaks') {
      gitleaksStdout = gitleaksReport();
      return outcome({ exitCode: 42, stdout: Buffer.from(gitleaksStdout), stderr: Buffer.from(`WRN leaks found: ${planted.length} ${planted[0].value}\n`) });
    }
    if (req.file === 'semgrep') return outcome({ stdout: Buffer.from(JSON.stringify({ version: '1.178.0', results: [], errors: [], paths: { scanned: ['src/config.js'] } })) });
    if (req.file === 'npm') return outcome({ stdout: Buffer.from(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 }, dependencies: { total: 1 } } })) });
    throw new Error(`unexpected tool ${req.file}`);
  };
}

function wire(): void {
  const run = runner();
  const scans = createScanActivities({
    runner: run,
    clock: () => T0,
    evidenceRoot,
    tmpRoot,
    frameworkVersion: '0.0.0-sweep',
    workerEnv: { PATH: '/usr/bin' },
    configDir: '/opt/tessera/config/scanners',
  });
  harness.activities = {
    initAuditRun: activities.initAuditRun as Fn,
    fetchSource: (async (auditRun: AuditRun, repoUrl: string): Promise<FetchedSource> =>
      lifecycle.fetchSource(auditRun, repoUrl, { runner: run, store: createEvidenceStore(evidenceRoot, RUN_ID), clock: () => T0, frameworkVersion: '0.0.0-sweep', tmpRoot })) as Fn,
    detectTechStack: activities.detectTechStack as Fn,
    generateScopeDocument: activities.generateScopeDocument as Fn,
    runGitleaks: scans.runGitleaks as Fn,
    runSemgrep: scans.runSemgrep as Fn,
    runNpmAudit: scans.runNpmAudit as Fn,
    runLicenseCheck: scans.runLicenseCheck as Fn,
    reviewCriticalPaths: activities.reviewCriticalPaths as Fn,
    mapToCompliance: activities.mapToCompliance as Fn,
    crossValidate: activities.crossValidate as Fn,
    generateReport: activities.generateReport as Fn,
    cleanupRun: activities.cleanupRun as Fn,
    sealEvidence: activities.sealEvidence as Fn,
    signEvidence: activities.signEvidence as Fn,
  };
}

async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await filesUnder(abs)));
    else if (entry.isFile()) out.push(abs);
  }
  return out.sort();
}

function encodings(value: string): string[] {
  const b64 = Buffer.from(value, 'utf8').toString('base64');
  const percent = encodeURIComponent(value);
  return [...new Set([value, b64, b64.replace(/=+$/, ''), b64.replace(/\+/g, '-').replace(/\//g, '_'), percent, percent.toLowerCase(), JSON.stringify(value).slice(1, -1)])];
}

beforeEach(async () => {
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-sweep-'));
  evidenceRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-sweep-ev-'));
  outDir = await mkdtemp(path.join(os.tmpdir(), 'tessera-sweep-out-'));
  savedEnv = { TMPDIR: process.env.TMPDIR, TESSERA_EVIDENCE_ROOT: process.env.TESSERA_EVIDENCE_ROOT, TESSERA_SIGNING_KEY: process.env.TESSERA_SIGNING_KEY, TESSERA_REQUIRE_SIGNATURE: process.env.TESSERA_REQUIRE_SIGNATURE };
  process.env.TMPDIR = tmpRoot;
  process.env.TESSERA_EVIDENCE_ROOT = evidenceRoot;
  process.env.TESSERA_SIGNING_KEY = path.join(tmpRoot, 'no-key', 'ed25519.pem');
  delete process.env.TESSERA_REQUIRE_SIGNATURE;
  harness.logLines.length = 0;
  gitleaksStdout = '';
  wire();
});

afterEach(async () => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await chmod(path.join(evidenceRoot, RUN_ID), 0o700).catch(() => undefined);
  for (const dir of [tmpRoot, evidenceRoot, outDir]) await rm(dir, { recursive: true, force: true });
});

describe('end-to-end secret sweep (TS-027, TS-028, TS-029, SC-005, FR-012, FR-014)', () => {
  it('keeps every planted secret out of evidence, report, workflow result and logs while type and location stay visible', async () => {
    const input: AuditInput = { repoUrl: REPO_URL, skipApproval: true, outputDir: outDir };
    const result: AuditResult = await applicationAudit(input);

    expect(gitleaksStdout).toContain(planted[1].value);
    const bundle = path.join(evidenceRoot, RUN_ID);
    expect(result.evidence?.bundlePath).toBe(bundle);
    expect((await verifyEvidenceBundle(bundle, { expectRootHash: result.evidence?.rootHash })).ok).toBe(true);

    const bundleFiles = await filesUnder(bundle);
    const reportFiles = await filesUnder(outDir);
    expect(bundleFiles.some((f) => f.endsWith('scan.gitleaks.a1.json'))).toBe(true);
    expect(bundleFiles.some((f) => f.includes(`${path.sep}artifacts${path.sep}scan.gitleaks.a1`))).toBe(true);
    expect(reportFiles).toContain(path.join(outDir, 'audit-report.md'));
    expect(harness.logLines.length).toBeGreaterThan(0);

    const haystacks: [string, string][] = [];
    for (const f of [...bundleFiles, ...reportFiles]) haystacks.push([f, await readFile(f, 'utf8')]);
    haystacks.push(['workflow result', JSON.stringify(result)]);
    haystacks.push(['log', harness.logLines.join('')]);
    for (const p of planted) {
      for (const form of encodings(p.value)) {
        for (const [where, text] of haystacks) {
          expect(text.includes(form), `${p.name} (${form === p.value ? 'raw' : 'encoded'}) found in ${where}`).toBe(false);
        }
      }
    }

    const leaks = result.findings.filter((f) => f.id.startsWith('LEAK-'));
    expect(leaks).toHaveLength(planted.length);
    for (const p of planted) {
      const f = leaks.find((l) => l.title.includes(p.rule));
      expect(f, p.rule).toBeDefined();
      expect(f?.evidence[0]).toMatchObject({ file: p.file, line: p.line });
    }
    const report = await readFile(path.join(outDir, 'audit-report.md'), 'utf8');
    for (const p of planted) expect(report).toContain(p.rule);
    const leakEvidence = await readFile(path.join(outDir, 'evidence', `${leaks[0].id}.json`), 'utf8');
    expect(JSON.parse(leakEvidence)).toMatchObject({ file: expect.stringMatching(/^src\//), line: expect.any(Number) });

    const records = await Promise.all(bundleFiles.filter((f) => f.includes(`${path.sep}records${path.sep}`)).map(async (f) => JSON.parse(await readFile(f, 'utf8')) as EvidenceRecord));
    const probe = records.find((r) => r.stepId === 'source.probe');
    expect(probe?.overrideAttempts.map((a) => a.path)).toEqual(['.gitleaks.toml', '.gitleaksignore', 'src/config.js']);
    const gitleaksRecord = records.find((r) => r.stepId === 'scan.gitleaks');
    expect(gitleaksRecord?.overrideAttempts.map((a) => a.path)).toEqual(['.gitleaks.toml', '.gitleaksignore', 'src/config.js']);
    expect(report).toContain('Scanner steering files neutralized: 2 control files, 1 inline markers');
  });
});
