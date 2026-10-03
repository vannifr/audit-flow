import assert from 'node:assert/strict';
import Module from 'node:module';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { RetryState } from '@temporalio/common';
import type { AuditRun, FetchedSource } from '../../../../../src/scan/lifecycle';
import type { ScannerId, ScannerStatusEntry } from '../../../../../src/scan/status';
import type { ProcessOutcome, ProcessRequest, ProcessRunner, ToolPolicy, ToolRunResult } from '../../../../../src/scan/tool-types';
import type { AuditInput, AuditResult } from '../../../../../src/types';

type Fn = (...args: unknown[]) => unknown;
type ToolFile = 'gitleaks' | 'semgrep' | 'npm' | 'git';
type RunnerBehaviour = (req: ProcessRequest) => ProcessOutcome | Promise<ProcessOutcome>;

export const T0 = new Date('2026-01-01T00:00:00.000Z');
export const REPO_URL = 'https://github.com/acme/app';
export const REVISION = 'a'.repeat(40);
export const RUN_ID = 'run-bdd-0001';
export const INPUT: AuditInput = { repoUrl: REPO_URL, skipApproval: true };
export const FIXTURES = path.resolve(__dirname, '../../../../../tests/fixtures/tools');
export const SHA256_EMPTY = createHash('sha256').update('').digest('hex');

export const SCANNER_BY_LABEL: Record<string, ScannerId> = {
  'secret scanner': 'gitleaks',
  'static analysis': 'semgrep',
  'dependency audit': 'npm-audit',
  'license check': 'license-check',
};

const TOOL_BY_SCANNER: Partial<Record<ScannerId, ToolFile>> = {
  gitleaks: 'gitleaks',
  semgrep: 'semgrep',
  'npm-audit': 'npm',
};

const ACTIVITY: Record<string, string> = {
  gitleaks: 'runGitleaks',
  semgrep: 'runSemgrep',
  'npm-audit': 'runNpmAudit',
  'license-check': 'runLicenseCheck',
};

const state = { attempt: 1, activities: {} as Record<string, Fn>, calls: [] as string[] };

const moduleInternals = Module as unknown as { _load: (request: string, ...rest: unknown[]) => unknown };
const originalLoad = moduleInternals._load;
const patched = new Map<string, unknown>();
moduleInternals._load = function load(request: string, ...rest: unknown[]): unknown {
  const real = originalLoad.call(this, request, ...rest);
  if (request === '@temporalio/workflow') {
    if (!patched.has(request)) {
      patched.set(request, {
        ...(real as object),
        proxyActivities: () =>
          new Proxy(
            {},
            {
              get: (_target, name: string) =>
                (...args: unknown[]) => {
                  state.calls.push(name);
                  const impl = state.activities[name];
                  if (impl === undefined) throw new Error(`unexpected activity ${name}`);
                  return impl(...args);
                },
            },
          ),
        workflowInfo: () => ({ workflowId: 'wf-bdd', runId: RUN_ID }),
        setHandler: () => undefined,
        condition: async (fn: () => boolean) => fn(),
      });
    }
    return patched.get(request);
  }
  if (request === '@temporalio/activity') {
    if (!patched.has(request)) {
      patched.set(request, { ...(real as object), Context: { current: () => ({ info: { attempt: state.attempt } }) } });
    }
    return patched.get(request);
  }
  return real;
};

export function outcome(partial: Partial<ProcessOutcome> = {}): ProcessOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    stdoutTruncated: false,
    timedOut: false,
    startedAt: T0,
    endedAt: T0,
    ...partial,
  };
}

export async function fixture(name: string): Promise<ProcessOutcome> {
  const f = JSON.parse(await readFile(path.join(FIXTURES, name), 'utf8')) as { exitCode: number; stdout: string; stderr: string };
  return outcome({ exitCode: f.exitCode, stdout: Buffer.from(f.stdout), stderr: Buffer.from(f.stderr) });
}

export const missingTool = (): ProcessOutcome => outcome({ exitCode: null, spawnErrorCode: 'ENOENT' });
export const crashingTool = (): ProcessOutcome =>
  outcome({ exitCode: 2, stdout: Buffer.from('not json'), stderr: Buffer.from('fatal: tool crashed') });
export const hangingTool = (): ProcessOutcome => outcome({ exitCode: null, signal: 'SIGKILL', timedOut: true });

export function toolFor(scanner: ScannerId): ToolFile {
  const tool = TOOL_BY_SCANNER[scanner];
  if (tool === undefined) throw new Error(`${scanner} is not run through the process runner`);
  return tool;
}

export function failureOf(error: unknown): { type: string; nonRetryable: boolean; details: unknown[] | undefined; message: string } {
  const e = error as { type?: string; nonRetryable?: boolean; details?: unknown[]; message?: string };
  return { type: String(e.type), nonRetryable: Boolean(e.nonRetryable), details: e.details, message: String(e.message) };
}

export class ScanWorld {
  tmpRoot = '';
  evidenceRoot = '';
  run!: AuditRun;
  source!: FetchedSource;
  runnerCalls: ProcessRequest[] = [];
  behaviours: Partial<Record<ToolFile, RunnerBehaviour>> = {};
  repoFiles: Record<string, string> = {};
  sourceBehaviour: RunnerBehaviour | undefined;
  result: AuditResult | undefined;
  error: unknown;
  reportInput: Record<string, unknown> | undefined;
  activityCalls: string[] = [];
  focus: ScannerId | undefined;
  directOutcome: ProcessOutcome | undefined;
  direct: ToolRunResult<unknown> | undefined;

  async prepare(): Promise<void> {
    this.tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-bdd-'));
    this.evidenceRoot = await mkdtemp(path.join(os.tmpdir(), 'tessera-bdd-ev-'));
    const workDir = path.join(this.tmpRoot, `tessera-${RUN_ID}`);
    this.run = { runId: RUN_ID, workDir, repoDir: path.join(workDir, 'repo') };
    this.source = { repoDir: this.run.repoDir, revision: REVISION };
    await mkdir(this.run.repoDir, { recursive: true, mode: 0o700 });
    await mkdir(path.join(workDir, 'home'), { mode: 0o700 });
    await mkdir(path.join(workDir, 'tmp'), { mode: 0o700 });
    this.repoFiles = {
      'package.json': '{"name":"app","version":"1.0.0"}',
      'package-lock.json': JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: { '': { name: 'app', version: '1.0.0' }, 'node_modules/left-pad': { version: '1.3.0', license: 'MIT' } },
      }),
      'index.js': 'module.exports = 1;\n',
    };
    this.behaviours = {
      gitleaks: await fixtureBehaviour('gitleaks-clean.json'),
      semgrep: await fixtureBehaviour('semgrep-clean.json'),
      npm: await fixtureBehaviour('npm-audit-clean.json'),
    };
  }

  async dispose(): Promise<void> {
    await rm(this.tmpRoot, { recursive: true, force: true });
    await rm(this.evidenceRoot, { recursive: true, force: true });
  }

  setTool(scanner: ScannerId, behaviour: RunnerBehaviour): void {
    this.behaviours[toolFor(scanner)] = behaviour;
  }

  breakLicenseLockfile(): void {
    this.repoFiles['package-lock.json'] = '{ this is not json';
  }

  private runner(): ProcessRunner {
    return async (req) => {
      this.runnerCalls.push(req);
      const tool = req.file as ToolFile;
      if (tool === 'git') {
        if (this.sourceBehaviour === undefined) throw new Error('unexpected git call');
        return this.sourceBehaviour(req);
      }
      if (req.args.length === 1 && (req.args[0] === 'version' || req.args[0] === '--version')) {
        const main = this.behaviours[tool];
        const probe = main === undefined ? undefined : await main(req);
        return probe?.spawnErrorCode === 'ENOENT' ? probe : outcome({ stdout: Buffer.from('1.2.3\n') });
      }
      const behaviour = this.behaviours[tool];
      if (behaviour === undefined) throw new Error(`no behaviour for ${tool}`);
      return behaviour(req);
    };
  }

  async runAudit(): Promise<void> {
    for (const [name, content] of Object.entries(this.repoFiles)) {
      await writeFile(path.join(this.run.repoDir, name), content);
    }
    const { createScanActivities } = await import('../../../../../src/scan/activities');
    const scans = createScanActivities({
      runner: this.runner(),
      clock: () => T0,
      evidenceRoot: this.evidenceRoot,
      tmpRoot: this.tmpRoot,
      frameworkVersion: '0.0.0-bdd',
      workerEnv: { PATH: '/usr/bin' },
      configDir: '/opt/tessera/config/scanners',
    });
    const lifecycle = await import('../../../../../src/scan/lifecycle');
    const { ActivityFailure, ApplicationFailure } = await import('@temporalio/workflow');
    const wrap = (cause: Error): Error =>
      new ActivityFailure('Activity task failed', 'activity', '1', RetryState.MAXIMUM_ATTEMPTS_REACHED, 'worker', cause);
    const fetchSource = this.sourceBehaviour
      ? async (run: AuditRun, repoUrl: string): Promise<FetchedSource> => {
          try {
            return await lifecycle.fetchSource(run, repoUrl, {
              runner: this.runner(),
              store: (await import('../../../../../src/evidence/store')).createEvidenceStore(this.evidenceRoot, RUN_ID),
              clock: () => T0,
              frameworkVersion: '0.0.0-bdd',
              tmpRoot: this.tmpRoot,
            });
          } catch (error) {
            if (error instanceof lifecycle.SourceFetchFailure) {
              throw wrap(
                ApplicationFailure.create({
                  type: error.kind === 'network' ? 'SourceNetworkError' : 'SourceUnavailableError',
                  message: error.message,
                  nonRetryable: !error.retryable,
                }),
              );
            }
            throw error;
          }
        }
      : async () => this.source;
    const fakes = {
      initAuditRun: async () => this.run,
      fetchSource,
      detectTechStack: async () => ({ language: 'nodejs', frameworks: ['Express'], hasPayments: false, hasPII: false, packageManager: 'npm' }),
      generateScopeDocument: async () => ({ repoUrl: '', techStack: {}, securityLevel: 1, frameworks: ['OWASP-ASVS'], inScope: [], outOfScope: [], createdAt: new Date(0) }),
      runGitleaks: scans.runGitleaks,
      runSemgrep: scans.runSemgrep,
      runNpmAudit: scans.runNpmAudit,
      runLicenseCheck: scans.runLicenseCheck,
      reviewCriticalPaths: async () => [],
      mapToCompliance: async () => [],
      crossValidate: async () => ({ falsePositives: [], severityCorrections: [], missingFindings: [], reviewNotes: '' }),
      generateReport: async (input: unknown) => {
        this.reportInput = input as Record<string, unknown>;
        return { reportPath: '/out/audit-report.md', evidencePath: '/out/evidence' };
      },
      cleanupRun: async (run: unknown) => lifecycle.cleanupRun(run as AuditRun, this.tmpRoot),
    };
    state.activities = {};
    state.calls = [];
    state.attempt = 1;
    for (const [name, impl] of Object.entries(fakes)) {
      state.activities[name] = impl as Fn;
    }
    const { applicationAudit } = (await import('../../../../../src/workflows/index')) as {
      applicationAudit: (input: AuditInput) => Promise<AuditResult>;
    };
    try {
      this.result = await applicationAudit(INPUT);
    } catch (error) {
      this.error = error;
    }
    this.activityCalls = [...state.calls];
  }

  async runDirectTool(): Promise<void> {
    assert(this.directOutcome, 'no direct tool outcome configured');
    const { runTool } = await import('../../../../../src/scan/run-tool');
    const { createEvidenceStore } = await import('../../../../../src/evidence/store');
    const main = this.directOutcome;
    const policy: ToolPolicy<unknown> = {
      tool: 'npm',
      scanner: 'npm-audit',
      versionArgs: ['--version'],
      parse: (output) => (output.length === 0 ? { ok: true, value: null } : { ok: true, value: output.toString('utf8') }),
      classify: (out) =>
        out.exitCode === 0 ? { status: 'completed', exitClass: 'success' } : { status: 'failed', exitClass: 'tool-error', cause: 'tool-error' },
      sanitize: (output) => ({ bytes: output, redactions: 0, mediaType: 'text/plain' }),
    };
    this.direct = await runTool(
      {
        stepId: 'scan.empty-tool',
        attempt: 1,
        runId: RUN_ID,
        source: { repoUrl: REPO_URL, revision: REVISION },
        args: ['run', 'check'],
        cwd: this.run.repoDir,
        timeoutMs: 1000,
        outputFrom: 'stdout',
        pathTokens: { [this.run.workDir]: '<WORK>' },
      },
      policy,
      {
        runner: async (req) => (req.args.length === 1 ? outcome({ stdout: Buffer.from('1.2.3\n') }) : main),
        store: createEvidenceStore(this.evidenceRoot, RUN_ID),
        clock: () => T0,
        frameworkVersion: '0.0.0-bdd',
      },
    );
  }

  async directRecord(): Promise<Record<string, any>> {
    return JSON.parse(await readFile(path.join(this.evidenceRoot, RUN_ID, 'records', 'scan.empty-tool.a1.json'), 'utf8')) as Record<string, any>;
  }

  called(name: string): boolean {
    return this.activityCalls.includes(name);
  }

  scannerEntry(scanner: ScannerId): ScannerStatusEntry {
    const list = (this.reportInput?.scanners ?? this.result?.scanners) as ScannerStatusEntry[] | undefined;
    const entry = list?.find((s) => s.scanner === scanner);
    if (entry === undefined) throw new Error(`no status entry for ${scanner}`);
    return entry;
  }

  async evidenceRecord(scanner: ScannerId): Promise<Record<string, any>> {
    const file = path.join(this.evidenceRoot, RUN_ID, 'records', `scan.${scanner}.a1.json`);
    return JSON.parse(await readFile(file, 'utf8')) as Record<string, any>;
  }

  activityFor(scanner: ScannerId): string {
    return ACTIVITY[scanner];
  }
}

async function fixtureBehaviour(name: string): Promise<RunnerBehaviour> {
  const out = await fixture(name);
  return () => out;
}
