import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import { lstat, mkdir, open, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { validateRepoUrl } from './repo-url';
import { runTool } from './run-tool';
import type { Classification, ParseResult, ProcessOutcome, RunToolDeps, ToolPolicy } from './tool-types';

export interface InitAuditRunInput {
  workflowId: string;
  temporalRunId: string;
  tmpRoot: string;
}

export interface AuditRun {
  runId: string;
  workDir: string;
  repoDir: string;
}

export type SourceErrorKind = 'network' | 'source-unavailable';

export interface SourceFetchError extends Error {
  kind: SourceErrorKind;
  retryable: boolean;
}

export interface FetchedSource {
  repoDir: string;
  revision: string;
  evidenceRecordIds?: string[];
}

export interface FetchSourceDeps extends RunToolDeps {
  tmpRoot?: string;
  attempt?: number;
}

export type LifecycleInputCode = 'invalid-run' | 'invalid-repo-url';

export class LifecycleInputError extends Error {
  readonly code: LifecycleInputCode;

  constructor(code: LifecycleInputCode, message: string) {
    super(message);
    this.name = 'LifecycleInputError';
    this.code = code;
  }
}

export class SourceFetchFailure extends Error implements SourceFetchError {
  readonly kind: SourceErrorKind;
  readonly retryable: boolean;
  readonly evidenceRecordIds: string[];

  constructor(kind: SourceErrorKind, retryable: boolean, message: string, evidenceRecordIds: string[] = []) {
    super(message);
    this.name = 'SourceFetchError';
    this.kind = kind;
    this.retryable = retryable;
    this.evidenceRecordIds = [...evidenceRecordIds];
  }
}

const WORKFLOW_ID = /^[A-Za-z0-9_-]{1,255}$/;
const RUN_ID = /^[A-Za-z0-9_-]{1,128}$/;
const REVISION = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const NETWORK_STDERR = /could not resolve host|timed out|early EOF|failed to connect|connection (?:refused|reset)/i;
const DIR_MODE = 0o700;
const WORK_PREFIX = 'tessera-';
const CLONE_TIMEOUT_MS = 300_000;
const REV_PARSE_TIMEOUT_MS = 30_000;

function isErrno(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code;
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function assertRunId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !RUN_ID.test(value)) {
    throw new LifecycleInputError('invalid-run', 'invalid temporalRunId: only letters, digits, "_" and "-" are allowed');
  }
}

function assertOwnedDir(st: Stats, dir: string): void {
  if (st.isSymbolicLink()) throw new Error(`audit run: refusing symlink at ${dir}`);
  if (!st.isDirectory()) throw new Error(`audit run: not a directory: ${dir}`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`audit run: ${dir} is not owned by the current user`);
}

async function ensurePrivateDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { mode: DIR_MODE });
  } catch (err) {
    if (!isErrno(err, 'EEXIST')) throw err;
  }
  const st = await lstat(dir);
  assertOwnedDir(st, dir);
  const fh = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const fst = await fh.stat();
    if (fst.ino !== st.ino || fst.dev !== st.dev) throw new Error(`audit run: ${dir} changed during check`);
    if ((fst.mode & 0o777) !== DIR_MODE) await fh.chmod(DIR_MODE);
  } finally {
    await fh.close();
  }
}

function workDirFor(tmpRoot: string, runId: string): string {
  return path.join(path.resolve(tmpRoot), `${WORK_PREFIX}${runId}`);
}

export async function initAuditRun(input: InitAuditRunInput): Promise<AuditRun> {
  if (typeof input.workflowId !== 'string' || !WORKFLOW_ID.test(input.workflowId)) {
    throw new LifecycleInputError('invalid-run', 'invalid workflowId: only letters, digits, "_" and "-" are allowed');
  }
  assertRunId(input.temporalRunId);
  if (typeof input.tmpRoot !== 'string' || !path.isAbsolute(input.tmpRoot)) {
    throw new LifecycleInputError('invalid-run', 'tmpRoot must be an absolute path');
  }
  const workDir = workDirFor(input.tmpRoot, input.temporalRunId);
  await ensurePrivateDir(workDir);
  await ensurePrivateDir(path.join(workDir, 'home'));
  await ensurePrivateDir(path.join(workDir, 'tmp'));
  return { runId: input.temporalRunId, workDir, repoDir: path.join(workDir, 'repo') };
}

function trustedRun(run: AuditRun, tmpRoot: string): AuditRun {
  assertRunId(run?.runId);
  if (typeof tmpRoot !== 'string' || !path.isAbsolute(tmpRoot)) {
    throw new LifecycleInputError('invalid-run', 'tmpRoot must be an absolute path');
  }
  const workDir = workDirFor(tmpRoot, run.runId);
  const repoDir = path.join(workDir, 'repo');
  if (run.workDir !== workDir || run.repoDir !== repoDir) {
    throw new LifecycleInputError('invalid-run', 'audit run paths do not match <tmp>/tessera-<runId>/repo');
  }
  return { runId: run.runId, workDir, repoDir };
}

const clonePolicy: ToolPolicy<null> = {
  tool: 'git',
  versionArgs: ['--version'],
  parse: (): ParseResult<null> => ({ ok: true, value: null }),
  classify: (outcome: ProcessOutcome): Classification => {
    if (outcome.exitCode === 0) return { status: 'completed', exitClass: 'success' };
    const stderr = outcome.stderr.toString('utf8');
    const firstLine = stderr.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? `git clone exited ${String(outcome.exitCode)}`;
    const cause = NETWORK_STDERR.test(stderr) ? 'network' : 'source-unavailable';
    return { status: 'failed', exitClass: 'tool-error', cause, causeDetail: firstLine };
  },
  sanitize: (output: Buffer) => ({ bytes: output, redactions: 0, mediaType: 'text/plain' }),
};

const revParsePolicy: ToolPolicy<string> = {
  tool: 'git',
  versionArgs: ['--version'],
  parse: (output: Buffer): ParseResult<string> => {
    const value = output.toString('utf8').trim();
    return REVISION.test(value) ? { ok: true, value } : { ok: false, error: 'invalid revision format' };
  },
  classify: (outcome: ProcessOutcome, parsed: ParseResult<string>): Classification =>
    outcome.exitCode === 0 && parsed.ok
      ? { status: 'completed', exitClass: 'success' }
      : { status: 'failed', exitClass: 'tool-error', cause: 'source-unavailable', causeDetail: 'git rev-parse did not return a revision' },
  sanitize: (output: Buffer) => ({ bytes: output, redactions: 0, mediaType: 'text/plain' }),
};

export async function fetchSource(input: AuditRun, repoUrl: string, deps: FetchSourceDeps): Promise<FetchedSource> {
  const run = trustedRun(input, deps.tmpRoot ?? os.tmpdir());
  try {
    validateRepoUrl(repoUrl);
  } catch {
    throw new LifecycleInputError('invalid-repo-url', 'invalid repository URL: only https://github.com/<owner>/<repo> is allowed');
  }
  const attempt = deps.attempt ?? 1;
  const pathTokens = { [run.workDir]: '<WORK>' };
  const common = { attempt, runId: run.runId, outputFrom: 'stdout' as const, pathTokens, inputs: { repoUrl } };

  await rm(run.repoDir, { recursive: true, force: true });

  const clone = await runTool(
    {
      ...common,
      stepId: 'source.clone',
      source: { repoUrl, revision: null },
      args: [
        '-c',
        'core.hooksPath=/dev/null',
        'clone',
        '--depth',
        '1',
        '--no-tags',
        '--single-branch',
        '--no-recurse-submodules',
        '--',
        repoUrl,
        run.repoDir,
      ],
      cwd: run.workDir,
      timeoutMs: CLONE_TIMEOUT_MS,
    },
    clonePolicy,
    deps,
  );
  if (clone.classification.status !== 'completed') {
    const network = clone.record.result.timedOut || clone.classification.cause === 'network';
    const detail = clone.classification.causeDetail ?? clone.classification.exitClass;
    throw network
      ? new SourceFetchFailure('network', true, `source fetch failed (network): ${detail}`, [clone.record.id])
      : new SourceFetchFailure('source-unavailable', false, `source unavailable: ${detail}`, [clone.record.id]);
  }

  const revParse = await runTool(
    {
      ...common,
      stepId: 'source.revision',
      source: { repoUrl, revision: null },
      args: [`--git-dir=${path.join(run.repoDir, '.git')}`, 'rev-parse', '--verify', 'HEAD'],
      cwd: run.workDir,
      timeoutMs: REV_PARSE_TIMEOUT_MS,
    },
    revParsePolicy,
    deps,
  );
  const revision = revParse.parsed.ok ? revParse.parsed.value : undefined;
  if (revParse.classification.status !== 'completed' || typeof revision !== 'string' || !REVISION.test(revision)) {
    throw new SourceFetchFailure('source-unavailable', false, 'could not determine a valid source revision', [clone.record.id, revParse.record.id]);
  }
  return { repoDir: run.repoDir, revision, evidenceRecordIds: [clone.record.id, revParse.record.id] };
}

export async function cleanupRun(run: AuditRun, tmpRoot: string): Promise<void> {
  const refuse = (reason: string): never => {
    throw new Error(`cleanupRun: refusing to remove ${String(run?.workDir)}: ${reason}`);
  };
  if (typeof tmpRoot !== 'string' || !path.isAbsolute(tmpRoot)) refuse('tmpRoot is not an absolute path');
  if (typeof run?.runId !== 'string' || !RUN_ID.test(run.runId)) refuse('invalid runId');
  const expected = workDirFor(tmpRoot, run.runId);
  if (run.workDir !== expected) refuse('path is outside <tmp>/tessera-<runId>');
  const evidenceRoot = process.env.TESSERA_EVIDENCE_ROOT;
  if (evidenceRoot !== undefined && evidenceRoot.length > 0 && isInside(path.resolve(evidenceRoot), expected)) {
    refuse('path is inside the evidence root');
  }
  let st: Stats;
  try {
    st = await lstat(expected);
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return;
    throw err;
  }
  if (st.isSymbolicLink()) refuse('path is a symlink');
  if (!st.isDirectory()) refuse('path is not a directory');
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) refuse('path is not owned by the current user');
  await rm(expected, { recursive: true, force: true, maxRetries: 3 });
}
