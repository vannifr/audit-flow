import { isUtf8 } from 'node:buffer';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { sha256Hex } from '../evidence/hash';
import { redactSecrets } from '../evidence/redact';
import type { ArtifactRef, EvidenceRecord, ExitClass } from '../evidence/types';
import { buildToolEnv } from './env';
import type { StatusCause } from './status';
import type {
  Classification,
  ParseResult,
  ProcessOutcome,
  ProcessRequest,
  ProcessRunner,
  RunTool,
  RunToolDeps,
  Sanitized,
  ToolInvocation,
  ToolPolicy,
  ToolRunResult,
} from './tool-types';

const WORK_TOKEN = '<WORK>';
const MIB = 1024 * 1024;
const DEFAULT_MAX_OUTPUT_MB = 64;
const MAX_STDERR_BYTES = MIB;
const VERSION_TIMEOUT_MS = 30_000;
const VERSION_MAX_BYTES = 64 * 1024;
const MAX_DETAIL = 500;
const MAX_VERSION = 200;

type Tokenizer = (text: string) => string;

interface RawOutput {
  bytes: Buffer;
  truncated: boolean;
}

type ReportRead = { kind: 'ok'; output: RawOutput } | { kind: 'missing' } | { kind: 'rejected' };

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

function makeTokenizer(pathTokens: Record<string, string>): Tokenizer {
  const entries = Object.entries(pathTokens)
    .filter(([from]) => path.isAbsolute(from) && from.length > 1)
    .sort((a, b) => b[0].length - a[0].length)
    .map(([from, token]) => ({ re: new RegExp(`${escapeRegExp(from)}(?![A-Za-z0-9._-])`, 'g'), token }));
  return (text) => entries.reduce((acc, { re, token }) => acc.replace(re, () => token), text);
}

function scrub(text: string, tokenize: Tokenizer): string {
  return tokenize(redactSecrets(text).text);
}

function detail(text: string | undefined, tokenize: Tokenizer): string | undefined {
  if (text === undefined || text.length === 0) return undefined;
  return scrub(text, tokenize).slice(0, MAX_DETAIL);
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function workDirOf(pathTokens: Record<string, string>): string | null {
  const match = Object.entries(pathTokens).find(([from, token]) => token === WORK_TOKEN && path.isAbsolute(from));
  return match === undefined ? null : path.resolve(match[0]);
}

function defaultMaxOutputBytes(): number {
  const raw = process.env.TESSERA_MAX_OUTPUT_MB;
  if (raw !== undefined && /^\d{1,5}$/.test(raw) && Number(raw) > 0) return Number(raw) * MIB;
  return DEFAULT_MAX_OUTPUT_MB * MIB;
}

function validDate(value: unknown, fallback: () => Date): Date {
  return value instanceof Date && !Number.isNaN(value.getTime()) ? value : fallback();
}

async function safeRun(runner: ProcessRunner, req: ProcessRequest, clock: () => Date): Promise<ProcessOutcome> {
  const startedAt = clock();
  try {
    return await runner(req);
  } catch (err) {
    const code = typeof err === 'object' && err !== null ? (err as { code?: unknown }).code : undefined;
    return {
      exitCode: null,
      signal: null,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false,
      timedOut: false,
      spawnErrorCode: typeof code === 'string' && code.length > 0 ? code : 'ERUNNER',
      startedAt,
      endedAt: clock(),
    };
  }
}

async function readReport(file: string, cwd: string, workDir: string, maxBytes: number): Promise<ReportRead> {
  const resolved = path.resolve(cwd, file);
  if (!isInside(workDir, resolved)) return { kind: 'rejected' };
  let real: string;
  let realWork: string;
  try {
    real = await realpath(resolved);
    realWork = await realpath(workDir);
  } catch {
    return { kind: 'missing' };
  }
  if (!isInside(realWork, real)) return { kind: 'rejected' };
  let fh;
  try {
    fh = await open(real, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return { kind: 'rejected' };
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) return { kind: 'rejected' };
    const want = Math.min(st.size, maxBytes);
    const buf = Buffer.alloc(want);
    let offset = 0;
    while (offset < want) {
      const { bytesRead } = await fh.read(buf, offset, want - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return { kind: 'ok', output: { bytes: buf.subarray(0, offset), truncated: st.size > maxBytes } };
  } finally {
    await fh.close();
  }
}

function safeParse<T>(policy: ToolPolicy<T>, bytes: Buffer): ParseResult<T> {
  try {
    return policy.parse(bytes);
  } catch {
    return { ok: false, error: 'parser threw' };
  }
}

function safeClassify<T>(policy: ToolPolicy<T>, outcome: ProcessOutcome, parsed: ParseResult<T>): Classification {
  try {
    return policy.classify(outcome, parsed);
  } catch {
    return { status: 'failed', exitClass: 'tool-error', cause: 'tool-error', causeDetail: 'classifier threw' };
  }
}

function fallbackSanitize(bytes: Buffer): Sanitized {
  const redacted = redactSecrets(bytes.toString('utf8'));
  return { bytes: Buffer.from(redacted.text, 'utf8'), redactions: redacted.redactions, mediaType: 'text/plain' };
}

function safeSanitize<T>(policy: ToolPolicy<T>, bytes: Buffer, parsed: ParseResult<T>): Sanitized {
  try {
    const result = policy.sanitize(bytes, parsed);
    if (!Buffer.isBuffer(result.bytes)) return fallbackSanitize(bytes);
    return result;
  } catch {
    return fallbackSanitize(bytes);
  }
}

function tokenizeBytes(bytes: Buffer, tokenize: Tokenizer): Buffer {
  if (!isUtf8(bytes)) return bytes;
  const text = bytes.toString('utf8');
  const replaced = tokenize(text);
  return replaced === text ? bytes : Buffer.from(replaced, 'utf8');
}

function override(
  base: Classification,
  outcome: ProcessOutcome,
  parsed: ParseResult<unknown>,
  truncated: boolean,
  tool: string,
  timeoutMs: number,
): Classification {
  const set = (status: Classification['status'], exitClass: ExitClass, cause: StatusCause, causeDetail?: string): Classification =>
    causeDetail === undefined ? { status, exitClass, cause } : { status, exitClass, cause, causeDetail };
  if (outcome.spawnErrorCode === 'ENOENT') return set('unavailable', 'not-installed', 'not-installed', `${tool} not found on PATH`);
  if (outcome.spawnErrorCode !== undefined) return set('failed', 'spawn-error', 'spawn-error', `spawn error ${outcome.spawnErrorCode}`);
  if (outcome.timedOut) return set('failed', 'timeout', 'timeout', `exceeded ${timeoutMs} ms`);
  if (truncated) return set('partial', 'output-truncated', 'output-truncated', 'output exceeded the size limit');
  if (outcome.exitCode === null) return set('failed', 'killed', 'killed', `terminated by signal ${outcome.signal ?? 'unknown'}`);
  if (!parsed.ok) return set('failed', base.exitClass, 'parse-error', parsed.error ?? 'output could not be parsed');
  return base;
}

function precheck(inv: ToolInvocation, workDir: string | null, maxOutputBytes: number): string | null {
  if (workDir === null) return `no absolute ${WORK_TOKEN} path token`;
  if (!path.isAbsolute(inv.cwd) || !isInside(workDir, path.resolve(inv.cwd))) return 'cwd outside the work dir';
  if (!Number.isSafeInteger(inv.timeoutMs) || inv.timeoutMs <= 0) return 'invalid timeout';
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) return 'invalid output limit';
  return null;
}

function versionFrom(outcome: ProcessOutcome, tokenize: Tokenizer): string | null {
  if (outcome.spawnErrorCode !== undefined || outcome.timedOut || outcome.exitCode !== 0) return null;
  const line = outcome.stdout
    .toString('utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0);
  if (line === undefined) return null;
  return scrub(line, tokenize).slice(0, MAX_VERSION);
}

function scrubRecord(values: Record<string, string> | undefined, tokenize: Tokenizer): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(values ?? {})) out[key] = scrub(value, tokenize);
  return out;
}

interface Stage<T> {
  outcome: ProcessOutcome;
  toolVersion: string | null;
  envOverrides: Record<string, string>;
  envPassthrough: string[];
  raw: RawOutput | null;
  parsed: ParseResult<T>;
  classification: Classification;
}

function notRunStage<T>(problem: string | null, deps: RunToolDeps): Stage<T> {
  const now = deps.clock();
  const reason = problem ?? 'invalid invocation';
  return {
    outcome: {
      exitCode: null,
      signal: null,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false,
      timedOut: false,
      startedAt: now,
      endedAt: now,
    },
    toolVersion: null,
    envOverrides: {},
    envPassthrough: [],
    raw: null,
    parsed: { ok: false, error: reason },
    classification: { status: 'failed', exitClass: 'not-run', cause: 'spawn-error', causeDetail: reason },
  };
}

async function captureRaw(
  inv: ToolInvocation,
  outcome: ProcessOutcome,
  workDir: string,
  maxOutputBytes: number,
): Promise<{ raw: RawOutput | null; reportProblem: string | null }> {
  if (outcome.spawnErrorCode !== undefined) return { raw: null, reportProblem: null };
  if (inv.outputFrom === 'stdout') {
    const truncated = outcome.stdoutTruncated || outcome.stdout.length > maxOutputBytes;
    return { raw: { bytes: outcome.stdout.subarray(0, maxOutputBytes), truncated }, reportProblem: null };
  }
  const report = await readReport(inv.outputFrom.file, inv.cwd, workDir, maxOutputBytes);
  if (report.kind === 'ok') return { raw: report.output, reportProblem: null };
  return { raw: null, reportProblem: report.kind === 'rejected' ? 'report path rejected' : 'report not produced' };
}

async function executeStage<T>(
  inv: ToolInvocation,
  policy: ToolPolicy<T>,
  deps: RunToolDeps,
  workDir: string,
  maxOutputBytes: number,
  tokenize: Tokenizer,
): Promise<Stage<T>> {
  const built = buildToolEnv(policy.tool, workDir, process.env);
  const extra = inv.envOverrides ?? {};
  const env: Record<string, string> = { ...built.env, ...extra };
  const envOverrides = { ...built.overrides, ...extra };
  const envPassthrough = built.passthrough.filter((name) => !(name in extra));

  const probe = await safeRun(
    deps.runner,
    {
      file: policy.tool,
      args: [...policy.versionArgs],
      cwd: workDir,
      env,
      timeoutMs: Math.min(inv.timeoutMs, VERSION_TIMEOUT_MS),
      maxOutputBytes: VERSION_MAX_BYTES,
      maxStderrBytes: VERSION_MAX_BYTES,
    },
    deps.clock,
  );
  const toolVersion = versionFrom(probe, tokenize);

  const outcome = await safeRun(
    deps.runner,
    {
      file: policy.tool,
      args: [...inv.args],
      cwd: inv.cwd,
      env,
      timeoutMs: inv.timeoutMs,
      maxOutputBytes,
      maxStderrBytes: MAX_STDERR_BYTES,
    },
    deps.clock,
  );

  const { raw, reportProblem } = await captureRaw(inv, outcome, workDir, maxOutputBytes);
  const parsed: ParseResult<T> = raw !== null ? safeParse(policy, raw.bytes) : { ok: false, error: reportProblem ?? 'tool not started' };
  const classification = override(
    safeClassify(policy, outcome, parsed),
    outcome,
    parsed,
    raw?.truncated ?? false,
    policy.tool,
    inv.timeoutMs,
  );
  return { outcome, toolVersion, envOverrides, envPassthrough, raw, parsed, classification };
}

async function writeOutputArtifact<T>(
  inv: ToolInvocation,
  policy: ToolPolicy<T>,
  deps: RunToolDeps,
  recordId: string,
  raw: RawOutput | null,
  parsed: ParseResult<T>,
  tokenize: Tokenizer,
): Promise<ArtifactRef | null> {
  if (raw === null) return null;
  const sanitized = safeSanitize(policy, raw.bytes, parsed);
  const kind = inv.outputFrom === 'stdout' ? 'stdout' : 'report';
  const ext = sanitized.mediaType === 'application/json' ? 'json' : 'txt';
  return deps.store.writeArtifact(recordId, `${kind}.${ext}`, tokenizeBytes(sanitized.bytes, tokenize), {
    mediaType: sanitized.mediaType,
    rawBytes: raw.bytes.length,
    rawSha256: sha256Hex(raw.bytes),
    redactions: sanitized.redactions,
    truncated: raw.truncated,
  });
}

async function writeStderrArtifact(deps: RunToolDeps, recordId: string, outcome: ProcessOutcome, tokenize: Tokenizer): Promise<ArtifactRef | null> {
  if (outcome.stderr.length === 0) return null;
  const capped = outcome.stderr.subarray(0, MAX_STDERR_BYTES);
  const redacted = redactSecrets(capped.toString('utf8'));
  return deps.store.writeArtifact(recordId, 'stderr.txt', Buffer.from(tokenize(redacted.text), 'utf8'), {
    mediaType: 'text/plain',
    rawBytes: outcome.stderr.length,
    rawSha256: sha256Hex(outcome.stderr),
    redactions: redacted.redactions,
    truncated: outcome.stderr.length >= MAX_STDERR_BYTES,
  });
}

export const runTool: RunTool = async <T>(
  inv: ToolInvocation,
  policy: ToolPolicy<T>,
  deps: RunToolDeps,
  findingIdsFor?: (parsed: ParseResult<T>) => string[],
): Promise<ToolRunResult<T>> => {
  const recordId = `${inv.stepId}.a${inv.attempt}`;
  const tokenize = makeTokenizer(inv.pathTokens);
  const workDir = workDirOf(inv.pathTokens);
  const maxOutputBytes = inv.maxOutputBytes ?? defaultMaxOutputBytes();
  const problem = precheck(inv, workDir, maxOutputBytes);

  const stage: Stage<T> =
    problem !== null || workDir === null
      ? notRunStage<T>(problem, deps)
      : await executeStage(inv, policy, deps, workDir, maxOutputBytes, tokenize);
  const { outcome, toolVersion, envOverrides, envPassthrough, raw, parsed } = stage;
  let { classification } = stage;

  const output = await writeOutputArtifact(inv, policy, deps, recordId, raw, parsed, tokenize);
  const stderr = await writeStderrArtifact(deps, recordId, outcome, tokenize);

  let findingIds: string[] = [];
  if (findingIdsFor !== undefined) {
    try {
      findingIds = [...findingIdsFor(parsed)];
    } catch {
      classification = { status: 'failed', exitClass: classification.exitClass, cause: 'tool-error', causeDetail: 'finding linkage failed' };
    }
  }

  const startedAt = validDate(outcome.startedAt, deps.clock);
  let endedAt = validDate(outcome.endedAt, deps.clock);
  if (endedAt.getTime() < startedAt.getTime()) endedAt = startedAt;
  const causeDetail = detail(classification.causeDetail, tokenize);
  classification = {
    status: classification.status,
    exitClass: classification.exitClass,
    ...(classification.cause !== undefined ? { cause: classification.cause } : {}),
    ...(causeDetail !== undefined ? { causeDetail } : {}),
  };

  const record: EvidenceRecord = {
    schema: 'tessera.evidence/v1',
    id: recordId,
    runId: inv.runId,
    stepId: inv.stepId,
    attempt: inv.attempt,
    kind: 'tool-run',
    ...(policy.scanner !== undefined ? { scanner: policy.scanner } : {}),
    action: {
      command: policy.tool,
      args: inv.args.map((arg) => scrub(arg, tokenize)),
      cwd: scrub(inv.cwd, tokenize),
      envOverrides: scrubRecord(envOverrides, tokenize),
      envPassthrough,
      inputs: scrubRecord(inv.inputs, tokenize),
    },
    tool: { name: policy.tool, version: toolVersion },
    source: { repoUrl: redactSecrets(inv.source.repoUrl).text, revision: inv.source.revision },
    startedAt: startedAt.toISOString(),
    endedAt: endedAt.toISOString(),
    durationMs: endedAt.getTime() - startedAt.getTime(),
    result: {
      exitCode: outcome.exitCode,
      signal: outcome.signal,
      exitClass: classification.exitClass,
      timedOut: outcome.timedOut,
      ...(outcome.spawnErrorCode !== undefined ? { spawnErrorCode: outcome.spawnErrorCode } : {}),
    },
    status: classification.status,
    ...(classification.cause !== undefined ? { cause: classification.cause } : {}),
    ...(classification.causeDetail !== undefined ? { causeDetail: classification.causeDetail } : {}),
    output,
    stderr,
    findingIds,
    overrideAttempts: [...(inv.overrideAttempts ?? [])],
    recordedBy: { framework: 'tessera', version: deps.frameworkVersion },
  };

  const evidence = await deps.store.writeRecord(record);
  return { classification, parsed, toolVersion, record, evidence };
};
