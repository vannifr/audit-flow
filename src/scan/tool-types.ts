import type { ScannerStatusValue, StatusCause, ScannerId } from './status';
import type { EvidenceRecord, EvidenceRef, EvidenceStore, ExitClass, OverrideAttempt } from '../evidence/types';

export interface ProcessRequest {
  file: string;
  args: readonly string[];
  cwd: string;
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
  maxOutputBytes: number;
  maxStderrBytes: number;
}

export interface ProcessOutcome {
  exitCode: number | null;
  signal: string | null;
  stdout: Buffer;
  stderr: Buffer;
  stdoutTruncated: boolean;
  timedOut: boolean;
  spawnErrorCode?: string;
  startedAt: Date;
  endedAt: Date;
}

export type ProcessRunner = (req: ProcessRequest) => Promise<ProcessOutcome>;

export interface ParseResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

export interface Classification {
  status: ScannerStatusValue;
  exitClass: ExitClass;
  cause?: StatusCause;
  causeDetail?: string;
}

export interface Sanitized {
  bytes: Buffer;
  redactions: number;
  mediaType: 'application/json' | 'text/plain';
}

export interface ToolPolicy<T> {
  tool: 'git' | 'npm' | 'gitleaks' | 'semgrep';
  scanner?: ScannerId;
  versionArgs: readonly string[];
  parse(output: Buffer): ParseResult<T>;
  classify(outcome: ProcessOutcome, parsed: ParseResult<T>): Classification;
  sanitize(output: Buffer, parsed: ParseResult<T>): Sanitized;
}

export interface ToolInvocation {
  stepId: string;
  attempt: number;
  runId: string;
  source: { repoUrl: string; revision: string | null };
  args: readonly string[];
  cwd: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  envOverrides?: Readonly<Record<string, string>>;
  outputFrom: 'stdout' | { file: string };
  inputs?: Record<string, string>;
  overrideAttempts?: OverrideAttempt[];
  pathTokens: Record<string, string>;
}

export interface RunToolDeps {
  runner: ProcessRunner;
  store: EvidenceStore;
  clock: () => Date;
  frameworkVersion: string;
}

export interface ToolRunResult<T> {
  classification: Classification;
  parsed: ParseResult<T>;
  toolVersion: string | null;
  record: EvidenceRecord;
  evidence: EvidenceRef;
}

export type RunTool = <T>(
  inv: ToolInvocation,
  policy: ToolPolicy<T>,
  deps: RunToolDeps,
  findingIdsFor?: (parsed: ParseResult<T>) => string[],
) => Promise<ToolRunResult<T>>;

export type BuildToolEnv = (
  tool: ToolPolicy<unknown>['tool'],
  workDir: string,
  workerEnv: Readonly<Record<string, string | undefined>>,
) => { env: Record<string, string>; overrides: Record<string, string>; passthrough: string[] };
