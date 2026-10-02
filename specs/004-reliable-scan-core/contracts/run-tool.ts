// Contract: central tool runner (FR-004, FR-005, FR-006, FR-012, FR-013, FR-014)
// Target modules: src/scan/process-runner.ts, src/scan/run-tool.ts, src/scan/policies/*.ts
// Replaces every promisify(exec) call. No shell is ever involved.

import type { ScannerStatusValue, StatusCause, ScannerId } from './scanner-status';
import type { EvidenceRecord, EvidenceRef, EvidenceStore, ExitClass, OverrideAttempt } from './evidence-record';

// ---------- Layer 1: injectable process runner (the only code that touches child_process) ----------

export interface ProcessRequest {
  file: string;                       // binary name resolved via the allowlisted PATH, never a shell string
  args: readonly string[];            // passed as an array; user-controlled positionals follow a "--" separator where the tool supports it
  cwd: string;
  env: Readonly<Record<string, string>>; // complete environment (built by buildToolEnv), not merged with process.env
  timeoutMs: number;
  maxOutputBytes: number;             // stdout cap; default 64 MiB, env TESSERA_MAX_OUTPUT_MB
  maxStderrBytes: number;             // default 1 MiB
}

export interface ProcessOutcome {
  exitCode: number | null;
  signal: string | null;
  stdout: Buffer;
  stderr: Buffer;
  stdoutTruncated: boolean;           // maxOutputBytes exceeded (ERR_CHILD_PROCESS_STDIO_MAXBUFFER)
  timedOut: boolean;
  spawnErrorCode?: string;            // e.g. "ENOENT" -> not-installed
  startedAt: Date;
  endedAt: Date;
}

// Never rejects: every failure mode is expressed in ProcessOutcome.
// Default implementation: child_process.execFile with { shell: false, encoding: 'buffer', killSignal: 'SIGKILL', windowsHide: true }.
export type ProcessRunner = (req: ProcessRequest) => Promise<ProcessOutcome>;

// ---------- Layer 2: per-tool policy (pure, unit-testable without processes) ----------

export interface ParseResult<T> {
  ok: boolean;
  value?: T;
  error?: string;                     // redacted, <= 500 chars
}

export interface Classification {
  status: ScannerStatusValue;
  exitClass: ExitClass;
  cause?: StatusCause;
  causeDetail?: string;
}

export interface Sanitized {
  bytes: Buffer;                      // what is stored as the evidence artifact
  redactions: number;
  mediaType: 'application/json' | 'text/plain';
}

export interface ToolPolicy<T> {
  tool: 'git' | 'npm' | 'gitleaks' | 'semgrep';
  scanner?: ScannerId;
  versionArgs: readonly string[];     // git/npm/semgrep: ["--version"], gitleaks: ["version"]
  parse(output: Buffer): ParseResult<T>;
  classify(outcome: ProcessOutcome, parsed: ParseResult<T>): Classification;
  sanitize(output: Buffer, parsed: ParseResult<T>): Sanitized;
}

// ---------- Layer 3: runTool = process + policy + evidence ----------

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
  outputFrom: 'stdout' | { file: string }; // file mode reads a report path inside the work dir
  inputs?: Record<string, string>;
  overrideAttempts?: OverrideAttempt[];
  pathTokens: Record<string, string>;     // absolute path -> token, e.g. { "/tmp/tessera-<id>": "<WORK>" }
}

export interface RunToolDeps {
  runner: ProcessRunner;
  store: EvidenceStore;
  clock: () => Date;
  frameworkVersion: string;
}

export interface ToolRunResult<T> {
  classification: Classification;
  parsed: ParseResult<T>;             // in-memory only; never returned from an activity
  toolVersion: string | null;
  record: EvidenceRecord;
  evidence: EvidenceRef;
}

// Writes exactly one evidence record per call, also on spawn failure, timeout or parse error (FR-005).
// Throws only on evidence-store failure (fail closed: no record means no claim).
export type RunTool = <T>(
  inv: ToolInvocation,
  policy: ToolPolicy<T>,
  deps: RunToolDeps,
  findingIdsFor?: (parsed: ParseResult<T>) => string[],
) => Promise<ToolRunResult<T>>;

// Environment allowlist (src/scan/env.ts):
//   base:        PATH, LANG, LC_ALL, TZ=UTC, HOME=<WORK>/home, TMPDIR=<WORK>/tmp, NO_COLOR=1
//   passthrough: HTTPS_PROXY, HTTP_PROXY, NO_PROXY (operator network config, recorded by name only)
//   git only:    GIT_TERMINAL_PROMPT=0, GIT_ASKPASS=, GIT_LFS_SKIP_SMUDGE=1, GIT_CONFIG_NOSYSTEM=1,
//                GIT_CONFIG_GLOBAL=/dev/null, passthrough GIT_CONFIG_COUNT/KEY_n/VALUE_n (operator rewrite rules)
//   never:       NODE_OPTIONS, npm_config_*, GITHUB_TOKEN, SEMGREP_*, any other worker variable
export type BuildToolEnv = (
  tool: ToolPolicy<unknown>['tool'],
  workDir: string,
  workerEnv: Readonly<Record<string, string | undefined>>,
) => { env: Record<string, string>; overrides: Record<string, string>; passthrough: string[] };

// Exit-code policy table (implemented in policies, asserted by unit tests):
//   git clone      0 success | 128 + transient stderr -> failed/network (activity retries) | other -> failed/tool-error
//   git rev-parse  0 + /^[0-9a-f]{40}([0-9a-f]{24})?$/ -> success | else failed
//   npm audit      0 or 1 + JSON {vulnerabilities, metadata} -> completed (1 = issues-found)
//                  JSON {error:{code}} -> failed (ENOLOCK -> skipped/no-lockfile) | non-JSON -> failed/parse-error
//   gitleaks       0 -> completed | 42 (--exit-code 42) -> completed/issues-found | 1 or other -> failed/tool-error
//   semgrep        0 or 1 + JSON: errors[] empty -> completed, errors[] non-empty with results -> partial/tool-reported-errors
//                  >= 2 + JSON with results -> partial | >= 2 without results -> failed/tool-error | non-JSON -> failed/parse-error
//   all tools      spawn ENOENT -> unavailable/not-installed | timeout -> failed/timeout | stdout cap hit -> partial/output-truncated
