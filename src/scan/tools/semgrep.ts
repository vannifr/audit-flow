import { redactSecrets } from '../../evidence/redact';
import type { Finding } from '../../types';
import { MAX_FINDINGS_PER_STEP } from '../scan-types';
import type { ScanContext, ScanFinding, ScanStep, ScanStepResult } from '../scan-types';
import type { ScannerStatusEntry } from '../status';
import { runTool } from '../run-tool';
import { overrideAttemptsFor } from '../source-probe';
import type { Classification, ParseResult, ProcessOutcome, Sanitized, ToolInvocation, ToolPolicy } from '../tool-types';

type Json = Record<string, unknown>;

export interface SemgrepReport {
  results: unknown[];
  errors: unknown[];
  paths?: unknown;
  version?: unknown;
}

const STEP_ID = 'scan.semgrep';
const TIMEOUT_MS = 180_000;
const PACKS = ['p/javascript', 'p/nodejs'] as const;
const WORK_TOKEN = '<WORK>';

const SEMGREP_ARGS: readonly string[] = [
  '--metrics=off',
  ...PACKS.flatMap((pack) => ['--config', pack]),
  '--disable-nosem',
  '--disable-version-check',
  '--json',
  '--quiet',
  '.',
];

function isObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function lineOf(result: Json): number | undefined {
  const start = result.start;
  if (!isObject(start)) return undefined;
  return typeof start.line === 'number' ? start.line : undefined;
}

function relPath(value: unknown): string {
  return (str(value) ?? '<unknown>').replace(/^(\.\/)+/, '');
}

function severityToP(severity: unknown): Finding['severity'] {
  switch (typeof severity === 'string' ? severity.toUpperCase() : '') {
    case 'ERROR':
      return 'P0';
    case 'WARNING':
      return 'P1';
    case 'INFO':
      return 'P2';
    default:
      return 'P3';
  }
}

function parse(output: Buffer): ParseResult<SemgrepReport> {
  let body: unknown;
  try {
    body = JSON.parse(output.toString('utf8'));
  } catch {
    return { ok: false, error: 'semgrep output is not valid JSON' };
  }
  if (!isObject(body) || !Array.isArray(body.results)) {
    return { ok: false, error: 'semgrep output has no results array' };
  }
  if (body.errors !== undefined && !Array.isArray(body.errors)) {
    return { ok: false, error: 'semgrep errors field is not an array' };
  }
  return {
    ok: true,
    value: { results: body.results, errors: body.errors ?? [], paths: body.paths, version: body.version },
  };
}

function classify(outcome: ProcessOutcome, parsed: ParseResult<SemgrepReport>): Classification {
  if (!parsed.ok || parsed.value === undefined) {
    return { status: 'failed', exitClass: 'tool-error', cause: 'parse-error', causeDetail: parsed.error };
  }
  const report = parsed.value;
  const hasResults = report.results.length > 0;
  if (outcome.exitCode === 0 || outcome.exitCode === 1) {
    if (report.errors.length > 0) {
      return {
        status: 'partial',
        exitClass: 'tool-error',
        cause: 'tool-reported-errors',
        causeDetail: `${report.errors.length} error(s) reported by semgrep`,
      };
    }
    return hasResults
      ? { status: 'completed', exitClass: 'issues-found', cause: 'issues-found' }
      : { status: 'completed', exitClass: 'success' };
  }
  return {
    status: hasResults ? 'partial' : 'failed',
    exitClass: 'tool-error',
    cause: 'tool-error',
    causeDetail: `semgrep exited with ${outcome.exitCode ?? 'no exit code'}`,
  };
}

function sanitize(output: Buffer, parsed: ParseResult<SemgrepReport>): Sanitized {
  if (!parsed.ok || parsed.value === undefined) {
    const redacted = redactSecrets(output.toString('utf8'));
    return { bytes: Buffer.from(redacted.text, 'utf8'), redactions: redacted.redactions, mediaType: 'text/plain' };
  }
  let redactions = 0;
  const clean = (value: unknown): string | undefined => {
    const text = str(value);
    if (text === undefined) return undefined;
    const redacted = redactSecrets(text);
    redactions += redacted.redactions;
    return redacted.text;
  };
  const results = parsed.value.results.filter(isObject).map((r) => {
    const extra = isObject(r.extra) ? r.extra : {};
    return {
      check_id: r.check_id,
      path: r.path,
      start: r.start,
      end: r.end,
      extra: { message: clean(extra.message), severity: extra.severity, metadata: extra.metadata },
    };
  });
  const errors = parsed.value.errors.filter(isObject).map((e) => ({
    code: e.code,
    level: e.level,
    type: e.type,
    message: clean(e.message),
  }));
  const body = { version: parsed.value.version, results, errors, paths: parsed.value.paths };
  return { bytes: Buffer.from(JSON.stringify(body), 'utf8'), redactions, mediaType: 'application/json' };
}

export const semgrepPolicy: ToolPolicy<SemgrepReport> = {
  tool: 'semgrep',
  scanner: 'semgrep',
  versionArgs: ['--version'],
  parse,
  classify,
  sanitize,
};

interface Hit {
  title: string;
  file: string;
  line: number | undefined;
  message: string;
  severity: Finding['severity'];
}

function hitsOf(report: SemgrepReport | undefined): Hit[] {
  const seen = new Set<string>();
  const hits: Hit[] = [];
  for (const r of (report?.results ?? []).filter(isObject)) {
    const checkId = str(r.check_id) ?? 'unknown-rule';
    const file = relPath(r.path);
    const line = lineOf(r);
    const key = `${checkId}\u0000${file}\u0000${line ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const extra = isObject(r.extra) ? r.extra : {};
    hits.push({
      title: checkId.split('.').pop() ?? checkId,
      file,
      line,
      message: redactSecrets(str(extra.message) ?? 'Security issue detected').text,
      severity: severityToP(extra.severity),
    });
  }
  return hits;
}

function findingIdsOf(hits: Hit[]): string[] {
  return hits.slice(0, MAX_FINDINGS_PER_STEP).map((_, i) => `SAST-${i + 1}`);
}

export const runSemgrepScan: ScanStep = async (ctx: ScanContext): Promise<ScanStepResult> => {
  const invocation: ToolInvocation = {
    stepId: STEP_ID,
    attempt: ctx.attempt,
    runId: ctx.run.runId,
    source: { repoUrl: ctx.repoUrl, revision: ctx.source.revision },
    args: SEMGREP_ARGS,
    cwd: ctx.source.repoDir,
    timeoutMs: TIMEOUT_MS,
    outputFrom: 'stdout',
    inputs: { configs: PACKS.join(',') },
    overrideAttempts: overrideAttemptsFor('semgrep', ctx.overrideAttempts),
    pathTokens: { [ctx.run.workDir]: WORK_TOKEN },
  };
  const result = await runTool(invocation, semgrepPolicy, ctx.deps, (parsed) => findingIdsOf(hitsOf(parsed.value)));
  const hits = hitsOf(result.parsed.value);
  const kept = hits.slice(0, MAX_FINDINGS_PER_STEP);
  const createdAt = ctx.deps.clock();
  const findings: ScanFinding[] = kept.map((hit, i) => ({
    id: `SAST-${i + 1}`,
    title: hit.title,
    description: hit.message,
    severity: hit.severity,
    category: 'security-injection',
    evidence: [
      {
        type: 'scan-output',
        file: hit.file,
        ...(hit.line !== undefined ? { line: hit.line } : {}),
        content: `${hit.file}${hit.line !== undefined ? `:${hit.line}` : ''} ${hit.message}`,
        tool: 'semgrep',
        timestamp: createdAt,
      },
    ],
    remediation: { description: 'Fix the security issue', effort: 'hours', priority: 'immediate' },
    verified: false,
    createdAt,
    evidenceRef: result.evidence,
    scanner: 'semgrep',
  }));

  let { status, cause, causeDetail } = {
    status: result.classification.status,
    cause: result.classification.cause,
    causeDetail: result.classification.causeDetail,
  };
  if (hits.length > MAX_FINDINGS_PER_STEP && status === 'completed') {
    status = 'partial';
    cause = 'findings-truncated';
    causeDetail = `${hits.length} findings, kept ${MAX_FINDINGS_PER_STEP}`;
  }

  const entry: ScannerStatusEntry = {
    scanner: 'semgrep',
    required: true,
    status,
    ...(cause !== undefined ? { cause } : {}),
    ...(causeDetail !== undefined ? { causeDetail } : {}),
    heuristic: false,
    toolVersion: result.toolVersion,
    findingCount: findings.length,
    evidenceRecordIds: [result.record.id],
  };
  return { scanner: 'semgrep', status: entry, findings, evidence: result.evidence };
};
