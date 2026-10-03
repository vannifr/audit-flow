import { lstat, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { sha256Hex } from '../../evidence/hash';
import type { EvidenceRef } from '../../evidence/types';
import type { Evidence } from '../../types';
import { runTool } from '../run-tool';
import { overrideAttemptsFor } from '../source-probe';
import { MAX_FINDINGS_PER_STEP } from '../scan-types';
import type { ScanContext, ScanFinding, ScanStep, ScanStepResult } from '../scan-types';
import type { ScannerStatusEntry, ScannerStatusValue, StatusCause } from '../status';
import type { Classification, ParseResult, ProcessOutcome, ToolPolicy } from '../tool-types';
import { recordInProcessStep } from './in-process';

export interface NpmAuditVia {
  title?: unknown;
  url?: unknown;
  name?: unknown;
}

export interface NpmAuditVulnerability {
  name?: unknown;
  severity?: unknown;
  range?: unknown;
  via?: unknown;
  fixAvailable?: unknown;
}

export interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: unknown;
  error?: { code?: unknown; summary?: unknown };
}

const STEP_ID = 'scan.npm-audit';
const SCANNER = 'npm-audit' as const;
const WORK_TOKEN = '<WORK>';
const NPM_DIR = 'npm-audit';
const TIMEOUT_MS = 120_000;
const MAX_TITLE = 120;
const MAX_CONTENT = 4000;
const NPM_LOCKFILES = ['npm-shrinkwrap.json', 'package-lock.json'] as const;
const OTHER_LOCKFILES = ['yarn.lock', 'pnpm-lock.yaml'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseReport(output: Buffer): ParseResult<NpmAuditReport> {
  const text = output.toString('utf8').trim();
  if (text.length === 0) return { ok: false, error: 'npm audit produced no output' };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, error: 'npm audit output is not valid JSON' };
  }
  if (!isRecord(json)) return { ok: false, error: 'npm audit output is not a JSON object' };
  if (isRecord(json.error)) return { ok: true, value: json as NpmAuditReport };
  if (isRecord(json.vulnerabilities) && isRecord(json.metadata)) return { ok: true, value: json as NpmAuditReport };
  return { ok: false, error: 'npm audit output has an unexpected shape' };
}

function classifyReport(outcome: ProcessOutcome, parsed: ParseResult<NpmAuditReport>): Classification {
  if (!parsed.ok || parsed.value === undefined) {
    return { status: 'failed', exitClass: 'tool-error', cause: 'parse-error', causeDetail: parsed.error };
  }
  const error = parsed.value.error;
  if (error !== undefined) {
    const code = typeof error.code === 'string' ? error.code : 'unknown';
    if (code === 'ENOLOCK') {
      return { status: 'skipped', exitClass: 'tool-error', cause: 'no-lockfile', causeDetail: 'npm audit requires a lockfile' };
    }
    const summary = typeof error.summary === 'string' ? `: ${error.summary}` : '';
    return { status: 'failed', exitClass: 'tool-error', cause: 'tool-error', causeDetail: `npm audit error ${code}${summary}` };
  }
  if (outcome.exitCode === 0) return { status: 'completed', exitClass: 'success' };
  if (outcome.exitCode === 1) return { status: 'completed', exitClass: 'issues-found', cause: 'issues-found' };
  return { status: 'failed', exitClass: 'tool-error', cause: 'tool-error', causeDetail: `npm audit exited with ${outcome.exitCode}` };
}

export const npmAuditPolicy: ToolPolicy<NpmAuditReport> = {
  tool: 'npm',
  scanner: SCANNER,
  versionArgs: ['--version'],
  parse: parseReport,
  classify: classifyReport,
  sanitize: (output, parsed) => ({
    bytes: output,
    redactions: 0,
    mediaType: parsed.ok ? 'application/json' : 'text/plain',
  }),
};

type Severity = ScanFinding['severity'];

function mapSeverity(value: unknown): Severity {
  switch (typeof value === 'string' ? value.toLowerCase() : '') {
    case 'critical':
      return 'P0';
    case 'high':
      return 'P1';
    case 'moderate':
      return 'P2';
    default:
      return 'P3';
  }
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function viaItems(vuln: NpmAuditVulnerability): unknown[] {
  return Array.isArray(vuln.via) ? vuln.via : [];
}

function viaDescriptions(vuln: NpmAuditVulnerability): string[] {
  const out: string[] = [];
  for (const item of viaItems(vuln)) {
    if (typeof item === 'string') {
      out.push(item);
    } else if (isRecord(item)) {
      const title = str(item.title);
      const url = str(item.url);
      const label = [title, url].filter((part) => part.length > 0).join(' ');
      if (label.length > 0) out.push(label);
    }
  }
  return out;
}

function shortTitle(vuln: NpmAuditVulnerability): string {
  for (const item of viaItems(vuln)) {
    if (isRecord(item) && str(item.title).length > 0) return str(item.title).slice(0, MAX_TITLE);
  }
  return 'known vulnerability';
}

function fixVersion(fix: unknown): string | null {
  return isRecord(fix) && str(fix.version).length > 0 ? str(fix.version) : null;
}

function entries(report: NpmAuditReport | undefined): [string, NpmAuditVulnerability][] {
  if (report === undefined || !isRecord(report.vulnerabilities)) return [];
  return Object.entries(report.vulnerabilities).filter((entry): entry is [string, NpmAuditVulnerability] => isRecord(entry[1]));
}

function buildFindings(report: NpmAuditReport, evidence: EvidenceRef, now: Date): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const [name, vuln] of entries(report).slice(0, MAX_FINDINGS_PER_STEP)) {
    const severity = mapSeverity(vuln.severity);
    const via = viaDescriptions(vuln);
    const fix = fixVersion(vuln.fixAvailable);
    const content = JSON.stringify({
      package: name,
      range: str(vuln.range),
      via,
      fixAvailable: vuln.fixAvailable ?? false,
    }).slice(0, MAX_CONTENT);
    const item: Evidence = { type: 'scan-output', file: 'package.json', content, tool: 'npm', timestamp: now };
    const viaSuffix = via.length > 0 ? `: ${via.join('; ')}` : '';
    findings.push({
      id: `DEP-${findings.length + 1}`,
      title: `${name}: ${shortTitle(vuln)}`,
      description: `Known vulnerability in dependency ${name}${viaSuffix}`.slice(0, MAX_CONTENT),
      severity,
      category: 'security-dependencies',
      evidence: [item],
      remediation: {
        description: `Update ${name} to ${fix ?? 'latest'}`,
        effort: 'hours',
        priority: severity === 'P0' ? 'immediate' : 'short-term',
      },
      verified: true,
      createdAt: now,
      evidenceRef: { ...evidence, locator: `vulnerabilities.${name}` },
      scanner: SCANNER,
      heuristic: false,
    });
  }
  return findings;
}

function findingIds(report: NpmAuditReport | undefined): string[] {
  return entries(report)
    .slice(0, MAX_FINDINGS_PER_STEP)
    .map((_, index) => `DEP-${index + 1}`);
}

async function isRegularFile(file: string): Promise<boolean> {
  try {
    return (await lstat(file)).isFile();
  } catch {
    return false;
  }
}

async function firstFile(dir: string, names: readonly string[]): Promise<string | null> {
  for (const name of names) {
    if (await isRegularFile(path.join(dir, name))) return name;
  }
  return null;
}

async function skip(
  ctx: ScanContext,
  cause: Extract<StatusCause, 'not-applicable' | 'no-lockfile' | 'unsupported-lockfile'>,
  detail: string,
  required: boolean,
): Promise<ScanStepResult> {
  const { record, evidence } = await recordInProcessStep(ctx, {
    stepId: STEP_ID,
    scanner: SCANNER,
    toolName: 'npm',
    status: 'skipped',
    cause,
    causeDetail: detail,
  });
  return {
    scanner: SCANNER,
    status: entry(required, 'skipped', cause, detail, null, 0, [record.id]),
    findings: [],
    evidence,
  };
}

function entry(
  required: boolean,
  status: ScannerStatusValue,
  cause: StatusCause | undefined,
  causeDetail: string | undefined,
  toolVersion: string | null,
  findingCount: number,
  evidenceRecordIds: string[],
): ScannerStatusEntry {
  return {
    scanner: SCANNER,
    required,
    status,
    ...(cause !== undefined ? { cause } : {}),
    ...(causeDetail !== undefined ? { causeDetail } : {}),
    heuristic: false,
    toolVersion,
    findingCount,
    evidenceRecordIds,
  };
}

async function failPrepare(ctx: ScanContext): Promise<ScanStepResult> {
  const detail = 'could not prepare the isolated npm audit directory';
  const { record, evidence } = await recordInProcessStep(ctx, {
    stepId: STEP_ID,
    scanner: SCANNER,
    toolName: 'npm',
    status: 'failed',
    cause: 'tool-error',
    causeDetail: detail,
  });
  return { scanner: SCANNER, status: entry(true, 'failed', 'tool-error', detail, null, 0, [record.id]), findings: [], evidence };
}

export const runNpmAuditScan: ScanStep = async (ctx) => {
  const repoDir = ctx.source.repoDir;
  if (!(await isRegularFile(path.join(repoDir, 'package.json')))) {
    return skip(ctx, 'not-applicable', 'no package.json in the source', false);
  }
  const lockfile = await firstFile(repoDir, NPM_LOCKFILES);
  if (lockfile === null) {
    const other = await firstFile(repoDir, OTHER_LOCKFILES);
    if (other !== null) return skip(ctx, 'unsupported-lockfile', `${other} is not supported by npm audit`, true);
    return skip(ctx, 'no-lockfile', 'no npm lockfile in the source', true);
  }

  const isolated = path.join(ctx.run.workDir, NPM_DIR);
  let lockfileSha256: string;
  try {
    const manifest = await readFile(path.join(repoDir, 'package.json'));
    const lock = await readFile(path.join(repoDir, lockfile));
    lockfileSha256 = sha256Hex(lock);
    await rm(isolated, { recursive: true, force: true });
    await mkdir(isolated, { recursive: true, mode: 0o700 });
    await writeFile(path.join(isolated, 'package.json'), manifest, { mode: 0o600 });
    await writeFile(path.join(isolated, lockfile), lock, { mode: 0o600 });
  } catch {
    return failPrepare(ctx);
  }

  const result = await runTool(
    {
      stepId: STEP_ID,
      attempt: ctx.attempt,
      runId: ctx.run.runId,
      source: { repoUrl: ctx.repoUrl, revision: ctx.source.revision },
      args: ['audit', '--json'],
      cwd: isolated,
      timeoutMs: TIMEOUT_MS,
      outputFrom: 'stdout',
      inputs: { lockfileSha256 },
      overrideAttempts: overrideAttemptsFor('npm-audit', ctx.overrideAttempts),
      pathTokens: { [ctx.run.workDir]: WORK_TOKEN },
    },
    npmAuditPolicy,
    ctx.deps,
    (parsed) => findingIds(parsed.value),
  );

  const { classification } = result;
  const report = result.parsed.value;
  const analysed = classification.status === 'completed' && report !== undefined;
  const findings = analysed ? buildFindings(report, result.evidence, ctx.deps.clock()) : [];
  const truncated = analysed && entries(report).length > MAX_FINDINGS_PER_STEP;
  const status: ScannerStatusValue = truncated ? 'partial' : classification.status;
  const cause = truncated ? 'findings-truncated' : classification.cause;
  return {
    scanner: SCANNER,
    status: entry(
      true,
      status,
      cause,
      truncated ? `more than ${MAX_FINDINGS_PER_STEP} vulnerabilities; the report was cut off` : classification.causeDetail,
      result.toolVersion,
      findings.length,
      [result.record.id],
    ),
    findings,
    evidence: result.evidence,
  };
};
