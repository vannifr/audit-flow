import path from 'node:path';
import { redactSecrets } from '../../evidence/redact';
import type { ScanContext, ScanFinding, ScanStep, ScanStepResult } from '../scan-types';
import { MAX_FINDINGS_PER_STEP } from '../scan-types';
import { runTool } from '../run-tool';
import type { ScannerStatusEntry } from '../status';
import type { Classification, ParseResult, ProcessOutcome, Sanitized, ToolPolicy } from '../tool-types';

export interface GitleaksLeak {
  RuleID: string;
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Fingerprint: string;
  Match: string;
  Secret: string;
}

const EXIT_LEAKS = 42;
const STEP_ID = 'scan.gitleaks';
const TIMEOUT_MS = 300_000;
const REDACTED = '[REDACTED]';
const REMEDIATION =
  'Remove secret from code and rotate immediately. Move to environment variables or secrets manager.';

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function num(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function normalize(item: unknown): GitleaksLeak | null {
  if (typeof item !== 'object' || item === null || Array.isArray(item)) return null;
  const raw = item as Record<string, unknown>;
  const ruleId = str(raw.RuleID);
  const file = str(raw.File);
  if (ruleId.length === 0 || file.length === 0) return null;
  return {
    RuleID: ruleId,
    Description: str(raw.Description),
    File: file,
    StartLine: num(raw.StartLine),
    EndLine: num(raw.EndLine),
    Fingerprint: str(raw.Fingerprint),
    Match: str(raw.Match),
    Secret: str(raw.Secret),
  };
}

function parse(output: Buffer): ParseResult<GitleaksLeak[]> {
  const text = output.toString('utf8').trim();
  if (text.length === 0) return { ok: true, value: [] };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, error: 'gitleaks output is not valid JSON' };
  }
  if (!Array.isArray(json)) return { ok: false, error: 'gitleaks output is not a JSON array' };
  const leaks: GitleaksLeak[] = [];
  for (const item of json) {
    const leak = normalize(item);
    if (leak === null) return { ok: false, error: 'gitleaks report entry has an unexpected shape' };
    leaks.push(leak);
  }
  return { ok: true, value: leaks };
}

function classify(outcome: ProcessOutcome, parsed: ParseResult<GitleaksLeak[]>): Classification {
  const code = outcome.exitCode;
  if (code !== 0 && code !== EXIT_LEAKS) {
    return {
      status: 'failed',
      exitClass: 'tool-error',
      cause: 'tool-error',
      causeDetail: code === null ? 'gitleaks produced no exit code' : `gitleaks exited with code ${code}`,
    };
  }
  if (outcome.stdout.toString('utf8').trim().length === 0) {
    return { status: 'failed', exitClass: 'tool-error', cause: 'parse-error', causeDetail: 'gitleaks produced no report' };
  }
  const count = parsed.ok && parsed.value !== undefined ? parsed.value.length : 0;
  const exitClass = code === 0 ? 'success' : 'issues-found';
  if (count > MAX_FINDINGS_PER_STEP) {
    return {
      status: 'partial',
      exitClass,
      cause: 'findings-truncated',
      causeDetail: `${count} leaks found, first ${MAX_FINDINGS_PER_STEP} reported`,
    };
  }
  if (code === 0) return { status: 'completed', exitClass };
  return { status: 'completed', exitClass, cause: 'issues-found' };
}

function sanitize(output: Buffer, parsed: ParseResult<GitleaksLeak[]>): Sanitized {
  if (!parsed.ok || parsed.value === undefined) {
    const redacted = redactSecrets(output.toString('utf8'));
    return { bytes: Buffer.from(redacted.text, 'utf8'), redactions: redacted.redactions, mediaType: 'text/plain' };
  }
  let redactions = 0;
  const safe = parsed.value.map((leak) => {
    const known = leak.Secret.length > 0 ? [leak.Secret] : [];
    const clean = (text: string): string => {
      const result = redactSecrets(text, known);
      redactions += result.redactions;
      return result.text;
    };
    if (leak.Secret.length > 0 || leak.Match.length > 0) redactions += 1;
    return {
      RuleID: clean(leak.RuleID),
      Description: clean(leak.Description),
      File: clean(leak.File),
      StartLine: leak.StartLine,
      EndLine: leak.EndLine,
      Fingerprint: clean(leak.Fingerprint),
      Match: REDACTED,
      Secret: REDACTED,
    };
  });
  return { bytes: Buffer.from(JSON.stringify(safe, null, 2), 'utf8'), redactions, mediaType: 'application/json' };
}

export const gitleaksPolicy: ToolPolicy<GitleaksLeak[]> = {
  tool: 'gitleaks',
  scanner: 'gitleaks',
  versionArgs: ['version'],
  parse,
  classify,
  sanitize,
};

function relativeFile(file: string, repoDir: string): string {
  if (!path.isAbsolute(file)) return file;
  const rel = path.relative(repoDir, file);
  return rel.length > 0 && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : file;
}

function buildArgs(ctx: ScanContext): string[] {
  return [
    'dir',
    '--no-banner',
    '--redact=100',
    '--exit-code',
    String(EXIT_LEAKS),
    '--report-format',
    'json',
    '--report-path',
    '-',
    '--config',
    path.join(ctx.configDir, 'gitleaks.toml'),
    '--ignore-gitleaks-allow',
    '.',
  ];
}

function keptLeaks(parsed: ParseResult<GitleaksLeak[]>): GitleaksLeak[] {
  return parsed.ok && parsed.value !== undefined ? parsed.value.slice(0, MAX_FINDINGS_PER_STEP) : [];
}

export const runGitleaksScan: ScanStep = async (ctx): Promise<ScanStepResult> => {
  const result = await runTool(
    {
      stepId: STEP_ID,
      attempt: ctx.attempt,
      runId: ctx.run.runId,
      source: { repoUrl: ctx.repoUrl, revision: ctx.source.revision },
      args: buildArgs(ctx),
      cwd: ctx.source.repoDir,
      timeoutMs: TIMEOUT_MS,
      outputFrom: 'stdout',
      pathTokens: { [ctx.source.repoDir]: '<SRC>', [ctx.run.workDir]: '<WORK>' },
    },
    gitleaksPolicy,
    ctx.deps,
    (parsed) => keptLeaks(parsed).map((_, index) => `LEAK-${index + 1}`),
  );

  const { classification } = result;
  const usable = classification.status === 'completed' || classification.status === 'partial';
  const createdAt = ctx.deps.clock();
  const findings: ScanFinding[] = usable
    ? keptLeaks(result.parsed).map((leak, index) => {
        const file = redactSecrets(relativeFile(leak.File, ctx.source.repoDir)).text;
        const known = leak.Secret.length > 0 ? [leak.Secret] : [];
        return {
          id: `LEAK-${index + 1}`,
          title: redactSecrets(`Secret detected: ${leak.RuleID}`, known).text,
          description: `Hardcoded secret found in ${file}`,
          severity: 'P0',
          category: 'security-data',
          evidence: [
            {
              type: 'scan-output',
              file,
              line: leak.StartLine,
              content: redactSecrets(leak.Match, known).text,
              tool: 'gitleaks',
              timestamp: createdAt,
            },
          ],
          remediation: { description: REMEDIATION, effort: 'hours', priority: 'immediate' },
          verified: false,
          createdAt,
          evidenceRef: result.evidence,
          scanner: 'gitleaks',
        };
      })
    : [];

  const status: ScannerStatusEntry = {
    scanner: 'gitleaks',
    required: true,
    status: classification.status,
    ...(classification.cause !== undefined ? { cause: classification.cause } : {}),
    ...(classification.causeDetail !== undefined ? { causeDetail: classification.causeDetail } : {}),
    heuristic: false,
    toolVersion: result.toolVersion,
    findingCount: findings.length,
    evidenceRecordIds: [result.record.id],
  };

  return { scanner: 'gitleaks', status, findings, evidence: result.evidence };
};
