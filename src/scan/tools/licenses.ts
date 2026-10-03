import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { sha256Hex } from '../../evidence/hash';
import { redactSecrets } from '../../evidence/redact';
import type { Evidence } from '../../types';
import { MAX_FINDINGS_PER_STEP } from '../scan-types';
import type { ScanContext, ScanFinding, ScanStep, ScanStepResult } from '../scan-types';
import type { ScannerStatusEntry, ScannerStatusValue, StatusCause } from '../status';
import { recordInProcessStep } from './in-process';

export const MAX_LOCKFILE_BYTES = 50 * 1024 * 1024;

const STEP_ID = 'license-check';
const TOOL_NAME = 'tessera-license-check';
const LOCKFILES = ['npm-shrinkwrap.json', 'package-lock.json'] as const;
const UNSUPPORTED_LOCKFILES = ['yarn.lock', 'pnpm-lock.yaml'] as const;
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const MISSING_NAMES_SHOWN = 20;
const MAX_CONTENT = 500;
const MAX_TITLE = 300;

type LockfileName = (typeof LOCKFILES)[number];

interface PackageVerdict {
  name: string;
  version: string;
  license: string;
}

interface Assessment {
  packages: number;
  violations: PackageVerdict[];
  missing: string[];
  rejected: number;
  malformed: number;
}

interface Outcome {
  status: ScannerStatusValue;
  cause?: StatusCause;
  causeDetail?: string;
  inputs: Record<string, string>;
  lockfileName?: LockfileName;
  assessment?: Assessment;
  lockfileVersion?: number;
}

type Node =
  | { op: 'leaf'; id: string }
  | { op: 'and' | 'or'; items: Node[] };

function clean(text: string, max: number): string {
  const flat = Array.from(text, (ch) => ((ch.codePointAt(0) ?? 0) < 32 || (ch.codePointAt(0) ?? 0) === 127 ? ' ' : ch)).join('');
  const redacted = redactSecrets(flat).text;
  return redacted.length > max ? `${redacted.slice(0, max - 3)}...` : redacted;
}

const GPL_VERSION = /(-?V?\d+(\.\d+)*)?/;
const GPL_SUFFIX = /(\+|-ONLY|-OR-LATER|-WITH-.*)?/;
const GPL_ID = new RegExp(`^A?GPL${GPL_VERSION.source}${GPL_SUFFIX.source}$`);

function isStrongCopyleft(id: string): boolean {
  const s = id.trim().toUpperCase().replace(/[\s_]+/g, '-').replace(/^GNU-/, '');
  if (GPL_ID.test(s)) return true;
  return /^(AFFERO-)?GENERAL-PUBLIC-LICEN[CS]E/.test(s);
}

function tokenize(expr: string): string[] {
  return expr.replace(/([()])/g, ' $1 ').split(/\s+/).filter((t) => t.length > 0);
}

function parseExpression(expr: string): Node | null {
  const tokens = tokenize(expr);
  let pos = 0;
  const peek = (): string | undefined => tokens[pos];
  const isOp = (t: string | undefined, op: string): boolean => t !== undefined && t.toUpperCase() === op;

  const parseAtom = (): Node | null => {
    const t = peek();
    if (t === undefined || t === ')' || isOp(t, 'AND') || isOp(t, 'OR') || isOp(t, 'WITH')) return null;
    pos++;
    if (t === '(') {
      const inner = parseOr();
      if (inner === null || peek() !== ')') return null;
      pos++;
      return inner;
    }
    if (isOp(peek(), 'WITH')) {
      pos++;
      const exc = peek();
      if (exc === undefined || exc === '(' || exc === ')') return null;
      pos++;
    }
    return { op: 'leaf', id: t };
  };

  const parseBinary = (op: 'and' | 'or', next: () => Node | null): Node | null => {
    const first = next();
    if (first === null) return null;
    const items = [first];
    while (isOp(peek(), op.toUpperCase())) {
      pos++;
      const item = next();
      if (item === null) return null;
      items.push(item);
    }
    return items.length === 1 ? first : { op, items };
  };

  const parseAnd = (): Node | null => parseBinary('and', parseAtom);
  const parseOr = (): Node | null => parseBinary('or', parseAnd);

  const tree = parseOr();
  return tree !== null && pos === tokens.length ? tree : null;
}

function violates(node: Node): boolean {
  if (node.op === 'leaf') return isStrongCopyleft(node.id);
  if (node.op === 'and') return node.items.some(violates);
  return node.items.every(violates);
}

function isViolation(license: string): boolean {
  const tree = parseExpression(license);
  if (tree !== null) return violates(tree);
  if (isStrongCopyleft(license)) return true;
  const tokens = tokenize(license);
  return !tokens.some((t) => t.toUpperCase() === 'OR') && tokens.some(isStrongCopyleft);
}

function licenseText(value: unknown): string | null {
  if (typeof value === 'string') return value.trim().length > 0 ? value.trim() : null;
  if (Array.isArray(value)) {
    const parts = value.map(licenseText).filter((p): p is string => p !== null);
    if (parts.length === 0) return null;
    return parts.map((p) => (/\s/.test(p) ? `(${p})` : p)).join(' OR ');
  }
  if (typeof value === 'object' && value !== null && Object.hasOwn(value, 'type')) {
    return licenseText((value as { type: unknown }).type);
  }
  return null;
}

function packageName(key: string): string {
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  return idx === -1 ? key : key.slice(idx + marker.length);
}

function hasForbiddenSegment(key: string): boolean {
  return key.split('/').some((seg) => FORBIDDEN_SEGMENTS.has(seg));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ownString(obj: Record<string, unknown>, key: string): string | undefined {
  if (!Object.hasOwn(obj, key)) return undefined;
  const v = obj[key];
  return typeof v === 'string' ? v : undefined;
}

function assess(packages: Record<string, unknown>): Assessment {
  const result: Assessment = { packages: 0, violations: [], missing: [], rejected: 0, malformed: 0 };
  for (const key of Object.keys(packages)) {
    if (key === '') continue;
    if (hasForbiddenSegment(key)) {
      result.rejected++;
      continue;
    }
    const entry = packages[key];
    if (!isRecord(entry)) {
      result.malformed++;
      continue;
    }
    if (Object.hasOwn(entry, 'link') && entry.link === true) continue;
    result.packages++;
    const name = packageName(key);
    const version = ownString(entry, 'version') ?? 'unknown';
    const license = Object.hasOwn(entry, 'license') ? licenseText(entry.license) : null;
    if (license === null) {
      result.missing.push(name);
    } else if (isViolation(license)) {
      result.violations.push({ name, version, license });
    }
  }
  return result;
}

async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

type ReadResult = { ok: true; bytes: Buffer } | { ok: false; detail: string };

async function readLockfile(file: string, name: string): Promise<ReadResult> {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'unknown';
    const detail = code === 'ELOOP' ? `${name} is a symlink and was not read` : `${name} could not be opened (${code})`;
    return { ok: false, detail };
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) return { ok: false, detail: `${name} is not a regular file and was not read` };
    if (info.size > MAX_LOCKFILE_BYTES) {
      return { ok: false, detail: `${name} is ${info.size} bytes, above the 50 MB limit; not read` };
    }
    return { ok: true, bytes: await handle.readFile() };
  } catch (err) {
    return { ok: false, detail: `${name} could not be read (${(err as NodeJS.ErrnoException).code ?? 'unknown'})` };
  } finally {
    await handle.close();
  }
}

async function findLockfile(repoDir: string): Promise<LockfileName | undefined> {
  for (const name of LOCKFILES) {
    if (await exists(path.join(repoDir, name))) return name;
  }
  return undefined;
}

async function noLockfileOutcome(repoDir: string): Promise<Outcome> {
  const other: string[] = [];
  for (const name of UNSUPPORTED_LOCKFILES) {
    if (await exists(path.join(repoDir, name))) other.push(name);
  }
  if (other.length > 0) {
    return {
      status: 'skipped',
      cause: 'unsupported-lockfile',
      causeDetail: `only ${other.join(', ')} found; licenses are read from package-lock.json or npm-shrinkwrap.json`,
      inputs: { lockfileName: other.join(',') },
    };
  }
  return { status: 'skipped', cause: 'no-lockfile', causeDetail: 'package.json has no lockfile; licenses not checked', inputs: {} };
}

type ParsedLockfile = { ok: true; doc: Record<string, unknown> } | { ok: false; outcome: Outcome };

function parseLockfile(bytes: Buffer, lockfileName: LockfileName, inputs: Record<string, string>): ParsedLockfile {
  let doc: unknown;
  try {
    doc = JSON.parse(bytes.toString('utf8'));
  } catch {
    return { ok: false, outcome: { status: 'failed', cause: 'parse-error', causeDetail: `${lockfileName} is not valid JSON`, inputs, lockfileName } };
  }
  if (!isRecord(doc)) {
    return { ok: false, outcome: { status: 'failed', cause: 'parse-error', causeDetail: `${lockfileName} is not a JSON object`, inputs, lockfileName } };
  }
  return { ok: true, doc };
}

function lockfileV1Outcome(doc: Record<string, unknown>, lockfileName: LockfileName, inputs: Record<string, string>): Outcome {
  const deps = Object.hasOwn(doc, 'dependencies') && isRecord(doc.dependencies) ? doc.dependencies : {};
  inputs.packages = String(Object.keys(deps).length);
  return {
    status: 'partial',
    cause: 'unsupported-lockfile',
    causeDetail: `${lockfileName} uses lockfileVersion 1, which has no license fields; licenses not checked`,
    inputs,
    lockfileName,
    lockfileVersion: 1,
  };
}

function assessedOutcome(packages: Record<string, unknown>, lockfileName: LockfileName, inputs: Record<string, string>, version: 2 | 3): Outcome {
  const assessment = assess(packages);
  inputs.packages = String(assessment.packages);
  const notes: string[] = [];
  if (assessment.missing.length > 0) {
    notes.push(`${assessment.missing.length} package(s) have no license field and were not assessed`);
  }
  const invalid = assessment.rejected + assessment.malformed;
  if (invalid > 0) {
    notes.push(`${invalid} lockfile entr${invalid === 1 ? 'y was' : 'ies were'} invalid or used a forbidden package name and were ignored`);
  }
  return {
    status: invalid > 0 ? 'partial' : 'completed',
    cause: invalid > 0 ? 'parse-error' : undefined,
    causeDetail: notes.length > 0 ? notes.join('; ') : undefined,
    inputs,
    lockfileName,
    assessment,
    lockfileVersion: version,
  };
}

async function evaluate(repoDir: string): Promise<Outcome> {
  if (!(await exists(path.join(repoDir, 'package.json')))) {
    return { status: 'skipped', cause: 'not-applicable', causeDetail: 'no package.json at the repository root', inputs: {} };
  }
  const lockfileName = await findLockfile(repoDir);
  if (lockfileName === undefined) return noLockfileOutcome(repoDir);
  const read = await readLockfile(path.join(repoDir, lockfileName), lockfileName);
  if (!read.ok) {
    return { status: 'failed', cause: 'tool-error', causeDetail: read.detail, inputs: { lockfileName }, lockfileName };
  }
  const inputs: Record<string, string> = { lockfileSha256: sha256Hex(read.bytes), lockfileName };
  const parsed = parseLockfile(read.bytes, lockfileName, inputs);
  if (!parsed.ok) return parsed.outcome;
  const doc = parsed.doc;
  const version = Object.hasOwn(doc, 'lockfileVersion') ? doc.lockfileVersion : undefined;
  if (version === 1) return lockfileV1Outcome(doc, lockfileName, inputs);
  if (version !== 2 && version !== 3) {
    return {
      status: 'failed',
      cause: 'unsupported-lockfile',
      causeDetail: `${lockfileName} has unsupported lockfileVersion ${clean(JSON.stringify(version) ?? 'missing', 40)}`,
      inputs,
      lockfileName,
    };
  }
  const packages = Object.hasOwn(doc, 'packages') ? doc.packages : undefined;
  if (!isRecord(packages)) {
    return { status: 'failed', cause: 'parse-error', causeDetail: `${lockfileName} has no packages object`, inputs, lockfileName };
  }
  return assessedOutcome(packages, lockfileName, inputs, version);
}

function evidenceItem(file: string, content: string, ctx: ScanContext): Evidence {
  return { type: 'scan-output', file, content: clean(content, MAX_CONTENT), tool: 'license-check', timestamp: ctx.deps.clock() };
}

function buildFindings(ctx: ScanContext, file: string, a: Assessment): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const v of a.violations) {
    findings.push({
      id: `LIC-${findings.length + 1}`,
      title: clean(`License violation in ${v.name}`, MAX_TITLE),
      description: clean(
        `Package ${v.name}@${v.version} is licensed under ${v.license}; every license option is GPL or AGPL, which may not be compatible with commercial use`,
        MAX_CONTENT,
      ),
      severity: 'P1',
      category: 'compliance',
      evidence: [evidenceItem(file, `${v.name}@${v.version}: ${v.license}`, ctx)],
      remediation: { description: 'Review license compatibility or find alternative package', effort: 'hours', priority: 'short-term' },
      verified: true,
      createdAt: ctx.deps.clock(),
      scanner: 'license-check',
      heuristic: false,
    });
  }
  if (a.missing.length > 0) {
    const shown = a.missing.slice(0, MISSING_NAMES_SHOWN);
    findings.push({
      id: `LIC-${findings.length + 1}`,
      title: `${a.missing.length} package(s) without license information`,
      description: clean(
        `${a.missing.length} package(s) in ${file} have no license field; their licenses were not checked and may include GPL or AGPL`,
        MAX_CONTENT,
      ),
      severity: 'P3',
      category: 'compliance',
      evidence: [evidenceItem(file, `${a.missing.length} without license: ${shown.join(', ')}${a.missing.length > shown.length ? ', ...' : ''}`, ctx)],
      remediation: { description: 'Determine the license of these packages manually', effort: 'hours', priority: 'medium-term' },
      verified: true,
      createdAt: ctx.deps.clock(),
      scanner: 'license-check',
      heuristic: false,
    });
  }
  return findings;
}

export const runLicenseScan: ScanStep = async (ctx: ScanContext): Promise<ScanStepResult> => {
  const outcome = await evaluate(ctx.source.repoDir);
  const file = outcome.lockfileName ?? 'package-lock.json';
  let findings = outcome.assessment ? buildFindings(ctx, file, outcome.assessment) : [];
  let status = outcome.status;
  let cause = outcome.cause;
  let causeDetail = outcome.causeDetail;
  if (findings.length > MAX_FINDINGS_PER_STEP) {
    const total = findings.length;
    findings = findings.slice(0, MAX_FINDINGS_PER_STEP);
    status = 'partial';
    cause = 'findings-truncated';
    const note = `${total} findings, only the first ${MAX_FINDINGS_PER_STEP} are reported; the full list is in the evidence artifact`;
    causeDetail = causeDetail === undefined ? note : `${note}; ${causeDetail}`;
  }
  const output = outcome.assessment
    ? {
        bytes: Buffer.from(
          JSON.stringify({
            lockfileName: outcome.lockfileName,
            lockfileVersion: outcome.lockfileVersion,
            packages: outcome.assessment.packages,
            violations: outcome.assessment.violations,
            missingLicense: { count: outcome.assessment.missing.length, names: outcome.assessment.missing },
            ignoredEntries: outcome.assessment.rejected + outcome.assessment.malformed,
          }),
          'utf8',
        ),
        mediaType: 'application/json' as const,
        suffix: 'summary.json',
      }
    : undefined;
  const { record, evidence } = await recordInProcessStep(ctx, {
    stepId: STEP_ID,
    scanner: 'license-check',
    toolName: TOOL_NAME,
    status,
    cause,
    causeDetail,
    inputs: outcome.inputs,
    output,
    findingIds: findings.map((f) => f.id),
  });
  for (const f of findings) f.evidenceRef = evidence;
  const entry: ScannerStatusEntry = {
    scanner: 'license-check',
    required: cause !== 'not-applicable',
    status,
    heuristic: false,
    toolVersion: null,
    findingCount: findings.length,
    evidenceRecordIds: [record.id],
  };
  if (cause !== undefined) entry.cause = cause;
  if (causeDetail !== undefined) entry.causeDetail = causeDetail;
  return { scanner: 'license-check', status: entry, findings, evidence };
};
