import { constants } from 'node:fs';
import type { Stats } from 'node:fs';
import { createHash } from 'node:crypto';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { redactSecrets } from '../evidence/redact';
import type { OverrideAttempt } from '../evidence/types';
import { MAX_SOURCE_FILE_BYTES, readSourceFile, walkTree } from './safe-walk';
import type { TreeEntry, TreeEntryType } from './safe-walk';
import type { ScannerId } from './status';

type FileNeutralization = 'removed-from-working-copy' | 'isolated-working-dir';

interface ControlFileRule {
  kind: 'control-file' | 'project-config';
  scanner: ScannerId;
  description: string;
  neutralizedBy: FileNeutralization;
}

const REMOVED: FileNeutralization = 'removed-from-working-copy';
const ISOLATED: FileNeutralization = 'isolated-working-dir';

const CONTROL_FILES: ReadonlyMap<string, ControlFileRule> = new Map<string, ControlFileRule>([
  ['.gitleaks.toml', { kind: 'project-config', scanner: 'gitleaks', description: 'gitleaks configuration', neutralizedBy: REMOVED }],
  ['gitleaks.toml', { kind: 'project-config', scanner: 'gitleaks', description: 'gitleaks configuration', neutralizedBy: REMOVED }],
  ['.gitleaksignore', { kind: 'control-file', scanner: 'gitleaks', description: 'gitleaks ignore list', neutralizedBy: REMOVED }],
  ['.semgrepignore', { kind: 'control-file', scanner: 'semgrep', description: 'semgrep ignore list', neutralizedBy: REMOVED }],
  ['.semgrep.yml', { kind: 'project-config', scanner: 'semgrep', description: 'semgrep configuration', neutralizedBy: REMOVED }],
  ['.semgrep.yaml', { kind: 'project-config', scanner: 'semgrep', description: 'semgrep configuration', neutralizedBy: REMOVED }],
  ['.semgrep', { kind: 'project-config', scanner: 'semgrep', description: 'semgrep configuration directory', neutralizedBy: REMOVED }],
  ['.npmrc', { kind: 'project-config', scanner: 'npm-audit', description: 'npm configuration', neutralizedBy: ISOLATED }],
  ['.yarnrc', { kind: 'project-config', scanner: 'npm-audit', description: 'yarn configuration', neutralizedBy: ISOLATED }],
  ['.yarnrc.yml', { kind: 'project-config', scanner: 'npm-audit', description: 'yarn configuration', neutralizedBy: ISOLATED }],
  ['.nsprc', { kind: 'project-config', scanner: 'npm-audit', description: 'npm audit exceptions (nsp)', neutralizedBy: REMOVED }],
  ['.snyk', { kind: 'project-config', scanner: 'npm-audit', description: 'snyk policy', neutralizedBy: REMOVED }],
]);

export const CONTROL_FILE_NAMES: readonly string[] = [...CONTROL_FILES.keys()];

export const INLINE_MARKERS = ['gitleaks:allow', 'nosemgrep', 'nosem', 'nosec'] as const;
export type InlineMarker = (typeof INLINE_MARKERS)[number];

const MARKER_RULES: readonly { marker: InlineMarker; scanner: ScannerId; pattern: RegExp }[] = [
  { marker: 'gitleaks:allow', scanner: 'gitleaks', pattern: /gitleaks:allow/g },
  { marker: 'nosemgrep', scanner: 'semgrep', pattern: /\bnosemgrep\b/g },
  { marker: 'nosem', scanner: 'semgrep', pattern: /\bnosem\b/g },
  { marker: 'nosec', scanner: 'semgrep', pattern: /\bnosec\b/g },
];

export const MAX_OVERRIDE_ATTEMPTS = 1000;
const MAX_PATH_CHARS = 1024;
const MAX_DETAIL_CHARS = 200;
const HASH_CHUNK = 64 * 1024;
const NEUTRAL_SUFFIX = '.tessera-neutralized';
const MAX_NEUTRAL_NAMES = 100;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MARKER_DETAIL = /^inline marker "([a-z:]{1,32})" x([1-9]\d{0,9})$/;
const KINDS: ReadonlySet<string> = new Set(['control-file', 'inline-marker', 'project-config']);
const NEUTRALIZATIONS: ReadonlySet<string> = new Set(['removed-from-working-copy', 'framework-flag', 'isolated-working-dir', 'reported-as-finding']);

export interface ProbeOptions {
  maxDepth?: number;
  maxEntries?: number;
  maxMarkerFiles?: number;
  maxMarkerBytes?: number;
  maxFileBytes?: number;
  maxAttempts?: number;
}

export interface ProbeResult {
  attempts: OverrideAttempt[];
  controlFiles: number;
  inlineMarkers: number;
  entriesVisited: number;
  markerFilesScanned: number;
  truncated: boolean;
  truncation?: string;
}

function isControlChar(char: string): boolean {
  return char < ' ' || char === '\u007f';
}

function hasControlChars(text: string): boolean {
  for (const char of text) if (isControlChar(char)) return true;
  return false;
}

export function replaceControlChars(text: string, replacement: string): string {
  let out = '';
  for (const char of text) out += isControlChar(char) ? replacement : char;
  return out;
}

export function inlineMarkerDetail(marker: InlineMarker, count: number): string {
  return `inline marker "${marker}" x${count}`;
}

export function parseInlineMarkerDetail(detail: string): { marker: InlineMarker; count: number } | null {
  const match = MARKER_DETAIL.exec(detail);
  if (match === null) return null;
  const marker = INLINE_MARKERS.find((m) => m === match[1]);
  return marker === undefined ? null : { marker, count: Number(match[2]) };
}

function lastSegment(relative: string): string {
  return relative.slice(relative.lastIndexOf('/') + 1);
}

function controlRule(name: string): ControlFileRule | undefined {
  return CONTROL_FILES.get(name.toLowerCase());
}

function scannerOf(attempt: OverrideAttempt): ScannerId | null {
  if (attempt.kind === 'inline-marker') {
    const parsed = parseInlineMarkerDetail(attempt.detail);
    return parsed === null ? null : (MARKER_RULES.find((r) => r.marker === parsed.marker)?.scanner ?? null);
  }
  return controlRule(lastSegment(attempt.path))?.scanner ?? null;
}

export function overrideAttemptsFor(scanner: ScannerId, attempts: readonly OverrideAttempt[] | undefined): OverrideAttempt[] {
  return (attempts ?? []).filter((a) => scannerOf(a) === scanner).map((a) => ({ ...a }));
}

export function steeringCounts(attempts: readonly OverrideAttempt[] | undefined): { controlFiles: number; inlineMarkers: number } {
  let controlFiles = 0;
  let inlineMarkers = 0;
  for (const attempt of attempts ?? []) {
    if (attempt.kind === 'inline-marker') inlineMarkers += parseInlineMarkerDetail(attempt.detail)?.count ?? 0;
    else controlFiles += 1;
  }
  return { controlFiles, inlineMarkers };
}

function validPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PATH_CHARS) return false;
  if (hasControlChars(value) || value.startsWith('/')) return false;
  return value.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..');
}

function validDetail(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_DETAIL_CHARS && !hasControlChars(value);
}

function sanitizeOne(value: unknown): OverrideAttempt | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.kind !== 'string' || !KINDS.has(raw.kind)) return null;
  if (typeof raw.neutralizedBy !== 'string' || !NEUTRALIZATIONS.has(raw.neutralizedBy)) return null;
  if (!validPath(raw.path) || !validDetail(raw.detail)) return null;
  if (raw.sha256 !== undefined && (typeof raw.sha256 !== 'string' || !SHA256_HEX.test(raw.sha256))) return null;
  const kind = raw.kind as OverrideAttempt['kind'];
  if (kind === 'inline-marker' && parseInlineMarkerDetail(raw.detail) === null) return null;
  const clean: OverrideAttempt = { kind, path: raw.path, detail: raw.detail, neutralizedBy: raw.neutralizedBy as OverrideAttempt['neutralizedBy'] };
  if (typeof raw.sha256 === 'string') clean.sha256 = raw.sha256;
  return clean;
}

export function sanitizeOverrideAttempts(value: unknown): OverrideAttempt[] {
  if (!Array.isArray(value)) return [];
  const out: OverrideAttempt[] = [];
  for (const item of value) {
    if (out.length >= MAX_OVERRIDE_ATTEMPTS) break;
    const clean = sanitizeOne(item);
    if (clean !== null) out.push(clean);
  }
  return out;
}

function safeRelative(relative: string): string {
  const redacted = redactSecrets(replaceControlChars(relative, '?')).text;
  return redacted.length <= MAX_PATH_CHARS ? redacted : `...${redacted.slice(-(MAX_PATH_CHARS - 3))}`;
}

function compare(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function typeOf(st: Stats): TreeEntryType {
  if (st.isSymbolicLink()) return 'symlink';
  if (st.isDirectory()) return 'directory';
  if (st.isFile()) return 'file';
  return 'other';
}

function refuse(reason: string): never {
  throw new Error(`source probe: ${reason}`);
}

interface ProbeRoot {
  root: string;
  realRoot: string;
  dev: number;
}

async function openRoot(repoDir: string): Promise<ProbeRoot> {
  if (typeof repoDir !== 'string' || !path.isAbsolute(repoDir)) refuse('source dir must be an absolute path');
  const root = path.resolve(repoDir);
  const st = await lstat(root);
  if (st.isSymbolicLink()) refuse('refusing a source dir that is a symbolic link');
  if (!st.isDirectory()) refuse('source dir is not a directory');
  return { root, realRoot: await realpath(root), dev: st.dev };
}

async function checkedEntry(probeRoot: ProbeRoot, entry: TreeEntry): Promise<Stats> {
  const rel = path.relative(probeRoot.root, entry.absolute);
  if (rel.length === 0 || path.isAbsolute(rel) || rel.split(path.sep).some((s) => s === '..' || s === '.' || s === '')) {
    refuse('refusing an entry outside the source');
  }
  const parentRel = path.dirname(rel);
  const expectedParent = parentRel === '.' ? probeRoot.realRoot : path.join(probeRoot.realRoot, parentRel);
  if ((await realpath(path.dirname(entry.absolute))) !== expectedParent) refuse('refusing an entry whose parent leaves the source');
  const st = await lstat(entry.absolute);
  if (st.dev !== probeRoot.dev) refuse('refusing an entry on another file system');
  if (typeOf(st) !== entry.type) refuse('an entry changed type during the probe');
  return st;
}

async function freeNeutralName(absolute: string): Promise<string> {
  for (let i = 0; i < MAX_NEUTRAL_NAMES; i++) {
    const counter = i === 0 ? '' : `-${i}`;
    const candidate = `${absolute}${NEUTRAL_SUFFIX}${counter}`;
    try {
      await lstat(candidate);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return candidate;
      throw err;
    }
  }
  return refuse('no free name to neutralize a control file');
}

async function neutralizeInside(probeRoot: ProbeRoot, entry: TreeEntry): Promise<string | null> {
  const st = await checkedEntry(probeRoot, entry);
  if (st.isFile() || st.isDirectory()) {
    const target = await freeNeutralName(entry.absolute);
    await rename(entry.absolute, target);
    return path.basename(target);
  }
  await unlink(entry.absolute);
  return null;
}

async function hashFile(absolute: string, expected: Stats, maxBytes: number): Promise<string | null> {
  if (expected.size > maxBytes) return null;
  const handle = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.ino !== expected.ino || st.dev !== expected.dev) refuse('a file changed during the probe');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(HASH_CHUNK);
    let total = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, HASH_CHUNK, total);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) return null;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

function qualifier(type: TreeEntryType, oversize: boolean, maxFileBytes: number): string {
  if (type === 'symlink') return ' (symbolic link, not followed)';
  if (type === 'directory') return ' (directory)';
  if (type === 'other') return ' (special file)';
  return oversize ? ` (larger than ${maxFileBytes} bytes, not hashed)` : '';
}

async function neutralizeControlFile(probeRoot: ProbeRoot, entry: TreeEntry, rule: ControlFileRule, maxFileBytes: number): Promise<OverrideAttempt> {
  const st = await checkedEntry(probeRoot, entry);
  const sha256 = entry.type === 'file' ? await hashFile(entry.absolute, st, maxFileBytes) : null;
  let action = 'kept; npm audit runs in an isolated working dir';
  if (rule.neutralizedBy === REMOVED) {
    const renamed = await neutralizeInside(probeRoot, entry);
    action = renamed === null ? 'removed from the working copy' : `removed; content kept as ${renamed} for scanning`;
  }
  const attempt: OverrideAttempt = {
    kind: rule.kind,
    path: safeRelative(entry.relative),
    detail: `${rule.description}, ${action}${qualifier(entry.type, entry.type === 'file' && sha256 === null, maxFileBytes)}`,
    neutralizedBy: rule.neutralizedBy,
  };
  if (sha256 !== null) attempt.sha256 = sha256;
  return attempt;
}

function markerAttempts(entry: TreeEntry, text: string): OverrideAttempt[] {
  const out: OverrideAttempt[] = [];
  for (const rule of MARKER_RULES) {
    const count = [...text.matchAll(rule.pattern)].length;
    if (count > 0) out.push({ kind: 'inline-marker', path: safeRelative(entry.relative), detail: inlineMarkerDetail(rule.marker, count), neutralizedBy: 'framework-flag' });
  }
  return out;
}

function byPathThenDetail(a: OverrideAttempt, b: OverrideAttempt): number {
  return compare(a.path, b.path) || compare(a.detail, b.detail);
}

interface MarkerLimits {
  maxFiles: number;
  maxBytes: number;
  maxFileBytes: number;
}

function markerLimitReached(filesScanned: number, bytesRead: number, limits: MarkerLimits): string | null {
  if (filesScanned >= limits.maxFiles) return `marker file limit ${limits.maxFiles} reached`;
  if (bytesRead >= limits.maxBytes) return `marker byte limit ${limits.maxBytes} reached`;
  return null;
}

async function scanMarkers(entries: readonly TreeEntry[], limits: MarkerLimits, truncation: string[]): Promise<{ markers: OverrideAttempt[]; markerFilesScanned: number }> {
  const markers: OverrideAttempt[] = [];
  let markerFilesScanned = 0;
  let markerBytes = 0;
  for (const entry of entries) {
    if (entry.type !== 'file' || controlRule(entry.name) !== undefined) continue;
    const limit = markerLimitReached(markerFilesScanned, markerBytes, limits);
    if (limit !== null) {
      truncation.push(limit);
      break;
    }
    const text = await readSourceFile(entry.absolute, limits.maxFileBytes);
    if (text === null) continue;
    markerFilesScanned += 1;
    markerBytes += Buffer.byteLength(text, 'utf8');
    if (!text.includes('\u0000')) markers.push(...markerAttempts(entry, text));
  }
  return { markers, markerFilesScanned };
}

export async function probeSource(repoDir: string, options: ProbeOptions = {}): Promise<ProbeResult> {
  const maxFileBytes = options.maxFileBytes ?? MAX_SOURCE_FILE_BYTES;
  const maxMarkerFiles = options.maxMarkerFiles ?? 20_000;
  const maxMarkerBytes = options.maxMarkerBytes ?? 256 * 1024 * 1024;
  const maxAttempts = options.maxAttempts ?? MAX_OVERRIDE_ATTEMPTS;
  const probeRoot = await openRoot(repoDir);
  const walk = await walkTree(probeRoot.root, {
    maxDepth: options.maxDepth ?? 64,
    maxEntries: options.maxEntries ?? 200_000,
    descend: (entry) => entry.name !== '.git' && controlRule(entry.name)?.neutralizedBy !== REMOVED,
  });
  const truncation: string[] = [];
  if (walk.truncated === 'entries') truncation.push(`entries limit ${options.maxEntries ?? 200_000} reached`);
  if (walk.truncated === 'depth') truncation.push(`depth limit ${options.maxDepth ?? 64} reached`);

  const controls: OverrideAttempt[] = [];
  for (const entry of walk.entries) {
    const rule = controlRule(entry.name);
    if (rule !== undefined) controls.push(await neutralizeControlFile(probeRoot, entry, rule, maxFileBytes));
  }

  const { markers, markerFilesScanned } = await scanMarkers(walk.entries, { maxFiles: maxMarkerFiles, maxBytes: maxMarkerBytes, maxFileBytes }, truncation);

  controls.sort(byPathThenDetail);
  markers.sort(byPathThenDetail);
  const counts = steeringCounts([...controls, ...markers]);
  let attempts = [...controls, ...markers];
  if (attempts.length > maxAttempts) {
    truncation.push(`attempt list capped at ${maxAttempts}`);
    attempts = attempts.slice(0, maxAttempts);
  }
  const result: ProbeResult = {
    attempts,
    controlFiles: counts.controlFiles,
    inlineMarkers: counts.inlineMarkers,
    entriesVisited: walk.entries.length,
    markerFilesScanned,
    truncated: truncation.length > 0,
  };
  if (truncation.length > 0) result.truncation = truncation.join('; ');
  return result;
}
