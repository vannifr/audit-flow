import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const ROOT = resolve(__dirname, '..', '..');
const SRC = join(ROOT, 'src');
const LEGACY = 'src/activities/index.ts';
const RUNNER = 'src/scan/process-runner.ts';
const LIFECYCLE = 'src/scan/lifecycle.ts';
const LEGACY_EXEC_BASELINE = 23;

const FORBIDDEN =
  /\bexecSync\s*\(|(?<![.\w])exec\s*\(|\bspawnSync\b|promisify\(\s*exec\s*\)|shell\s*:\s*true|from\s+['"](?:node:)?child_process['"]/;
const FORBIDDEN_G = new RegExp(FORBIDDEN.source, 'g');
const EXEC_ASYNC_G = /\bexecAsync\s*\(/g;
const CHILD_PROCESS_IMPORT = /from\s+['"](?:node:)?child_process['"]|require\(\s*['"](?:node:)?child_process['"]\s*\)/;

interface Hit {
  file: string;
  line: number;
  text: string;
}

function findHits(source: string, file: string, pattern: RegExp): Hit[] {
  const hits: Hit[] = [];
  source.split('\n').forEach((text, index) => {
    const re = new RegExp(pattern.source, 'g');
    if (re.test(text)) hits.push({ file, line: index + 1, text: text.trim() });
  });
  return hits;
}

function countMatches(source: string, pattern: RegExp): number {
  return (source.match(new RegExp(pattern.source, 'g')) ?? []).length;
}

function listSources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listSources(full));
    else if (/\.(ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry)) out.push(full);
  }
  return out;
}

function rel(file: string): string {
  return relative(ROOT, file).split('\\').join('/');
}

function format(hits: Hit[]): string {
  return hits.map((h) => `${h.file}:${h.line}: ${h.text}`).join('\n');
}

describe('exec detector', () => {
  it('finds exec( but not execFile(', () => {
    expect(FORBIDDEN.test('const r = exec("ls");')).toBe(true);
    expect(FORBIDDEN.test('execFile("ls", [])')).toBe(false);
    expect(FORBIDDEN.test('RE.exec(text)')).toBe(false);
    expect(FORBIDDEN.test('execSync("ls")')).toBe(true);
    expect(FORBIDDEN.test('const f = promisify(exec);')).toBe(true);
    expect(FORBIDDEN.test('execFile(c, a, { shell: true })')).toBe(true);
    expect(FORBIDDEN.test("import { x } from 'node:child_process';")).toBe(true);
    expect(countMatches('execAsync(a); execAsync(b)', EXEC_ASYNC_G)).toBe(2);
    expect(countMatches('execFile(a)', EXEC_ASYNC_G)).toBe(0);
  });
});

describe('architecture exec ratchet', () => {
  const files = listSources(SRC).map((f) => ({ path: rel(f), source: readFileSync(f, 'utf8') }));

  it('finds source files to scan', () => {
    expect(files.length).toBeGreaterThan(0);
    expect(files.some((f) => f.path === LEGACY)).toBe(true);
  });

  it('allows no shell-form process execution outside the legacy activities file', () => {
    const hits = files
      .filter((f) => f.path !== LEGACY)
      .flatMap((f) => {
        const found = findHits(f.source, f.path, FORBIDDEN_G);
        if (f.path !== RUNNER) return found;
        return found.filter((h) => !/from\s+['"]node:child_process['"]/.test(h.text));
      });
    expect(hits, `forbidden exec usage found:\n${format(hits)}`).toEqual([]);
  });

  it('keeps child_process confined to the process runner outside the legacy file', () => {
    const hits = files
      .filter((f) => f.path !== LEGACY && f.path !== RUNNER)
      .flatMap((f) => findHits(f.source, f.path, CHILD_PROCESS_IMPORT));
    expect(hits, `child_process may only be imported by ${RUNNER}:\n${format(hits)}`).toEqual([]);
  });

  it('keeps the lifecycle on runTool without child_process', () => {
    const lifecycle = files.find((f) => f.path === LIFECYCLE);
    expect(lifecycle, `${LIFECYCLE} not found`).toBeDefined();
    const hits = findHits(lifecycle!.source, LIFECYCLE, CHILD_PROCESS_IMPORT);
    expect(hits, `${LIFECYCLE} must go through runTool:\n${format(hits)}`).toEqual([]);
  });

  it('uses execFile with shell false in the process runner', () => {
    const runner = files.find((f) => f.path === RUNNER);
    expect(runner, `${RUNNER} not found`).toBeDefined();
    expect(runner!.source).toMatch(/\bexecFile\b/);
    expect(runner!.source).not.toMatch(/shell\s*:\s*true/);
  });

  it('never lets the legacy execAsync call count rise or stay above a lowered count', () => {
    const legacy = files.find((f) => f.path === LEGACY)!;
    const hits = findHits(legacy.source, LEGACY, EXEC_ASYNC_G);
    const count = countMatches(legacy.source, EXEC_ASYNC_G);
    if (count > LEGACY_EXEC_BASELINE) {
      throw new Error(
        `${LEGACY} has ${count} execAsync( calls, baseline is ${LEGACY_EXEC_BASELINE}; new shell execution is not allowed, use runTool. Calls:\n${format(hits)}`,
      );
    }
    if (count < LEGACY_EXEC_BASELINE) {
      throw new Error(
        `${LEGACY} has ${count} execAsync( calls, below baseline ${LEGACY_EXEC_BASELINE}: lower LEGACY_EXEC_BASELINE to ${count} in tests/unit/architecture-exec-ratchet.test.ts`,
      );
    }
    expect(count).toBe(LEGACY_EXEC_BASELINE);
  });

  it('adds no new child_process usage to the legacy file beyond the existing exec import', () => {
    const legacy = files.find((f) => f.path === LEGACY)!;
    const imports = findHits(legacy.source, LEGACY, CHILD_PROCESS_IMPORT);
    expect(
      imports.map((h) => h.text),
      `unexpected child_process imports:\n${format(imports)}`,
    ).toEqual(["import { exec } from 'child_process';"]);
    const promisified = findHits(legacy.source, LEGACY, /promisify\(\s*exec\s*\)/);
    expect(promisified, `promisify(exec) must appear exactly once:\n${format(promisified)}`).toHaveLength(1);
    const others = findHits(legacy.source, LEGACY, /\bexecSync\s*\(|(?<![.\w])exec\s*\(|\bspawnSync\b|\bspawn\s*\(|\bexecFile(?:Sync)?\s*\(|shell\s*:\s*true/);
    expect(others, `new process execution forms in ${LEGACY}:\n${format(others)}`).toEqual([]);
  });
});
