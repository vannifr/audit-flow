import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, symlink, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const childProcessCalls: string[] = [];
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const trap = (name: string) => (...args: unknown[]) => {
    childProcessCalls.push(`${name}:${JSON.stringify(args[0])}`);
    throw new Error(`child_process.${name} is forbidden here`);
  };
  return {
    ...actual,
    exec: trap('exec'),
    execSync: trap('execSync'),
    execFile: trap('execFile'),
    execFileSync: trap('execFileSync'),
    spawn: trap('spawn'),
    spawnSync: trap('spawnSync'),
    fork: trap('fork'),
  };
});

import { detectTechStack, reviewCriticalPaths, checkToolRequirements } from '../../src/activities/index';

const PASSWORD = 'admin1234';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

let repo: string;
let outside: string;

beforeEach(async () => {
  childProcessCalls.length = 0;
  repo = await mkdtemp(path.join(tmpdir(), 'review-repo-'));
  outside = await mkdtemp(path.join(tmpdir(), 'review-outside-'));
});

afterEach(async () => {
  await rm(repo, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
});

async function plantAuth(): Promise<void> {
  await mkdir(path.join(repo, 'src'));
  await writeFile(
    path.join(repo, 'src', 'auth.js'),
    [
      'const a = 1;',
      `const password = "${PASSWORD}";`,
      `const apiKey = "${AWS_KEY}";`,
      `const secret = "${SECRET}";`,
      'eval(userInput);',
    ].join('\n'),
  );
}

describe('reviewCriticalPaths redaction (FR-012)', () => {
  it('keeps file and line but no part of the secret values anywhere in the findings', async () => {
    await plantAuth();
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain('1234');
    expect(serialized).not.toContain(AWS_KEY);
    expect(serialized).not.toContain('AKIAIOSF');
    expect(serialized).not.toContain(SECRET);
    expect(serialized).not.toContain('wJalrXUt');
    const pw = findings.find((f) => f.title === 'Hardcoded password');
    expect(pw?.evidence[0].file).toBe('src/auth.js');
    expect(pw?.evidence[0].line).toBe(2);
    expect(pw?.description).toContain('src/auth.js');
    expect(pw?.description).toContain('line 2');
    expect(pw?.evidence[0].content).toContain('[REDACTED');
    const key = findings.find((f) => f.title === 'Hardcoded API key');
    expect(key?.evidence[0].line).toBe(3);
    const secret = findings.find((f) => f.title === 'Hardcoded secret');
    expect(secret?.evidence[0].line).toBe(4);
  });

  it('redacts a short password the pattern heuristics alone would leave', async () => {
    await mkdir(path.join(repo, 'auth'));
    await writeFile(path.join(repo, 'auth', 'a.js'), 'const password = "x9";\n');
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    expect(JSON.stringify(findings)).not.toContain('x9');
    expect(findings).toHaveLength(1);
  });

  it('redacts a secret that sits inside a non-secret match', async () => {
    await mkdir(path.join(repo, 'auth'));
    await writeFile(path.join(repo, 'auth', 'a.js'), `eval("token=${AWS_KEY}");\n`);
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    expect(findings.length).toBeGreaterThan(0);
    expect(JSON.stringify(findings)).not.toContain(AWS_KEY);
  });

  it('labels every finding as code-review evidence', async () => {
    await plantAuth();
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    expect(findings.length).toBeGreaterThanOrEqual(4);
    for (const f of findings) {
      expect(f.evidence.every((e) => e.tool === 'code-review' && e.type === 'code-review')).toBe(true);
      expect(f.category).toBe('security-code-review');
    }
  });

  it('keeps non-secret findings with line numbers', async () => {
    await plantAuth();
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    const ev = findings.find((f) => f.title === 'eval() usage');
    expect(ev?.evidence[0].line).toBe(5);
    expect(ev?.evidence[0].content).toBe('eval(');
  });
});

describe('no child process on the workflow path', () => {
  it('detectTechStack and reviewCriticalPaths start no child process', async () => {
    await plantAuth();
    await writeFile(path.join(repo, 'package.json'), JSON.stringify({ dependencies: { express: '4' } }));
    const stack = await detectTechStack(repo);
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    expect(stack.language).toBe('nodejs');
    expect(stack.hasPII).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
    expect(childProcessCalls).toEqual([]);
  });

  it('a file name with shell characters causes nothing', async () => {
    const marker = path.join(repo, 'x.js');
    await writeFile(path.join(repo, 'a;touch x.js'), 'const email = 1;\n');
    await writeFile(path.join(repo, 'auth$(touch x.js).js'), 'const password = "abcdefgh";\n');
    const stack = await detectTechStack(repo);
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    expect(stack.hasPII).toBe(true);
    expect(findings).toHaveLength(1);
    await expect(stat(marker)).rejects.toThrow();
    expect(childProcessCalls).toEqual([]);
  });

  it('a repo path with shell characters is not interpreted', async () => {
    const weird = path.join(repo, 'a b;touch pwned');
    await mkdir(weird);
    await writeFile(path.join(weird, 'x.js'), 'const email = 1;\n');
    const stack = await detectTechStack(weird);
    expect(stack.hasPII).toBe(true);
    await expect(stat(path.join(repo, 'pwned'))).rejects.toThrow();
    expect(childProcessCalls).toEqual([]);
  });

  it('checkToolRequirements only runs static commands without input', async () => {
    await checkToolRequirements();
    expect(childProcessCalls.length).toBeGreaterThan(0);
    for (const call of childProcessCalls) {
      expect(call).toMatch(/^exec:"(npm|git|gitleaks|semgrep) --version"$/);
    }
  });
});

describe('bounded in-process walk', () => {
  it('does not read a symlink to a file outside the repo', async () => {
    await writeFile(path.join(outside, 'auth.js'), `const password = "${PASSWORD}";\nconst email = 1;\n`);
    await symlink(path.join(outside, 'auth.js'), path.join(repo, 'auth.js'));
    await symlink(outside, path.join(repo, 'auth-dir'));
    const findings = await reviewCriticalPaths(repo, ['auth'], 'OWASP');
    const stack = await detectTechStack(repo);
    expect(findings).toEqual([]);
    expect(stack.hasPII).toBe(false);
  });

  it('skips node_modules and .git', async () => {
    for (const dir of ['node_modules', '.git']) {
      await mkdir(path.join(repo, dir, 'auth'), { recursive: true });
      await writeFile(path.join(repo, dir, 'auth', 'a.js'), `const password = "${PASSWORD}";\nconst email = 1;\n`);
    }
    expect(await reviewCriticalPaths(repo, ['auth'], 'OWASP')).toEqual([]);
    expect((await detectTechStack(repo)).hasPII).toBe(false);
  });

  it('looks at no more than 50 files for PII', async () => {
    for (let i = 0; i < 50; i++) await writeFile(path.join(repo, `a${String(i).padStart(2, '0')}.js`), 'const x = 1;\n');
    await writeFile(path.join(repo, 'z-late.js'), 'const email = 1;\n');
    expect((await detectTechStack(repo)).hasPII).toBe(false);
    await rm(path.join(repo, 'a00.js'));
    expect((await detectTechStack(repo)).hasPII).toBe(true);
  });

  it('skips files larger than 1 MB', async () => {
    await writeFile(path.join(repo, 'big.js'), `${'x'.repeat(1024 * 1024)}\nconst email = 1;\n`);
    expect((await detectTechStack(repo)).hasPII).toBe(false);
    await mkdir(path.join(repo, 'auth'));
    await writeFile(path.join(repo, 'auth', 'big.js'), `${'x'.repeat(1024 * 1024)}\nconst password = "${PASSWORD}";\n`);
    expect(await reviewCriticalPaths(repo, ['auth'], 'OWASP')).toEqual([]);
  });

  it('matches critical paths on the path inside the repo, not on the repo location', async () => {
    const nested = path.join(repo, 'auth-workspace');
    await mkdir(nested);
    await writeFile(path.join(nested, 'other.js'), `const password = "${PASSWORD}";\n`);
    expect(await reviewCriticalPaths(nested, ['auth'], 'OWASP')).toEqual([]);
  });
});
