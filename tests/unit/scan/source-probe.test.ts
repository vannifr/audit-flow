import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  CONTROL_FILE_NAMES,
  MAX_OVERRIDE_ATTEMPTS,
  inlineMarkerDetail,
  overrideAttemptsFor,
  parseInlineMarkerDetail,
  probeSource,
  sanitizeOverrideAttempts,
  steeringCounts,
} from '../../../src/scan/source-probe';
import type { OverrideAttempt } from '../../../src/evidence/types';

let root: string;
let repo: string;
let outside: string;

const sha = (text: string | Buffer): string => createHash('sha256').update(text).digest('hex');

async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function put(rel: string, content: string | Buffer): Promise<string> {
  const abs = path.join(repo, rel);
  await mkdir(path.dirname(abs), { recursive: true });
  await writeFile(abs, content);
  return abs;
}

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tessera-probe-'));
  repo = path.join(root, 'repo');
  outside = path.join(root, 'outside');
  await mkdir(repo, { mode: 0o700 });
  await mkdir(outside, { mode: 0o700 });
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('probeSource: control files (FR-014, R5)', () => {
  it('lists every steering file name from R5 in one place', () => {
    expect([...CONTROL_FILE_NAMES].sort()).toEqual(
      ['.gitleaks.toml', '.gitleaksignore', '.npmrc', '.nsprc', '.semgrep', '.semgrep.yaml', '.semgrep.yml', '.semgrepignore', '.snyk', '.yarnrc', '.yarnrc.yml', 'gitleaks.toml'].sort(),
    );
  });

  it('removes control files at any depth from the working copy and records path, sha256 and neutralization', async () => {
    await put('.gitleaks.toml', '[allowlist]\npaths = [".*"]\n');
    await put('.gitleaksignore', 'src/config.js:generic-api-key:4\n');
    await put('gitleaks.toml', 'title = "x"\n');
    await put('pkg/a/b/.semgrepignore', 'src/\n');
    await put('.semgrep.yml', 'rules: []\n');
    await put('deep/.semgrep.yaml', 'rules: []\n');
    await put('.nsprc', '{}\n');
    await put('.snyk', 'ignore: {}\n');
    await put('.semgrep/rules.yml', 'rules: []\n');
    await put('src/index.js', 'console.log(1)\n');

    const result = await probeSource(repo);

    for (const rel of ['.gitleaks.toml', '.gitleaksignore', 'gitleaks.toml', 'pkg/a/b/.semgrepignore', '.semgrep.yml', 'deep/.semgrep.yaml', '.nsprc', '.snyk', '.semgrep']) {
      expect(await exists(path.join(repo, rel)), rel).toBe(false);
    }
    expect(await exists(path.join(repo, 'src/index.js'))).toBe(true);
    const byPath = new Map(result.attempts.map((a) => [a.path, a]));
    expect(byPath.get('.gitleaksignore')).toEqual({
      kind: 'control-file',
      path: '.gitleaksignore',
      detail: expect.stringContaining('gitleaks ignore list'),
      sha256: sha('src/config.js:generic-api-key:4\n'),
      neutralizedBy: 'removed-from-working-copy',
    });
    expect(byPath.get('.gitleaks.toml')).toMatchObject({ kind: 'project-config', sha256: sha('[allowlist]\npaths = [".*"]\n'), neutralizedBy: 'removed-from-working-copy' });
    expect(byPath.get('pkg/a/b/.semgrepignore')).toMatchObject({ kind: 'control-file', sha256: sha('src/\n'), neutralizedBy: 'removed-from-working-copy' });
    expect(byPath.get('.semgrep')).toMatchObject({ kind: 'project-config', detail: expect.stringContaining('directory'), neutralizedBy: 'removed-from-working-copy' });
    expect(byPath.get('.semgrep')?.sha256).toBeUndefined();
    expect(result.controlFiles).toBe(9);
    expect(result.truncated).toBe(false);
  });

  it('keeps .npmrc and .yarnrc files, hashes them and records them as neutralized by the isolated working dir', async () => {
    await put('.npmrc', 'registry=http://127.0.0.1:9/\n');
    await put('sub/.yarnrc.yml', 'npmRegistryServer: "http://127.0.0.1:9"\n');

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.npmrc'))).toBe(true);
    expect(await exists(path.join(repo, 'sub/.yarnrc.yml'))).toBe(true);
    expect(result.attempts).toEqual([
      { kind: 'project-config', path: '.npmrc', detail: expect.stringContaining('npm configuration'), sha256: sha('registry=http://127.0.0.1:9/\n'), neutralizedBy: 'isolated-working-dir' },
      { kind: 'project-config', path: 'sub/.yarnrc.yml', detail: expect.stringContaining('yarn configuration'), sha256: sha('npmRegistryServer: "http://127.0.0.1:9"\n'), neutralizedBy: 'isolated-working-dir' },
    ]);
  });

  it('removes a symlinked control file without following it and leaves the target outside the source intact', async () => {
    const target = path.join(outside, 'precious.txt');
    await writeFile(target, 'keep me');
    await symlink(target, path.join(repo, '.gitleaksignore'));
    const dirTarget = path.join(outside, 'dir');
    await mkdir(dirTarget);
    await writeFile(path.join(dirTarget, 'x.yml'), 'keep');
    await symlink(dirTarget, path.join(repo, '.semgrep'));

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(await exists(path.join(repo, '.semgrep'))).toBe(false);
    expect(await readFile(target, 'utf8')).toBe('keep me');
    expect(await readFile(path.join(dirTarget, 'x.yml'), 'utf8')).toBe('keep');
    const link1 = result.attempts.find((a) => a.path === '.gitleaksignore');
    expect(link1).toMatchObject({ kind: 'control-file', detail: expect.stringContaining('symbolic link'), neutralizedBy: 'removed-from-working-copy' });
    expect(link1?.sha256).toBeUndefined();
  });

  it('never descends into a symlinked directory, so control files behind it are neither seen nor removed', async () => {
    await writeFile(path.join(outside, '.gitleaksignore'), 'outside');
    await writeFile(path.join(outside, 'leak.js'), '// gitleaks:allow\n');
    await symlink(outside, path.join(repo, 'linked'));

    const result = await probeSource(repo);

    expect(await readFile(path.join(outside, '.gitleaksignore'), 'utf8')).toBe('outside');
    expect(result.attempts).toEqual([]);
    expect(await exists(path.join(repo, 'linked'))).toBe(true);
  });

  it('unlinks a hardlinked control file inside the source while the other link keeps its content', async () => {
    const other = path.join(outside, 'hard.txt');
    await writeFile(other, 'shared content');
    await link(other, path.join(repo, '.gitleaksignore'));

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(await readFile(other, 'utf8')).toBe('shared content');
    expect(result.attempts[0]).toMatchObject({ path: '.gitleaksignore', sha256: sha('shared content') });
  });

  it('removes a control name that is a directory and a special file without reading them', async () => {
    await mkdir(path.join(repo, '.gitleaksignore'));
    await writeFile(path.join(repo, '.gitleaksignore', 'inner'), 'x');
    execFileSync('mkfifo', [path.join(repo, '.semgrepignore')]);

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(await exists(path.join(repo, '.semgrepignore'))).toBe(false);
    expect(result.attempts.find((a) => a.path === '.gitleaksignore')?.detail).toContain('directory');
    expect(result.attempts.find((a) => a.path === '.semgrepignore')?.detail).toContain('special file');
  });

  it('removes but does not hash a control file larger than the size limit', async () => {
    await put('.gitleaksignore', Buffer.alloc(2048, 'a'));

    const result = await probeSource(repo, { maxFileBytes: 1024 });

    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(result.attempts[0].sha256).toBeUndefined();
    expect(result.attempts[0].detail).toContain('not hashed');
  });

  it('hashes a control file larger than one read chunk exactly', async () => {
    const big = Buffer.alloc(200_000, 'b');
    await put('.gitleaksignore', big);

    const result = await probeSource(repo);

    expect(result.attempts[0].sha256).toBe(sha(big));
  });

  it('does not walk into .git and does not touch files there', async () => {
    await put('.git/info/.gitleaksignore', 'x');
    await put('.git/hooks/x.js', '// gitleaks:allow\n');

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.git/info/.gitleaksignore'))).toBe(true);
    expect(result.attempts).toEqual([]);
  });

  it('refuses a source dir that is a symlink or not a directory', async () => {
    const linked = path.join(root, 'linked-repo');
    await symlink(repo, linked);
    await expect(probeSource(linked)).rejects.toThrow(/source probe/);
    const file = path.join(root, 'file');
    await writeFile(file, 'x');
    await expect(probeSource(file)).rejects.toThrow(/source probe/);
    await expect(probeSource(path.join(root, 'missing'))).rejects.toThrow();
    await expect(probeSource('relative/repo')).rejects.toThrow(/source probe/);
  });

  it('fails closed when a directory cannot be listed', async () => {
    await put('locked/.gitleaksignore', 'x');
    const { chmod } = await import('node:fs/promises');
    await chmod(path.join(repo, 'locked'), 0o000);
    try {
      if (process.getuid?.() === 0) return;
      await expect(probeSource(repo)).rejects.toThrow();
    } finally {
      await chmod(path.join(repo, 'locked'), 0o700);
    }
  });

  it('records names with control characters or secrets in the path without exposing them', async () => {
    await put('AKIAIOSFODNN7EXAMPLE/.gitleaksignore', 'x');
    await put('bad\nname/.semgrepignore', 'x');

    const result = await probeSource(repo);

    const paths = result.attempts.map((a) => a.path);
    expect(paths.join('|')).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(paths.join('|')).not.toContain('\n');
    expect(paths).toHaveLength(2);
    expect(sanitizeOverrideAttempts(result.attempts)).toEqual(result.attempts);
  });
});

describe('probeSource: neutralized content stays scannable', () => {
  it('renames a removed control file in place so its bytes are still scanned but no tool reads it as configuration', async () => {
    await put('.gitleaksignore', 'token = "zz-secret-inside-ignore-file"\n');
    await put('.semgrep/rules.yml', 'rules: []\n');

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(await readFile(path.join(repo, '.gitleaksignore.tessera-neutralized'), 'utf8')).toBe('token = "zz-secret-inside-ignore-file"\n');
    expect(await readFile(path.join(repo, '.semgrep.tessera-neutralized', 'rules.yml'), 'utf8')).toBe('rules: []\n');
    expect(result.attempts.find((a) => a.path === '.gitleaksignore')?.detail).toContain('.gitleaksignore.tessera-neutralized');
  });

  it('never overwrites an existing file with the neutral name', async () => {
    await put('.gitleaksignore', 'ignore');
    await put('.gitleaksignore.tessera-neutralized', 'planted by the source');

    await probeSource(repo);

    expect(await readFile(path.join(repo, '.gitleaksignore.tessera-neutralized'), 'utf8')).toBe('planted by the source');
    expect(await readFile(path.join(repo, '.gitleaksignore.tessera-neutralized-1'), 'utf8')).toBe('ignore');
  });

  it('matches control file names case-insensitively for case-insensitive file systems', async () => {
    await put('.GitLeaksIgnore', 'x');
    await put('sub/.SemgrepIgnore', 'x');

    const result = await probeSource(repo);

    expect(await exists(path.join(repo, '.GitLeaksIgnore'))).toBe(false);
    expect(await exists(path.join(repo, 'sub/.SemgrepIgnore'))).toBe(false);
    expect(result.attempts.map((a) => [a.path, a.kind])).toEqual([
      ['.GitLeaksIgnore', 'control-file'],
      ['sub/.SemgrepIgnore', 'control-file'],
    ]);
    expect(overrideAttemptsFor('gitleaks', result.attempts).map((a) => a.path)).toEqual(['.GitLeaksIgnore']);
  });
});

describe('probeSource: inline markers', () => {
  it('counts gitleaks:allow, nosemgrep, nosem and nosec per file and sorts the attempts deterministically', async () => {
    await put('src/b.js', 'const k = "x"; // gitleaks:allow\nconst j = "y"; // gitleaks:allow\n');
    await put('src/a.js', 'eval(x); // nosemgrep\nrun(); // nosem\n');
    await put('tools/x.py', 'os.system(c)  # nosec\n');
    await put('src/clean.js', 'const nosemgrepish = 1;\n');

    const result = await probeSource(repo);

    expect(result.attempts).toEqual([
      { kind: 'inline-marker', path: 'src/a.js', detail: inlineMarkerDetail('nosem', 1), neutralizedBy: 'framework-flag' },
      { kind: 'inline-marker', path: 'src/a.js', detail: inlineMarkerDetail('nosemgrep', 1), neutralizedBy: 'framework-flag' },
      { kind: 'inline-marker', path: 'src/b.js', detail: inlineMarkerDetail('gitleaks:allow', 2), neutralizedBy: 'framework-flag' },
      { kind: 'inline-marker', path: 'tools/x.py', detail: inlineMarkerDetail('nosec', 1), neutralizedBy: 'framework-flag' },
    ]);
    expect(result.inlineMarkers).toBe(5);
    expect(result.markerFilesScanned).toBe(4);
    expect(await probeSource(repo)).toEqual(result);
  });

  it('skips binary files, files above the size limit and stops at the file and byte budget', async () => {
    await put('bin.dat', Buffer.concat([Buffer.from('gitleaks:allow'), Buffer.from([0, 1, 2])]));
    await put('big.js', `// nosemgrep\n${'x'.repeat(4096)}`);
    await put('small.js', '// nosemgrep\n');

    const sized = await probeSource(repo, { maxFileBytes: 1024 });
    expect(sized.attempts.map((a) => a.path)).toEqual(['small.js']);

    await put('z1.js', '// nosec\n');
    await put('z2.js', '// nosec\n');
    const capped = await probeSource(repo, { maxMarkerFiles: 2 });
    expect(capped.markerFilesScanned).toBe(2);
    expect(capped.truncated).toBe(true);
    expect(capped.truncation).toContain('marker');

    const bytes = await probeSource(repo, { maxMarkerBytes: 20 });
    expect(bytes.truncated).toBe(true);
  });

  it('control files come before markers and the list is capped', async () => {
    for (let i = 0; i < 5; i++) await put(`m${i}.js`, '// nosec\n');
    await put('z/.gitleaksignore', 'x');

    const result = await probeSource(repo, { maxAttempts: 3 });

    expect(result.attempts).toHaveLength(3);
    expect(result.attempts[0].path).toBe('z/.gitleaksignore');
    expect(result.truncated).toBe(true);
    expect(MAX_OVERRIDE_ATTEMPTS).toBeGreaterThanOrEqual(100);
  });
});

describe('probeSource: walk bounds', () => {
  it('walks breadth first so shallow control files are found before the entry budget runs out', async () => {
    for (let i = 0; i < 20; i++) await put(`!deep/d${i}/f.js`, 'x');
    await put('.gitleaksignore', 'x');

    const result = await probeSource(repo, { maxEntries: 5 });

    expect(result.attempts.map((a) => a.path)).toContain('.gitleaksignore');
    expect(await exists(path.join(repo, '.gitleaksignore'))).toBe(false);
    expect(result.truncated).toBe(true);
    expect(result.truncation).toContain('entries');
  });

  it('stops at the depth limit and says so', async () => {
    await put('a/b/c/d/.gitleaksignore', 'x');

    const result = await probeSource(repo, { maxDepth: 2 });

    expect(result.attempts).toEqual([]);
    expect(result.truncated).toBe(true);
    expect(result.truncation).toContain('depth');
  });
});

describe('override attempt helpers', () => {
  const attempts: OverrideAttempt[] = [
    { kind: 'control-file', path: '.gitleaksignore', detail: 'gitleaks ignore list', sha256: 'a'.repeat(64), neutralizedBy: 'removed-from-working-copy' },
    { kind: 'project-config', path: 'x/.gitleaks.toml', detail: 'gitleaks configuration', neutralizedBy: 'removed-from-working-copy' },
    { kind: 'control-file', path: '.semgrepignore', detail: 'semgrep ignore list', neutralizedBy: 'removed-from-working-copy' },
    { kind: 'project-config', path: '.semgrep', detail: 'semgrep configuration directory', neutralizedBy: 'removed-from-working-copy' },
    { kind: 'project-config', path: '.npmrc', detail: 'npm configuration', neutralizedBy: 'isolated-working-dir' },
    { kind: 'project-config', path: '.snyk', detail: 'snyk policy', neutralizedBy: 'removed-from-working-copy' },
    { kind: 'inline-marker', path: 'a.js', detail: inlineMarkerDetail('gitleaks:allow', 3), neutralizedBy: 'framework-flag' },
    { kind: 'inline-marker', path: 'a.js', detail: inlineMarkerDetail('nosemgrep', 2), neutralizedBy: 'framework-flag' },
    { kind: 'inline-marker', path: 'b.py', detail: inlineMarkerDetail('nosec', 1), neutralizedBy: 'framework-flag' },
  ];

  it('selects only the attempts that steer a given scanner', () => {
    expect(overrideAttemptsFor('gitleaks', attempts).map((a) => a.path + ':' + a.detail)).toEqual([
      '.gitleaksignore:gitleaks ignore list',
      'x/.gitleaks.toml:gitleaks configuration',
      `a.js:${inlineMarkerDetail('gitleaks:allow', 3)}`,
    ]);
    expect(overrideAttemptsFor('semgrep', attempts).map((a) => a.path)).toEqual(['.semgrepignore', '.semgrep', 'a.js', 'b.py']);
    expect(overrideAttemptsFor('npm-audit', attempts).map((a) => a.path)).toEqual(['.npmrc', '.snyk']);
    expect(overrideAttemptsFor('license-check', attempts)).toEqual([]);
    expect(overrideAttemptsFor('gitleaks', undefined)).toEqual([]);
  });

  it('counts control files and inline markers for the report', () => {
    expect(steeringCounts(attempts)).toEqual({ controlFiles: 6, inlineMarkers: 6 });
    expect(steeringCounts(undefined)).toEqual({ controlFiles: 0, inlineMarkers: 0 });
  });

  it('round-trips the inline marker detail and rejects other text', () => {
    expect(parseInlineMarkerDetail(inlineMarkerDetail('nosec', 7))).toEqual({ marker: 'nosec', count: 7 });
    expect(parseInlineMarkerDetail('something else')).toBeNull();
    expect(parseInlineMarkerDetail('inline marker "evil" x2')).toBeNull();
  });

  it('drops malformed attempts and caps the list', () => {
    const bad: unknown[] = [
      null,
      'x',
      { ...attempts[0], kind: 'other' },
      { ...attempts[0], neutralizedBy: 'nothing' },
      { ...attempts[0], path: '/etc/passwd' },
      { ...attempts[0], path: '../x' },
      { ...attempts[0], path: 'a/../../x' },
      { ...attempts[0], path: '' },
      { ...attempts[0], path: 'a\nb' },
      { ...attempts[0], path: 'p'.repeat(2000) },
      { ...attempts[0], detail: 'd'.repeat(500) },
      { ...attempts[0], detail: 7 },
      { ...attempts[0], sha256: 'zz' },
      attempts[1],
    ];
    expect(sanitizeOverrideAttempts(bad)).toEqual([attempts[1]]);
    expect(sanitizeOverrideAttempts('nope')).toEqual([]);
    const many = Array.from({ length: MAX_OVERRIDE_ATTEMPTS + 10 }, () => attempts[2]);
    expect(sanitizeOverrideAttempts(many)).toHaveLength(MAX_OVERRIDE_ATTEMPTS);
    const extra = sanitizeOverrideAttempts([{ ...attempts[0], injected: 'x' }]);
    expect(extra).toEqual([attempts[0]]);
  });
});

describe('probeSource: marker byte limit and control characters', () => {
  it('stops scanning once the byte limit is reached exactly', async () => {
    await put('a.ts', 'abcd');
    await put('b.ts', '// nosec');
    const result = await probeSource(repo, { maxMarkerBytes: 4 });
    expect(result.markerFilesScanned).toBe(1);
    expect(result.inlineMarkers).toBe(0);
    expect(result.truncation).toBe('marker byte limit 4 reached');
  });

  it('replaces every character below 0x20 and 0x7f', async () => {
    const { replaceControlChars } = await import('../../../src/scan/source-probe');
    expect(replaceControlChars('a\u001fb\u007f c\u0000', '?')).toBe('a?b? c?');
  });
});
