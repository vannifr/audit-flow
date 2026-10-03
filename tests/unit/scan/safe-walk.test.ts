import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { walkSourceFiles, readSourceFile } from '../../../src/scan/safe-walk';

let root: string;
let outside: string;

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'walk-root-'));
  outside = await mkdtemp(path.join(tmpdir(), 'walk-outside-'));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
});

const OPTS = { extensions: ['.js', '.ts'], maxFiles: 50 };

describe('walkSourceFiles', () => {
  it('returns matching files sorted and relative to the root', async () => {
    await mkdir(path.join(root, 'src'));
    await writeFile(path.join(root, 'b.js'), 'x');
    await writeFile(path.join(root, 'a.ts'), 'x');
    await writeFile(path.join(root, 'src', 'c.js'), 'x');
    await writeFile(path.join(root, 'notes.md'), 'x');
    const files = await walkSourceFiles(root, OPTS);
    expect(files.map((f) => f.relative)).toEqual(['a.ts', 'b.js', 'src/c.js']);
    expect(files[0].absolute).toBe(path.join(root, 'a.ts'));
  });

  it('skips node_modules, .git and other dot directories', async () => {
    for (const dir of ['node_modules', '.git', '.cache']) {
      await mkdir(path.join(root, dir));
      await writeFile(path.join(root, dir, 'x.js'), 'x');
    }
    await writeFile(path.join(root, 'ok.js'), 'x');
    const files = await walkSourceFiles(root, OPTS);
    expect(files.map((f) => f.relative)).toEqual(['ok.js']);
  });

  it('does not follow symlinked files or directories', async () => {
    await writeFile(path.join(outside, 'secret.js'), 'x');
    await mkdir(path.join(outside, 'dir'));
    await writeFile(path.join(outside, 'dir', 'deep.js'), 'x');
    await symlink(path.join(outside, 'secret.js'), path.join(root, 'link.js'));
    await symlink(path.join(outside, 'dir'), path.join(root, 'linkdir'));
    await writeFile(path.join(root, 'real.js'), 'x');
    const files = await walkSourceFiles(root, OPTS);
    expect(files.map((f) => f.relative)).toEqual(['real.js']);
  });

  it('stops at maxFiles', async () => {
    for (let i = 0; i < 80; i++) await writeFile(path.join(root, `f${String(i).padStart(2, '0')}.js`), 'x');
    expect(await walkSourceFiles(root, OPTS)).toHaveLength(50);
    expect(await walkSourceFiles(root, { ...OPTS, maxFiles: 3 })).toHaveLength(3);
  });

  it('applies the optional filter on the relative path', async () => {
    await mkdir(path.join(root, 'auth'));
    await writeFile(path.join(root, 'auth', 'login.js'), 'x');
    await writeFile(path.join(root, 'other.js'), 'x');
    const files = await walkSourceFiles(root, { ...OPTS, filter: (rel) => rel.includes('auth') });
    expect(files.map((f) => f.relative)).toEqual(['auth/login.js']);
  });

  it('handles file names with shell characters as plain names', async () => {
    await writeFile(path.join(root, 'a;touch x.js'), 'x');
    const files = await walkSourceFiles(root, OPTS);
    expect(files.map((f) => f.relative)).toEqual(['a;touch x.js']);
  });

  it('stops descending beyond maxDepth', async () => {
    let dir = root;
    for (let i = 0; i < 5; i++) {
      dir = path.join(dir, `d${i}`);
      await mkdir(dir);
      await writeFile(path.join(dir, `f${i}.js`), 'x');
    }
    const files = await walkSourceFiles(root, { ...OPTS, maxDepth: 2 });
    expect(files.map((f) => f.relative)).toEqual(['d0/d1/f1.js', 'd0/f0.js']);
  });

  it('returns an empty list when the root is missing', async () => {
    expect(await walkSourceFiles(path.join(root, 'nope'), OPTS)).toEqual([]);
  });
});

describe('readSourceFile', () => {
  it('reads a regular file', async () => {
    await writeFile(path.join(root, 'a.js'), 'hello');
    expect(await readSourceFile(path.join(root, 'a.js'), 1024)).toBe('hello');
  });

  it('refuses files larger than the limit', async () => {
    await writeFile(path.join(root, 'big.js'), 'x'.repeat(2048));
    expect(await readSourceFile(path.join(root, 'big.js'), 1024)).toBeNull();
  });

  it('refuses a symlink', async () => {
    await writeFile(path.join(outside, 's.js'), 'topsecret');
    await symlink(path.join(outside, 's.js'), path.join(root, 'l.js'));
    expect(await readSourceFile(path.join(root, 'l.js'), 1024)).toBeNull();
  });

  it('refuses a directory and a missing file', async () => {
    await mkdir(path.join(root, 'd.js'));
    expect(await readSourceFile(path.join(root, 'd.js'), 1024)).toBeNull();
    expect(await readSourceFile(path.join(root, 'missing.js'), 1024)).toBeNull();
  });
});

describe('walkSourceFiles root form', () => {
  it('strips every trailing slash from the root', async () => {
    await mkdir(path.join(root, 'd'));
    for (const rel of ['c.ts', 'a.ts', 'b.ts', 'd/e.ts', 'B.ts']) await writeFile(path.join(root, rel), 'x');
    const files = await walkSourceFiles(`${root}//`, OPTS);
    expect(files.map((f) => f.relative)).toEqual(['B.ts', 'a.ts', 'b.ts', 'c.ts', 'd/e.ts']);
    expect(files[0].absolute).toBe(`${root}/B.ts`);
  });
});
