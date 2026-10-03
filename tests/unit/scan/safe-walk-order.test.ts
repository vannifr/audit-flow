import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    readdir: async (...args: Parameters<typeof actual.readdir>) => {
      const listed = (await actual.readdir(...args)) as unknown[];
      return listed.reverse();
    },
  };
});

const { walkSourceFiles, walkTree } = await import('../../../src/scan/safe-walk');

let root: string;

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'walk-order-'));
  await mkdir(path.join(root, 'd'));
  for (const rel of ['c.ts', 'a.ts', 'B.ts', 'b.ts', 'd/f.ts', 'd/e.ts']) await writeFile(path.join(root, rel), 'x');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('walk ordering does not depend on readdir order', () => {
  it('walkSourceFiles returns files in byte order', async () => {
    const files = await walkSourceFiles(root, { extensions: ['.ts'], maxFiles: 50 });
    expect(files.map((f) => f.relative)).toEqual(['B.ts', 'a.ts', 'b.ts', 'c.ts', 'd/e.ts', 'd/f.ts']);
  });

  it('walkTree lists each directory in byte order', async () => {
    const walk = await walkTree(root, { maxDepth: 4, maxEntries: 50 });
    expect(walk.entries.map((e) => e.relative)).toEqual(['B.ts', 'a.ts', 'b.ts', 'c.ts', 'd', 'd/e.ts', 'd/f.ts']);
  });
});
