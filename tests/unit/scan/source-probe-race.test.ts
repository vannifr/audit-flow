import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { TreeWalkOptions, TreeWalkResult } from '../../../src/scan/safe-walk';

const race = vi.hoisted(() => ({ after: undefined as undefined | ((result: TreeWalkResult) => Promise<TreeWalkResult>) }));

vi.mock('../../../src/scan/safe-walk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/scan/safe-walk')>();
  return {
    ...actual,
    walkTree: async (root: string, options: TreeWalkOptions): Promise<TreeWalkResult> => {
      const result = await actual.walkTree(root, options);
      return race.after === undefined ? result : race.after(result);
    },
  };
});

const { probeSource } = await import('../../../src/scan/source-probe');

let root: string;
let repo: string;
let outside: string;

async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tessera-probe-race-'));
  repo = path.join(root, 'repo');
  outside = path.join(root, 'outside');
  await mkdir(path.join(repo, 'sub'), { recursive: true });
  await mkdir(outside);
  await writeFile(path.join(outside, '.gitleaksignore'), 'outside the source');
  race.after = undefined;
});

afterEach(async () => {
  race.after = undefined;
  await rm(root, { recursive: true, force: true });
});

describe('probeSource never touches anything outside the source, even if the walk is raced or wrong (FR-014, principle VIII)', () => {
  it('refuses when a directory on the path was swapped for a symlink to outside after the walk', async () => {
    await writeFile(path.join(repo, 'sub', '.gitleaksignore'), 'inside');
    race.after = async (result) => {
      await rename(path.join(repo, 'sub'), path.join(repo, 'sub-real'));
      await symlink(outside, path.join(repo, 'sub'));
      return result;
    };

    await expect(probeSource(repo)).rejects.toThrow(/source probe: refusing an entry whose parent leaves the source/);
    expect(await readFile(path.join(outside, '.gitleaksignore'), 'utf8')).toBe('outside the source');
    expect(await exists(path.join(outside, '.gitleaksignore.tessera-neutralized'))).toBe(false);
  });

  it('refuses an entry that the walk reports outside the source and leaves that file alone', async () => {
    race.after = async (result) => ({
      truncated: result.truncated,
      entries: [...result.entries, { absolute: `${repo}/../outside/.gitleaksignore`, relative: '../outside/.gitleaksignore', name: '.gitleaksignore', type: 'file', depth: 1 }],
    });

    await expect(probeSource(repo)).rejects.toThrow(/source probe: refusing an entry outside the source/);
    expect(await readFile(path.join(outside, '.gitleaksignore'), 'utf8')).toBe('outside the source');
    expect(await exists(path.join(outside, '.gitleaksignore.tessera-neutralized'))).toBe(false);
  });

  it('refuses an entry whose type changed after the walk', async () => {
    await writeFile(path.join(repo, '.gitleaksignore'), 'inside');
    race.after = async (result) => {
      await rm(path.join(repo, '.gitleaksignore'));
      await symlink(path.join(outside, '.gitleaksignore'), path.join(repo, '.gitleaksignore'));
      return result;
    };

    await expect(probeSource(repo)).rejects.toThrow(/changed type/);
    expect(await readFile(path.join(outside, '.gitleaksignore'), 'utf8')).toBe('outside the source');
  });
});
