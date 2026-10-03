import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';

export const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const DEFAULT_MAX_DEPTH = 12;
const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git']);

export interface SourceFile {
  absolute: string;
  relative: string;
}

export interface WalkOptions {
  extensions: readonly string[];
  maxFiles: number;
  maxDepth?: number;
  filter?: (relative: string) => boolean;
}

function withoutTrailingSlashes(root: string): string {
  let end = root.length;
  while (end > 0 && root[end - 1] === '/') end--;
  return root.slice(0, end);
}

function byName(a: { name: string }, b: { name: string }): number {
  if (a.name < b.name) return -1;
  return a.name > b.name ? 1 : 0;
}

function canDescend(name: string, depth: number, maxDepth: number): boolean {
  const skipped = name.startsWith('.') || SKIPPED_DIRECTORIES.has(name) || depth + 1 > maxDepth;
  return !skipped;
}

function acceptsFile(name: string, relative: string, options: WalkOptions): boolean {
  if (!options.extensions.some((ext) => name.endsWith(ext))) return false;
  return options.filter === undefined || options.filter(relative);
}

export async function walkSourceFiles(root: string, options: WalkOptions): Promise<SourceFile[]> {
  const results: SourceFile[] = [];
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const base = withoutTrailingSlashes(root);

  async function visit(absoluteDir: string, relativeDir: string, depth: number): Promise<void> {
    let entries;
    try {
      entries = await readdir(absoluteDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort(byName);
    for (const entry of entries) {
      if (results.length >= options.maxFiles) return;
      const absolute = `${absoluteDir}/${entry.name}`;
      const relative = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (canDescend(entry.name, depth, maxDepth)) await visit(absolute, relative, depth + 1);
      } else if (entry.isFile() && acceptsFile(entry.name, relative, options)) {
        results.push({ absolute, relative });
      }
    }
  }

  await visit(base === '' ? '/' : base, '', 0);
  return results;
}

export async function readSourceFile(file: string, maxBytes: number = MAX_SOURCE_FILE_BYTES): Promise<string | null> {
  try {
    const before = await lstat(file);
    if (!before.isFile() || before.size > maxBytes) return null;
    const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > maxBytes) return null;
      const buffer = Buffer.alloc(stat.size);
      const { bytesRead } = await handle.read(buffer, 0, stat.size, 0);
      return buffer.subarray(0, bytesRead).toString('utf-8');
    } finally {
      await handle.close();
    }
  } catch {
    return null;
  }
}

export type TreeEntryType = 'file' | 'directory' | 'symlink' | 'other';

export interface TreeEntry {
  absolute: string;
  relative: string;
  name: string;
  type: TreeEntryType;
  depth: number;
}

export interface TreeWalkOptions {
  maxDepth: number;
  maxEntries: number;
  descend?: (entry: TreeEntry) => boolean;
}

export interface TreeWalkResult {
  entries: TreeEntry[];
  truncated: 'depth' | 'entries' | null;
}

function entryType(entry: { isSymbolicLink(): boolean; isDirectory(): boolean; isFile(): boolean }): TreeEntryType {
  if (entry.isSymbolicLink()) return 'symlink';
  if (entry.isDirectory()) return 'directory';
  if (entry.isFile()) return 'file';
  return 'other';
}

function treeEntry(parent: { absolute: string; relative: string; depth: number }, dirent: { name: string; isSymbolicLink(): boolean; isDirectory(): boolean; isFile(): boolean }): TreeEntry {
  return {
    absolute: `${parent.absolute}/${dirent.name}`,
    relative: parent.relative === '' ? dirent.name : `${parent.relative}/${dirent.name}`,
    name: dirent.name,
    type: entryType(dirent),
    depth: parent.depth + 1,
  };
}

function wantsDescend(entry: TreeEntry, options: TreeWalkOptions): boolean {
  return entry.type === 'directory' && (options.descend === undefined || options.descend(entry));
}

export async function walkTree(root: string, options: TreeWalkOptions): Promise<TreeWalkResult> {
  const entries: TreeEntry[] = [];
  let truncated: TreeWalkResult['truncated'] = null;
  const queue: { absolute: string; relative: string; depth: number }[] = [{ absolute: root, relative: '', depth: 0 }];
  for (const next of queue) {
    const listed = await readdir(next.absolute, { withFileTypes: true });
    listed.sort(byName);
    for (const dirent of listed) {
      if (entries.length >= options.maxEntries) return { entries, truncated: 'entries' };
      const entry = treeEntry(next, dirent);
      entries.push(entry);
      if (!wantsDescend(entry, options)) continue;
      if (entry.depth >= options.maxDepth) {
        truncated = truncated ?? 'depth';
        continue;
      }
      queue.push({ absolute: entry.absolute, relative: entry.relative, depth: entry.depth });
    }
  }
  return { entries, truncated };
}
