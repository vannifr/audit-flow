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

export async function walkSourceFiles(root: string, options: WalkOptions): Promise<SourceFile[]> {
  const results: SourceFile[] = [];
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const base = root.replace(/\/+$/, '');

  async function visit(absoluteDir: string, relativeDir: string, depth: number): Promise<void> {
    let entries;
    try {
      entries = await readdir(absoluteDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (results.length >= options.maxFiles) return;
      const absolute = `${absoluteDir}/${entry.name}`;
      const relative = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || SKIPPED_DIRECTORIES.has(entry.name)) continue;
        if (depth + 1 > maxDepth) continue;
        await visit(absolute, relative, depth + 1);
      } else if (entry.isFile()) {
        if (!options.extensions.some((ext) => entry.name.endsWith(ext))) continue;
        if (options.filter !== undefined && !options.filter(relative)) continue;
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
