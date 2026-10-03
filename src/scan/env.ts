import path from 'node:path';
import type { BuildToolEnv } from './tool-types';

const BASE_PASSTHROUGH = ['PATH', 'LANG', 'LC_ALL'] as const;
const PROXY_PASSTHROUGH = ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY'] as const;
const MAX_GIT_CONFIG_COUNT = 100;

function gitConfigPassthrough(workerEnv: Readonly<Record<string, string | undefined>>): string[] {
  const raw = workerEnv.GIT_CONFIG_COUNT;
  if (raw === undefined || !/^[0-9]{1,3}$/.test(raw)) return [];
  const count = Number(raw);
  if (count > MAX_GIT_CONFIG_COUNT) return [];
  const names = ['GIT_CONFIG_COUNT'];
  for (let i = 0; i < count; i++) {
    for (const name of [`GIT_CONFIG_KEY_${i}`, `GIT_CONFIG_VALUE_${i}`]) {
      if (workerEnv[name] !== undefined) names.push(name);
    }
  }
  return names;
}

export const buildToolEnv: BuildToolEnv = (tool, workDir, workerEnv) => {
  const env: Record<string, string> = {};
  const overrides: Record<string, string> = {};
  const passthrough: string[] = [];

  for (const name of BASE_PASSTHROUGH) {
    const value = workerEnv[name];
    if (value !== undefined) env[name] = value;
  }

  overrides.TZ = 'UTC';
  overrides.HOME = path.posix.join(workDir, 'home');
  overrides.TMPDIR = path.posix.join(workDir, 'tmp');
  overrides.NO_COLOR = '1';

  const passNames: string[] = [...PROXY_PASSTHROUGH];

  if (tool === 'git') {
    overrides.GIT_TERMINAL_PROMPT = '0';
    overrides.GIT_ASKPASS = '';
    overrides.GIT_LFS_SKIP_SMUDGE = '1';
    overrides.GIT_CONFIG_NOSYSTEM = '1';
    overrides.GIT_CONFIG_GLOBAL = '/dev/null';
    passNames.push(...gitConfigPassthrough(workerEnv));
  }

  if (tool === 'semgrep') {
    if (workerEnv.EIO_BACKEND !== undefined) {
      passNames.push('EIO_BACKEND');
    } else {
      overrides.EIO_BACKEND = 'posix';
    }
  }

  for (const name of passNames) {
    const value = workerEnv[name];
    if (value === undefined) continue;
    env[name] = value;
    passthrough.push(name);
  }

  Object.assign(env, overrides);
  return { env, overrides, passthrough };
};
