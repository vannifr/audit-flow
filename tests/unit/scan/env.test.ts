import { describe, it, expect, vi, afterEach } from 'vitest';
import { buildToolEnv } from '../../../src/scan/env';

const WORK = '/tmp/tessera-abc';

const workerEnv = {
  PATH: '/usr/bin:/bin',
  LANG: 'en_US.UTF-8',
  LC_ALL: 'en_US.UTF-8',
  NODE_OPTIONS: '--require /evil.js',
  npm_config_registry: 'https://evil.example',
  npm_config_userconfig: '/evil/.npmrc',
  GITHUB_TOKEN: 'ghp_fake',
  SEMGREP_APP_TOKEN: 'fake',
  SEMGREP_RULES: 'fake',
  AWS_SECRET_ACCESS_KEY: 'fake',
  HTTPS_PROXY: 'http://proxy.internal:3128',
  HTTP_PROXY: 'http://proxy.internal:3128',
  NO_PROXY: 'localhost',
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_KEY_0: 'url.https://mirror/.insteadOf',
  GIT_CONFIG_VALUE_0: 'https://github.com/',
};

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('buildToolEnv', () => {
  it('never contains NODE_OPTIONS, npm_config_*, GITHUB_TOKEN or SEMGREP_* from the worker env', () => {
    for (const tool of ['git', 'npm', 'gitleaks', 'semgrep'] as const) {
      const { env } = buildToolEnv(tool, WORK, workerEnv);
      const keys = Object.keys(env);
      expect(keys).not.toContain('NODE_OPTIONS');
      expect(keys).not.toContain('GITHUB_TOKEN');
      expect(keys).not.toContain('AWS_SECRET_ACCESS_KEY');
      expect(keys.filter((k) => k.toLowerCase().startsWith('npm_config_'))).toEqual([]);
      expect(keys.filter((k) => k.startsWith('SEMGREP_'))).toEqual([]);
    }
  });

  it('sets HOME and TMPDIR under the work dir and the base variables', () => {
    const { env } = buildToolEnv('semgrep', WORK, workerEnv);
    expect(env.HOME).toBe(`${WORK}/home`);
    expect(env.TMPDIR).toBe(`${WORK}/tmp`);
    expect(env.TZ).toBe('UTC');
    expect(env.NO_COLOR).toBe('1');
    expect(env.PATH).toBe('/usr/bin:/bin');
    expect(env.LANG).toBe('en_US.UTF-8');
    expect(env.LC_ALL).toBe('en_US.UTF-8');
  });

  it('adds the git-only variables for tool git only', () => {
    const git = buildToolEnv('git', WORK, workerEnv).env;
    expect(git.GIT_TERMINAL_PROMPT).toBe('0');
    expect(git.GIT_ASKPASS).toBe('');
    expect(git.GIT_LFS_SKIP_SMUDGE).toBe('1');
    expect(git.GIT_CONFIG_NOSYSTEM).toBe('1');
    expect(git.GIT_CONFIG_GLOBAL).toBe('/dev/null');
    expect(git.GIT_CONFIG_COUNT).toBe('1');
    expect(git.GIT_CONFIG_KEY_0).toBe('url.https://mirror/.insteadOf');
    expect(git.GIT_CONFIG_VALUE_0).toBe('https://github.com/');
    for (const tool of ['npm', 'gitleaks', 'semgrep'] as const) {
      const keys = Object.keys(buildToolEnv(tool, WORK, workerEnv).env);
      expect(keys.filter((k) => k.startsWith('GIT_'))).toEqual([]);
    }
  });

  it('passes proxy variables through and lists their names without values', () => {
    const result = buildToolEnv('npm', WORK, workerEnv);
    expect(result.env.HTTPS_PROXY).toBe('http://proxy.internal:3128');
    expect(result.env.NO_PROXY).toBe('localhost');
    expect([...result.passthrough].sort()).toEqual(['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY']);
    expect(JSON.stringify(result.passthrough)).not.toContain('proxy.internal');
    expect(JSON.stringify(result.overrides)).not.toContain('proxy.internal');
  });

  it('omits proxy names that are not set in the worker env', () => {
    const result = buildToolEnv('npm', WORK, { PATH: '/usr/bin' });
    expect(result.passthrough).toEqual([]);
    expect(Object.keys(result.env)).not.toContain('HTTPS_PROXY');
  });

  it('never leaks denied variables set in both workerEnv and process.env', () => {
    const denied = {
      NODE_OPTIONS: '--require /evil.js',
      GITHUB_TOKEN: 'ghp_fake',
      SEMGREP_APP_TOKEN: 'fake',
      npm_config_registry: 'https://evil.example',
    };
    for (const [k, v] of Object.entries(denied)) vi.stubEnv(k, v);
    for (const tool of ['git', 'npm', 'gitleaks', 'semgrep'] as const) {
      const result = buildToolEnv(tool, WORK, { PATH: '/usr/bin', ...denied });
      for (const name of Object.keys(denied)) {
        expect(Object.keys(result.env)).not.toContain(name);
        expect(Object.keys(result.overrides)).not.toContain(name);
        expect(result.passthrough).not.toContain(name);
      }
      expect(JSON.stringify(result)).not.toContain('ghp_fake');
      expect(JSON.stringify(result)).not.toContain('evil');
    }
  });

  it('sets EIO_BACKEND=posix for semgrep when the worker does not set it', () => {
    const result = buildToolEnv('semgrep', WORK, { PATH: '/usr/bin' });
    expect(result.env.EIO_BACKEND).toBe('posix');
    expect(result.overrides.EIO_BACKEND).toBe('posix');
    expect(result.passthrough).not.toContain('EIO_BACKEND');
  });

  it('passes the worker EIO_BACKEND through for semgrep when it is set', () => {
    const result = buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', EIO_BACKEND: 'libuv' });
    expect(result.env.EIO_BACKEND).toBe('libuv');
    expect(result.passthrough).toContain('EIO_BACKEND');
    expect(result.overrides.EIO_BACKEND).toBeUndefined();
  });

  it('does not set EIO_BACKEND for other tools', () => {
    for (const tool of ['git', 'npm', 'gitleaks'] as const) {
      const result = buildToolEnv(tool, WORK, { PATH: '/usr/bin', EIO_BACKEND: 'libuv' });
      expect(Object.keys(result.env)).not.toContain('EIO_BACKEND');
      expect(Object.keys(buildToolEnv(tool, WORK, { PATH: '/usr/bin' }).env)).not.toContain('EIO_BACKEND');
    }
  });

  it('does not pass GIT_CONFIG_COUNT with an invalid value or above 100', () => {
    for (const bad of ['abc', '-1', '1.5', '', ' 1', '101', '1000', '0x10', '99999']) {
      const result = buildToolEnv('git', WORK, {
        PATH: '/usr/bin',
        GIT_CONFIG_COUNT: bad,
        GIT_CONFIG_KEY_0: 'k',
        GIT_CONFIG_VALUE_0: 'v',
      });
      expect(Object.keys(result.env)).not.toContain('GIT_CONFIG_COUNT');
      expect(Object.keys(result.env)).not.toContain('GIT_CONFIG_KEY_0');
      expect(result.passthrough).not.toContain('GIT_CONFIG_COUNT');
    }
  });

  it('passes GIT_CONFIG_COUNT of exactly 100 and only the indexed keys below the count', () => {
    const result = buildToolEnv('git', WORK, {
      PATH: '/usr/bin',
      GIT_CONFIG_COUNT: '100',
      GIT_CONFIG_KEY_99: 'k99',
      GIT_CONFIG_VALUE_99: 'v99',
      GIT_CONFIG_KEY_100: 'k100',
    });
    expect(result.env.GIT_CONFIG_COUNT).toBe('100');
    expect(result.env.GIT_CONFIG_KEY_99).toBe('k99');
    expect(Object.keys(result.env)).not.toContain('GIT_CONFIG_KEY_100');
  });

  describe('python user site for semgrep', () => {
    it('derives PYTHONUSERBASE from the worker HOME because HOME itself points into the work dir', () => {
      const result = buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', HOME: '/home/operator' });
      expect(result.env.PYTHONUSERBASE).toBe('/home/operator/.local');
      expect(result.env.HOME).toBe(`${WORK}/home`);
    });

    it('prefers an explicit worker PYTHONUSERBASE', () => {
      const result = buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', HOME: '/home/operator', PYTHONUSERBASE: '/opt/py' });
      expect(result.env.PYTHONUSERBASE).toBe('/opt/py');
    });

    it('records only the name, never the value, and never as an override', () => {
      const result = buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', HOME: '/home/operator' });
      expect(result.passthrough).toContain('PYTHONUSERBASE');
      expect(Object.keys(result.overrides)).not.toContain('PYTHONUSERBASE');
    });

    it('ignores a relative or malformed value', () => {
      expect(buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', PYTHONUSERBASE: 'relative/dir' }).env.PYTHONUSERBASE).toBeUndefined();
      expect(buildToolEnv('semgrep', WORK, { PATH: '/usr/bin', PYTHONUSERBASE: '/a\nb' }).env.PYTHONUSERBASE).toBeUndefined();
    });

    it('is not set for other tools', () => {
      for (const tool of ['git', 'npm', 'gitleaks'] as const) {
        expect(buildToolEnv(tool, WORK, { PATH: '/usr/bin', HOME: '/home/operator' }).env.PYTHONUSERBASE).toBeUndefined();
      }
    });
  });
});
