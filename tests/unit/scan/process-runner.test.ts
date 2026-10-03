import { describe, it, expect, vi, afterEach } from 'vitest';
import { defaultProcessRunner } from '../../../src/scan/process-runner';
import type { ProcessRequest } from '../../../src/scan/tool-types';

function request(args: string[], overrides: Partial<ProcessRequest> = {}): ProcessRequest {
  return {
    file: process.execPath,
    args,
    cwd: process.cwd(),
    env: {},
    timeoutMs: 10_000,
    maxOutputBytes: 1024 * 1024,
    maxStderrBytes: 1024 * 1024,
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('defaultProcessRunner', () => {
  it('delivers arguments with shell metacharacters literally', async () => {
    const hostile = ['a;b', '$(id)', '`id`', 'with space', '&& echo x', '| cat', '> /tmp/x', "'q'", '"d"'];
    const out = await defaultProcessRunner(request(['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', ...hostile]));
    expect(out.exitCode).toBe(0);
    expect(JSON.parse(out.stdout.toString('utf8'))).toEqual(hostile);
  });

  it('does not interpret arguments through a shell (shell:false)', async () => {
    const out = await defaultProcessRunner(request(['-e', 'process.stdout.write(process.argv[1])', '--', '-p 1+1; echo hacked']));
    expect(out.stdout.toString('utf8')).toBe('-p 1+1; echo hacked');
    expect(out.stdout.toString('utf8')).not.toContain('\nhacked');
    const direct = await defaultProcessRunner(request(['-p', '1+1; echo hacked']));
    expect(direct.exitCode).not.toBe(0);
    expect(direct.stdout.toString('utf8')).not.toContain('hacked');
  });

  it('reports a missing binary as spawnErrorCode ENOENT', async () => {
    const out = await defaultProcessRunner(request([], { file: 'tessera-no-such-binary-xyz' }));
    expect(out.spawnErrorCode).toBe('ENOENT');
    expect(out.exitCode).toBeNull();
    expect(out.timedOut).toBe(false);
  });

  it('marks a process exceeding timeoutMs as timedOut', async () => {
    const out = await defaultProcessRunner(request(['-e', 'setTimeout(() => {}, 20000)'], { timeoutMs: 300 }));
    expect(out.timedOut).toBe(true);
    expect(out.exitCode).toBeNull();
    expect(out.stdoutTruncated).toBe(false);
  });

  it('marks output above maxOutputBytes as stdoutTruncated and caps the buffer', async () => {
    const out = await defaultProcessRunner(
      request(['-e', "process.stdout.write('x'.repeat(200000))"], { maxOutputBytes: 1000 }),
    );
    expect(out.stdoutTruncated).toBe(true);
    expect(out.timedOut).toBe(false);
    expect(out.stdout.length).toBeLessThanOrEqual(1000);
  });

  it('does not mark output within the limit as truncated', async () => {
    const out = await defaultProcessRunner(request(['-e', "process.stdout.write('x'.repeat(500))"], { maxOutputBytes: 1000 }));
    expect(out.stdoutTruncated).toBe(false);
    expect(out.stdout).toHaveLength(500);
  });

  it('caps stderr at maxStderrBytes', async () => {
    const out = await defaultProcessRunner(request(['-e', "process.stderr.write('e'.repeat(5000))"], { maxStderrBytes: 100 }));
    expect(out.stderr).toHaveLength(100);
  });

  it('returns the exit code of the process', async () => {
    const out = await defaultProcessRunner(request(['-e', 'process.exit(3)']));
    expect(out.exitCode).toBe(3);
    expect(out.timedOut).toBe(false);
    expect(out.spawnErrorCode).toBeUndefined();
  });

  it('gives the child only the supplied env and none of process.env', async () => {
    vi.stubEnv('TESSERA_TEST_LEAK', 'leaked-value');
    vi.stubEnv('GITHUB_TOKEN', 'ghp_leak');
    const out = await defaultProcessRunner(
      request(['-e', 'process.stdout.write(JSON.stringify(process.env))'], { env: { ONLY_THIS: 'yes' } }),
    );
    const childEnv = JSON.parse(out.stdout.toString('utf8')) as Record<string, string>;
    expect(childEnv.ONLY_THIS).toBe('yes');
    expect(childEnv.TESSERA_TEST_LEAK).toBeUndefined();
    expect(childEnv.GITHUB_TOKEN).toBeUndefined();
    expect(Object.keys(childEnv)).toEqual(['ONLY_THIS']);
  });

  it('runs in the requested cwd', async () => {
    const out = await defaultProcessRunner(request(['-e', 'process.stdout.write(process.cwd())'], { cwd: '/' }));
    expect(out.stdout.toString('utf8')).toBe('/');
  });

  it('never rejects on invalid requests and returns an outcome instead', async () => {
    for (const bad of [
      request([], { timeoutMs: 0 }),
      request([], { timeoutMs: -5 }),
      request([], { timeoutMs: Number.NaN }),
      request([], { maxOutputBytes: 0 }),
      request([], { file: '' }),
    ]) {
      const out = await defaultProcessRunner(bad);
      expect(out.spawnErrorCode).toBeDefined();
      expect(out.exitCode).toBeNull();
      expect(out.startedAt).toBeInstanceOf(Date);
      expect(out.endedAt).toBeInstanceOf(Date);
    }
  });

  it('never rejects when the cwd does not exist', async () => {
    const out = await defaultProcessRunner(request([], { cwd: '/nonexistent-tessera-dir' }));
    expect(out.spawnErrorCode).toBeDefined();
    expect(out.exitCode).toBeNull();
  });
});
