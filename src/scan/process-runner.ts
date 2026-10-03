import { execFile } from 'node:child_process';
import type { ChildProcess, ExecFileException } from 'node:child_process';
import type { ProcessOutcome, ProcessRequest, ProcessRunner } from './tool-types';

const MAXBUFFER_CODE = 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';

function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function toBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  return Buffer.alloc(0);
}

function errorCode(err: unknown): string {
  if (typeof err === 'object' && err !== null) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string' && code.length > 0) return code;
  }
  return 'ESPAWN';
}

function spawnFailure(code: string, startedAt: Date): ProcessOutcome {
  return {
    exitCode: null,
    signal: null,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    stdoutTruncated: false,
    timedOut: false,
    spawnErrorCode: code,
    startedAt,
    endedAt: new Date(),
  };
}

export const defaultProcessRunner: ProcessRunner = (req: ProcessRequest) =>
  new Promise<ProcessOutcome>((resolve) => {
    const startedAt = new Date();
    if (
      typeof req.file !== 'string' ||
      req.file.length === 0 ||
      !isPositiveInteger(req.timeoutMs) ||
      !isPositiveInteger(req.maxOutputBytes) ||
      !Number.isSafeInteger(req.maxStderrBytes) ||
      req.maxStderrBytes < 0
    ) {
      resolve(spawnFailure('EINVAL', startedAt));
      return;
    }

    const onDone = (err: ExecFileException | null, stdoutRaw: unknown, stderrRaw: unknown): void => {
      const endedAt = new Date();
      let stdout = toBuffer(stdoutRaw);
      let stderr = toBuffer(stderrRaw);
      if (stderr.length > req.maxStderrBytes) stderr = stderr.subarray(0, req.maxStderrBytes);

      if (err === null) {
        resolve({ exitCode: 0, signal: null, stdout, stderr, stdoutTruncated: false, timedOut: false, startedAt, endedAt });
        return;
      }

      const code: unknown = err.code;
      const maxBufferHit = code === MAXBUFFER_CODE;
      const timedOut = !maxBufferHit && err.killed === true;

      const stdoutTruncated = maxBufferHit && stdout.length >= req.maxOutputBytes;
      if (stdout.length > req.maxOutputBytes) stdout = stdout.subarray(0, req.maxOutputBytes);

      const fallbackSignal = maxBufferHit ? 'SIGKILL' : null;
      const outcome: ProcessOutcome = {
        exitCode: typeof code === 'number' ? code : null,
        signal: typeof err.signal === 'string' ? err.signal : fallbackSignal,
        stdout,
        stderr,
        stdoutTruncated,
        timedOut,
        startedAt,
        endedAt,
      };
      if (typeof code === 'string' && !maxBufferHit) outcome.spawnErrorCode = code;
      resolve(outcome);
    };

    try {
      const child: ChildProcess = execFile(
        req.file,
        [...req.args],
        {
          cwd: req.cwd,
          env: { ...req.env },
          shell: false,
          encoding: 'buffer',
          killSignal: 'SIGKILL',
          windowsHide: true,
          timeout: req.timeoutMs,
          maxBuffer: req.maxOutputBytes,
        },
        onDone,
      );
      child.stdin?.on('error', () => undefined);
      child.stdin?.end();
    } catch (err) {
      resolve(spawnFailure(errorCode(err), startedAt));
    }
  });
