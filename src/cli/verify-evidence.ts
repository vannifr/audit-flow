import path from 'node:path';
import { traceEvidence, verifyEvidenceBundle } from '../evidence/verify';
import type { VerifyReport } from '../evidence/verify';

export interface CliIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

interface CliArgs {
  bundleDir: string;
  expectRoot?: string;
  json: boolean;
  trace?: string;
}

const USAGE = 'usage: npm run evidence:verify -- <bundle-dir> [--expect-root <sha256>] [--json] [--trace <recordId>]\n';
const HEX64 = /^[0-9a-fA-F]{64}$/;

function plain(value: string): string {
  return /^[\x20-\x7e]*$/.test(value) ? value : JSON.stringify(value);
}

function parseArgs(argv: string[]): CliArgs | string {
  let bundleDir: string | undefined;
  let expectRoot: string | undefined;
  let trace: string | undefined;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') {
      json = true;
    } else if (arg === '--expect-root' || arg === '--trace') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) return `${arg} requires a value`;
      i += 1;
      if (arg === '--expect-root') {
        if (!HEX64.test(value)) return '--expect-root must be a sha256 hex digest';
        expectRoot = value.toLowerCase();
      } else {
        trace = value;
      }
    } else if (arg.startsWith('-')) {
      return `unknown option ${plain(arg)}`;
    } else if (bundleDir === undefined) {
      bundleDir = arg;
    } else {
      return 'only one bundle directory can be given';
    }
  }
  if (bundleDir === undefined) return 'missing bundle directory';
  return { bundleDir: path.resolve(bundleDir), expectRoot, json, trace };
}

function textReport(report: VerifyReport): string {
  const lines = [
    report.ok ? 'VERIFIED' : 'FAILED',
    `runId: ${plain(report.runId ?? 'unknown')}`,
    `root hash: ${report.rootHash ?? 'unknown'}`,
    `checked entries: ${report.checkedEntries}`,
  ];
  if (report.rootMatches === true) lines.push('expected root: matches');
  if (report.rootMatches === false) lines.push('expected root: does not match');
  for (const issue of report.issues) lines.push(`${issue.problem} ${plain(issue.path)}`);
  return `${lines.join('\n')}\n`;
}

export async function runVerifyCli(argv: string[], io: CliIo): Promise<number> {
  const args = parseArgs(argv);
  if (typeof args === 'string') {
    io.stderr(`${args}\n${USAGE}`);
    return 2;
  }
  let report: VerifyReport;
  try {
    report = await verifyEvidenceBundle(args.bundleDir, args.expectRoot === undefined ? {} : { expectRootHash: args.expectRoot });
  } catch (error) {
    io.stderr(`cannot read bundle ${plain(args.bundleDir)}: ${error instanceof Error ? plain(error.message) : 'unknown error'}\n`);
    return 2;
  }
  if (args.trace === undefined || !report.ok) {
    io.stdout(args.json ? `${JSON.stringify(report, null, 2)}\n` : textReport(report));
    return report.ok ? 0 : 1;
  }
  try {
    const trace = await traceEvidence(args.bundleDir, args.trace);
    if (args.json) {
      io.stdout(`${JSON.stringify({ report, trace }, null, 2)}\n`);
    } else {
      const lines = [
        textReport(report).trimEnd(),
        `record: ${trace.recordId}`,
        `step: ${plain(trace.record.stepId)}`,
        `tool: ${plain(trace.record.tool.name)} ${plain(trace.record.tool.version ?? 'unknown')}`,
        `source: ${plain(trace.source.repoUrl)}`,
        `revision: ${plain(trace.source.revision ?? 'unknown')}`,
        ...trace.artifacts.map((a) => `artifact: ${plain(a.path)} sha256 ${a.sha256} raw sha256 ${a.rawSha256}`),
        `root hash: ${trace.rootHash}`,
      ];
      io.stdout(`${lines.join('\n')}\n`);
    }
    return 0;
  } catch (error) {
    io.stderr(`${error instanceof Error ? plain(error.message) : 'trace failed'}\n`);
    return 1;
  }
}

async function main(): Promise<void> {
  const code = await runVerifyCli(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  });
  process.exitCode = code;
}

if (require.main === module) {
  void main();
}
