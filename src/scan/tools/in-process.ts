import { sha256Hex } from '../../evidence/hash';
import type { ArtifactRef, EvidenceRecord, EvidenceRef } from '../../evidence/types';
import { redactSecrets } from '../../evidence/redact';
import type { ScanContext } from '../scan-types';
import type { ScannerId, ScannerStatusValue, StatusCause } from '../status';

export interface InProcessStep {
  stepId: string;
  scanner: ScannerId;
  toolName: string;
  status: ScannerStatusValue;
  cause?: StatusCause;
  causeDetail?: string;
  inputs?: Record<string, string>;
  output?: { bytes: Buffer; mediaType: ArtifactRef['mediaType']; suffix: string };
  findingIds?: string[];
}

export interface InProcessResult {
  record: EvidenceRecord;
  evidence: EvidenceRef;
}

export async function recordInProcessStep(ctx: ScanContext, step: InProcessStep): Promise<InProcessResult> {
  const startedAt = ctx.deps.clock();
  const id = `${step.stepId}.a${ctx.attempt}`;
  let output: ArtifactRef | null = null;
  if (step.output) {
    const redacted = redactSecrets(step.output.bytes.toString('utf8'));
    const stored = Buffer.from(redacted.text, 'utf8');
    output = await ctx.deps.store.writeArtifact(id, step.output.suffix, stored, {
      mediaType: step.output.mediaType,
      rawBytes: step.output.bytes.length,
      rawSha256: sha256Hex(step.output.bytes),
      redactions: redacted.redactions,
      truncated: false,
    });
  }
  const endedAt = ctx.deps.clock();
  const record: EvidenceRecord = {
    schema: 'tessera.evidence/v1',
    id,
    runId: ctx.run.runId,
    stepId: step.stepId,
    attempt: ctx.attempt,
    kind: 'in-process',
    scanner: step.scanner,
    action: { command: null, args: [], cwd: '<WORK>', envOverrides: {}, envPassthrough: [], inputs: step.inputs ?? {} },
    tool: { name: step.toolName, version: null },
    source: { repoUrl: ctx.repoUrl, revision: ctx.source.revision },
    startedAt: startedAt.toISOString(),
    endedAt: endedAt.toISOString(),
    durationMs: Math.max(0, endedAt.getTime() - startedAt.getTime()),
    result: {
      exitCode: null,
      signal: null,
      exitClass: step.status === 'completed' ? 'success' : 'not-run',
      timedOut: false,
    },
    status: step.status,
    cause: step.cause,
    causeDetail: step.causeDetail,
    output,
    stderr: null,
    findingIds: step.findingIds ?? [],
    overrideAttempts: [],
    recordedBy: { framework: 'tessera', version: ctx.deps.frameworkVersion },
  };
  const evidence = await ctx.deps.store.writeRecord(record);
  return { record, evidence };
}
