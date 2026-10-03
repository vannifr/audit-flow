import type { ScannerId, ScannerStatusValue, StatusCause } from '../scan/status';

export type Sha256Hex = string;

export type ExitClass =
  | 'success'
  | 'issues-found'
  | 'tool-error'
  | 'timeout'
  | 'killed'
  | 'not-installed'
  | 'spawn-error'
  | 'output-truncated'
  | 'not-run';

export type EvidenceKind = 'tool-run' | 'in-process' | 'source-probe' | 'lifecycle';

export interface ArtifactRef {
  path: string;
  mediaType: 'application/json' | 'text/plain';
  bytes: number;
  sha256: Sha256Hex;
  rawBytes: number;
  rawSha256: Sha256Hex;
  redactions: number;
  truncated: boolean;
}

export interface OverrideAttempt {
  kind: 'control-file' | 'inline-marker' | 'project-config';
  path: string;
  detail: string;
  sha256?: Sha256Hex;
  neutralizedBy: 'removed-from-working-copy' | 'framework-flag' | 'isolated-working-dir' | 'reported-as-finding';
}

export interface EvidenceRecord {
  schema: 'tessera.evidence/v1';
  id: string;
  runId: string;
  stepId: string;
  attempt: number;
  kind: EvidenceKind;
  scanner?: ScannerId;
  action: {
    command: string | null;
    args: string[];
    cwd: string;
    envOverrides: Record<string, string>;
    envPassthrough: string[];
    inputs: Record<string, string>;
  };
  tool: { name: string; version: string | null };
  source: { repoUrl: string; revision: string | null };
  startedAt: string;
  endedAt: string;
  durationMs: number;
  result: {
    exitCode: number | null;
    signal: string | null;
    exitClass: ExitClass;
    timedOut: boolean;
    spawnErrorCode?: string;
  };
  status: ScannerStatusValue;
  cause?: StatusCause;
  causeDetail?: string;
  output: ArtifactRef | null;
  stderr: ArtifactRef | null;
  findingIds: string[];
  overrideAttempts: OverrideAttempt[];
  recordedBy: { framework: 'tessera'; version: string };
}

export interface EvidenceRef {
  recordId: string;
  recordSha256: Sha256Hex;
  locator?: string;
}
export interface FindingEvidenceExtension {
  evidenceRef?: EvidenceRef;
  scanner?: ScannerId;
  heuristic?: boolean;
}

export interface EvidenceStore {
  readonly bundleDir: string;
  writeArtifact(recordId: string, suffix: string, bytes: Buffer, meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>): Promise<ArtifactRef>;
  writeRecord(record: EvidenceRecord): Promise<EvidenceRef>;
}

export interface ManifestEntry {
  seq: number;
  path: string;
  kind: 'record' | 'artifact';
  recordId: string;
  bytes: number;
  sha256: Sha256Hex;
  chainHash: Sha256Hex;
  used: boolean;
}

export interface EvidenceManifest {
  schema: 'tessera.manifest/v1';
  runId: string;
  workflowId: string;
  temporalRunId: string;
  source: { repoUrl: string; revision: string | null };
  sealedAt: string;
  retainUntil: string;
  framework: { name: 'tessera'; version: string };
  hashAlgorithm: 'sha256';
  entries: ManifestEntry[];
  abandoned: { path: string; bytes: number; sha256: Sha256Hex }[];
  chain: {
    algorithm: 'tessera-chain/v1';
    genesis: Sha256Hex;
    head: Sha256Hex;
  };
  rootHash: Sha256Hex;
}

export interface SealEvidenceInput {
  runId: string;
  usedRecordIds: string[];
}

export interface SealEvidenceResult {
  bundlePath: string;
  rootHash: Sha256Hex;
  recordCount: number;
  artifactCount: number;
  abandonedCount: number;
  selfVerified: boolean;
}
