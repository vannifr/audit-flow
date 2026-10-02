// Contract: evidence record (FR-005, FR-006, FR-008, FR-012, FR-013, FR-014, FR-015)
// Target module: src/evidence/store.ts (writer) and src/types/index.ts (types).
// Stored as <bundle>/records/<id>.json, mode 0600 at creation, 0400 after sealing.

import type { ScannerId, ScannerStatusValue, StatusCause } from './scanner-status';

export type Sha256Hex = string; // /^[0-9a-f]{64}$/

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
  path: string;            // relative posix path inside the bundle, e.g. "artifacts/scan.npm-audit.a1.stdout.json"
  mediaType: 'application/json' | 'text/plain';
  bytes: number;
  sha256: Sha256Hex;       // hash of the stored (sanitized) bytes; verified by the manifest
  rawBytes: number;
  rawSha256: Sha256Hex;    // hash of the exact bytes the tool emitted, before sanitizing
  redactions: number;
  truncated: boolean;
}

export interface OverrideAttempt {
  kind: 'control-file' | 'inline-marker' | 'project-config';
  path: string;            // relative to the source root
  detail: string;          // e.g. ".gitleaksignore removed from working copy", "nosemgrep marker (neutralized by --disable-nosem)"
  sha256?: Sha256Hex;      // of the original control file, when one was removed
  neutralizedBy: 'removed-from-working-copy' | 'framework-flag' | 'isolated-working-dir' | 'reported-as-finding';
}

export interface EvidenceRecord {
  schema: 'tessera.evidence/v1';
  id: string;              // `${stepId}.a${attempt}`, /^[a-z0-9][a-z0-9.-]{0,95}$/
  runId: string;           // AuditRun.runId; identical for every record in a bundle (FR-015)
  stepId: string;          // e.g. "source.clone", "source.revision", "source.probe", "scan.npm-audit"
  attempt: number;         // Temporal activity attempt, >= 1
  kind: EvidenceKind;
  scanner?: ScannerId;
  action: {
    command: string | null;        // binary name for tool runs, null for in-process steps
    args: string[];                // redacted; absolute paths replaced by tokens <WORK>, <SOURCE>, <CONFIG>
    cwd: string;                   // token form
    envOverrides: Record<string, string>; // framework-set variables only; passthrough variables recorded by name below
    envPassthrough: string[];
    inputs: Record<string, string>;        // e.g. { "package-lock.json.sha256": "...", "repoUrl": "..." }
  };
  tool: { name: string; version: string | null };
  source: { repoUrl: string; revision: string | null }; // FR-008
  startedAt: string;       // ISO-8601 UTC
  endedAt: string;         // ISO-8601 UTC, >= startedAt
  durationMs: number;
  result: {
    exitCode: number | null;       // null when not spawned or killed by signal
    signal: string | null;
    exitClass: ExitClass;
    timedOut: boolean;
    spawnErrorCode?: string;       // e.g. "ENOENT"
  };
  status: ScannerStatusValue;      // status contribution of this step
  cause?: StatusCause;
  causeDetail?: string;            // redacted, <= 500 chars
  output: ArtifactRef | null;      // primary output (stdout or report file); null when nothing was produced
  stderr: ArtifactRef | null;      // redacted stderr, capped at 1 MiB
  findingIds: string[];            // FR-007 back-reference
  overrideAttempts: OverrideAttempt[]; // FR-014
  recordedBy: { framework: 'tessera'; version: string };
}

export interface EvidenceRef {
  recordId: string;
  recordSha256: Sha256Hex;
  locator?: string;        // JSON pointer into the output artifact, e.g. "/vulnerabilities/lodash/via/0"
}

// Finding extension (additive, backward compatible; src/types/index.ts)
export interface FindingEvidenceExtension {
  evidenceRef?: EvidenceRef;   // required for every finding produced inside applicationAudit (FR-007), enforced by the outcome guard
  scanner?: ScannerId;
  heuristic?: boolean;         // true for code-review regex findings (principle VII labeling)
}

export interface EvidenceStore {
  readonly bundleDir: string;
  writeArtifact(recordId: string, suffix: string, bytes: Buffer, meta: Omit<ArtifactRef, 'path' | 'bytes' | 'sha256'>): Promise<ArtifactRef>;
  // Publishes atomically: write to records/.staging/<id>.json, fsync, link() to records/<id>.json, unlink staging.
  // link() fails with EEXIST for an existing id; the store then returns the existing record's hash (idempotent re-delivery).
  writeRecord(record: EvidenceRecord): Promise<EvidenceRef>;
}
