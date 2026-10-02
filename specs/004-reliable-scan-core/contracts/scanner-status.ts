// Contract: scanner status and audit outcome (FR-001, FR-002, FR-003, FR-004, FR-016)
// Target module: src/scan/status.ts — pure, no Node imports, safe to import from workflow code.

export type ScannerId =
  | 'npm-audit'
  | 'gitleaks'
  | 'semgrep'
  | 'license-check'
  | 'code-review';

export type ScannerStatusValue =
  | 'completed'
  | 'partial'
  | 'failed'
  | 'skipped'
  | 'unavailable';

export type StatusCause =
  | 'issues-found'
  | 'not-installed'
  | 'spawn-error'
  | 'timeout'
  | 'killed'
  | 'tool-error'
  | 'tool-reported-errors'
  | 'parse-error'
  | 'output-truncated'
  | 'findings-truncated'
  | 'no-lockfile'
  | 'unsupported-lockfile'
  | 'not-applicable'
  | 'source-unavailable'
  | 'activity-failed'
  | 'network';

export interface ScannerStatusEntry {
  scanner: ScannerId;
  required: boolean;
  status: ScannerStatusValue;
  cause?: StatusCause;
  causeDetail?: string;
  heuristic: boolean;
  toolVersion: string | null;
  findingCount: number;
  evidenceRecordIds: string[];
}

export type AuditOutcome = 'complete' | 'incomplete';

export interface NotPerformed {
  scanner: ScannerId | 'source' | 'evidence';
  status: ScannerStatusValue | 'untraced-findings';
  cause?: StatusCause;
  summary: string;
}

export interface OutcomeDecision {
  outcome: AuditOutcome;
  notPerformed: NotPerformed[];
  completedScanners: ScannerId[];
}

export interface ComputeOutcomeInput {
  scanners: ScannerStatusEntry[];
  untracedFindingIds: string[];
}

// Rule (FR-002): outcome is 'incomplete' iff
//   some entry has required === true and status !== 'completed', or
//   untracedFindingIds.length > 0 (FR-007 guard).
// Every such entry appears in notPerformed, in input order.
// FR-003: an area may be shown as clean only when its entry has status 'completed'.
export type ComputeOutcome = (input: ComputeOutcomeInput) => OutcomeDecision;

export type MayReportClean = (entry: ScannerStatusEntry) => boolean;
