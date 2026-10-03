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

export type ComputeOutcome = (input: ComputeOutcomeInput) => OutcomeDecision;

export type MayReportClean = (entry: ScannerStatusEntry) => boolean;

const STATUS_TEXT: Record<Exclude<ScannerStatusValue, 'completed'>, string> = {
  partial: 'ran only partially',
  failed: 'failed',
  skipped: 'was skipped',
  unavailable: 'was not available',
};

function notPerformedFor(entry: ScannerStatusEntry): NotPerformed {
  const status = entry.status as Exclude<ScannerStatusValue, 'completed'>;
  const reason = entry.cause === undefined ? '' : ` (${entry.cause})`;
  const item: NotPerformed = {
    scanner: entry.scanner,
    status: entry.status,
    summary: `Required scanner ${entry.scanner} ${STATUS_TEXT[status]}${reason}; its area is not verified.`,
  };
  if (entry.cause !== undefined) {
    item.cause = entry.cause;
  }
  return item;
}

export function computeOutcome(input: ComputeOutcomeInput): OutcomeDecision {
  const notPerformed: NotPerformed[] = [];
  const completedScanners: ScannerId[] = [];
  for (const entry of input.scanners) {
    if (entry.status === 'completed') {
      completedScanners.push(entry.scanner);
    } else if (entry.required) {
      notPerformed.push(notPerformedFor(entry));
    }
  }
  const untracedCount = input.untracedFindingIds.length;
  if (untracedCount > 0) {
    notPerformed.push({
      scanner: 'evidence',
      status: 'untraced-findings',
      summary: `${untracedCount} finding(s) could not be traced to an evidence record.`,
    });
  }
  return {
    outcome: notPerformed.length > 0 ? 'incomplete' : 'complete',
    notPerformed,
    completedScanners,
  };
}

export function mayReportClean(entry: ScannerStatusEntry): boolean {
  return entry.status === 'completed';
}
