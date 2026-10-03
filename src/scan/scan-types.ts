import type { Finding } from '../types';
import type { EvidenceRef, FindingEvidenceExtension, OverrideAttempt } from '../evidence/types';
import type { AuditRun, FetchedSource } from './lifecycle';
import type { ScannerId, ScannerStatusEntry } from './status';
import type { RunToolDeps } from './tool-types';

export type ScanFinding = Finding & FindingEvidenceExtension;

export interface ScanContext {
  run: AuditRun;
  source: FetchedSource;
  repoUrl: string;
  attempt: number;
  deps: RunToolDeps;
  workerEnv: Readonly<Record<string, string | undefined>>;
  configDir: string;
  overrideAttempts?: OverrideAttempt[];
}

export interface ScanStepResult {
  scanner: ScannerId;
  status: ScannerStatusEntry;
  findings: ScanFinding[];
  evidence: EvidenceRef;
}

export type ScanStep = (ctx: ScanContext) => Promise<ScanStepResult>;

export const MAX_FINDINGS_PER_STEP = 2000;
