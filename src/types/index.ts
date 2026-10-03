import type { AuditOutcome, NotPerformed, ScannerStatusEntry } from '../scan/status';

// Application Audit Types

export interface AuditInput {
  repoUrl: string;
  scope?: 'full' | 'security' | 'compliance';
  frameworks?: ComplianceFramework[];
  skipApproval?: boolean;
  deadline?: string;
  outputDir?: string;
}

export interface AuditResult {
  status: AuditStatus;
  findings: Finding[];
  complianceMap: ComplianceMap[];
  reportPath: string;
  evidencePath: string;
  duration: number;
  startTime: Date;
  endTime: Date;
  outcome: AuditOutcome;
  notPerformed: NotPerformed[];
  scanners: ScannerStatusEntry[];
  source: { repoUrl: string; revision: string | null };
  reviewAdvice: ReviewAdvice[];
  evidence?: { bundlePath: string; rootHash: string; recordCount: number };
}

export type AuditStatus =
  | 'pending'
  | 'discovery'
  | 'scanning'
  | 'reviewing'
  | 'compliance'
  | 'validation'
  | 'awaiting-approval'
  | 'reporting'
  | 'completed'
  | 'failed';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: 'P0' | 'P1' | 'P2' | 'P3';
  category: FindingCategory;
  evidence: Evidence[];
  remediation: Remediation;
  complianceMapping?: ComplianceMapping;
  verified: boolean;
  createdAt: Date;
}

export type FindingCategory =
  | 'security-injection'
  | 'security-auth'
  | 'security-data'
  | 'security-config'
  | 'security-dependencies'
  | 'security-code-review'
  | 'performance'
  | 'accessibility'
  | 'reliability'
  | 'observability'
  | 'testing'
  | 'cicd'
  | 'compliance';

export interface Evidence {
  type: 'code-snippet' | 'scan-output' | 'config' | 'log' | 'screenshot' | 'curl' | 'code-review';
  file?: string;
  line?: number;
  content: string;
  tool: string;
  timestamp: Date;
}

export interface Remediation {
  description: string;
  effort: 'hours' | 'days' | 'weeks';
  priority: 'immediate' | 'short-term' | 'medium-term' | 'long-term';
  alternatives?: AlternativeRemediation[];
}

export interface AlternativeRemediation {
  description: string;
  effort: string;
  tradeOffs: string;
}

export interface TechStack {
  language: string;
  frameworks: string[];
  database?: string;
  hosting?: string;
  hasPayments: boolean;
  hasPII: boolean;
  packageManager: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'other';
}

export type ComplianceFramework =
  | 'ISO27001'
  | 'SOC2'
  | 'PCI-DSS'
  | 'GDPR'
  | 'HIPAA'
  | 'OWASP-ASVS';

export interface ComplianceMap {
  framework: ComplianceFramework;
  controls: ControlStatus[];
  overallScore: number;
}

export interface ControlStatus {
  controlId: string;
  title: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'not-applicable' | 'unverified';
  evidence: string[];
  gaps?: string[];
}

export interface ComplianceMapping {
  framework: ComplianceFramework;
  controlId: string;
  controlTitle: string;
}

export interface ReviewResult {
  falsePositives: string[];
  severityCorrections: SeverityCorrection[];
  missingFindings: Finding[];
  reviewNotes: string;
}

export interface ReviewAdvice {
  findingId: string;
  kind: 'severity-correction' | 'false-positive';
  currentSeverity?: 'P0' | 'P1' | 'P2' | 'P3';
  suggestedSeverity?: 'P0' | 'P1' | 'P2' | 'P3';
  reason?: string;
}

export interface SeverityCorrection {
  findingId: string;
  newSeverity: 'P0' | 'P1' | 'P2' | 'P3';
  reason: string;
}

export interface ScopeDocument {
  repoUrl: string;
  techStack: TechStack;
  securityLevel: 1 | 2 | 3;
  frameworks: ComplianceFramework[];
  inScope: string[];
  outOfScope: string[];
  createdAt: Date;
}

export interface ScanResult {
  tool: string;
  exitCode: number;
  output: string;
  findings: Finding[];
  duration: number;
  success: boolean;
}

export interface AuditState {
  currentPhase: string;
  findings: Finding[];
  techStack: TechStack | null;
  scope: ScopeDocument | null;
  p0Approved: boolean;
  error?: string;
  scanners?: ScannerStatusEntry[];
  outcome?: AuditOutcome;
  notPerformed?: NotPerformed[];
  revision?: string;
  reviewAdvice?: ReviewAdvice[];
}