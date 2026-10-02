// Contract: evidence manifest and bundle layout (FR-009, FR-011, FR-015, FR-017)
// Target module: src/evidence/manifest.ts
//
// Bundle layout (one folder per audit run, handed over as a whole):
//   <EVIDENCE_ROOT>/<workflowSlug>-<temporalRunId>/      mode 0700 while open, 0500 after sealing
//     records/<recordId>.json                            EvidenceRecord, 0600 -> 0400
//     records/.staging/                                  never-published partial writes (listed as abandoned)
//     artifacts/<recordId>.<suffix>                      sanitized tool output, 0600 -> 0400
//     manifest.json                                      EvidenceManifest, 0400
//     SHA256SUMS                                         coreutils format over records/ and artifacts/, 0400

import type { Sha256Hex } from './evidence-record';

export interface ManifestEntry {
  seq: number;              // 1-based, order of the chain
  path: string;             // relative posix path, no "..", no leading "/"
  kind: 'record' | 'artifact';
  recordId: string;
  bytes: number;
  sha256: Sha256Hex;
  chainHash: Sha256Hex;     // sha256(prevChainHash + "\n" + seq + "\n" + path + "\n" + sha256)
  used: boolean;            // false for records of attempts whose result the workflow did not use
}

export interface EvidenceManifest {
  schema: 'tessera.manifest/v1';
  runId: string;
  workflowId: string;
  temporalRunId: string;
  source: { repoUrl: string; revision: string | null };
  sealedAt: string;         // ISO-8601 UTC
  retainUntil: string;      // sealedAt + 365 days (FR-011 retention marker)
  framework: { name: 'tessera'; version: string };
  hashAlgorithm: 'sha256';
  entries: ManifestEntry[]; // sorted by path (byte order) before seq assignment
  abandoned: { path: string; bytes: number; sha256: Sha256Hex }[];
  chain: {
    algorithm: 'tessera-chain/v1';
    genesis: Sha256Hex;     // sha256("tessera:" + runId)
    head: Sha256Hex;        // chainHash of the last entry, or genesis when empty
  };
  rootHash: Sha256Hex;      // === chain.head; anchored outside the folder (workflow result, Temporal history, report)
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
  selfVerified: boolean;    // sealEvidence runs verifyEvidenceBundle on its own output before returning
}
