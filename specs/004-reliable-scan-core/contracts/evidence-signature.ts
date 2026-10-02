// Contract: manifest signature (FR-018, FR-019, FR-020)
// Target modules: src/evidence/sign.ts, src/evidence/verify.ts (signature part)
//
// signature.json lives in the bundle next to manifest.json (mode 0400 after sealing).
// The signing key is never inside the bundle or EVIDENCE_ROOT.

import type { Sha256Hex } from './evidence-record';

export interface EvidenceSignature {
  schema: 'tessera.signature/v1';
  alg: 'ed25519';
  keyId: Sha256Hex;          // sha256 of the SPKI DER of the public key
  runId: string;
  rootHash: Sha256Hex;
  manifestSha256: Sha256Hex; // sha256 of the manifest.json bytes
  signedAt: string;          // ISO-8601 UTC, signer's own clock (not independently attested)
  signature: string;         // base64 over the payload below
}

// payload = `tessera-sig/v1\n${runId}\n${rootHash}\n${manifestSha256}\n${signedAt}`

export type SignatureStatus = 'valid' | 'invalid' | 'unsigned' | 'unknown-key';

export interface SignatureReport {
  status: SignatureStatus;
  keyId: string | null;
  signedAt: string | null;
  timeAttested: false;       // always false at assurance level 1
}

export type AssuranceLevel = 0 | 1;  // 2 and 3 are defined in docs/assurance-roadmap.md

export interface SignOptions {
  keyPath: string;           // must resolve outside the evidence root
}

export interface VerifySignatureOptions {
  trustedKeys: string[];     // public key files or directories; empty means everything is unknown-key
}

// computeAssuranceLevel(verifyReport, signatureReport): 1 only if hashes verify AND status === 'valid'
export function computeAssuranceLevel(hashesOk: boolean, sig: SignatureReport): AssuranceLevel {
  return hashesOk && sig.status === 'valid' ? 1 : 0;
}
