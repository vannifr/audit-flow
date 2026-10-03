import type { AuditOutcome, NotPerformed, ScannerStatusEntry } from '../scan/status';

export interface ReportSignature {
  signed: boolean;
  keyId?: string;
  signedAt?: string;
  level: 0 | 1;
}

export interface OutcomeBlockInput {
  outcome?: AuditOutcome;
  notPerformed?: NotPerformed[];
  scanners?: ScannerStatusEntry[];
  revision?: string | null;
  evidence?: { bundlePath: string; rootHash: string };
  signature?: ReportSignature;
  steering?: { controlFiles: number; inlineMarkers: number };
  findingCount: number;
}

const TABLE_HEADER = '| Scanner | Required | Status | Cause | Heuristic | Findings | Tool version |';
const TABLE_RULE = '|---------|----------|--------|-------|-----------|----------|--------------|';

function cell(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').replace(/\|/g, '/');
}

function scannerRow(entry: ScannerStatusEntry): string {
  const columns = [
    cell(entry.scanner),
    entry.required ? 'yes' : 'no',
    cell(entry.status),
    cell(entry.cause ?? '-'),
    entry.heuristic ? 'heuristic' : 'no',
    String(entry.findingCount),
    cell(entry.toolVersion ?? 'n/a'),
  ];
  return `| ${columns.join(' | ')} |`;
}

function shellArg(value: string): string {
  return /^[A-Za-z0-9._/:=+-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

function validSignature(signature: ReportSignature | undefined): signature is ReportSignature & { keyId: string; signedAt: string } {
  return (
    signature !== undefined &&
    signature.signed === true &&
    signature.level === 1 &&
    typeof signature.keyId === 'string' &&
    /^[0-9a-f]{64}$/.test(signature.keyId) &&
    typeof signature.signedAt === 'string'
  );
}

function signatureLines(signature: ReportSignature): string[] {
  if (validSignature(signature)) {
    return [
      `Signature: valid, key ${signature.keyId}, signed ${cell(signature.signedAt)} (signing time is not independently attested)`,
      'Signed: manifest.json (run id, root hash and the sha256 of the manifest bytes) with Ed25519',
      'Assurance level: 1',
    ];
  }
  const line = signature.signed === true ? 'Signature: present but not valid for the signing key' : 'Signature: none';
  return [line, 'Assurance level: 0'];
}

function steeringLines(steering: OutcomeBlockInput['steering']): string[] {
  if (steering === undefined || steering.controlFiles + steering.inlineMarkers <= 0) return [];
  return [`Scanner steering files neutralized: ${steering.controlFiles} control files, ${steering.inlineMarkers} inline markers`];
}

function evidenceLines(
  evidence: { bundlePath: string; rootHash: string },
  signature: ReportSignature | undefined,
  steering: OutcomeBlockInput['steering'],
): string[] {
  const bundle = cell(evidence.bundlePath);
  const root = cell(evidence.rootHash);
  const signed = validSignature(signature);
  return [
    `Evidence bundle: ${bundle}`,
    `Evidence root hash: ${root}`,
    `Verify: npm run evidence:verify -- ${shellArg(bundle)} --expect-root ${shellArg(root)} --pubkey <path to the public key>`,
    'Without Tessera, `sha256sum -c SHA256SUMS` in the bundle folder detects only changed or missing files; added files, the hash chain and the root hash need the verify command.',
    signed ? 'Integrity: hashes and a signed manifest' : 'Integrity: hashes only; the manifest is not signed',
    ...(signature === undefined ? [] : signatureLines(signature)),
    ...steeringLines(steering),
    '',
  ];
}

function outcomeLine(outcome: AuditOutcome | undefined): string {
  if (outcome === 'complete') return 'Audit outcome: COMPLETE';
  if (outcome === 'incomplete') return 'Audit outcome: INCOMPLETE';
  return 'Audit outcome: UNKNOWN (scanner status not provided)';
}

export function renderOutcomeBlock(input: OutcomeBlockInput): string {
  const lines: string[] = [outcomeLine(input.outcome), ''];

  if (input.outcome === 'incomplete') {
    lines.push('Not performed:');
    const items = input.notPerformed ?? [];
    if (items.length === 0) lines.push('- no cause recorded');
    for (const item of items) {
      lines.push(`- ${cell(item.scanner)}: ${cell(item.status)}, ${cell(item.cause ?? 'no cause recorded')}`);
    }
    lines.push('');
  }

  if (input.scanners !== undefined) {
    lines.push(TABLE_HEADER, TABLE_RULE, ...input.scanners.map(scannerRow), '');
  }

  if (input.outcome === 'complete') {
    if (input.findingCount === 0) lines.push('No findings');
    const completed = input.scanners?.filter((s) => s.status === 'completed').map((s) => s.scanner);
    lines.push(`Completed scanners: ${completed === undefined ? 'not provided' : completed.join(', ') || 'none'}`, '');
  }

  if (typeof input.revision === 'string' && input.revision.length > 0) {
    lines.push(`Source revision: ${cell(input.revision)}`, '');
  }

  if (input.evidence !== undefined) lines.push(...evidenceLines(input.evidence, input.signature, input.steering));

  return `${lines.join('\n')}\n`;
}
