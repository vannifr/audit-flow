import type { AuditOutcome, NotPerformed, ScannerStatusEntry } from '../scan/status';

export interface OutcomeBlockInput {
  outcome?: AuditOutcome;
  notPerformed?: NotPerformed[];
  scanners?: ScannerStatusEntry[];
  revision?: string | null;
  evidence?: { bundlePath: string; rootHash: string };
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

function evidenceLines(evidence: { bundlePath: string; rootHash: string }): string[] {
  const bundle = cell(evidence.bundlePath);
  const root = cell(evidence.rootHash);
  return [
    `Evidence bundle: ${bundle}`,
    `Evidence root hash: ${root}`,
    `Verify: npm run evidence:verify -- ${shellArg(bundle)} --expect-root ${shellArg(root)}`,
    'Without Tessera, `sha256sum -c SHA256SUMS` in the bundle folder detects only changed or missing files; added files, the hash chain and the root hash need the verify command.',
    'Integrity: hashes only; the manifest is not signed',
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

  if (input.evidence !== undefined) lines.push(...evidenceLines(input.evidence));

  return `${lines.join('\n')}\n`;
}
