import { describe, it, expect } from 'vitest';
import { computeOutcome, mayReportClean, type ScannerStatusEntry, type ComputeOutcomeInput } from '../../../src/scan/status';

describe('Scanner Status Model', () => {
  it('TS-001 unavailable required scanner makes the audit incomplete', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'gitleaks',
          required: true,
          status: 'unavailable',
          cause: 'not-installed',
          heuristic: false,
          toolVersion: null,
          findingCount: 0,
          evidenceRecordIds: [],
        }
      ],
      untracedFindingIds: []
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed).toContainEqual({
      scanner: 'gitleaks',
      status: 'unavailable',
      cause: 'not-installed',
      summary: expect.any(String)
    });
  });

  it('TS-002 crashing scanner is reported as failed', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'semgrep',
          required: true,
          status: 'failed',
          cause: 'spawn-error',
          heuristic: false,
          toolVersion: null,
          findingCount: 0,
          evidenceRecordIds: [],
        }
      ],
      untracedFindingIds: []
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed).toContainEqual({
      scanner: 'semgrep',
      status: 'failed',
      cause: 'spawn-error',
      summary: expect.any(String)
    });
  });

  it('TS-003 clean result names the scanners that completed', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'gitleaks',
          required: true,
          status: 'completed',
          heuristic: false,
          toolVersion: '1.0.0',
          findingCount: 0,
          evidenceRecordIds: [],
        },
        {
          scanner: 'npm-audit',
          required: true,
          status: 'completed',
          heuristic: false,
          toolVersion: '2.0.0',
          findingCount: 0,
          evidenceRecordIds: [],
        }
      ],
      untracedFindingIds: []
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('complete');
    expect(result.completedScanners).toContain('gitleaks');
    expect(result.completedScanners).toContain('npm-audit');
  });

  it('TS-004 non-required scanner that failed does not make the outcome incomplete', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'gitleaks',
          required: true,
          status: 'completed',
          heuristic: false,
          toolVersion: '1.0.0',
          findingCount: 0,
          evidenceRecordIds: [],
        },
        {
          scanner: 'license-check',
          required: false,
          status: 'failed',
          cause: 'tool-error',
          heuristic: false,
          toolVersion: '1.0.0',
          findingCount: 0,
          evidenceRecordIds: [],
        }
      ],
      untracedFindingIds: []
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('complete');
  });

  it('TS-005 required scanner with unavailable or failed status makes outcome incomplete', () => {
    const scenarios = [
      { scanner: 'npm-audit' as const, state: 'unavailable' as const },
      { scanner: 'npm-audit' as const, state: 'failed' as const },
      { scanner: 'gitleaks' as const, state: 'unavailable' as const },
      { scanner: 'gitleaks' as const, state: 'failed' as const },
      { scanner: 'semgrep' as const, state: 'unavailable' as const },
      { scanner: 'semgrep' as const, state: 'failed' as const },
      { scanner: 'license-check' as const, state: 'failed' as const },
    ];

    for (const scenario of scenarios) {
      const input: ComputeOutcomeInput = {
        scanners: [
          {
            scanner: scenario.scanner,
            required: true,
            status: scenario.state,
            cause: scenario.state === 'unavailable' ? 'not-installed' : 'tool-error',
            heuristic: false,
            toolVersion: '1.0.0',
            findingCount: 0,
            evidenceRecordIds: [],
          }
        ],
        untracedFindingIds: []
      };

      const result = computeOutcome(input);
      expect(result.outcome).toBe('incomplete');
      expect(result.notPerformed).toContainEqual({
        scanner: scenario.scanner,
        status: scenario.state,
        cause: scenario.state === 'unavailable' ? 'not-installed' : 'tool-error',
        summary: expect.any(String)
      });
    }
  });

  it('TS-006 untracedFindingIds non-empty gives incomplete with an entry scanner "evidence"', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'gitleaks',
          required: true,
          status: 'completed',
          heuristic: false,
          toolVersion: '1.0.0',
          findingCount: 0,
          evidenceRecordIds: [],
        }
      ],
      untracedFindingIds: ['finding1', 'finding2']
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed).toContainEqual({
      scanner: 'evidence',
      status: 'untraced-findings',
      summary: expect.any(String)
    });
  });

  it('TS-004 cause issues-found with status completed is complete', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        {
          scanner: 'gitleaks',
          required: true,
          status: 'completed',
          cause: 'issues-found',
          heuristic: false,
          toolVersion: '1.0.0',
          findingCount: 2,
          evidenceRecordIds: ['evidence1'],
        }
      ],
      untracedFindingIds: []
    };
    
    const result = computeOutcome(input);
    expect(result.outcome).toBe('complete');
  });

  describe('mayReportClean function', () => {
    it('returns true only for status completed (table test over all five statuses and heuristic true/false)', () => {
      const statuses: ('completed' | 'partial' | 'failed' | 'skipped' | 'unavailable')[] = 
        ['completed', 'partial', 'failed', 'skipped', 'unavailable'];
      
      for (const status of statuses) {
        for (const heuristic of [true, false]) {
          const entry: ScannerStatusEntry = {
            scanner: 'gitleaks',
            required: true,
            status,
            heuristic,
            toolVersion: '1.0.0',
            findingCount: 0,
            evidenceRecordIds: [],
          };
          
          if (status === 'completed') {
            expect(mayReportClean(entry)).toBe(true);
          } else {
            expect(mayReportClean(entry)).toBe(false);
          }
        }
      }
    });
  });
});
type Entry = ScannerStatusEntry;

function makeEntry(overrides: Partial<Entry> & Pick<Entry, 'scanner' | 'status'>): Entry {
  return {
    required: true,
    heuristic: false,
    toolVersion: '1.0.0',
    findingCount: 0,
    evidenceRecordIds: [],
    ...overrides,
  };
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

describe('Scanner Status Model hardening', () => {
  it('FR-002 required entry with partial, skipped or skipped/no-lockfile is incomplete and listed in notPerformed', () => {
    const cases: { status: Entry['status']; cause?: Entry['cause'] }[] = [
      { status: 'partial', cause: 'findings-truncated' },
      { status: 'partial' },
      { status: 'skipped' },
      { status: 'skipped', cause: 'no-lockfile' },
      { status: 'skipped', cause: 'unsupported-lockfile' },
    ];
    for (const item of cases) {
      const entry = makeEntry({ scanner: 'npm-audit', status: item.status, cause: item.cause });
      const result = computeOutcome({ scanners: [entry], untracedFindingIds: [] });
      expect(result.outcome).toBe('incomplete');
      expect(result.completedScanners).toEqual([]);
      expect(result.notPerformed).toHaveLength(1);
      expect(result.notPerformed[0]).toMatchObject({ scanner: 'npm-audit', status: item.status });
      expect(result.notPerformed[0]?.cause).toBe(item.cause);
    }
  });

  it('FR-002 notPerformed keeps exact input order for several required non-completed entries', () => {
    const scanners = [
      makeEntry({ scanner: 'semgrep', status: 'failed', cause: 'timeout' }),
      makeEntry({ scanner: 'gitleaks', status: 'completed' }),
      makeEntry({ scanner: 'npm-audit', status: 'skipped', cause: 'no-lockfile' }),
      makeEntry({ scanner: 'license-check', status: 'partial', cause: 'findings-truncated' }),
      makeEntry({ scanner: 'code-review', status: 'unavailable', cause: 'not-installed' }),
    ];
    const result = computeOutcome({ scanners, untracedFindingIds: [] });
    expect(result.notPerformed).toEqual([
      { scanner: 'semgrep', status: 'failed', cause: 'timeout', summary: expect.any(String) },
      { scanner: 'npm-audit', status: 'skipped', cause: 'no-lockfile', summary: expect.any(String) },
      { scanner: 'license-check', status: 'partial', cause: 'findings-truncated', summary: expect.any(String) },
      { scanner: 'code-review', status: 'unavailable', cause: 'not-installed', summary: expect.any(String) },
    ]);
  });

  it('FR-003 completedScanners lists completed entries in exact input order', () => {
    const scanners = [
      makeEntry({ scanner: 'semgrep', status: 'completed' }),
      makeEntry({ scanner: 'gitleaks', status: 'failed', cause: 'tool-error' }),
      makeEntry({ scanner: 'npm-audit', status: 'completed' }),
      makeEntry({ scanner: 'license-check', status: 'partial' }),
      makeEntry({ scanner: 'code-review', status: 'completed', required: false }),
    ];
    const result = computeOutcome({ scanners, untracedFindingIds: [] });
    expect(result.completedScanners).toEqual(['semgrep', 'npm-audit', 'code-review']);
  });

  it('FR-003 completedScanners contains only entries with status completed for every other status', () => {
    const others: Entry['status'][] = ['partial', 'failed', 'skipped', 'unavailable'];
    for (const required of [true, false]) {
      const scanners = others.map((status) => makeEntry({ scanner: 'gitleaks', status, required }));
      const result = computeOutcome({ scanners, untracedFindingIds: [] });
      expect(result.completedScanners).toEqual([]);
    }
  });

  it('FR-002 non-required non-completed entries are absent from notPerformed and keep the outcome complete', () => {
    const statuses: Entry['status'][] = ['partial', 'failed', 'skipped', 'unavailable'];
    const scanners = [
      makeEntry({ scanner: 'gitleaks', status: 'completed' }),
      ...statuses.map((status) => makeEntry({ scanner: 'license-check', status, required: false })),
    ];
    const result = computeOutcome({ scanners, untracedFindingIds: [] });
    expect(result.outcome).toBe('complete');
    expect(result.notPerformed).toEqual([]);
    expect(result.completedScanners).toEqual(['gitleaks']);
  });

  it('FR-001 computeOutcome does not mutate its input', () => {
    const input: ComputeOutcomeInput = {
      scanners: [
        makeEntry({ scanner: 'gitleaks', status: 'failed', cause: 'tool-error', evidenceRecordIds: ['e1'] }),
        makeEntry({ scanner: 'semgrep', status: 'completed' }),
        makeEntry({ scanner: 'npm-audit', status: 'skipped', cause: 'no-lockfile', required: false }),
      ],
      untracedFindingIds: ['f1'],
    };
    const snapshot = structuredClone(input);
    computeOutcome(deepFreeze(input));
    expect(input).toEqual(snapshot);
  });

  it('FR-002 mixed case lists non-completed required scanners in input order and then the evidence entry', () => {
    const scanners = [
      makeEntry({ scanner: 'npm-audit', status: 'skipped', cause: 'no-lockfile' }),
      makeEntry({ scanner: 'gitleaks', status: 'completed' }),
      makeEntry({ scanner: 'semgrep', status: 'partial', cause: 'output-truncated' }),
      makeEntry({ scanner: 'license-check', status: 'failed', cause: 'tool-error', required: false }),
    ];
    const result = computeOutcome({ scanners, untracedFindingIds: ['f1', 'f2'] });
    expect(result.outcome).toBe('incomplete');
    expect(result.notPerformed).toEqual([
      { scanner: 'npm-audit', status: 'skipped', cause: 'no-lockfile', summary: expect.any(String) },
      { scanner: 'semgrep', status: 'partial', cause: 'output-truncated', summary: expect.any(String) },
      { scanner: 'evidence', status: 'untraced-findings', summary: expect.any(String) },
    ]);
    expect(result.completedScanners).toEqual(['gitleaks']);
  });
});
