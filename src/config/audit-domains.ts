/**
 * Audit Domain Configuration
 * 
 * Single source of truth for all audit checks and their implementation status.
 * This drives:
 * - Workflow execution (skip unimplemented checks)
 * - Documentation generation (AUDIT-COVERAGE.md)
 * - Progress tracking
 */

export type AuditDomain =
  | 'security'
  | 'performance'
  | 'reliability'
  | 'observability'
  | 'testing'
  | 'cicd'
  | 'documentation'
  | 'accessibility'
  | 'seo'
  | 'privacy'
  | 'cost'
  | 'code-quality'
  | 'blind-spots';

export type AuditCheck = {
  id: string;
  name: string;
  description: string;
  tool: string | null;
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  implemented: boolean;
  active: boolean;
  notes?: string;
  phase?: 'discovery' | 'scanning' | 'reviewing' | 'compliance' | 'validation' | 'reporting';
};

export type AuditDomainConfig = {
  name: string;
  description: string;
  checks: AuditCheck[];
};

/**
 * Complete audit domain configuration
 * Based on Audit Framework Baseline and enterprise requirements
 */
export const AUDIT_DOMAINS: Record<AuditDomain, AuditDomainConfig> = {
  security: {
    name: 'Security & Compliance',
    description: 'Application security, authentication, data protection, vulnerability management',
    checks: [
      {
        id: 'dependency-vulns',
        name: 'Dependency Vulnerabilities',
        description: 'Scan dependencies for known vulnerabilities (npm audit)',
        tool: 'npm-audit',
        priority: 'P0',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'secret-scanning',
        name: 'Secret Detection',
        description: 'Detect hardcoded secrets, API keys, tokens (gitleaks)',
        tool: 'gitleaks',
        priority: 'P0',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'sast',
        name: 'Static Application Security Testing',
        description: 'SQL injection, XSS, command injection detection (semgrep)',
        tool: 'semgrep',
        priority: 'P0',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'license-compliance',
        name: 'License Compliance',
        description: 'Check license compatibility (license-checker)',
        tool: 'license-checker',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'auth-session',
        name: 'Authentication & Session Security',
        description: 'Review auth mechanisms, session management, password policies',
        tool: null,
        priority: 'P0',
        implemented: false,
        active: false,
        notes: 'Requires manual review or AI code review',
      },
      {
        id: 'csrf-protection',
        name: 'CSRF Protection',
        description: 'Verify CSRF tokens, same-site cookies',
        tool: null,
        priority: 'P1',
        implemented: false,
        active: false,
      },
      {
        id: 'input-validation',
        name: 'Input Validation',
        description: 'Verify input sanitization, parameterized queries, SQL injection',
        tool: 'semgrep',
        priority: 'P0',
        implemented: true,
        active: true,
        phase: 'scanning',
        notes: 'Custom SQL injection rules added',
      },
      {
        id: 'data-encryption',
        name: 'Data Encryption at Rest/Transit',
        description: 'Verify TLS, encryption keys, data classification',
        tool: null,
        priority: 'P1',
        implemented: false,
        active: false,
      },
      {
        id: 'exploitability',
        name: 'Exploitability Assessment',
        description: 'CVSS scoring, exploit-db check, attack vector analysis (ISO 25010 §2.1)',
        tool: 'cvss-calculator',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'auditability',
        name: 'Auditability & Control',
        description: 'Audit logging, traceability, tamper-proof logs (ISO 25010 §2.1)',
        tool: 'audit-logger',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'transparency',
        name: 'Transparency (AI/ML)',
        description: 'Explainability, bias detection, model documentation (ISO 25010 §2.1)',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Optional - AI/ML systems only',
      },
    ],
  },

  performance: {
    name: 'Performance & Scalability',
    description: 'Frontend performance, backend performance, load testing',
    checks: [
      {
        id: 'lighthouse-perf',
        name: 'Lighthouse Performance',
        description: 'Core Web Vitals, LCP, FID, CLS',
        tool: 'lighthouse',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'load-test',
        name: 'Load Testing',
        description: 'Stress test critical endpoints',
        tool: 'k6',
        priority: 'P2',
        implemented: false,
        active: false,
      },
      {
        id: 'bundle-size',
        name: 'Bundle Size Analysis',
        description: 'Check JS/CSS bundle sizes',
        tool: 'webpack-bundle-analyzer',
        priority: 'P2',
        implemented: false,
        active: false,
      },
      {
        id: 'throughput',
        name: 'Throughput Testing',
        description: 'Measure requests/sec, transactions/sec under load (ISO 25010 §6.1.1)',
        tool: 'k6',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'boot-time',
        name: 'Boot Time Measurement',
        description: 'Measure startup time for mobile/embedded/desktop apps (ISO 25010 §6.1.2)',
        tool: 'lighthouse',
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Optional - mobile/embedded only',
      },
      {
        id: 'volume-testing',
        name: 'Volume Testing',
        description: 'Test with large data volumes (ISO 25010 §6.1.3)',
        tool: 'k6',
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Optional - big data systems only',
      },
    ],
  },

  reliability: {
    name: 'Reliability & Availability',
    description: 'Error handling, uptime, disaster recovery',
    checks: [
      {
        id: 'error-handling',
        name: 'Error Handling Review',
        description: 'Check error boundaries, try-catch coverage',
        tool: 'reliability-check',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'retry-logic',
        name: 'Retry Logic',
        description: 'Check for retry patterns, backoff',
        tool: 'reliability-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'health-check',
        name: 'Health Check Endpoint',
        description: 'Verify /health endpoint exists',
        tool: 'reliability-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'durability',
        name: 'Durability Testing',
        description: 'Long-term reliability test (24h+), data integrity checks (ISO 25010 §4.1)',
        tool: 'chaos-toolkit',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'stability',
        name: 'Stability Testing',
        description: '72h continuous operation test, crash rate monitoring (ISO 25010 §4.1)',
        tool: 'chaos-toolkit',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'robustness',
        name: 'Robustness Testing',
        description: 'Fuzzing, boundary testing, invalid input handling (ISO 25010 §4.1)',
        tool: 'zap-fuzz',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'resilience',
        name: 'Resilience Testing',
        description: 'Chaos engineering, automatic failover, self-healing (ISO 25010 §4.1)',
        tool: 'litmus-chaos',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'safety',
        name: 'Safety Requirements',
        description: 'Hazard analysis, safety certifications (IEC 61508, ISO 26262) (Wikipedia NFR)',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Optional - IoT/embedded/medical/automotive only',
      },
    ],
  },

  observability: {
    name: 'Observability',
    description: 'Logging, monitoring, alerting, tracing',
    checks: [
      {
        id: 'structured-logging',
        name: 'Structured Logging',
        description: 'Verify JSON logging, request IDs, log levels',
        tool: 'observability-check',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'metrics',
        name: 'Metrics Collection',
        description: 'Verify metrics instrumentation',
        tool: 'observability-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'tracing',
        name: 'Distributed Tracing',
        description: 'Verify OpenTelemetry or similar',
        tool: 'observability-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
    ],
  },

  testing: {
    name: 'Testing',
    description: 'Unit tests, integration tests, E2E tests, security tests',
    checks: [
      {
        id: 'unit-tests',
        name: 'Unit Test Coverage',
        description: 'Check test coverage >= 80%',
        tool: 'vitest',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'CI check, not in audit workflow',
      },
      {
        id: 'integration-tests',
        name: 'Integration Tests',
        description: 'Verify integration test coverage',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
      },
      {
        id: 'e2e-tests',
        name: 'E2E Tests',
        description: 'Verify E2E test coverage',
        tool: 'playwright',
        priority: 'P2',
        implemented: false,
        active: false,
      },
    ],
  },

  cicd: {
    name: 'CI/CD & Release Management',
    description: 'Pipeline configuration, security gates, deployment procedures',
    checks: [
      {
        id: 'pipeline-config',
        name: 'Pipeline Configuration',
        description: 'Review CI/CD pipeline setup',
        tool: 'cicd-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'security-gates',
        name: 'Security Gates in CI',
        description: 'Verify SAST, SCA, secret scanning in CI',
        tool: 'cicd-check',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'rollback-procedure',
        name: 'Rollback Procedure',
        description: 'Verify rollback mechanism exists',
        tool: 'cicd-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
    ],
  },

  documentation: {
    name: 'Documentation',
    description: 'Technical documentation, operational docs, API docs',
    checks: [
      {
        id: 'readme',
        name: 'README Documentation',
        description: 'Verify README completeness',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
      },
      {
        id: 'api-docs',
        name: 'API Documentation',
        description: 'OpenAPI/Swagger docs',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
      },
      {
        id: 'runbooks',
        name: 'Operational Runbooks',
        description: 'Incident response, DR procedures',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
    ],
  },

  accessibility: {
    name: 'Accessibility',
    description: 'WCAG 2.2 compliance, screen reader support',
    checks: [
      {
        id: 'wcag-aa',
        name: 'WCAG 2.2 Level AA',
        description: 'Automated accessibility scan',
        tool: 'axe-cli',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'lighthouse-a11y',
        name: 'Lighthouse Accessibility',
        description: 'Accessibility category scan',
        tool: 'lighthouse',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
    ],
  },

  seo: {
    name: 'SEO',
    description: 'Technical SEO, content optimization, performance',
    checks: [
      {
        id: 'lighthouse-seo',
        name: 'Lighthouse SEO',
        description: 'SEO category scan',
        tool: 'lighthouse',
        priority: 'P3',
        implemented: false,
        active: false,
      },
      {
        id: 'structured-data',
        name: 'Structured Data',
        description: 'Schema.org validation',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
    ],
  },

  privacy: {
    name: 'Privacy & GDPR',
    description: 'Data protection, consent management, data subject rights',
    checks: [
      {
        id: 'consent-banner',
        name: 'Consent Management',
        description: 'Verify cookie consent implementation',
        tool: null,
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'Manual review required',
      },
      {
        id: 'data-classification',
        name: 'Data Classification',
        description: 'PII identification and classification',
        tool: null,
        priority: 'P1',
        implemented: false,
        active: false,
      },
    ],
  },

  cost: {
    name: 'Cost Optimization',
    description: 'Cloud costs, resource utilization, efficiency',
    checks: [
      {
        id: 'cloud-costs',
        name: 'Cloud Cost Analysis',
        description: 'Analyze cloud spending',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
      {
        id: 'resource-utilization',
        name: 'Resource Utilization',
        description: 'CPU, memory, storage efficiency',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
    ],
  },

  'code-quality': {
    name: 'Code Quality',
    description: 'Code complexity, maintainability, technical debt',
    checks: [
      {
        id: 'linting',
        name: 'Linting',
        description: 'ESLint, Prettier checks',
        tool: 'eslint',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'type-safety',
        name: 'Type Safety',
        description: 'TypeScript strict mode',
        tool: 'tsc',
        priority: 'P1',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'code-complexity',
        name: 'Code Complexity',
        description: 'File size, maintainability',
        tool: 'code-quality-check',
        priority: 'P2',
        implemented: true,
        active: true,
        phase: 'scanning',
      },
      {
        id: 'mttr',
        name: 'MTTR Measurement',
        description: 'Mean Time To Repair calculation and tracking (ISO 25010 §13.4)',
        tool: 'jira-metrics',
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'readability',
        name: 'Code Readability',
        description: 'Naming conventions, comments, cyclomatic complexity (ISO 25010 §13.5)',
        tool: 'eslint-complexity',
        priority: 'P1',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
      {
        id: 'extensibility',
        name: 'Extensibility',
        description: 'Plugin architecture, module boundaries, feature flags (ISO 25010 §13.6)',
        tool: 'module-analyzer',
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'New NFR from ISO 25010',
      },
    ],
  },

  'blind-spots': {
    name: 'Blinde Vlekken',
    description: 'Organizational aspects, vendor risk, sustainability, legal',
    checks: [
      {
        id: 'bus-factor',
        name: 'Bus Factor',
        description: 'Knowledge concentration risk',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Manual review required',
      },
      {
        id: 'vendor-risk',
        name: 'Vendor & Dependency Risk',
        description: 'Third-party service dependencies',
        tool: null,
        priority: 'P1',
        implemented: false,
        active: false,
      },
      {
        id: 'sustainability',
        name: 'Sustainability & Green IT',
        description: 'Environmental impact',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
      {
        id: 'legal-aspects',
        name: 'Legal Aspects',
        description: 'Licenses, ToS, IP, DPAs',
        tool: null,
        priority: 'P2',
        implemented: false,
        active: false,
        notes: 'Legal review required',
      },
      {
        id: 'exit-strategy',
        name: 'Exit Strategy',
        description: 'Vendor lock-in, migration paths',
        tool: null,
        priority: 'P3',
        implemented: false,
        active: false,
      },
    ],
  },
};

/**
 * Get all implemented checks
 */
export function getImplementedChecks(): AuditCheck[] {
  return Object.values(AUDIT_DOMAINS)
    .flatMap(domain => domain.checks)
    .filter(check => check.implemented);
}

/**
 * Get all active checks (implemented and running)
 */
export function getActiveChecks(): AuditCheck[] {
  return Object.values(AUDIT_DOMAINS)
    .flatMap(domain => domain.checks)
    .filter(check => check.active);
}

/**
 * Get checks by domain
 */
export function getChecksByDomain(domain: AuditDomain): AuditCheck[] {
  return AUDIT_DOMAINS[domain].checks;
}

/**
 * Calculate coverage statistics
 */
export function calculateCoverage(): {
  total: number;
  implemented: number;
  active: number;
  byDomain: Record<AuditDomain, { total: number; implemented: number; active: number }>;
} {
  const byDomain = {} as Record<AuditDomain, { total: number; implemented: number; active: number }>;

  let total = 0;
  let implemented = 0;
  let active = 0;

  for (const [domainKey, domain] of Object.entries(AUDIT_DOMAINS)) {
    const domainTotal = domain.checks.length;
    const domainImplemented = domain.checks.filter(c => c.implemented).length;
    const domainActive = domain.checks.filter(c => c.active).length;

    byDomain[domainKey as AuditDomain] = {
      total: domainTotal,
      implemented: domainImplemented,
      active: domainActive,
    };

    total += domainTotal;
    implemented += domainImplemented;
    active += domainActive;
  }

  return { total, implemented, active, byDomain };
}

/**
 * Generate markdown documentation
 */
export function generateCoverageMarkdown(): string {
  const coverage = calculateCoverage();

  const lines: string[] = [
    '# Audit Coverage Report',
    '',
    `**Generated:** ${new Date().toISOString()}`,
    '',
    '## Summary',
    '',
    `| Metric | Count | Percentage |`,
    `|--------|-------|------------|`,
    `| Total Checks | ${coverage.total} | 100% |`,
    `| Implemented | ${coverage.implemented} | ${((coverage.implemented / coverage.total) * 100).toFixed(1)}% |`,
    `| Active | ${coverage.active} | ${((coverage.active / coverage.total) * 100).toFixed(1)}% |`,
    '',
    '## Coverage by Domain',
    '',
    '| Domain | Total | Implemented | Active | Coverage |',
    '|--------|-------|-------------|--------|----------|',
  ];

  for (const [domainKey, domain] of Object.entries(AUDIT_DOMAINS)) {
    const stats = coverage.byDomain[domainKey as AuditDomain];
    const pct = stats.total > 0 ? ((stats.implemented / stats.total) * 100).toFixed(1) : '0.0';
    lines.push(`| ${domain.name} | ${stats.total} | ${stats.implemented} | ${stats.active} | ${pct}% |`);
  }

  lines.push('', '## Implemented Checks', '');

  for (const [domainKey, domain] of Object.entries(AUDIT_DOMAINS)) {
    const implementedChecks = domain.checks.filter(c => c.implemented);
    if (implementedChecks.length > 0) {
      lines.push(`### ${domain.name}`, '');
      for (const check of implementedChecks) {
        const status = check.active ? 'Active' : 'Implemented';
        const tool = check.tool ? ` (${check.tool})` : '';
        lines.push(`- **${check.name}**${tool} — ${check.description} [${status}]`);
      }
      lines.push('');
    }
  }

  lines.push('## Not Implemented Checks', '');

  for (const [domainKey, domain] of Object.entries(AUDIT_DOMAINS)) {
    const notImplemented = domain.checks.filter(c => !c.implemented);
    if (notImplemented.length > 0) {
      lines.push(`### ${domain.name}`, '');
      for (const check of notImplemented) {
        const tool = check.tool ? ` (planned: ${check.tool})` : '';
        const notes = check.notes ? ` — *${check.notes}*` : '';
        lines.push(`- ${check.name}${tool}${notes}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}