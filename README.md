# Application Audit Orchestration

> Temporal-based workflow orchestration for enterprise application audits

## Overview

This project implements a fully automated application audit framework using Temporal.io for workflow orchestration. It supports:

- Multi-phase audit workflow
- Parallel execution of security scans
- Human-in-the-loop approval for critical findings
- Cross-validation by different AI models
- Compliance mapping (ISO 27001, SOC 2, PCI-DSS, GDPR)
- Enterprise-grade monitoring and observability

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TEMPORAL SERVER                           │
│  (Workflow Engine + State Persistence + Monitoring)         │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────┴──────┐   ┌───────┴──────┐   ┌───────┴──────┐
│  AUDIT CLIENT │   │ AUDIT WORKER │   │  TEMPORAL UI │
│  (CLI/API)    │   │ (Activities) │   │  (Monitoring)│
└──────────────┘   └──────────────┘   └──────────────┘
```

## Prerequisites

- Node.js 18+ (v22 recommended)
- Temporal CLI: `brew install temporal`
- Or Docker (for Temporal server)

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start Temporal Server

```bash
# Option A: Using Temporal CLI
temporal server start-dev

# Option B: Using Docker
docker-compose up -d
```

### 3. Build the Project

```bash
npm run build
```

### 4. Start the Worker

In one terminal:

```bash
npm run start
```

### 5. Start an Audit

In another terminal:

```bash
# Basic audit
npm run workflow -- start vannifr/event-ticketing

# With compliance frameworks
npm run workflow -- start vannifr/event-ticketing --frameworks GDPR,PCI-DSS

# Watch progress
npm run workflow -- watch <workflow-id>
```

## Usage

### Start an Audit

```bash
npm run workflow -- start <repo-url> [options]

Options:
  --frameworks <list>  Compliance frameworks (comma-separated)
                       Values: ISO27001, SOC2, PCI-DSS, GDPR, HIPAA, OWASP-ASVS
  --scope <type>       Audit scope (full, security, compliance)
  --skip-approval      Skip P0 approval
  --output <dir>       Output directory for reports
```

### Monitor Progress

```bash
# Check status
npm run workflow -- status <workflow-id>

# Watch real-time progress
npm run workflow -- watch <workflow-id>

# View findings
npm run workflow -- findings <workflow-id>
```

### Human Approval

When P0 (critical) findings are detected, the workflow pauses for approval:

```bash
# Approve P0 findings
npm run workflow -- approve <workflow-id>

# Reject P0 findings
npm run workflow -- reject <workflow-id>
```

### Temporal UI

Open http://localhost:8233 to view workflows in the Temporal Web UI.

## Workflow Phases

1. **Discovery** — Clone repo, detect tech stack, generate scope
2. **Scanning** — Run npm audit, gitleaks, semgrep, license check (parallel)
3. **Reviewing** — AI code review of critical paths
4. **Compliance** — Map findings to compliance frameworks
5. **Validation** — Cross-validation by second AI model
6. **Approval** — Human approval for P0 findings (if any)
7. **Reporting** — Generate audit report and evidence

## Output

```
/tmp/audit-<workflow-id>/
├── audit-report.md        # Full audit report
├── npm-audit.json         # npm audit results
├── gitleaks-report.json   # Secret scan results
├── semgrep-report.json    # SAST results
├── licenses.json          # License check results
└── evidence/              # Evidence per finding
    ├── NPM-1.json
    ├── LEAK-1.json
    └── ...
```

## Configuration

### Guardrails

Guardrails are enforced at workflow level:

- **Timeout:** 8 hours max
- **Retry:** 3 attempts per activity
- **Approval:** Required for P0 findings
- **Concurrency:** Max 4 parallel scans

### Environment Variables

```bash
TEMPORAL_ADDRESS=localhost:7233
AUDIT_OUTPUT_DIR=/path/to/reports
```

## Development

### Project Structure

```
src/
├── activities/          # Activity implementations
│   └── index.ts
├── workflows/           # Workflow definitions
│   └── index.ts
├── types/               # TypeScript types
│   └── index.ts
├── worker.ts            # Worker entry point
└── client.ts            # Client CLI
```

### Testing

```bash
npm test
```

### Linting

```bash
npm run lint
```

## Deployment

### Production Setup

1. Use Temporal Cloud or self-hosted Temporal cluster
2. Deploy worker as container (Kubernetes/Docker)
3. Configure authentication (mTLS)
4. Set up monitoring (Prometheus/Grafana)

### Docker

```bash
docker build -t audit-worker .
docker run -e TEMPORAL_ADDRESS=temporal:7233 audit-worker
```

### Kubernetes

See `k8s/` directory for Kubernetes manifests.

## Extending

### Adding New Activities

1. Define activity in `src/activities/index.ts`
2. Add to `proxyActivities` in workflow
3. Call from workflow phase

### Adding New Compliance Frameworks

1. Add framework to `ComplianceFramework` type
2. Implement control loader in `loadControls()`
3. Map findings to controls in `mapToCompliance()`

### Integrating Qwen Agent

The `reviewCriticalPaths` and `crossValidate` activities are placeholders for Qwen Agent integration. To implement:

1. Install Qwen Code SDK or use HTTP API
2. Pass file contents and checklist to agent
3. Parse agent findings into `Finding` type
4. Return findings to workflow

## License

MIT