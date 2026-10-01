# Audit Orchestration Premise

## What

Temporal-based workflow orchestration system for enterprise application audits. Automates multi-phase security audits with parallel scanning, AI-powered code review, compliance mapping (ISO 27001, SOC 2, PCI-DSS, GDPR), and human-in-the-loop approval for critical findings. Generates audit reports with evidence trails for enterprise consulting engagements.

## Who

- **Enterprise Consultants** — Deliver traceable, compliant audits to enterprise clients
- **DevOps Teams** — Integrate automated audits into CI/CD pipelines
- **Security Teams** — Continuous security posture validation
- **Compliance Officers** — Evidence collection for compliance frameworks
- **Development Teams** — Understand and remediate findings

## Why

Enterprise applications require rigorous, auditable security reviews. Manual audits are:
- Time-consuming (weeks to months)
- Inconsistent (dependent on auditor expertise)
- Non-repeatable (no standardized process)
- Non-traceable (no evidence trail)

This system provides:
- **Automation** — Multi-phase audits in hours instead of weeks
- **Consistency** — Standardized checks across all audits
- **Traceability** — Evidence per finding, compliance mapping
- **Governance** — Human approval for critical findings
- **Repeatability** — Same process for every audit

## Domain

**Workflow Orchestration** — Temporal.io for durable execution, state persistence, and human-in-the-loop patterns.

**Security Auditing** — Application security, dependency scanning, secret detection, SAST, license compliance.

**Compliance Frameworks**:
- ISO 27001:2022 — Information security management
- SOC 2 Type II — Service organization controls
- PCI-DSS — Payment card data security
- GDPR — EU data protection regulation

**Key Terms**:
- **Audit** — Complete security review of an application
- **Finding** — Identified issue with severity (P0-P3)
- **Evidence** — Proof artifact for a finding
- **Activity** — Atomic audit task (scan, review, validate)
- **Workflow** — Orchestrated sequence of activities
- **Signal** — Human-in-the-loop approval mechanism

## Scope

**In Scope**:
- Temporal workflow orchestration (6 phases)
- Security scans: npm audit, gitleaks, semgrep, license check
- AI code review of critical paths
- Compliance mapping to frameworks
- Cross-validation by second AI model
- Human approval for P0 findings
- Audit report generation with evidence

**Out of Scope**:
- Real-time monitoring (observability platform)
- Remediation automation (human decision required)
- Custom security rules authoring
- Multi-tenant SaaS deployment (single-tenant for now)
- Integration with ticketing systems (Jira, Linear)

**System Boundaries**:
```
┌─────────────────────────────────────────────────┐
│            AUDIT ORCHESTRATION                   │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Temporal │  │ Activities│  │  Client  │      │
│  │ Workflow │  │ (Scans)  │  │  (CLI)   │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│       │              │              │           │
│       └──────────────┴──────────────┘           │
│                      │                           │
│            ┌─────────┴─────────┐                │
│            │   Audit Report    │                │
│            │   + Evidence      │                │
│            └───────────────────┘                │
└─────────────────────────────────────────────────┘
         │                           │
    ┌────┴────┐                 ┌────┴────┐
    │ GitHub  │                 │ Temporal│
    │ Repos   │                 │ Server  │
    └─────────┘                 └─────────┘
```

**Dependencies**:
- Temporal Server (self-hosted or Temporal Cloud)
- Node.js 18+ runtime
- GitHub access (for cloning repos)
- Security tools (npm audit, gitleaks, semgrep)
- AI models (for code review and validation)