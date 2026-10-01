# Quickstart: Start Audit Workflow

**Date**: 2026-10-01
**Feature**: 001-start-audit-workflow

## Prerequisites

- Temporal server running (`temporal server start-dev`)
- Node.js 18+ installed
- Worker started (`npm run start`)

## Test Scenarios

### Scenario 1: Start Basic Audit

**Given**: Temporal server is running
**When**: I start an audit for a public repository
**Then**: Workflow initiates and returns workflow ID

```bash
# Start audit
npm run workflow -- start https://github.com/vannifr/event-ticketing

# Expected output:
# ✓ Started audit workflow
#   Workflow ID: audit-vannifr-event-ticketing-1234567890
#   Repository: https://github.com/vannifr/event-ticketing
#   Frameworks: OWASP-ASVS
```

**Verify**:
```bash
# Check status
npm run workflow -- status audit-vannifr-event-ticketing-1234567890

# Expected output:
# Audit Status: Scanning
```

---

### Scenario 2: Start Audit with Compliance Frameworks

**Given**: Temporal server is running
**When**: I specify ISO 27001 and PCI-DSS compliance
**Then**: Findings are mapped to those frameworks

```bash
# Start audit with frameworks
npm run workflow -- start https://github.com/vannifr/event-ticketing --frameworks ISO27001,PCI-DSS

# Expected output:
# ✓ Started audit workflow
#   Frameworks: ISO27001, PCI-DSS
```

---

### Scenario 3: Monitor Audit Progress

**Given**: An audit is running
**When**: I watch the workflow
**Then**: I see real-time phase updates

```bash
# Watch progress
npm run workflow -- watch audit-vannifr-event-ticketing-1234567890

# Expected output:
# [2026-10-01T10:00:00Z] Phase: Discovery
# [2026-10-01T10:02:00Z] Phase: Scanning
# [2026-10-01T10:12:00Z] Phase: Reviewing
# [2026-10-01T10:13:00Z] Phase: Compliance
# [2026-10-01T10:14:00Z] Phase: Validation
# [2026-10-01T10:15:00Z] Phase: Reporting
# [2026-10-01T10:15:30Z] Phase: Completed
# ✓ Audit completed
#   Report: /tmp/audit-1234567890/audit-report.md
#   Evidence: /tmp/audit-1234567890/evidence/
#   Duration: 15.5s
#   Findings: 3
```

---

### Scenario 4: Handle P0 Approval

**Given**: P0 findings are detected
**When**: Workflow pauses for approval
**Then**: I can approve or reject

```bash
# Check status (shows waiting for approval)
npm run workflow -- status audit-critical-repo-123

# Expected output:
# Audit Status: Waiting for P0 Approval
# P0 Findings: 2

# Approve P0 findings
npm run workflow -- approve audit-critical-repo-123

# Expected output:
# ✓ P0 findings approved

# Or reject
npm run workflow -- reject audit-critical-repo-123

# Expected output:
# ✓ P0 findings rejected
```

---

### Scenario 5: View Findings

**Given**: Audit is running or completed
**When**: I query findings
**Then**: I see prioritized list

```bash
# View all findings
npm run workflow -- findings audit-vannifr-event-ticketing-1234567890

# Expected output:
# Total Findings: 3
#
# P1 (1):
#   - NPM-1: Vulnerability in lodash
#
# P2 (2):
#   - LICENSE-1: License violation in package-x
#   - LICENSE-2: License violation in package-y
```

---

### Scenario 6: View Generated Report

**Given**: Audit completed
**When**: I open the report
**Then**: I see comprehensive audit results

```bash
# Open report
cat /tmp/audit-1234567890/audit-report.md

# Expected content:
# # Audit Report
#
# **Repository:** https://github.com/vannifr/event-ticketing
# **Workflow ID:** audit-1234567890
# **Date:** 2026-10-01T10:15:00Z
#
# ## Executive Summary
#
# - **Risk Level:** HIGH
# - **Critical (P0):** 0
# - **High (P1):** 1
# - **Medium (P2):** 2
# - **Low (P3):** 0
#
# ## Findings
#
# | ID | Title | Severity | Category |
# |----|-------|----------|----------|
# | NPM-1 | Vulnerability in lodash | P1 | security-dependencies |
# | LICENSE-1 | License violation in package-x | P2 | compliance |
# | LICENSE-2 | License violation in package-y | P2 | compliance |
```

---

## Error Scenarios

### Invalid Repository URL

```bash
npm run workflow -- start not-a-url

# Expected output:
# ✗ Error: Invalid repository URL format
```

### Inaccessible Repository

```bash
npm run workflow -- start https://github.com/nonexistent/repo

# Expected output:
# ✗ Error: Repository not accessible
```

### Temporal Server Not Running

```bash
npm run workflow -- start https://github.com/vannifr/event-ticketing

# Expected output:
# ✗ Error: Cannot connect to Temporal server at localhost:7233
```

---

## Temporal UI

Open http://localhost:8233 to view:
- Running workflows
- Workflow history
- Activity details
- Error traces

---

## Cleanup

```bash
# Remove audit artifacts
rm -rf /tmp/audit-*
```

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Workflow start time | < 5 seconds |
| Discovery phase | < 2 minutes |
| Scanning phase | < 15 minutes (for <1000 deps) |
| Total audit time | < 25 minutes |
| Status query time | < 100ms |