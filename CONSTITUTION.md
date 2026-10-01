# Audit Orchestration Constitution

## Core Principles

### I. Security-First Development

**Critical systems require security-first mindset.** This framework handles:
- Customer data in enterprise environments
- Security audit results with compliance implications
- Financial data (trading bots, payment systems)

**Requirements**:
- All code must pass security scanning before merge
- No hardcoded secrets, credentials, or API keys
- Input validation at all system boundaries
- Secure defaults for all configurations
- Audit trails for all security-relevant operations

### II. Test-Driven Development (NON-NEGOTIABLE)

**TDD mandatory for all production code**:
1. Write tests first → Get approval → Verify tests fail
2. Implement minimum code to pass tests
3. Refactor while keeping tests green

**Coverage requirements**:
- Minimum 80% code coverage for all modules
- 100% coverage for critical paths (workflow orchestration, security scans)
- Integration tests required for:
  - Temporal workflow execution
  - Security scan activities
  - Compliance mapping
  - Report generation

**Test types required**:
- Unit tests for activities and utilities
- Integration tests for workflows
- E2E tests for complete audit cycles
- BDD tests for user-facing features (via IIKit)

### III. Enterprise Compliance

**Regulatory requirements are non-negotiable**:
- ISO 27001:2022 — Information security management
- SOC 2 Type II — Service organization controls
- PCI-DSS — Payment card data security (when applicable)
- GDPR — EU data protection (when processing EU personal data)

**Compliance mapping**:
- Every finding must map to compliance controls
- Evidence must be traceable to requirements
- Audit reports must include compliance status
- Changes must be documented for audit trails

### IV. Traceability & Governance

**Every feature must be traceable**:
- Spec → Plan → Tasks → Tests → Code → Evidence
- User stories with acceptance criteria
- BDD scenarios for validation
- Pre-commit hooks for integrity

**Documentation requirements**:
- All public APIs documented with examples
- All workflows documented with diagrams
- All compliance mappings documented
- All security decisions documented

### V. Reliability & Observability

**Production systems must be observable**:
- Structured logging (JSON format)
- Request IDs for correlation
- Metrics for all operations
- Alerts for critical failures

**Reliability requirements**:
- Retry logic for transient failures
- Timeouts for all external calls
- Graceful degradation where possible
- Circuit breakers for dependencies

**Temporal-specific**:
- All workflows must have timeouts
- All activities must be idempotent where possible
- Signals must be documented
- Queries must be side-effect free

## Quality Gates

### Pre-Commit Checks (NON-NEGOTIABLE)

**Required before every commit**:
- ✅ TypeScript compilation (`tsc --noEmit`)
- ✅ Linting passes (`npm run lint`)
- ✅ Tests pass (`npm test`)
- ✅ Coverage threshold met (80%+)
- ✅ Security scan passes (`npm audit`)
- ✅ No secrets detected

**Bypassing prohibited**:
- ❌ NEVER use `git commit --no-verify` or `git commit -n`
- ❌ NEVER disable or delete `.git/hooks/`
- ❌ NEVER use git plumbing commands to circumvent hooks
- If blocked, **fix the root cause** — do not work around

### Pre-Merge Checks

**Required before merging to main**:
- ✅ All pre-commit checks pass
- ✅ Code review approved
- ✅ Integration tests pass
- ✅ Security review (for security-related changes)
- ✅ Documentation updated
- ✅ CHANGELOG updated

### CI/CD Pipeline

**Automated checks in CI**:
- Build: TypeScript compilation
- Test: Unit + integration tests
- Security: npm audit, gitleaks, semgrep
- Coverage: Report generation, threshold enforcement
- Compliance: Schema validation, assertion integrity

## Development Workflow

### Branch Strategy

**Trunk-based development**:
- Main branch is always deployable
- Feature branches: `feature/XXX-description`
- Fix branches: `fix/XXX-description`
- Short-lived branches (< 1 day preferred)

**Commit standards**:
- Conventional Commits format
- One logical change per commit
- Reference issue/task in commit message
- Sign commits (GPG recommended)

### Code Review

**All changes require review**:
- Minimum 1 approval for non-critical changes
- Minimum 2 approvals for critical changes (security, compliance, workflows)
- Security review required for:
  - Authentication/authorization changes
  - Data handling changes
  - Cryptographic operations
  - External integrations

**Review checklist**:
- [ ] Code follows standards
- [ ] Tests adequate and passing
- [ ] Security implications considered
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Error handling appropriate
- [ ] Logging adequate

### Technology Stack

**Approved technologies**:
- Runtime: Node.js 18+ (v22 recommended)
- Language: TypeScript (strict mode)
- Orchestration: Temporal.io
- Testing: Vitest (unit), Playwright (E2E)
- Linting: ESLint
- Security: npm audit, gitleaks, semgrep

**Dependency management**:
- Minimal dependencies (security surface)
- Lock files required (package-lock.json)
- Regular security audits (automated)
- License compliance checking

## Security Requirements

### Secrets Management

**NEVER**:
- Commit secrets to version control
- Log secrets or sensitive data
- Hardcode API keys or credentials
- Use production secrets in development

**ALWAYS**:
- Use environment variables for secrets
- Use `.env` files locally (gitignored)
- Use secure secret management in production
- Rotate secrets on compromise

### Data Protection

**Classification levels**:
- **Level 3 (Critical)**: Financial, health, government data
- **Level 2 (Sensitive)**: Personal data, credentials
- **Level 1 (Internal)**: Business data, non-public
- **Level 0 (Public)**: Publicly available data

**Handling requirements**:
- Level 3: Encryption at rest + in transit, audit logging
- Level 2: Encryption in transit, access control, audit logging
- Level 1: Access control, audit logging
- Level 0: No special handling

### Audit Trail

**All security-relevant operations must be logged**:
- Who performed the action
- What action was performed
- When the action occurred
- Where the action originated
- Result of the action

**Retention**:
- Audit logs retained for minimum 1 year
- Logs must be immutable
- Logs must be searchable

## Governance

### Constitution Authority

**This constitution supersedes**:
- Individual preferences
- Team conventions (unless documented in CONSTITUTION)
- External practices (unless explicitly adopted)

**Amendments require**:
- Documented rationale
- User approval
- Migration plan for existing code
- Version increment

### Conflict Resolution

**When conflicts arise**:
1. Refer to CONSTITUTION.md first
2. Check compliance requirements
3. Consult security team (for security matters)
4. Document decision and rationale

### Continuous Improvement

**Regular reviews**:
- Constitution review: Quarterly
- Security review: Monthly
- Dependency audit: Weekly (automated)
- Compliance review: Per regulatory cycle

## Integrity

### Pre-Commit Hook Enforcement (NON-NEGOTIABLE)

Pre-commit hooks are a critical integrity gate. The following are prohibited:

- **NEVER** use `git commit --no-verify` or `git commit -n` to bypass hooks
- **NEVER** delete, modify, or disable files in `.git/hooks/`
- **NEVER** use git plumbing commands (`git commit-tree`, `git mktree`) to circumvent hooks
- If a pre-commit hook blocks your commit, **fix the root cause** — do not work around the hook
- For assertion integrity failures: re-run `/iikit-04-testify` to regenerate hashes

**CI enforcement**: Add `verify-assertion-integrity.sh` to CI pipeline for server-side verification.

---

**Version**: 1.0.0 | **Ratified**: 2026-10-01 | **Last Amended**: 2026-10-01