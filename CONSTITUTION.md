<!--
Sync Impact Report
Version change: 1.0.0 -> 2.0.0 (MAJOR: sections removed, principle claims redefined)
Added principles: VI Evidence-First, VII No False Comfort, VIII Untrusted Input
  Isolation, IX Human Accountability, X Claims Match Reality, XI Independent
  Verification
Modified principles: II (coverage floor must be enforced by a gate that can
  fail), V (technology-neutral wording)
Removed sections: Technology Stack, Quality Metrics, Non-Functional Requirement
  tables, Performance Metrics, Enforcement (concrete tools, versions, numbers
  and configuration belong in plan.md per phase separation)
Removed claims: "build fails if coverage < 80%" and "64.89% coverage, 161 tests"
  (disproved by docs/review-report.md)
Follow-up TODOs: carry the removed technology, tooling and measurable NFR
  content into the plan of the next feature; align specs 001-003 with the
  .spec.md format; regenerate assertion hashes via /iikit-04-testify.
Project codename: Tessera (internal). The commercial name is not used here.
-->

# Audit Orchestration Constitution (Project Tessera)

## Core Principles

### I. Security-First Development

**Critical systems require a security-first mindset.** This framework handles:
- Customer data in enterprise environments
- Security audit results with compliance implications
- Evidence that third parties rely on

**Requirements**:
- All code passes security scanning before it reaches the trunk
- No hardcoded secrets, credentials, or API keys
- Input validation at all system boundaries
- Secure defaults for all configurations
- Audit trails for all security-relevant operations

### II. Test-Driven Development (NON-NEGOTIABLE)

**TDD is mandatory for all production code**:
1. Write tests first, get approval, verify the tests fail
2. Implement the minimum code to pass the tests
3. Refactor while keeping the tests green

**Coverage requirements**:
- A coverage floor is defined in the plan and enforced by an automated gate
- A gate that cannot fail does not count: every gate is proven to fail when its
  threshold is breached before it is relied upon
- Critical paths (workflow orchestration, security scans, approval handling)
  carry stricter coverage than the floor, stated in the plan
- Integration tests are required for workflow execution, scan activities,
  compliance mapping, and report generation

**Test types required**:
- Unit tests for activities and utilities
- Integration tests for workflows
- End-to-end tests for complete audit cycles
- Behavior tests for user-facing features, executed, not only written

**Assertion integrity**: skipping, emptying, or weakening a test to obtain a
green result is prohibited. A skipped test carries a recorded cause and owner.

### III. Enterprise Compliance

**Regulatory requirements are non-negotiable**:
- ISO 27001:2022 — Information security management
- SOC 2 Type II — Service organization controls
- PCI-DSS — Payment card data security (when applicable)
- GDPR — EU data protection (when processing EU personal data)

**Compliance mapping**:
- Every finding maps to compliance controls through a real mapping, never a
  placeholder
- Evidence is traceable to requirements
- Audit reports state compliance status and its limits
- Changes are documented for audit trails

### IV. Traceability & Governance

**Every feature is traceable**:
- Spec -> Plan -> Tasks -> Tests -> Code -> Evidence
- User stories with acceptance criteria
- Behavior scenarios for validation
- Pre-commit hooks for integrity

**Documentation requirements**:
- All public interfaces documented with examples
- All workflows documented with diagrams
- All compliance mappings documented
- All security decisions documented

### V. Reliability & Observability

**Production systems are observable**:
- Structured logging
- Correlation identifiers across a run
- Metrics for all operations
- Alerts for critical failures

**Reliability requirements**:
- Retry logic for transient failures, and no retry for invalid input
- Timeouts and liveness signals for all long-running and external calls
- A run interrupted by a crash resumes within a bounded, stated time
- Graceful degradation, always reported as degradation (see principle VII)

**Orchestration rules**:
- All workflows and activities have timeouts
- Activities are idempotent where possible
- Signals are documented and every signal outcome is handled
- Queries are side-effect free

### VI. Evidence-First

**Every statement the system makes is backed by a record of what happened**:
- Each executed step records the command and arguments, tool version, start and
  end time, exit code, and a content hash of its raw output
- Each finding links to the evidence record that produced it
- Each run records the identity of the audited source (revision) and a manifest
  of all evidence with hashes
- Evidence is immutable after creation and is retained for at least one year
- Evidence never contains unredacted secrets

### VII. No False Comfort

**"No findings" is only reported when the scan demonstrably ran**:
- Each scanner and check has an explicit status: completed, partial, failed,
  skipped, or unavailable
- A failed, missing, or partial scan is reported as INCOMPLETE and is visible in
  the summary, never silently treated as clean
- A tool that exits non-zero because it found issues is distinct from a tool that
  failed
- Risk levels and summaries state what was not scanned
- Placeholder or heuristic results are labeled as such and never presented as
  verified analysis

### VIII. Untrusted Input Isolation

**The audited source is hostile by default**:
- Audited code, configuration, and repository metadata never execute inside the
  framework's trust boundary
- Scanners run with framework-controlled configuration; settings shipped in the
  audited source cannot suppress, redirect, or alter a scan
- External commands receive arguments as data, never through shell
  interpretation
- Working locations are unpredictable, private, size-limited, and removed on
  every exit path
- Network exposure of orchestration components is explicit and authenticated

### IX. Human Accountability

**Decisions that accept risk belong to a person and are recorded**:
- Approval and rejection are both honored and both recorded with who, when, and
  what was decided
- Bypassing an approval is explicit, attributed, and shown in the report
- An unanswered approval ends in a defined, reported outcome, never in an
  implicit approval
- Generated or model-assisted conclusions are advice; they never lower a
  severity or remove a finding without human approval

### X. Claims Match Reality

**Documentation states only what has been measured**:
- Status figures (tests, coverage, domains, readiness) come from a single source
  produced by the pipeline, not from hand-maintained text
- A readiness or compliance claim cites the evidence that supports it
- Planned capabilities are labeled planned and are not counted as delivered
- Contradicting status documents are removed or reduced to links to the single
  source

### XI. Independent Verification

**The framework is measured against known truth**:
- A maintained ground-truth case set with known defects and clean controls
  exists, with recall and false-positive rates tracked per release
- A release does not claim a capability whose ground-truth recall is
  unmeasured
- Review of delivered work is performed independently of its author, by a
  person, or by the automated pipeline plus structured self-review for solo work

## Quality Gates

### Pre-Commit Checks (NON-NEGOTIABLE)

**Required before every commit**:
- Compilation or build succeeds
- Static analysis passes
- Tests pass and the coverage floor is met
- Dependency vulnerability scan passes at the agreed severity
- No secrets detected

**Bypassing prohibited**:
- NEVER use `git commit --no-verify` or `git commit -n`
- NEVER disable or delete `.git/hooks/`
- NEVER use git plumbing commands to circumvent hooks
- If blocked, **fix the root cause** — do not work around

### Pre-Merge Checks

**Required before work lands on the trunk**:
- All pre-commit checks pass
- Review is complete (see Development Workflow)
- Integration tests pass
- Security review for security-related changes
- Documentation updated in the same change

### CI/CD Pipeline

**Automated checks in CI mirror the local verification**:
- Build and test with coverage enforcement
- Security: dependency, secret, and static analysis scans
- Compliance: schema validation and assertion integrity
- Every gate blocks; a gate that is made non-blocking is recorded as a
  deviation with owner and deadline
- Local and CI verification stay equivalent: a gap between them is a defect

## Development Workflow

### Branch Strategy

**Trunk-based development**:
- The main branch is always deployable
- Small, atomic, green commits land on the trunk directly
- Unfinished or risky work ships dark behind a toggle, not on a long-lived branch

**Commit standards**:
- Conventional Commits format
- One logical change per commit
- Reference the task in the commit message

### Code Review

**All changes are reviewed**:
- Team work: at least one independent approval; two for critical changes
  (security, compliance, workflows)
- Solo work: automated pipeline plus structured self-review against spec and
  acceptance criteria
- Security review for authentication, data handling, cryptography, and external
  integrations

**Review checklist**:
- [ ] Code follows standards
- [ ] Tests adequate, meaningful, and passing
- [ ] Security implications considered
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Error handling appropriate
- [ ] Logging adequate
- [ ] Failure of any dependency is reported, not hidden

### Dependency Management

- Minimal dependencies (security surface)
- Lock files required and installation reproducible without workarounds
- Regular automated security audits
- License compliance checking

## Security Requirements

### Secrets Management

**NEVER**:
- Commit secrets to version control
- Log secrets or sensitive data, or write them to evidence unredacted
- Hardcode API keys or credentials
- Use production secrets in development

**ALWAYS**:
- Supply secrets through the environment or a secret manager
- Keep local secret files out of version control
- Rotate secrets on compromise

### Data Protection

**Classification levels**:
- **Level 3 (Critical)**: Financial, health, government data
- **Level 2 (Sensitive)**: Personal data, credentials
- **Level 1 (Internal)**: Business data, non-public
- **Level 0 (Public)**: Publicly available data

**Handling requirements**:
- Level 3: Encryption at rest and in transit, audit logging
- Level 2: Encryption in transit, access control, audit logging
- Level 1: Access control, audit logging
- Level 0: No special handling

### Audit Trail

**All security-relevant operations are logged**:
- Who performed the action
- What action was performed
- When the action occurred
- Where the action originated
- Result of the action

**Retention**:
- Audit logs retained for a minimum of 1 year
- Logs are immutable and searchable

## Governance

### Constitution Authority

**This constitution supersedes**:
- Individual preferences
- Team conventions (unless documented here)
- External practices (unless explicitly adopted)

**Amendments require**:
- Documented rationale
- Explicit user approval
- Migration plan for existing artifacts
- Version increment (MAJOR: principle removal or redefinition, MINOR: new
  principle, PATCH: clarification)

### Conflict Resolution

**When conflicts arise**:
1. Refer to this constitution first
2. Check compliance requirements
3. Consult the security owner (for security matters)
4. Document the decision and rationale

### Continuous Improvement

**Regular reviews**:
- Constitution review: quarterly
- Security review: monthly
- Dependency audit: continuous and automated
- Compliance review: per regulatory cycle
- Ground-truth recall and false-positive rates: every release

## Integrity

### Pre-Commit Hook Enforcement (NON-NEGOTIABLE)

Pre-commit hooks are a critical integrity gate. The following are prohibited:

- **NEVER** use `git commit --no-verify` or `git commit -n` to bypass hooks
- **NEVER** delete, modify, or disable files in `.git/hooks/`
- **NEVER** use git plumbing commands (`git commit-tree`, `git mktree`) to
  circumvent hooks
- If a pre-commit hook blocks your commit, **fix the root cause**
- For assertion integrity failures: re-run `/iikit-04-testify` to regenerate
  hashes

**CI enforcement**: assertion integrity is also verified server-side in CI.

---

**Version**: 2.0.0 | **Ratified**: 2026-10-01 | **Last Amended**: 2026-10-02
