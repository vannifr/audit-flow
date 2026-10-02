# Feature Specification: Reliable Scan Core

**Feature Branch**: `004-reliable-scan-core`
**Created**: 2026-10-02
**Status**: Draft
**Input**: User description: "Reliable scan core with per-step evidence records and honest scanner status"
**Project**: Tessera (internal codename)

## User Stories *(mandatory)*

### User Story 1 - Honest scan outcome (Priority: P1)

A consultant reads an audit report and needs to know which checks actually ran. Every scanner
and check shows an explicit status. If any scanner failed, was missing, or only partly ran,
the audit is marked INCOMPLETE and the summary says what was not scanned. A report never says
"no findings" for something that was not scanned.

**Why this priority**: Without it a failed scanner looks like a clean system. This is the
largest trust defect found in the independent review and blocks every enterprise use.

**Independent Test**: Run an audit against a source with known defects while one scanner is
made unavailable. The report is INCOMPLETE, names the unavailable scanner, and does not show
that scanner's area as clean.

**Acceptance Scenarios**:

1. **Given** a scanner is not installed, **When** an audit runs, **Then** the report shows that
   scanner as unavailable, the audit as INCOMPLETE, and no clean result for its area.
2. **Given** a scanner crashes mid-run, **When** the audit finishes, **Then** the scanner status
   is failed, the cause is recorded, and the audit is INCOMPLETE.
3. **Given** all scanners complete and find nothing, **When** the audit finishes, **Then** the
   report states "no findings" together with the list of completed scanners.
4. **Given** a scanner exits with a non-zero code because it found issues, **When** the audit
   finishes, **Then** the status is completed and the issues are reported as findings.

---

### User Story 2 - Evidence record for every step (Priority: P1)

An auditor wants proof of what the audit did, not only what it found. Every executed step
produces an evidence record: what was run and with which inputs, the tool version, start and
end time, the result code, and a fingerprint of the raw output. Every finding points to the
record that produced it. The run records which exact revision of the audited source was scanned.

**Why this priority**: This turns the audit trail into an evidence log that a third party can
rely on, as required by the constitution (Evidence-First).

**Independent Test**: Complete an audit, then pick any finding. Follow its link to the evidence
record and confirm the step, tool version, source revision, and raw-output fingerprint.

**Acceptance Scenarios**:

1. **Given** a completed audit, **When** a reviewer opens any finding, **Then** it links to the
   evidence record of the step that produced it.
2. **Given** a completed audit, **When** a reviewer lists the evidence, **Then** every executed
   step, including steps that found nothing or failed, has a record.
3. **Given** an audit of a source repository, **When** the run finishes, **Then** the evidence
   states the exact source revision that was scanned.

---

### User Story 3 - No findings lost when a tool reports issues (Priority: P2)

A dependency scanner reports vulnerabilities by returning a non-zero result. The audit treats
this as "issues found" and reports every vulnerability, not as an error to be discarded.

**Why this priority**: In the independent review, known vulnerable dependencies produced zero
findings. Recall on dependency defects is the most visible quality gap.

**Independent Test**: Audit the demo vulnerable source. The three planted dependency defects
(D05, D06, D07 in the ground truth) appear as findings with the expected severity.

**Acceptance Scenarios**:

1. **Given** a source with known vulnerable dependencies, **When** the audit runs, **Then** each
   known vulnerability is reported with severity and affected package.
2. **Given** a very large scanner output, **When** the audit runs, **Then** no findings are
   lost to output size limits; truncation is reported as partial.

---

### User Story 4 - Verifiable evidence integrity (Priority: P2)

A reviewer or client can verify that the evidence has not changed after the audit. A manifest
lists all evidence with fingerprints. A verification step recomputes them and reports any
mismatch, missing, or extra record.

**Why this priority**: Evidence only counts as proof if tampering is detectable.

**Independent Test**: Alter one evidence record after an audit. Verification reports exactly that
record as modified; unmodified evidence verifies clean.

**Acceptance Scenarios**:

1. **Given** unmodified evidence, **When** verification runs, **Then** it reports success.
2. **Given** one modified, deleted, or added record, **When** verification runs, **Then** it
   reports a failure naming that record.

---

### User Story 5 - Evidence without exposed secrets (Priority: P3)

Findings of type secret carry enough information to locate and fix the issue but never contain
the secret value in clear text in evidence, logs, or reports.

**Why this priority**: Evidence is shared with clients and retained; secrets in it are a
second leak.

**Independent Test**: Audit a source containing a planted secret. Search all evidence, logs, and
reports for the secret value; it does not appear.

**Acceptance Scenarios**:

1. **Given** a source with a planted secret, **When** the audit completes, **Then** the secret
   value appears nowhere in evidence, reports, or logs, while its location and type do.

---

### Edge Cases

- A scanner produces no output but a success code. The status is completed and the empty output
  is recorded with its fingerprint.
- A scanner hangs. The step ends after its time limit, status is failed with cause timeout.
- The audit run is interrupted and resumed. Evidence from steps completed before the
  interruption stays valid and is not duplicated.
- The audited source contains settings that try to disable or redirect a scanner. The scan
  ignores them and the attempt is noted in the evidence.
- Two audits run at the same time. Their evidence sets never mix.
- The source cannot be retrieved. The audit fails early with a clear cause and an INCOMPLETE
  outcome; no empty report is produced as if the audit had run.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST assign each scanner and check one status per audit: completed,
  partial, failed, skipped, or unavailable.
- **FR-002**: The system MUST mark an audit INCOMPLETE when any required scanner is not
  completed, and MUST state which checks were not performed.
- **FR-003**: The system MUST NOT report an area as clean unless its scanner status is completed.
- **FR-004**: The system MUST distinguish "scanner reported issues" from "scanner failed".
- **FR-005**: The system MUST create an evidence record for every executed step, including steps
  with no findings and steps that failed.
- **FR-006**: An evidence record MUST contain the action and its inputs, the tool identity and
  version, start and end time, the result code, and a fingerprint of the raw output.
- **FR-007**: Every finding MUST reference the evidence record that produced it.
- **FR-008**: The system MUST record the exact revision of the audited source in the evidence.
- **FR-009**: The system MUST produce a manifest listing all evidence records with their
  fingerprints for each audit.
- **FR-010**: The system MUST provide a verification that recomputes fingerprints and reports
  modified, missing, and extra records.
- **FR-011**: Evidence MUST be immutable after creation and retained for at least one year.
- **FR-012**: The system MUST redact secret values in evidence, logs, and reports while keeping
  type and location.
- **FR-013**: The system MUST report truncated or size-limited scanner output as partial.
- **FR-014**: Scan settings that originate from the audited source MUST NOT change scanner
  behavior, and any such attempt MUST be recorded.
- **FR-015**: Evidence from separate audits MUST NOT mix, including audits that run at the same
  time.
- **FR-016**: The report MUST show the overall audit outcome (complete or INCOMPLETE) and the
  scanner status table at the top.
- **FR-017**: The system MUST make the evidence set available as one folder containing all
  evidence records and the manifest, so it can be handed to a client or auditor and verified
  there.

**Delivery note (decided 2026-10-02)**: FR-011 is delivered in part by this feature: records are
written once, protected against change by ordinary means, and carry a retention date; storage that
even an administrator cannot alter is a separate operational step. Reports state this limit.

### Key Entities

- **Audit Run**: One execution of an audit against one source revision; has an overall outcome.
- **Scanner Status**: The result category of one scanner or check within an Audit Run.
- **Evidence Record**: Proof of one executed step: inputs, tool, times, result code, output
  fingerprint.
- **Finding**: A reported issue with severity, location, and a reference to its Evidence Record.
- **Evidence Manifest**: The list of all Evidence Records of an Audit Run with fingerprints.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of audits where a scanner is unavailable or failed, the report is marked
  INCOMPLETE and names that scanner (tested for each scanner in turn).
- **SC-002**: 100% of executed steps have an evidence record, and 100% of findings link to one.
- **SC-003**: Against the demo ground truth, the three dependency defects (D05, D06, D07) are
  found, and recall on all planted defects does not decrease compared with the baseline of
  6 of 18 recorded in the independent review.
- **SC-004**: Verification detects 100% of modified, deleted, and added evidence records in a
  tamper test, with no false alarms on unmodified evidence.
- **SC-005**: A search for each planted secret value across all evidence, logs, and reports
  returns zero matches.
- **SC-006**: A reviewer can trace any finding to its raw output and source revision in under
  2 minutes.
