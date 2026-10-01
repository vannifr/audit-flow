# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

Feature: Generate Audit Report
  @US-003 @P1
  As a security auditor
  I want a comprehensive audit report in Markdown format
  So that I can review findings and present them to stakeholders

  Background:
    Given an audit workflow has completed successfully
    And findings were identified during the audit

  @TS-016 @FR-001 @FR-002 @SC-001 @acceptance
  Scenario: Generate Markdown report
    Given the Reporting phase runs
    When the report is generated
    Then a Markdown file is created at the specified path
    And the report is generated within 30 seconds

  @TS-017 @FR-003 @FR-004 @acceptance
  Scenario: Report contains required sections
    Given a report is generated
    When I open the report
    Then it contains: executive summary, methodology, findings by severity, compliance mappings, recommendations
    And each finding includes: ID, severity, title, description, evidence path, remediation

  @TS-018 @FR-006 @SC-002 @acceptance
  Scenario: Collect evidence artifacts
    Given findings were identified
    When the report is generated
    Then an evidence JSON file is created for each finding
    And 100% of findings have corresponding evidence files

  @TS-019 @FR-007 @acceptance
  Scenario: Evidence file structure
    Given an evidence file exists for finding "NPM-1"
    When I open the evidence file
    Then it contains: scan type, raw output, affected files, line numbers, timestamps
    And the file is valid JSON format

  @TS-020 @FR-008 @FR-009 @SC-005 @acceptance
  Scenario: Generate compliance report
    Given I specified ISO 27001 compliance
    When the audit completes
    Then a compliance report is generated with ISO 27001 control mappings
    And the report shows: control ID, control name, status, evidence

  @TS-021 @FR-008 @acceptance
  Scenario: Multiple compliance reports
    Given I specified multiple frameworks "ISO27001,PCI-DSS,GDPR"
    When the audit completes
    Then separate compliance reports are generated for each framework

  @TS-022 @FR-009 @SC-006 @acceptance
  Scenario: Output directory structure
    Given an audit completes
    When I list the output directory
    Then it follows the structure: /tmp/audit-<id>/{report.md, evidence/, raw/, compliance/}
    And all artifacts are present