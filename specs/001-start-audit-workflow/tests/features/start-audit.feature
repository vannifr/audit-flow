# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

Feature: Start Security Audit
  @US-001 @P1
  As a security auditor
  I want to start an automated security audit for a code repository
  So that I can identify security vulnerabilities and compliance issues

  Background:
    Given the Temporal server is running
    And the audit worker is started

  @TS-001 @FR-001 @FR-002 @SC-001 @acceptance
  Scenario: Start audit with valid repository URL
    Given I have a valid GitHub repository URL "https://github.com/vannifr/event-ticketing"
    When I start an audit with default settings
    Then the system initiates a new audit workflow
    And returns a unique workflow ID
    And the workflow status is "Discovery"

  @TS-002 @FR-010 @SC-005 @acceptance
  Scenario: Check audit status
    Given an audit workflow is running with ID "audit-test-repo-123"
    When I check the status of the workflow
    Then the system returns the current phase within 100ms
    And the status includes: workflow ID, phase, start time

  @TS-003 @FR-004 @SC-003 @acceptance
  Scenario: Detect tech stack during Discovery phase
    Given I started an audit for "vannifr/event-ticketing"
    When the Discovery phase completes
    Then the system detects the technology stack
    And generates the audit scope
    And the Discovery phase completes within 2 minutes

  @TS-004 @FR-005 @SC-004 @acceptance
  Scenario: Run security scans in parallel
    Given the Discovery phase is complete
    When the Scanning phase runs
    Then the system runs npm audit, gitleaks, semgrep, and license check in parallel
    And all scans complete within 15 minutes for repositories with <1000 dependencies

  @TS-005 @FR-008 @FR-009 @acceptance
  Scenario: Configure compliance frameworks
    Given I want ISO 27001 compliance
    When I start an audit with "--frameworks ISO27001"
    Then the system maps all findings to ISO 27001 controls

  @TS-006 @FR-008 @FR-009 @acceptance
  Scenario: Configure multiple compliance frameworks
    Given I want multiple compliance frameworks
    When I start an audit with "--frameworks ISO27001,PCI-DSS,GDPR"
    Then the system maps findings to all specified frameworks

  @TS-007 @FR-007 @FR-013 @FR-014 @acceptance
  Scenario: Handle activity failure with retry
    Given an activity fails due to transient error
    When the failure occurs
    Then the system retries the activity up to 3 times
    And enforces timeouts for all activities
    And logs the failure with details

  @TS-008 @FR-001 @acceptance
  Scenario: Handle invalid repository URL
    Given I have an invalid repository URL "not-a-url"
    When I start an audit
    Then the system returns an error "Invalid repository URL format"
    And does not initiate a workflow

  @TS-009 @FR-001 @acceptance
  Scenario: Handle inaccessible repository
    Given I have a repository URL that does not exist "https://github.com/nonexistent/repo"
    When I start an audit
    Then the system returns an error "Repository not accessible"
    And does not initiate a workflow