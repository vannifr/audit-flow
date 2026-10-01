# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

Feature: P0 Approval Workflow
  @US-002 @P1
  As a security auditor
  I want the workflow to pause automatically when critical (P0) findings are detected
  So that I can review and approve them before proceeding

  Background:
    Given the Temporal server is running
    And an audit workflow is running

  @TS-010 @FR-001 @FR-002 @SC-001 @acceptance
  Scenario: Pause workflow for P0 findings
    Given P0 findings are detected during the Reviewing phase
    When the Reviewing phase completes
    Then the workflow pauses within 1 second
    And waits for approval signal
    And the status is "Waiting for P0 approval"

  @TS-011 @FR-002 @SC-003 @acceptance
  Scenario: No pause when no P0 findings
    Given no P0 findings are detected
    When the Reviewing phase completes
    Then the workflow proceeds directly to Reporting phase

  @TS-012 @FR-003 @FR-004 @SC-002 @acceptance
  Scenario: Approve P0 findings
    Given the workflow is paused for P0 approval
    When I send approval signal with "true"
    Then the workflow proceeds to Reporting phase
    And logs the approval decision with timestamp

  @TS-013 @FR-004 @SC-002 @acceptance
  Scenario: Reject P0 findings
    Given the workflow is paused for P0 approval
    When I send approval signal with "false"
    Then the workflow stops
    And marks the audit as "failed"
    And logs the rejection with timestamp

  @TS-014 @FR-005 @SC-004 @acceptance
  Scenario: Approval timeout
    Given the workflow is paused for P0 approval
    And the timeout is set to 24 hours
    When 24 hours pass without approval signal
    Then the workflow times out
    And stops with status "Approval timeout"

  @TS-015 @FR-002 @acceptance
  Scenario: Skip approval for CI/CD
    Given I start an audit with "--skip-approval"
    When P0 findings are detected
    Then the workflow proceeds without pausing