# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-002
Feature: Evidence record for every step
  Every executed step produces an evidence record, every finding points to one, and the scanned source revision is recorded.

  Background:
    Given a completed audit of a source repository

  @TS-012 @FR-007 @SC-002 @P1 @acceptance
  Scenario: A finding links to the evidence of the step that produced it
    When a reviewer opens any finding
    Then the finding references an evidence record
    And that record belongs to the step that produced the finding

  @TS-013 @FR-005 @SC-002 @P1 @acceptance
  Scenario: Every executed step has an evidence record
    When a reviewer lists the evidence
    Then every executed step has a record
    And steps that found nothing or failed have a record too

  @TS-014 @FR-008 @P1 @acceptance
  Scenario: The scanned source revision is recorded
    When the run finishes
    Then the evidence states the exact source revision that was scanned

  @TS-015 @FR-006 @P1 @contract
  Scenario: An evidence record carries what an auditor needs
    When a reviewer opens an evidence record
    Then it contains the action and its inputs
    And the tool identity and version
    And the start and end time
    And the result code
    And a fingerprint of the raw output

  @TS-016 @FR-009 @FR-017 @P1 @contract
  Scenario: The evidence set is one folder with a manifest
    When the audit is sealed
    Then one folder holds all evidence records and a manifest
    And the manifest lists every record with its fingerprint

  @TS-017 @FR-011 @P2 @validation
  Scenario: Evidence is written once and carries a retention date
    Given a sealed evidence set
    When a second write to an existing record is attempted
    Then the existing record is unchanged
    And the manifest carries a retention date at least one year ahead

  @TS-018 @FR-015 @P1 @validation
  Scenario: Evidence of concurrent audits never mixes
    Given two audits run at the same time
    When both finish
    Then each evidence set contains only records of its own run

  @TS-019 @FR-005 @P2 @validation
  Scenario: A resumed audit does not duplicate evidence
    Given an audit is interrupted after some steps completed
    When the audit resumes and finishes
    Then evidence of the earlier steps is still valid
    And no step has duplicate evidence

  @TS-020 @SC-006 @P2 @acceptance
  Scenario: A finding can be traced to raw output and source revision
    When a reviewer traces a finding
    Then the trace shows the evidence record, the raw output fingerprint and the source revision
    And the trace is available with one verification command
