# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-004
Feature: Verifiable evidence integrity
  A manifest with fingerprints lets a reviewer detect any change to the evidence after the audit.

  @TS-024 @FR-010 @P2 @acceptance
  Scenario: Unmodified evidence verifies
    Given an unmodified sealed evidence set
    When verification runs
    Then it reports success

  @TS-025 @FR-010 @SC-004 @P2 @acceptance
  Scenario Outline: Any change to the evidence set is detected
    Given a sealed evidence set where one record is "<change>"
    When verification runs
    Then it reports a failure naming that record

    Examples:
      | change    |
      | modified  |
      | deleted   |
      | added     |

  @TS-026 @SC-004 @P2 @validation
  Scenario: No false alarms on unmodified evidence
    Given an unmodified sealed evidence set with many records
    When verification runs repeatedly
    Then it never reports a failure
