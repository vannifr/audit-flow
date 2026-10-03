# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-001
Feature: Honest scan outcome
  Every scanner and check has an explicit status, and an audit never reports an area as clean unless its scanner completed.

  Background:
    Given an audit source with known content

  @TS-001 @FR-001 @FR-002 @FR-003 @SC-001 @P1 @acceptance
  Scenario: Unavailable scanner makes the audit incomplete
    Given the secret scanner is not installed
    When an audit runs
    Then the report shows the secret scanner as "unavailable"
    And the audit outcome is "INCOMPLETE"
    And the report does not show a clean result for secret scanning

  @TS-002 @FR-001 @FR-002 @P1 @acceptance
  Scenario: Crashing scanner is reported as failed
    Given the static analysis scanner crashes during the run
    When the audit finishes
    Then the scanner status is "failed" and the cause is recorded
    And the audit outcome is "INCOMPLETE"

  @TS-003 @FR-003 @P1 @acceptance
  Scenario: Clean result names the scanners that completed
    Given all required scanners complete and find nothing
    When the audit finishes
    Then the report states "no findings"
    And the report lists the completed scanners

  @TS-004 @FR-004 @P1 @acceptance
  Scenario: Non-zero exit because issues were found is not a failure
    Given a scanner exits with a non-zero code because it found issues
    When the audit finishes
    Then the scanner status is "completed"
    And the issues are reported as findings

  @TS-005 @FR-001 @FR-002 @SC-001 @P1 @acceptance
  Scenario Outline: Every required scanner is covered by the incomplete rule
    Given the scanner "<scanner>" is "<state>"
    When an audit runs
    Then the audit outcome is "INCOMPLETE"
    And the report names "<scanner>" as not completed

    Examples:
      | scanner          | state       |
      | secret scanner   | unavailable |
      | secret scanner   | failed      |
      | static analysis  | unavailable |
      | static analysis  | failed      |
      | dependency audit| unavailable |
      | dependency audit| failed      |
      | license check    | failed      |

  @TS-006 @FR-002 @P1 @validation
  Scenario: Report states which checks were not performed
    Given one required scanner did not complete
    When the audit finishes
    Then the summary lists every check that was not performed

  @TS-007 @FR-016 @P1 @contract
  Scenario: Outcome and scanner status table are at the top of the report
    When an audit finishes
    Then the first lines of the report show the overall outcome
    And a scanner status table follows before any finding

  @TS-008 @FR-013 @P2 @validation
  Scenario: Truncated scanner output is reported as partial
    Given a scanner produces more output than the size limit
    When the audit finishes
    Then the scanner status is "partial" with cause "output truncated"

  @TS-009 @FR-005 @FR-006 @P2 @validation
  Scenario: A scanner that succeeds with no output is recorded
    Given a scanner returns a success code and no output
    When the audit finishes
    Then the scanner status is "completed"
    And the empty output is recorded with its fingerprint

  @TS-010 @FR-001 @P2 @validation
  Scenario: A hanging scanner ends with cause timeout
    Given a scanner does not finish within its time limit
    When the audit runs
    Then the scanner status is "failed" with cause "timeout"

  @TS-011 @FR-002 @P2 @validation
  Scenario: An unreachable source fails early and honestly
    Given the audit source cannot be retrieved
    When an audit runs
    Then the audit fails early with a clear cause
    And the outcome is "INCOMPLETE"
    And no report is produced as if the audit had run
