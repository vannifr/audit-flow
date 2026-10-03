# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-003
Feature: No findings lost when a tool reports issues
  A dependency scanner that reports vulnerabilities through a non-zero result still yields every vulnerability.

  @TS-021 @FR-004 @SC-003 @P2 @acceptance
  Scenario: Known vulnerable dependencies are reported
    Given a source with known vulnerable dependencies
    When the audit runs
    Then each known vulnerability is reported with severity and affected package

  @TS-022 @FR-013 @P2 @acceptance
  Scenario: Very large scanner output does not drop findings silently
    Given a scanner produces very large output
    When the audit runs
    Then no findings are lost to the output size limit
    And truncation is reported as partial

  @TS-023 @SC-003 @P2 @contract
  Scenario: Ground truth recall on the demo case
    Given the demo vulnerable application with known planted defects
    When the audit runs
    Then the three planted dependency defects D05, D06 and D07 are found
    And the number of planted defects found is at least 8 of 18
