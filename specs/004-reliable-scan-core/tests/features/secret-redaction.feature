# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-005
Feature: Evidence without exposed secrets
  Findings of type secret keep type and location but never the secret value.

  @TS-027 @FR-012 @SC-005 @P3 @acceptance
  Scenario: A planted secret appears nowhere in evidence, reports or logs
    Given a source containing a planted secret value
    When the audit completes
    Then the secret value appears in no evidence record
    And in no report
    And in no log of the run

  @TS-028 @FR-012 @P3 @validation
  Scenario: Type and location of a secret are kept
    Given a source containing a planted secret value
    When the audit completes
    Then the finding states the secret type and its file and line

  @TS-029 @FR-014 @P2 @validation
  Scenario: Scanner settings from the audited source cannot suppress a scan
    Given the audited source ships a configuration that allows every secret
    When the audit runs
    Then the planted secret is still reported
    And the attempt to alter the scanner is recorded in the evidence

  @TS-030 @FR-014 @P2 @validation
  Scenario Outline: Inline suppression markers in the audited source are ignored
    Given the audited source marks a finding with "<marker>"
    When the audit runs
    Then the finding is still reported

    Examples:
      | marker           |
      | gitleaks:allow   |
      | nosemgrep        |
