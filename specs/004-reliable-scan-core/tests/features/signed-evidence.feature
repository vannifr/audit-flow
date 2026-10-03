# DO NOT MODIFY SCENARIOS
# Derived from requirements. Fix code to pass tests; re-run /iikit-04-testify if requirements change.

@US-006
Feature: Signed evidence
  The evidence manifest is signed so that others can check who vouches for it and that it has not been rewritten.

  @TS-031 @FR-018 @FR-019 @P2 @acceptance
  Scenario: A completed audit verifies with the published public key
    Given a completed audit
    When verification runs with the published public key
    Then it reports the signature as valid
    And it names the key

  @TS-032 @FR-019 @SC-007 @P2 @acceptance
  Scenario: A recomputed manifest invalidates the signature
    Given evidence where a record was changed and the manifest recomputed by hand
    When verification runs
    Then it reports the signature as invalid

  @TS-033 @FR-019 @SC-008 @P2 @acceptance
  Scenario Outline: Verification never reports verified without a trusted valid signature
    Given evidence that is "<condition>"
    When verification runs
    Then it reports "<outcome>"
    And it does not report the evidence as verified

    Examples:
      | condition                         | outcome     |
      | unsigned                          | unsigned    |
      | signed by a key the verifier lacks| unknown-key |

  @TS-034 @FR-020 @P2 @acceptance
  Scenario: The report states what was signed and the limits of the time
    Given a signed audit
    When a reviewer reads the report
    Then the report states what was signed and by which key
    And states that the signing time is not independently attested
    And shows the computed assurance level

  @TS-035 @FR-018 @P2 @validation
  Scenario: A signing key inside the evidence folder is refused
    Given the signing key is located inside the evidence folder
    When the audit is sealed
    Then signing is refused with a clear cause

  @TS-036 @FR-018 @FR-020 @P2 @validation
  Scenario: Missing key when a signature is required
    Given no signing key is configured and a signature is required
    When an audit runs
    Then the audit outcome is "INCOMPLETE"
    And the computed assurance level is 0
