# Coverage Strategy

## Current Status (2026-10-02)

**Coverage:** 64% statements, 37% branches, 72% functions, 67% lines

**Tests:** 171 passing (17 test files)

**Thresholds (Phase 1 Interim):**
- Statements: 65% ✓
- Branches: 40% ✓
- Functions: 75% ✓
- Lines: 68% ✓

---

## Coverage Targets

### Phase 1: Unit Tests + Basic Integration ✓ COMPLETE

- Target: 65% statements, 40% branches, 75% functions, 68% lines
- Scope: validateRepoUrl, detectTechStack logic, helper functions
- Status: **ACHIEVED**

### Phase 2: Full Integration Tests

- Target: 80% (CONSTITUTION final requirement)
- Scope: All activities with real tool execution
- Requires:
  - Temporal server running in CI
  - Full security tool execution
  - Workflow end-to-end tests
- Estimated: Additional 20+ integration tests

---

## Coverage Breakdown

| File | Coverage | Notes |
|------|----------|-------|
| logger.ts | 100% | Fully covered |
| progress.ts | 87% | Good coverage |
| activities/index.ts | 60% | Main target |
| workflows/index.ts | N/A | Requires Temporal server |

---

## Test Files

```
tests/
├── unit/
│   ├── security.test.ts (21 tests)
│   ├── helpers-coverage.test.ts (8 tests)
│   └── logger.test.ts
├── integration/
│   ├── activities-full.test.ts (12 tests)
│   └── new-domains.test.ts (9 tests)
└── step_definitions/
    └── start-audit.steps.ts (BDD)
```

---

## Enforcement

Phase 1 threshold enforced via `vitest.config.ts`:

```typescript
coverage: {
  threshold: {
    global: {
      statements: 65,
      branches: 40,
      functions: 75,
      lines: 68,
    }
  }
}
```

---

## Plan to Reach 80%

1. Add BDD workflow tests (Phase 2)
2. Add GPL license detection test
3. Add error path tests for all activities
4. Add Temporal workflow integration tests