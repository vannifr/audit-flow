# Review Instructies — Audit Flow

**Project:** Tessera  
**Repository:** https://github.com/vannifr/tessera  
**CI:** https://ci.vannifr.ovh/repos/25  
**Datum:** 2026-10-02  
**Reviewer:** qwen3-max-2026-01-23 (onafhankelijke review)

---

## Doel

Onafhankelijke, bewijsgebaseerde review van de enterprise-grade audit workflow engine om:

1. **Security & Quality bevindingen** te identificeren (P0-P3 severity)
2. **CI/Local parity** te valideren (90%+ coverage vereist)
3. **Enterprise claims** te verifiëren met pipeline bewijs
4. **Actiegerichte aanbevelingen** te geven voor productie readiness

---

## Review Scope

### 1. Codebase Review — Security First

**Kritieke bestanden:**

| Categorie | Bestand | Focus | Checklist |
|-----------|---------|-------|-----------|
| **Activities** | `src/activities/index.ts` | Command injection, input validation | [ ] `validateRepoUrl` regex security<br>[ ] `execFileSync` parameter sanitization<br>[ ] No hardcoded secrets |
| **Workflows** | `src/workflows/index.ts` | Signal handling, error propagation | [ ] ApplicationFailure usage<br>[ ] Timeout handling<br>[ ] Retry policies |
| **Client** | `src/client.ts` | API correctness | [ ] Type safety<br>[ ] Connection validation |
| **Config** | `src/config/audit-domains.ts` | Compliance mapping | [ ] Domain coverage completeness |
| **Errors** | `src/errors.ts` | Error exposure | [ ] No sensitive data in messages |

**Review criteria:**
- ✅ **Security:** Input validatie, command injection preventie, secrets handling
- ✅ **Error handling:** try-catch coverage, ApplicationFailure patterns
- ✅ **Type safety:** TypeScript strict mode, geen `any` of `@ts-ignore`
- ✅ **Code quality:** DRY principles, cyclomatic complexity < 10
- ✅ **Testing:** Coverage 80%+, meaningful assertions (geen placeholder tests)

**Quick checks:**
```bash
# Command injection risks
grep -n "execFileSync\|execSync" src/activities/index.ts

# Type safety violations
grep -r ": any" src/ --include="*.ts" | grep -v "node_modules"
grep -r "@ts-ignore" src/ --include="*.ts"

# Hardcoded secrets (false positive check)
grep -r "secret\|password\|token" src/ --include="*.ts" | grep -v "test"
```

---

### 2. CI/CD Review — Pipeline Integrity

**Bestanden:**

| Bestand | Focus | Validatie |
|---------|-------|-----------|
| `.woodpecker.yml` | Step ordering, blocking vs ignore | [ ] Alle security checks blocking (behalve devDependencies)<br>[ ] Globale secrets gebruikt |
| `vitest.config.ts` | Coverage thresholds | [ ] 80% threshold<br>[ ] HTML + text reporters |
| `sonar-project.properties` | Quality gate | [ ] Coverage paths correct<br>[ ] Quality gate actief |
| `.gitleaksignore` | False positives | [ ] Elke entry legitiem gedocumenteerd |
| `.githooks/pre-commit` | Local verify | [ ] Matcht CI steps |
| `.githooks/pre-push` | Gitleaks | [ ] Diff-scoped scan |

**Review vragen:**
- [ ] Dekt `npm run verify` 100% van CI checks (behalve SonarQube)?
- [ ] Zijn alle security stappen **blocking** (exit code 1 bij failure)?
- [ ] Is gitleaks **diff-scoped** (alleen staged changes)?
- [ ] Zijn secrets als **globale secrets** geconfigureerd in Woodpecker?

**Quick checks:**
```bash
# CI vs Local parity
npm run verify  # Moet alle CI checks lokaal reproduceren

# Gitleaks scope
cat .githooks/pre-push | grep "gitleaks"
# Verwacht: gitleaks protect --staged (diff-scoped)

# SonarQube quality gate
cat sonar-project.properties | grep "qualitygate"
```

---

### 3. Enterprise Gaps Review — Bewijsverificatie

**Te verifiëren claims uit ENTERPRISE-STATUS.md:**

| Claim | Pipeline Bewijs | Verificatie Commando |
|-------|-----------------|---------------------|
| Coverage ≥ 80% | Pipeline #14, test step | `npm run test:coverage` → check summary |
| SonarQube quality gate | Pipeline #14, sonarqube step | Check logs voor "Quality Gate status" |
| Gitleaks blocking | Pipeline #14, secrets-scan step | Check exit code bij failure |
| SAST blocking | Pipeline #14, sast step | Check semgrep exit code |
| License check blocking | Pipeline #14, license-check step | Check exit code |
| CI/Local parity | `.githooks/` vs `.woodpecker.yml` | Diff vergelijking |
| 95% enterprise score | ENTERPRISE-STATUS.md | Audit tegen framework |

**Te documenteren:**
- ✅ Per claim: **pipeline nummer + step naam + exit code/screenshot**
- ✅ Gaps die nog open staan (P2/P3) met **impact assessment**
- ✅ False positives in `.gitleaksignore`: **legitimering per entry**

**Pipeline verificatie (via MCP):**
```javascript
// Pipeline #14 details
mcp__woodpecker-ci__get_pipeline --repoId 25 --number 14

// Step logs voor bewijs
mcp__woodpecker-ci__get_step_logs --repoId 25 --number 14 --stepId <step_id>
```

---

### 4. Security Audit — Deep Dive

**Kritieke aspecten:**

| Aspect | Locatie | Check | Tool |
|--------|---------|-------|------|
| Command injection | `src/activities/index.ts` | `validateRepoUrl` regex strength | Manual review |
| Secrets in code | Alle bestanden | Geen hardcoded credentials | `grep`, gitleaks |
| Input validation | Alle activities | Parameter sanitization | Manual review |
| Error exposure | `src/errors.ts` | Geen sensitive data in errors | Manual review |
| Dependencies | `package.json` | High/critical vulnerabilities | `npm audit` |
| SAST coverage | `.woodpecker.yml` | Semgrep rulesets | `semgrep` |

**Security scans:**
```bash
# Dependency audit
npm audit --audit-level=high

# Secrets scan (diff-scoped)
gitleaks protect --staged --verbose

# SAST scan
semgrep --config=p/security-audit --config=p/typescript src/

# Custom rules (SQL injection, etc.)
semgrep --config=semgrep-rules/ src/
```

---

### 5. Testing Review — Coverage & Quality

**Test categoriën:**

| Type | Locatie | Focus | Checklist |
|------|---------|-------|-----------|
| Unit | `tests/unit/*.test.ts` | Isolated logic | [ ] Meaningful assertions<br>[ ] Edge cases |
| Integration | `tests/integration/*.test.ts` | Real tool usage | [ ] Error handling<br>[ ] Timeout tests |
| BDD | `specs/*/tests/step_definitions/*.steps.ts` | Gherkin coverage | [ ] All scenarios covered |
| E2E | `scripts/test-audit-run.ts` | Full workflow | [ ] Geen echte secrets |

**Coverage verificatie:**
```bash
npm run test:coverage
# Check: coverage/lcov-report/index.html
# Verwacht: ≥ 80% statements, branches, functions, lines
```

---

## Review Proces — Stapsgewijs

### Stap 1: Documentatie Review (5 min)
```bash
cat ENTERPRISE-STATUS.md    # Claims verifiëren
cat README.md               # Setup instructies
cat CONSTITUTION.md         # Governance principles
cat AUDIT-COVERAGE.md       # Audit scope
```

### Stap 2: Codebase Security Scan (15 min)
```bash
# Command injection
grep -n "execFileSync" src/activities/index.ts
# Verwacht: Alle parameters gevalideerd via validateRepoUrl

# Type safety
grep -r ": any" src/ --include="*.ts" | wc -l
# Verwacht: 0 (of < 5 met goede reden)

# Secrets
grep -r "secret\|password\|token" src/ --include="*.ts" --exclude-dir=node_modules
# Verwacht: Alleen in test files of environment variables
```

### Stap 3: CI/Local Parity Verificatie (10 min)
```bash
# Local verify command
npm run verify

# Git hooks
cat .githooks/pre-commit
cat .githooks/pre-push

# Vergelijk met CI
cat .woodpecker.yml | grep -A 10 "pipeline:"
```

### Stap 4: Pipeline Bewijs Verzamelen (15 min)
Via Woodpecker CI MCP tools:
1. Get pipeline #14 details
2. Download step logs voor elke claim
3. Screenshot exit codes en quality gate status

### Stap 5: Security Scans Uitvoeren (10 min)
```bash
npm audit --audit-level=high
gitleaks protect --staged --verbose
semgrep --config=p/security-audit src/
```

### Stap 6: Coverage Verificatie (5 min)
```bash
npm run test:coverage
open coverage/lcov-report/index.html  # Of bekijk terminal output
```

---

## Output Format — Structured Report

### 1. Executive Summary

**Overall Assessment:** [Pass / Fail / Conditional]

**Critical Metrics:**
- Security findings: P0: [X], P1: [Y], P2: [Z]
- CI/Local parity: [X]%
- Test coverage: [X]%
- Enterprise score: [X]% (geverifieerd)

**Go/No-Go Recommendation:**
- [ ] **GO** — Geen P0 findings, < 3 P1, parity > 90%
- [ ] **CONDITIONAL** — P1 findings oplosbaar in [X] dagen
- [ ] **NO-GO** — P0 findings of parity < 90%

---

### 2. Bevindingen per Categorie

#### Security Bevindingen

| ID | Finding | Severity | Locatie | Impact | Aanbeveling |
|----|---------|----------|---------|--------|-------------|
| S01 | Command injection risk in `validateRepoUrl` | P0 | `src/activities/index.ts:45` | High | Strengere regex + allowlist |
| S02 | Hardcoded test secret | P2 | `tests/integration/fixture.ts:12` | Low | Move to `.env.test` |

#### Quality Bevindingen

| ID | Finding | Severity | Locatie | Impact | Aanbeveling |
|----|---------|----------|---------|--------|-------------|
| Q01 | Cyclomatic complexity 15 | P2 | `src/workflows/index.ts:78` | Medium | Refactor into smaller functions |

#### CI/CD Bevindingen

| ID | Finding | Severity | Stap | Impact | Aanbeveling |
|----|---------|----------|------|--------|-------------|
| C01 | SonarQube niet lokaal reproduceerbaar | P3 | sonarqube | Low | Document gap in README |

---

### 3. CI/Local Parity Matrix

| CI Stap | Local Command | Dekking | Gap | Severity |
|---------|---------------|---------|-----|----------|
| build | `npm run build` | ✅ 100% | - | - |
| test:coverage | `npm run test:coverage` | ✅ 100% | - | - |
| lint | `npm run lint` | ✅ 100% | - | - |
| gitleaks | `gitleaks protect --staged` | ✅ 100% | - | - |
| semgrep | `semgrep --config=p/security-audit` | ✅ 100% | - | - |
| sonarqube | ❌ geen local | ⚠️ 0% | SonarQube requires server | P3 (documented) |
| **Totaal** | | **90%** | 1 gap | |

---

### 4. Enterprise Gaps Status

| Gap | Status | Pipeline Bewijs | Notes |
|-----|--------|-----------------|-------|
| Coverage < 80% | ✅ Resolved | Pipeline #14, test step (82.3%) | - |
| SonarQube quality gate | ✅ Verified | Pipeline #14, sonarqube step (PASSED) | - |
| Gitleaks blocking | ✅ Verified | Pipeline #14, secrets-scan (exit 1 bij failure) | - |
| SAST blocking | ✅ Verified | Pipeline #14, sast step (exit 1 bij findings) | - |
| License check | ✅ Verified | Pipeline #14, license-check (exit 1 bij violations) | - |
| CI/Local parity | ✅ Verified | 90% coverage, 1 documented gap | SonarQube server requirement |
| **Overall Score** | **95%** | **Alle claims verified** | **Enterprise-ready** |

---

### 5. Aanbevelingen — Prioritized

#### Critical (P0) — Must fix before production
1. [ ] Fix command injection in `validateRepoUrl` (S01)
2. [ ] ...

#### High (P1) — Fix in next sprint (1-2 weken)
1. [ ] Add input validation for [X] (S03)
2. [ ] ...

#### Medium (P2) — Plan for Phase 2
1. [ ] Refactor high-complexity function (Q01)
2. [ ] ...

#### Low (P3) — Nice to have
1. [ ] Document SonarQube gap in README (C01)
2. [ ] ...

---

## Success Criteria — Pass Conditions

De review **slaagt** als:

- ✅ **Geen P0 security findings** (command injection, hardcoded secrets, etc.)
- ✅ **< 3 P1 findings** (high impact maar niet kritiek)
- ✅ **CI/Local parity ≥ 90%** (alle security checks lokaal reproduceerbaar)
- ✅ **Test coverage ≥ 80%** (statements, branches, functions, lines)
- ✅ **Alle enterprise claims ondersteund door pipeline bewijs**
- ✅ **SonarQube quality gate PASSED** in laatste pipeline

---

## Context voor de Reviewer

### Project Stack
- **Workflow Engine:** Temporal.io (TypeScript SDK)
- **Governance:** IIKit (CONSTITUTION.md, spec-driven development)
- **CI/CD:** Woodpecker CI (self-hosted op ci.vannifr.ovh)
- **Code Quality:** SonarQube (local instance: http://sonarqube:9000)
- **Testing:** Vitest + Cucumber BDD
- **Security:** Gitleaks + Semgrep + npm audit

### Developer Context
- **Profiel:** Solo developer (trading bots, VPS, Python/Node.js)
- **Focus:** Correctheid en security zijn **cruciaal** (geen team review)
- **Trade-off:** Prefers simple & performant (Bun/TypeScript, SQLite)

### Key Constraints
- **No production deployment** zonder P0-free review
- **CI/Local parity** is non-negotiable (solo developer workflow)
- **Evidence-based** — elke claim moet pipeline bewijs hebben

---

## Start de Review

### Optie 1: Automatische Review Agent
```bash
/review --effort high --topology minimal
```
- Gebruikt `qwen3-max-2026-01-23` voor onafhankelijke review
- Output: Structured report in deze format

### Optie 2: Manual Fork Review
1. Start een fork met deze instructies als prompt
2. Volg het stapsgewijze proces
3. Document bevindingen in het output format

### Optie 3: Hybrid (Recommended)
1. Run `/review --effort high` voor baseline
2. Manual verification van security-critical findings
3. Pipeline bewijs verzamelen via MCP tools
4. Final report samenstellen

---

## Loop Detection & Exit Strategy

### Loop Detection Rules

De review **MOET STOPPEN** als aan één van deze voorwaarden wordt voldaan:

1. **Tijdslimiet overschreden:**
   - Max 60 minuten voor volledige review
   - Individuele stap > 15 minuten → abort en rapporteer blocker

2. **Herhalende bevindingen:**
   - Dezelfde finding gerapporteerd > 3 keer
   - Geen nieuwe bevindingen in laatste 2 iteraties

3. **Pipeline bewijs niet verkrijgbaar:**
   - MCP tools falen na 3 retries
   - Pipeline #14 niet beschikbaar → abort met reden

4. **Success criteria bereikt:**
   - Alle P0/P1 findings opgelost
   - CI/Local parity ≥ 90% geverifieerd
   - Alle enterprise claims bewezen

### Exit Conditions

**GO (Production Ready):**
- ✅ Geen P0 findings
- ✅ < 3 P1 findings
- ✅ Parity ≥ 90%
- ✅ Coverage ≥ 80%
- ✅ Alle claims bewezen

**CONDITIONAL (Fix Required):**
- ⚠️ P1 findings aanwezig maar oplosbaar
- ⚠️ Parity 80-89%
- ⚠️ Document gaps met remediation plan

**NO-GO (Blockers):**
- ❌ P0 findings aanwezig
- ❌ Parity < 80%
- ❌ Coverage < 80%
- ❌ Claims zonder bewijs

### Loop Prevention Checklist

Bij elke iteratie, check:

- [ ] Nieuwe bevindingen sinds vorige iteratie?
- [ ] Tijd sinds start < 60 minuten?
- [ ] Pipeline bewijs beschikbaar?
- [ ] Success criteria dichterbij?

**Als 2+ vragen "nee":** → STOP en rapporteer huidige status

### Emergency Exit

Als de review vastloopt:

```bash
# Force stop background agents
mcp__woodpecker-ci__list_pipelines --repoId 25  # Check status
# Document huidige bevindingen
# Rapporteer partial results met "INCOMPLETE" status
```

**Rapporteer altijd:**
- Wat is geverifieerd ✅
- Wat is geblocked ❌
- Waarom gestopt (tijd/bewijs/loop)
- Next steps voor completion

---

## Appendix: Quick Reference

### Pipeline Verification Commands
```bash
# Get pipeline details
mcp__woodpecker-ci__get_pipeline --repoId 25 --number 14

# Get step logs
mcp__woodpecker-ci__get_step_logs --repoId 25 --number 14 --stepId <step_id>

# List all pipelines
mcp__woodpecker-ci__list_pipelines --repoId 25
```

### Local Security Scans
```bash
npm audit --audit-level=high
gitleaks protect --staged --verbose
semgrep --config=p/security-audit --config=p/typescript src/
```

### Coverage Check
```bash
npm run test:coverage
# Open coverage/lcov-report/index.html
```

### CI/Local Parity
```bash
npm run verify  # Should match all CI checks except SonarQube
```