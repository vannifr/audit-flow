# Review Instructies — Audit Flow

**Project:** audit-flow
**Repository:** https://github.com/vannifr/audit-flow
**CI:** https://ci.vannifr.ovh/repos/25
**Datum:** 2026-10-02
**Reviewer:** qwen3-max-2026-01-23 (onafhankelijke review)

---

## Doel

Een onafhankelijke review van de volledige codebase, CI/CD setup, en enterprise-grade status om:
1. Bevindingen te identificeren (security, quality, architecture)
2. CI/Local parity te valideren
3. Enterprise gaps te verifiëren
4. Aanbevelingen voor verbetering te geven

---

## Review Scope

### 1. Codebase Review

**Bestanden om te reviewen:**

| Categorie | Bestanden | Focus |
|-----------|-----------|-------|
| **Core workflows** | `src/workflows/index.ts` | Workflow definitie, signal handling, error handling |
| **Activities** | `src/activities/index.ts` (716 regels) | Security validatie, tool integratie, error handling |
| **Client** | `src/client.ts` | API correctheid, type safety |
| **Config** | `src/config/audit-domains.ts` | Domain coverage, compliance mapping |
| **Security** | `src/activities/index.ts` (validateRepoUrl, etc.) | Command injection prevention, input validation |
| **Logging** | `src/logger.ts` | Structured logging, Pino usage |
| **Errors** | `src/errors.ts` | ApplicationFailure patterns |

**Review criteria:**
- [ ] Security: Input validatie, command injection preventie, secrets handling
- [ ] Error handling: try-catch coverage, ApplicationFailure usage
- [ ] Type safety: TypeScript strict mode, any usage
- [ ] Code quality: DRY, SOLID principles, complexity
- [ ] Testing: Coverage 80%+, meaningful assertions

---

### 2. CI/CD Review

**Bestanden om te reviewen:**

| Bestand | Focus |
|---------|-------|
| `.woodpecker.yml` | YAML syntax, step ordering, blocking vs ignore |
| `vitest.config.ts` | Coverage thresholds (80%), reporter config |
| `sonar-project.properties` | SonarQube config, coverage paths |
| `.gitleaksignore` | False positives legitimering |
| `.githooks/pre-commit` | Local verify coverage |
| `.githooks/pre-push` | Gitleaks integration |

**Review vragen:**
- [ ] Dekt `npm run verify` alles wat CI checkt?
- [ ] Zijn alle security stappen blocking (behalve devDependencies)?
- [ ] Zijn secrets correct geconfigureerd (globale secrets)?
- [ ] Is SonarQube quality gate actief?
- [ ] Is gitleaks diff-scoped (niet full-history)?

---

### 3. Enterprise Gaps Review

**Te verifiëren claims uit ENTERPRISE-STATUS.md:**

| Claim | Bewijs vereist |
|-------|----------------|
| Coverage 80% | Vitest output: `npm run test:coverage` |
| SonarQube quality gate | Pipeline #14 logs: sonarqube step |
| Gitleaks blocking | Pipeline #14 logs: secrets-scan step |
| SAST blocking | Pipeline #14 logs: sast step |
| License check blocking | Pipeline #14 logs: license-check step |
| CI/Local parity | `.githooks/` vs `.woodpecker.yml` |
| 95% enterprise score | Audit tegen enterprise framework |

**Te documenteren:**
- [ ] Per claim: pipeline nummer + step output als bewijs
- [ ] Gaps die nog open staan (P2/P3)
- [ ] False positives in gitleaksignore: zijn ze legitiem?

---

### 4. Security Audit

**Te controleren:**

| Aspect | Locatie | Check |
|--------|---------|-------|
| Command injection | `src/activities/index.ts` | `validateRepoUrl` regex, `execFileSync` usage |
| Secrets in code | Alle bestanden | Geen hardcoded secrets |
| SQL injection | `src/activities/index.ts` | Semgrep custom rules |
| Input validation | Alle activities | Parameter validation |
| Error exposure | `src/errors.ts` | Geen sensitive data in errors |
| Dependencies | `package.json` | `npm audit --audit-level=high` |

---

### 5. Testing Review

**Te controleren:**

| Aspect | Bestanden | Check |
|--------|-----------|-------|
| Unit tests | `tests/unit/*.test.ts` | Coverage, meaningful assertions |
| Integration tests | `tests/integration/*.test.ts` | Real tool usage, error handling |
| BDD tests | `specs/*/tests/step_definitions/*.steps.ts` | Gherkin coverage |
| Test fixtures | `scripts/test-audit-run.ts` | Geen echte secrets |

---

## Review Proces

### Stap 1: Lees de documentatie
```bash
cd /home/vannifr/projects/audit-flow
cat ENTERPRISE-STATUS.md
cat README.md
cat CONSTITUTION.md
```

### Stap 2: Review de codebase
```bash
# Security review
grep -r "execSync\|execAsync" src/
grep -r "child_process" src/
grep -r "validateRepoUrl" src/

# Type safety review
grep -r ": any" src/
grep -r "@ts-ignore" src/
```

### Stap 3: Verifieer CI/Local parity
```bash
# Check of verify command bestaat
npm run verify

# Check git hooks
cat .githooks/pre-commit
cat .githooks/pre-push

# Vergelijk met CI
diff <(grep -A 5 "commands:" .woodpecker.yml) <(cat .githooks/pre-commit)
```

### Stap 4: Check pipeline bewijs
```bash
# Via MCP tools:
mcp__woodpecker-ci__get_pipeline --repoId 25 --number 14
mcp__woodpecker-ci__get_step_logs --repoId 25 --number 14 --stepId <step_id>
```

### Stap 5: Security scan lokaal
```bash
npm audit --audit-level=high
gitleaks directory --verbose .
semgrep --config=p/security-audit --config=p/typescript .
```

---

## Output Format

De reviewer moet een rapport produceren met:

### 1. Executive Summary
- Overall assessment (Pass/Fail/Conditional)
- Critical findings count (P0/P1)
- Enterprise score bevestiging

### 2. Bevindingen per categorie

```markdown
## Security
| ID | Finding | Severity | Locatie | Aanbeveling |
|----|---------|----------|---------|-------------|
| S01 | ... | P0/P1/P2 | file:line | ... |

## Quality
| ID | Finding | Severity | Locatie | Aanbeveling |
|----|---------|----------|---------|-------------|

## CI/CD
| ID | Finding | Severity | Stap | Aanbeveling |
|----|---------|----------|------|-------------|
```

### 3. CI/Local Parity Matrix

| CI Stap | Local Command | Dekking | Gap |
|---------|---------------|---------|-----|
| build | `npm run build` | ✅ | - |
| test | `npm run test:coverage` | ✅ | - |
| lint | `npm run lint` | ✅ | - |
| sonarqube | ❌ geen local | ⚠️ | Documented gap |
| ... | ... | ... | ... |

### 4. Enterprise Gaps Status

| Gap | Status | Bewijs |
|-----|--------|--------|
| Coverage < 80% | ✅ Resolved | Pipeline #14: test step |
| ... | ... | ... |

### 5. Aanbevelingen

1. **Critical (P0):** Must fix before production
2. **High (P1):** Should fix in next sprint
3. **Medium (P2):** Plan for Phase 2
4. **Low (P3):** Nice to have

---

## Success Criteria

De review slaagt als:

- [ ] Geen P0 security findings
- [ ] < 3 P1 findings
- [ ] CI/Local parity > 90%
- [ ] Enterprise score bevestigd (95%)
- [ ] Alle claims ondersteund door bewijs

---

## Context voor de reviewer

Dit project is gebouwd met:
- **IIKit governance** (CONSTITUTION.md, spec-driven development)
- **Temporal.io** workflow orchestration
- **Woodpecker CI** (self-hosted op ci.vannifr.ovh)
- **Lokale SonarQube** (http://sonarqube:9000)

De developer is een solo developer met trading bot achtergrond. Correctheid en security zijn cruciaal.

---

## Start de review

Gebruik de `review` agent met `qwen3-max-2026-01-23` model voor onafhankelijke review:

```
/review --effort high --topology minimal
```

Of gebruik een fork met deze instructies als prompt.