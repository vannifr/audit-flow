# Test Strategy: src/activities/index.ts

**Doel:** Complete test blueprint voor alle 28 exported functions in activities layer  
**Priority:** Security-first aanpak, enterprise claims verificatie  
**Target coverage:** 80% overall, 90% voor P0 security functies

---

## P0 - Security Critical (5 functies, ~400 regels)

### 1. validateRepoUrl()
**Regels:** 101-118 (18 regels)  
**Doel:** Voorkom command injection via repository URL  
**Enterprise claim:** Security scanning (SAST, secrets)

**Test cases:**
- ✅ Valid GitHub HTTPS URLs
  - `https://github.com/owner/repo`
  - `https://github.com/owner/repo.git`
  - `https://github.com/my-org/my-repo-name`
- ❌ Non-GitHub URLs
  - `https://gitlab.com/owner/repo`
  - `https://bitbucket.org/owner/repo`
- ❌ HTTP (non-HTTPS) URLs
  - `http://github.com/owner/repo`
- ❌ SSH URLs
  - `git@github.com:owner/repo.git`
- ❌ Command injection attempts
  - `https://github.com/owner/repo;rm -rf /`
  - `https://github.com/owner/repo|cat /etc/passwd`
  - `https://github.com/owner/repo&whoami`
  - `https://github.com/owner/repo\`id\``
  - `https://github.com/owner/repo${PATH}`
- ❌ Path traversal
  - `https://github.com/owner/../../../etc/passwd`
- ❌ File protocol
  - `file:///etc/passwd`
- ❌ Edge cases
  - Empty string
  - URL met query parameters
  - Very long URLs (> 200 chars)

**Expected coverage:** +2%  
**Bestaande tests:** ✅ 9 tests in activities-coverage.test.ts

---

### 2. runNpmAudit()
**Regels:** 330-385 (56 regels)  
**Doel:** Parse npm audit output, map severity naar P0-P3  
**Enterprise claim:** Dependency audit (blocking in CI)

**Test cases:**
- ✅ Parse valid JSON output
  - Single vulnerability
  - Multiple vulnerabilities
  - Mixed severity levels
- ✅ Map severity correctly
  - critical → P0
  - high → P1
  - moderate → P2
  - low → P3
- ✅ Handle no vulnerabilities
  - Empty vulnerabilities object
- ❌ Error handling
  - Invalid JSON output
  - npm not installed
  - Command timeout
  - Non-existent directory
- ❌ Edge cases
  - Large dependency trees (> 1000 deps)
  - Nested vulnerabilities
  - Vulnerabilities met advisories

**Expected coverage:** +3%  
**Bestaande tests:** ⚠️ 1 test faalt (should parse npm audit results)

---

### 3. runGitleaks()
**Regels:** 387-452 (66 regels)  
**Doel:** Detecteer hardcoded secrets in code  
**Enterprise claim:** Secrets scanning (blocking in CI)

**Test cases:**
- ✅ Parse valid gitleaks JSON output
  - Single secret finding
  - Multiple secrets
  - Different secret types (AWS, GitHub, etc.)
- ✅ Classify severity as P0
  - All secrets are P0 (critical)
- ✅ Handle no secrets found
  - Empty array
- ❌ Error handling
  - Invalid JSON output
  - gitleaks not installed
  - Command timeout
  - Non-existent directory
- ❌ Edge cases
  - Secrets in binary files
  - Secrets in comments
  - False positives (test data)

**Expected coverage:** +3%  
**Bestaande tests:** ⚠️ 1 test faalt (should handle gitleaks errors)

---

### 4. runSemgrep()
**Regels:** 454-520 (67 regels)  
**Doel:** SAST scan voor security vulnerabilities  
**Enterprise claim:** SAST scanning (blocking in CI)

**Test cases:**
- ✅ Parse valid semgrep JSON output
  - Single finding
  - Multiple findings
  - Different check_ids (sql-injection, xss, etc.)
- ✅ Map severity correctly
  - ERROR → P1
  - WARNING → P2
  - INFO → P3
- ✅ Handle no findings
  - Empty results array
- ❌ Error handling
  - Invalid JSON output
  - semgrep not installed
  - Command timeout
  - Non-existent directory
  - Invalid rules file
- ❌ Edge cases
  - Large codebases (> 100 files)
  - Custom rules
  - Multiple languages

**Expected coverage:** +3%  
**Bestaande tests:** ⚠️ 1 test faalt (should parse semgrep results)

---

### 5. runLicenseCheck()
**Regels:** 522-595 (74 regels)  
**Doel:** Detecteer GPL/AGPL license violations  
**Enterprise claim:** License compliance (blocking in CI)

**Test cases:**
- ✅ Parse valid license-checker JSON output
  - Single package
  - Multiple packages
  - Different license types
- ✅ Detect GPL violations
  - GPL-3.0 → P2
  - AGPL-3.0 → P2
  - SSPL-1.0 → P2
- ✅ Allow permissive licenses
  - MIT, Apache-2.0, BSD-3-Clause
- ❌ Error handling
  - Invalid JSON output
  - license-checker not installed
  - Command timeout
  - Non-existent directory
- ❌ Edge cases
  - Dual-licensed packages (MIT OR Apache-2.0)
  - Unknown licenses
  - Scoped packages (@org/package)

**Expected coverage:** +3%  
**Bestaande tests:** ⚠️ 1 test faalt (should detect GPL license violation)

---

## P1 - Business Logic (8 functies, ~600 regels)

### 6. cloneRepository()
**Regels:** 121-165 (45 regels)  
**Doel:** Clone git repository met validatie  
**Enterprise claim:** Workflow correctness

**Test cases:**
- ✅ Clone valid repository
  - HTTPS URL
  - Specific branch
  - With cleanup
- ❌ Error handling
  - Invalid URL (fails validateRepoUrl)
  - Network timeout
  - Repository not found
  - Permission denied
- ❌ Edge cases
  - Large repositories (> 1GB)
  - Shallow clone
  - Existing directory

**Expected coverage:** +2%  
**Bestaande tests:** ⚠️ 1 test faalt (should clone repository successfully)

---

### 7. detectTechStack()
**Regels:** 167-277 (111 regels)  
**Doel:** Detecteer taal, frameworks, dependencies  
**Enterprise claim:** Audit scope bepaling

**Test cases:**
- ✅ Detect Node.js projects
  - package.json present
  - Detect frameworks (Express, Next.js, React)
  - Detect package manager (npm, yarn, pnpm)
- ✅ Detect Python projects
  - requirements.txt present
  - Detect frameworks (Django, Flask)
- ✅ Detect databases
  - Prisma (PostgreSQL)
  - MongoDB
  - SQLite
- ✅ Detect payments integration
  - Stripe, PayPal
- ✅ Detect PII handling
  - GDPR keywords
- ❌ Error handling
  - Empty directory
  - No package.json
  - Invalid JSON in package.json
- ❌ Edge cases
  - Monorepo structure
  - Multiple package.json files
  - Workspace dependencies

**Expected coverage:** +4%  
**Bestaande tests:** ✅ 8 tests in activities.test.ts

---

### 8. generateScopeDocument()
**Regels:** 279-328 (50 regels)  
**Doel:** Genereer audit scope document  
**Enterprise claim:** Audit rapportage

**Test cases:**
- ✅ Generate valid scope document
  - With tech stack
  - With compliance map
  - With critical paths
- ✅ Format as JSON
  - Valid JSON structure
  - All required fields
- ❌ Error handling
  - Invalid tech stack
  - Missing required fields
- ❌ Edge cases
  - Large scope (> 100 files)
  - Multiple compliance frameworks

**Expected coverage:** +2%  
**Bestaande tests:** ❌ Geen tests

---

### 9. generateReport()
**Regels:** 763-839 (77 regels)  
**Doel:** Genereer audit rapport in Markdown  
**Enterprise claim:** Audit deliverable

**Test cases:**
- ✅ Generate valid report
  - With findings
  - With evidence
  - With remediation
- ✅ Format as Markdown
  - Headers, lists, code blocks
  - Finding severity badges
- ✅ Include all sections
  - Executive summary
  - Findings per category
  - Recommendations
- ❌ Error handling
  - No findings
  - Invalid findings structure
- ❌ Edge cases
  - Large number of findings (> 100)
  - Findings without evidence

**Expected coverage:** +3%  
**Bestaande tests:** ❌ Geen tests

---

### 10. reviewCriticalPaths()
**Regels:** 597-691 (95 regels)  
**Doel:** Review auth, login, payment, session code  
**Enterprise claim:** Security review

**Test cases:**
- ✅ Find matching files
  - auth, login, password, session, token
  - Recursive search
- ✅ Apply review checklist
  - OWASP-Top-10
  - Custom checklist
- ✅ Generate findings
  - Missing validation
  - Insecure patterns
- ❌ Error handling
  - No matching files
  - Invalid checklist
- ❌ Edge cases
  - Large codebases
  - Minified files

**Expected coverage:** +3%  
**Bestaande tests:** ❌ Geen tests

---

### 11. cleanup()
**Regels:** 841-891 (51 regels)  
**Doel:** Cleanup tijdelijke repository directories  
**Enterprise claim:** Resource management

**Test cases:**
- ✅ Cleanup existing directory
  - Remove files recursively
  - Handle nested directories
- ✅ Handle non-existent directory
  - No error thrown
- ❌ Error handling
  - Permission denied
  - Directory in use
- ❌ Edge cases
  - Very large directories
  - Symbolic links

**Expected coverage:** +2%  
**Bestaande tests:** ⚠️ 1 test faalt (should cleanup repository directory)

---

### 12. checkToolRequirements()
**Regels:** 52-81 (30 regels)  
**Doel:** Check welke audit tools geïnstalleerd zijn  
**Enterprise claim:** Tool availability

**Test cases:**
- ✅ Detect installed tools
  - npm, git (required)
  - gitleaks, semgrep (optional)
- ✅ Detect missing tools
  - Tool not in PATH
  - Version check
- ✅ Return tool status
  - name, installed, version, required
- ❌ Error handling
  - Command execution fails
  - Version parse error
- ❌ Edge cases
  - Multiple versions installed
  - Aliased commands

**Expected coverage:** +1%  
**Bestaande tests:** ❌ Geen tests

---

### 13. getMissingRequiredTools()
**Regels:** 83-88 (6 regels)  
**Doel:** Filter missing required tools  
**Enterprise claim:** Tool validation

**Test cases:**
- ✅ Filter required tools
  - Only required: true
  - Only installed: false
- ✅ Return empty array
  - All required tools installed
- ❌ Edge cases
  - Empty status array

**Expected coverage:** +0.5%  
**Bestaande tests:** ❌ Geen tests

---

### 14. getMissingOptionalTools()
**Regels:** 90-95 (6 regels)  
**Doel:** Filter missing optional tools  
**Enterprise claim:** Tool recommendations

**Test cases:**
- ✅ Filter optional tools
  - Only required: false
  - Only installed: false
- ✅ Return empty array
  - All optional tools installed
- ❌ Edge cases
  - Empty status array

**Expected coverage:** +0.5%  
**Bestaande tests:** ❌ Geen tests

---

## P2 - Quality Checks (10 functies, ~1000 regels)

### 15. runLighthouse()
**Regels:** 893-1019 (127 regels)  
**Doel:** Performance audit (LCP, FID, CLS)  
**Enterprise claim:** Performance NFR

**Test cases:**
- ✅ Parse Lighthouse JSON output
  - Performance score
  - Core Web Vitals (LCP, FID, CLS)
- ✅ Generate findings
  - Poor performance (< 50)
  - Needs improvement (50-90)
  - Good performance (> 90)
- ❌ Error handling
  - Invalid URL
  - Lighthouse not installed
  - Command timeout
- ❌ Edge cases
  - SPA with client-side routing
  - Authenticated pages

**Expected coverage:** +4%  
**Bestaande tests:** ❌ Geen tests

---

### 16. runAxeAccessibility()
**Regels:** 1021-1092 (72 regels)  
**Doel:** Accessibility audit (WCAG 2.1)  
**Enterprise claim:** Accessibility NFR

**Test cases:**
- ✅ Parse axe JSON output
  - Violations
  - Incomplete checks
- ✅ Map severity
  - Critical → P1
  - Serious → P2
  - Moderate → P3
- ❌ Error handling
  - Invalid URL
  - axe not installed
  - Command timeout
- ❌ Edge cases
  - Dynamic content
  - iframe content

**Expected coverage:** +3%  
**Bestaande tests:** ❌ Geen tests

---

### 17. runSqlInjectionCheck()
**Regels:** 1094-1195 (102 regels)  
**Doel:** SQL injection detection  
**Enterprise claim:** Security scanning

**Test cases:**
- ✅ Detect SQL injection patterns
  - String concatenation
  - exec/query met user input
- ✅ Parse semgrep output
  - SQL injection findings
- ✅ Generate findings
  - Severity based on context
- ❌ Error handling
  - semgrep not installed
  - Command timeout
- ❌ Edge cases
  - Parameterized queries (false positive)
  - ORM usage

**Expected coverage:** +3%  
**Bestaande tests:** ❌ Geen tests

---

### 18. checkReliability()
**Regels:** 1197-1363 (167 regels)  
**Doel:** Check reliability patterns  
**Enterprise claim:** Reliability NFR

**Test cases:**
- ✅ Detect error handling
  - try-catch blocks
  - Error boundaries
- ✅ Detect retry logic
  - Exponential backoff
  - Circuit breakers
- ✅ Detect health checks
  - /health endpoint
  - Readiness probes
- ✅ Generate findings
  - Missing error handling
  - No retry logic
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Monorepo structure
  - Microservices

**Expected coverage:** +5%  
**Bestaande tests:** ❌ Geen tests

---

### 19. checkObservability()
**Regels:** 1365-1505 (141 regels)  
**Doel:** Check logging, metrics, tracing  
**Enterprise claim:** Observability NFR

**Test cases:**
- ✅ Detect structured logging
  - Pino, Winston, Bunyan
- ✅ Detect metrics
  - Prometheus, StatsD
- ✅ Detect tracing
  - OpenTelemetry, Jaeger
- ✅ Detect alerting
  - PagerDuty, OpsGenie
- ✅ Generate findings
  - Missing structured logging
  - No metrics
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Custom logging
  - Cloud-native observability

**Expected coverage:** +5%  
**Bestaande tests:** ❌ Geen tests

---

### 20. checkCicd()
**Regels:** 1507-1640 (134 regels)  
**Doel:** Check CI/CD pipeline configuration  
**Enterprise claim:** CI/CD NFR

**Test cases:**
- ✅ Detect CI/CD files
  - .woodpecker.yml, .github/workflows
  - Jenkinsfile, .gitlab-ci.yml
- ✅ Detect pipeline stages
  - build, test, deploy
  - Security gates
- ✅ Detect quality gates
  - Coverage thresholds
  - Linting
- ✅ Generate findings
  - Missing security gates
  - No quality checks
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Multiple CI systems
  - Monorepo pipelines

**Expected coverage:** +4%  
**Bestaande tests:** ❌ Geen tests

---

### 21. waitForHumanApproval()
**Regels:** 1642-1669 (28 regels)  
**Doel:** Wait for human approval signal  
**Enterprise claim:** Workflow control

**Test cases:**
- ✅ Wait for signal
  - Approval received
  - Rejection received
- ✅ Return approval status
  - approved: true/false
- ❌ Error handling
  - Signal timeout
  - Invalid signal
- ❌ Edge cases
  - Multiple approval requests

**Expected coverage:** +1%  
**Bestaande tests:** ❌ Geen tests

---

### 22. checkCodeQuality()
**Regels:** 1671-1848 (178 regels)  
**Doel:** Check code quality metrics  
**Enterprise claim:** Code quality NFR

**Test cases:**
- ✅ Detect linting
  - ESLint, Prettier
- ✅ Detect type safety
  - TypeScript strict mode
- ✅ Detect complexity
  - Cyclomatic complexity
  - Function length
- ✅ Generate findings
  - High complexity
  - Missing type safety
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Mixed JS/TS
  - Legacy code

**Expected coverage:** +5%  
**Bestaande tests:** ❌ Geen tests

---

### 23. checkDocumentation()
**Regels:** 1850-1980 (131 regels)  
**Doel:** Check documentation completeness  
**Enterprise claim:** Documentation NFR

**Test cases:**
- ✅ Detect README
  - README.md present
  - Installation instructions
- ✅ Detect API docs
  - OpenAPI/Swagger
  - JSDoc comments
- ✅ Detect operational docs
  - Deployment guide
  - Runbooks
- ✅ Generate findings
  - Missing README
  - No API docs
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Monorepo structure
  - Generated docs

**Expected coverage:** +4%  
**Bestaande tests:** ❌ Geen tests

---

### 24. checkPrivacy()
**Regels:** 1982-2093 (112 regels)  
**Doel:** Check GDPR/privacy compliance  
**Enterprise claim:** Privacy NFR

**Test cases:**
- ✅ Detect PII handling
  - Personal data fields
  - Encryption at rest
- ✅ Detect consent management
  - Cookie consent
  - Privacy policy
- ✅ Detect data retention
  - Retention policies
  - Deletion procedures
- ✅ Generate findings
  - Missing encryption
  - No consent management
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Third-party integrations
  - Data exports

**Expected coverage:** +4%  
**Bestaande tests:** ❌ Geen tests

---

## P3 - Compliance & Advanced (5 functies, ~800 regels)

### 25. mapToCompliance()
**Regels:** 693-741 (49 regels)  
**Doel:** Map findings naar compliance frameworks  
**Enterprise claim:** Compliance reporting

**Test cases:**
- ✅ Map to frameworks
  - OWASP-Top-10
  - SOC2
  - ISO27001
- ✅ Load controls
  - Framework-specific controls
- ✅ Generate compliance matrix
  - Finding → Control mapping
- ❌ Error handling
  - Invalid framework
  - Missing controls file
- ❌ Edge cases
  - Multiple frameworks
  - Custom controls

**Expected coverage:** +2%  
**Bestaande tests:** ❌ Geen tests

---

### 26. crossValidate()
**Regels:** 743-761 (19 regels)  
**Doel:** Cross-validate findings met AI model  
**Enterprise claim:** AI-assisted review

**Test cases:**
- ✅ Call AI model
  - qwen3-max
  - Findings als input
- ✅ Parse validation result
  - Confirmed findings
  - False positives
- ❌ Error handling
  - AI model unavailable
  - Invalid response
- ❌ Edge cases
  - Large number of findings
  - Rate limiting

**Expected coverage:** +1%  
**Bestaande tests:** ❌ Geen tests

---

### 27. checkFunctionalRequirements()
**Regels:** 2095-2225 (131 regels)  
**Doel:** Check business logic correctness  
**Enterprise claim:** Functional audit

**Test cases:**
- ✅ Detect business logic
  - API endpoints
  - Database operations
- ✅ Detect state management
  - State machines
  - Event sourcing
- ✅ Detect reporting
  - Analytics
  - Dashboards
- ✅ Generate findings
  - Missing validation
  - No error handling
- ❌ Error handling
  - Invalid directory
- ❌ Edge cases
  - Microservices
  - Event-driven architecture

**Expected coverage:** +4%  
**Bestaande tests:** ❌ Geen tests

---

### 28. checkBlindSpots()
**Regels:** 2227-2400 (174 regels)  
**Doel:** Detect organizational blind spots  
**Enterprise claim:** Comprehensive audit

**Test cases:**
- ✅ Detect bus factor
  - Git contributors
  - Code ownership
- ✅ Detect on-call procedures
  - ONCALL.md, docs/on-call
- ✅ Detect exit strategy
  - Data export
  - Vendor exit
- ✅ Generate findings
  - Low bus factor
  - No on-call docs
- ❌ Error handling
  - Invalid directory
  - Git not available
- ❌ Edge cases
  - Single developer
  - Open source project

**Expected coverage:** +5%  
**Bestaande tests:** ❌ Geen tests

---

## Summary

| Priority | Functies | Regels | Expected Coverage | Bestaande Tests |
|----------|----------|--------|-------------------|-----------------|
| **P0** | 5 | ~400 | +14% | 9 tests (5 falen) |
| **P1** | 8 | ~600 | +16% | 8 tests |
| **P2** | 10 | ~1000 | +33% | 0 tests |
| **P3** | 5 | ~800 | +12% | 0 tests |
| **Totaal** | **28** | **~2800** | **+75%** | **17 tests** |

**Current coverage:** 48%  
**Target coverage:** 80%  
**Gap:** +32% (mainly P2 functions)

---

## Implementation Plan

### Phase 1: Fix Failing Tests (15 min)
1. Fix 5 falende tests in activities-coverage.test.ts
2. Verify coverage report generates correctly
3. **Doel:** 100% pass rate, baseline coverage visible

### Phase 2: P0 Security Tests (30 min)
1. Verbeter bestaande P0 tests
2. Voeg edge cases toe
3. **Doel:** 90% coverage op P0 functies

### Phase 3: P1 Business Logic Tests (45 min)
1. Nieuwe tests voor generateScopeDocument, generateReport
2. Verbeter bestaande detectTechStack tests
3. **Doel:** 80% coverage op P1 functies

### Phase 4: P2 Quality Tests (60 min)
1. Nieuwe tests voor reliability, observability, cicd
2. Focus op NFR verificatie
3. **Doel:** 70% coverage op P2 functies

### Phase 5: P3 Compliance Tests (30 min)
1. Nieuwe tests voor compliance mapping
2. Focus op audit reporting
3. **Doel:** 60% coverage op P3 functies

**Total time:** ~3 hours  
**Expected result:** 80%+ overall coverage
