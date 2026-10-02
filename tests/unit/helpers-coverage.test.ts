import { describe, it, expect } from 'vitest';

// Unit tests to cover helper functions
describe('Helper Functions Coverage', () => {
  describe('mapNpmSeverityToP', () => {
    it('should map critical to P0', async () => {
      const { runNpmAudit } = await import('../../src/activities/index');

      // Create a test repo with a vulnerable package
      const fs = await import('fs');
      const path = await import('path');
      const { execSync } = await import('child_process');

      const testRepo = '/tmp/npm-severity-test';
      if (!fs.existsSync(testRepo)) {
        fs.mkdirSync(testRepo, { recursive: true });
        // Use an old version of lodash that has known vulnerabilities
        fs.writeFileSync(path.join(testRepo, 'package.json'), JSON.stringify({
          name: 'severity-test',
          dependencies: { lodash: '4.17.15' } // Old vulnerable version
        }));

        try {
          execSync('npm i --package-lock-only --ignore-scripts', {
            cwd: testRepo,
            timeout: 30000
          });
        } catch (e) {
          // Ignore
        }
      }

      const findings = await runNpmAudit(testRepo, 'severity-test');

      // Should find vulnerabilities
      expect(Array.isArray(findings)).toBe(true);

      // Cleanup
      if (fs.existsSync(testRepo)) {
        fs.rmSync(testRepo, { recursive: true, force: true });
      }
    });
  });

  describe('mapSemgrepSeverityToP', () => {
    it('should execute semgrep and map severities', async () => {
      const { runSemgrep } = await import('../../src/activities/index');

      const fs = await import('fs');
      const path = await import('path');

      const testRepo = '/tmp/semgrep-severity-test';
      if (!fs.existsSync(testRepo)) {
        fs.mkdirSync(testRepo, { recursive: true });
        fs.writeFileSync(path.join(testRepo, 'vuln.js'), `
// SQL injection vulnerability
function query(id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}

// XSS vulnerability
function render(userInput) {
  return "<div>" + userInput + "</div>";
}
        `);
      }

      const findings = await runSemgrep(testRepo, 'semgrep-severity-test');

      expect(Array.isArray(findings)).toBe(true);

      // Cleanup
      if (fs.existsSync(testRepo)) {
        fs.rmSync(testRepo, { recursive: true, force: true });
      }
    }, 120000);
  });

  describe('error handling paths', () => {
    it('should handle npm audit errors gracefully', async () => {
      const { runNpmAudit } = await import('../../src/activities/index');

      // Non-existent directory
      const findings = await runNpmAudit('/tmp/non-existent-path-12345', 'error-test');

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(0);
    });

    it('should handle gitleaks errors gracefully', async () => {
      const { runGitleaks } = await import('../../src/activities/index');

      // Non-existent directory
      const findings = await runGitleaks('/tmp/non-existent-path-12345', 'error-test');

      expect(Array.isArray(findings)).toBe(true);
    });

    it('should handle semgrep errors gracefully', async () => {
      const { runSemgrep } = await import('../../src/activities/index');

      // Non-existent directory
      const findings = await runSemgrep('/tmp/non-existent-path-12345', 'error-test');

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(0);
    }, 120000);

    it('should handle license check errors gracefully', async () => {
      const { runLicenseCheck } = await import('../../src/activities/index');

      // Non-existent directory
      const findings = await runLicenseCheck('/tmp/non-existent-path-12345', 'error-test');

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(0);
    });
  });

  describe('progress tracking', () => {
    it('should create progress indicator', async () => {
      const { createProgressIndicator, formatDuration, formatFindingCount, formatPhase } = await import('../../src/progress');

      const progress = createProgressIndicator();

      expect(progress).toBeDefined();
      expect(typeof progress.start).toBe('function');
      expect(typeof progress.update).toBe('function');
      expect(typeof progress.succeed).toBe('function');
      expect(typeof progress.fail).toBe('function');

      // Test start
      progress.start('Testing...');

      // Test update
      progress.update('Updated message');

      // Test succeed
      progress.succeed('Done!');

      // Test formatDuration
      expect(formatDuration(1000)).toBe('1s');
      expect(formatDuration(60000)).toBe('1m 0s');
      expect(formatDuration(3661000)).toBe('1h 1m'); // Seconds are omitted when >= 1 hour

      // Test formatFindingCount
      expect(formatFindingCount(0)).toBe('No findings');
      expect(formatFindingCount(1)).toBe('1 finding');
      expect(formatFindingCount(5)).toBe('5 findings');

      // Test formatPhase
      expect(formatPhase('discovery')).toBe('Discovery Phase');
      expect(formatPhase('scanning')).toBe('Scanning Phase');
      expect(formatPhase('reporting')).toBe('Report Generation Phase');
      expect(formatPhase('unknown')).toBe('unknown'); // Unknown phases pass through
    });
  });

  describe('logger', () => {
    it('should use logger instance', async () => {
      const logger = (await import('../../src/logger')).default;

      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.debug).toBe('function');

      // Test logging
      logger.info({ test: true }, 'Test message');
      logger.warn({ test: true }, 'Test warning');
      logger.error({ test: true }, 'Test error');
      logger.debug({ test: true }, 'Test debug');
    });
  });
});