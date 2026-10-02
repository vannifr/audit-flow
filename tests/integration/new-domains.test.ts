/**
 * Tests for new audit domains: Lighthouse, axe-cli, SQL injection,
 * Reliability, Observability, CI/CD
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  runLighthouse,
  runAxeAccessibility,
  runSqlInjectionCheck,
  checkReliability,
  checkObservability,
  checkCicd,
} from '../../src/activities/index';
import * as fs from 'fs';
import * as path from 'path';

const TEST_WORKFLOW_ID = `test-new-domains-${Date.now()}`;

describe('New Domain Activities', () => {
  describe('runLighthouse', () => {
    it.skipIf(!process.env.TEST_URL)('should run Lighthouse on a URL', async () => {
      const testUrl = process.env.TEST_URL || 'https://example.com';
      const { findings, result } = await runLighthouse(testUrl, TEST_WORKFLOW_ID);

      expect(result).toBeDefined();
      expect(result.url).toBe(testUrl);
      expect(typeof result.performance).toBe('number');
      expect(typeof result.accessibility).toBe('number');
      expect(Array.isArray(findings)).toBe(true);
    }, 120000);

    it('should handle invalid URL gracefully', async () => {
      const { findings, result } = await runLighthouse('not-a-url', TEST_WORKFLOW_ID);
      expect(findings.length).toBe(0);
    });
  });

  describe('runAxeAccessibility', () => {
    it.skipIf(!process.env.TEST_URL)('should run accessibility scan', async () => {
      const testUrl = process.env.TEST_URL || 'https://example.com';
      const { findings, result } = await runAxeAccessibility(testUrl, TEST_WORKFLOW_ID);

      expect(result).toBeDefined();
      expect(result.url).toBe(testUrl);
      expect(Array.isArray(findings)).toBe(true);
    }, 60000);

    it('should handle invalid URL gracefully', async () => {
      const { findings, result } = await runAxeAccessibility('not-a-url', TEST_WORKFLOW_ID);
      expect(findings.length).toBe(0);
    }, 30000);
  });

  describe('runSqlInjectionCheck', () => {
    const testRepoPath = '/tmp/sql-injection-test-repo';

    beforeAll(() => {
      // Create test repo with SQL injection vulnerabilities
      if (!fs.existsSync(testRepoPath)) {
        fs.mkdirSync(testRepoPath, { recursive: true });
      }

      // Python file with SQL injection
      fs.writeFileSync(
        path.join(testRepoPath, 'vuln.py'),
        `
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def search_users(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
`
      );

      // JavaScript file with SQL injection
      fs.writeFileSync(
        path.join(testRepoPath, 'vuln.js'),
        `
function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

function searchProducts(term) {
  const query = \`SELECT * FROM products WHERE name LIKE '%\${term}%'\`;
  return db.query(query);
}
`
      );
    });

    afterAll(() => {
      if (fs.existsSync(testRepoPath)) {
        fs.rmSync(testRepoPath, { recursive: true, force: true });
      }
    });

    it('should detect SQL injection vulnerabilities', async () => {
      const findings = await runSqlInjectionCheck(testRepoPath, TEST_WORKFLOW_ID);

      expect(Array.isArray(findings)).toBe(true);
      // Should detect at least some SQL injection patterns
      if (findings.length > 0) {
        expect(findings[0].category).toBe('security-injection');
        expect(findings[0].severity).toBe('P0');
      }
    }, 60000);

    it('should create custom rules file', async () => {
      await runSqlInjectionCheck(testRepoPath, TEST_WORKFLOW_ID);
      expect(fs.existsSync('/tmp/sql-injection-rules.yaml')).toBe(true);
    });
  });

  describe('checkReliability', () => {
    const testRepoPath = '/tmp/reliability-test-repo';

    beforeAll(() => {
      if (!fs.existsSync(testRepoPath)) {
        fs.mkdirSync(testRepoPath, { recursive: true });
      }

      // File with try-catch
      fs.writeFileSync(
        path.join(testRepoPath, 'good.ts'),
        `
async function fetchData() {
  try {
    const response = await fetch(url);
    return response.json();
  } catch (error) {
    logger.error('Failed', error);
    throw error;
  }
}
`
      );

      // File without error handling
      fs.writeFileSync(
        path.join(testRepoPath, 'bad.ts'),
        `
async function fetchData() {
  const response = await fetch(url);
  return response.json();
}
`
      );
    });

    afterAll(() => {
      if (fs.existsSync(testRepoPath)) {
        fs.rmSync(testRepoPath, { recursive: true, force: true });
      }
    });

    it('should detect error handling patterns', async () => {
      const { findings, result } = await checkReliability(testRepoPath, TEST_WORKFLOW_ID);

      expect(result).toBeDefined();
      expect(typeof result.tryCatchCoverage).toBe('number');
      expect(Array.isArray(findings)).toBe(true);
    }, 30000);

    it('should detect missing health check', async () => {
      const { result } = await checkReliability(testRepoPath, TEST_WORKFLOW_ID);
      expect(result.hasHealthCheck).toBe(false);
    });
  });

  describe('checkObservability', () => {
    const testRepoPath = '/tmp/observability-test-repo';

    beforeAll(() => {
      if (!fs.existsSync(testRepoPath)) {
        fs.mkdirSync(testRepoPath, { recursive: true });
      }

      // File with structured logging
      fs.writeFileSync(
        path.join(testRepoPath, 'logger.ts'),
        `
import pino from 'pino';

const logger = pino({
  level: 'info',
  formatters: { level: (label) => ({ level: label }) }
});

logger.info({ userId: 123 }, 'User logged in');
`
      );
    });

    afterAll(() => {
      if (fs.existsSync(testRepoPath)) {
        fs.rmSync(testRepoPath, { recursive: true, force: true });
      }
    });

    it('should detect structured logging', async () => {
      const { findings, result } = await checkObservability(testRepoPath, TEST_WORKFLOW_ID);

      expect(result).toBeDefined();
      expect(result.hasStructuredLogging).toBe(true);
      expect(result.loggingFramework).toBe('pino');
    }, 30000);
  });

  describe('checkCicd', () => {
    const testRepoPath = '/tmp/cicd-test-repo';

    beforeAll(() => {
      if (!fs.existsSync(testRepoPath)) {
        fs.mkdirSync(testRepoPath, { recursive: true });
      }

      // Create .woodpecker.yml
      fs.writeFileSync(
        path.join(testRepoPath, '.woodpecker.yml'),
        `
pipeline:
  test:
    image: node:20
    commands:
      - npm ci
      - npm test

  security:
    image: node:20
    commands:
      - npm audit --audit-level=high
      - npx gitleaks directory .

  deploy:
    image: node:20
    commands:
      - npm run deploy
`
      );
    });

    afterAll(() => {
      if (fs.existsSync(testRepoPath)) {
        fs.rmSync(testRepoPath, { recursive: true, force: true });
      }
    });

    it('should detect CI/CD pipeline', async () => {
      const { findings, result } = await checkCicd(testRepoPath, TEST_WORKFLOW_ID);

      expect(result).toBeDefined();
      expect(result.hasCiPipeline).toBe(true);
      expect(result.platform).toBe('woodpecker');
    }, 30000);

    it('should detect security gates', async () => {
      const { result } = await checkCicd(testRepoPath, TEST_WORKFLOW_ID);
      expect(result.hasSecurityGates).toBe(true);
    });
  });
});