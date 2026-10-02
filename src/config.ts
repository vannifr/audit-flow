import { ApplicationFailure } from '@temporalio/activity';
import logger from './logger';

export interface Config {
  temporal: {
    address: string;
    namespace: string;
    taskQueue: string;
  };
  logging: {
    level: string;
    nodeEnv: string;
  };
  security: {
    githubToken?: string;
    allowedOrgs: string[];
  };
  output: {
    outputDir: string;
  };
  external?: {
    semgrepApiKey?: string;
    snykToken?: string;
  };
}

function parseAllowedOrgs(): string[] {
  const orgsStr = process.env.ALLOWED_ORGS || '';
  if (!orgsStr) return [];
  return orgsStr.split(',').map(org => org.trim()).filter(Boolean);
}

export function loadConfig(): Config {
  const config: Config = {
    temporal: {
      address: process.env.TEMPORAL_ADDRESS || 'localhost:7233',
      namespace: process.env.TEMPORAL_NAMESPACE || 'default',
      taskQueue: process.env.TEMPORAL_TASK_QUEUE || 'audit',
    },
    logging: {
      level: process.env.LOG_LEVEL || 'info',
      nodeEnv: process.env.NODE_ENV || 'development',
    },
    security: {
      githubToken: process.env.GITHUB_TOKEN,
      allowedOrgs: parseAllowedOrgs(),
    },
    output: {
      outputDir: process.env.OUTPUT_DIR || './audit-reports',
    },
    external: {
      semgrepApiKey: process.env.SEMGREP_API_KEY,
      snykToken: process.env.SNYK_TOKEN,
    },
  };

  // Validate critical configuration
  if (!config.temporal.address) {
    throw ApplicationFailure.create({
      message: 'TEMPORAL_ADDRESS is required',
      type: 'ConfigurationError',
    });
  }

  logger.info({ config: { ...config, security: { ...config.security, githubToken: '***' } } }, 'Configuration loaded');

  return config;
}

// Singleton config instance
let _config: Config | null = null;

export function getConfig(): Config {
  if (!_config) {
    _config = loadConfig();
  }
  return _config;
}

export function validateRepoOrg(repoUrl: string): boolean {
  const config = getConfig();

  // If no allowed orgs specified, allow all
  if (config.security.allowedOrgs.length === 0) {
    return true;
  }

  // Extract org from URL
  const match = repoUrl.match(/github\.com\/([^/]+)\//);
  if (!match) {
    return false;
  }

  const org = match[1];
  return config.security.allowedOrgs.includes(org);
}