import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ApplicationFailure } from '@temporalio/activity';
import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import {
  checkToolRequirements,
  getMissingRequiredTools,
  getMissingOptionalTools,
  validateRepoUrl,
  detectTechStack,
} from '../../src/activities/index';

// Mock external dependencies
vi.mock('child_process', () => ({
  exec: vi.fn((command, options, callback) => {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    // Simulate async execution
    setTimeout(() => {
      callback(null, { stdout: 'v1.0.0\n', stderr: '' });
    }, 0);
    return { on: vi.fn() };
  }),
  spawn: vi.fn(() => ({
    on: vi.fn((event, cb) => {
      if (event === 'close') {
        setTimeout(() => cb(0), 0);
      }
      return {};
    }),
  })),
}));

vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn(),
    mkdirSync: vi.fn(),
    rmSync: vi.fn(),
    readFileSync: vi.fn(),
    writeFileSync: vi.fn(),
    promises: {
      readdir: vi.fn(),
      rm: vi.fn(),
    },
  };
});

vi.mock('path', () => ({
  join: vi.fn((...args) => args.join('/')),
  dirname: vi.fn((p) => p.split('/').slice(0, -1).join('/')),
}));

vi.mock('@temporalio/activity', () => ({
  ApplicationFailure: {
    create: vi.fn((opts) => {
      const error = new Error(opts.message);
      (error as any).type = opts.type;
      return error;
    }),
  },
}));

describe('checkToolRequirements', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (childProcess.exec as any).mockImplementation((command, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      callback(null, { stdout: 'v1.0.0\n', stderr: '' });
    });
  });

  it('should detect installed tools', async () => {
    const results = await checkToolRequirements();
    
    expect(results.length).toBeGreaterThan(0);
    const npmTool = results.find(r => r.name === 'npm');
    expect(npmTool).toBeDefined();
    expect(npmTool?.installed).toBe(true);
    expect(npmTool?.version).toBe('v1.0.0');
  });

  it('should detect missing tools', async () => {
    (childProcess.exec as any).mockImplementation((command, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      callback(new Error('command not found'), { stdout: '', stderr: '' });
    });

    const results = await checkToolRequirements();
    
    expect(results.length).toBeGreaterThan(0);
    results.forEach(tool => {
      expect(tool.installed).toBe(false);
      expect(tool.installCommand).toBeDefined();
    });
  });

  it('should handle command execution errors', async () => {
    (childProcess.exec as any).mockImplementation((command, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      callback(new Error('timeout'), { stdout: '', stderr: '' });
    });

    const results = await checkToolRequirements();
    
    expect(results.length).toBeGreaterThan(0);
    results.forEach(tool => {
      expect(tool.installed).toBe(false);
    });
  });
});

describe('getMissingRequiredTools', () => {
  it('should return only missing required tools', () => {
    const status = [
      { name: 'npm', installed: false, required: true },
      { name: 'git', installed: true, required: true },
      { name: 'gitleaks', installed: false, required: false },
    ] as any[];

    const missing = getMissingRequiredTools(status);
    
    expect(missing).toHaveLength(1);
    expect(missing[0].name).toBe('npm');
    expect(missing[0].required).toBe(true);
  });

  it('should return empty array if all required tools are installed', () => {
    const status = [
      { name: 'npm', installed: true, required: true },
      { name: 'git', installed: true, required: true },
    ] as any[];

    const missing = getMissingRequiredTools(status);
    
    expect(missing).toHaveLength(0);
  });
});

describe('getMissingOptionalTools', () => {
  it('should return only missing optional tools', () => {
    const status = [
      { name: 'npm', installed: false, required: true },
      { name: 'git', installed: true, required: true },
      { name: 'gitleaks', installed: false, required: false },
      { name: 'semgrep', installed: false, required: false },
    ] as any[];

    const missing = getMissingOptionalTools(status);
    
    expect(missing).toHaveLength(2);
    expect(missing[0].required).toBe(false);
  });

  it('should return empty array if all optional tools are installed', () => {
    const status = [
      { name: 'gitleaks', installed: true, required: false },
      { name: 'semgrep', installed: true, required: false },
    ] as any[];

    const missing = getMissingOptionalTools(status);
    
    expect(missing).toHaveLength(0);
  });
});

describe('validateRepoUrl', () => {
  it('should accept valid GitHub HTTPS URLs', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo')).not.toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo.git')).not.toThrow();
    expect(() => validateRepoUrl('https://github.com/my-org/my-repo-name')).not.toThrow();
  });

  it('should reject non-GitHub URLs', () => {
    expect(() => validateRepoUrl('https://gitlab.com/owner/repo')).toThrow();
    expect(() => validateRepoUrl('https://bitbucket.org/owner/repo')).toThrow();
  });

  it('should reject HTTP (non-HTTPS) URLs', () => {
    expect(() => validateRepoUrl('http://github.com/owner/repo')).toThrow();
  });

  it('should reject SSH URLs', () => {
    expect(() => validateRepoUrl('git@github.com:owner/repo.git')).toThrow();
  });

  it('should reject command injection attempts', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo;rm -rf /')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo|cat /etc/passwd')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo&whoami')).toThrow();
  });

  it('should reject path traversal attempts', () => {
    expect(() => validateRepoUrl('https://github.com/owner/../../../etc/passwd')).toThrow();
  });

  it('should reject file:// protocol', () => {
    expect(() => validateRepoUrl('file:///etc/passwd')).toThrow();
  });

  it('should reject empty strings', () => {
    expect(() => validateRepoUrl('')).toThrow();
  });

  it('should reject URLs with special characters', () => {
    expect(() => validateRepoUrl('https://github.com/owner/repo`id`')).toThrow();
    expect(() => validateRepoUrl('https://github.com/owner/repo${PATH}')).toThrow();
  });
});

describe('detectTechStack', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (fs as any).existsSync = vi.fn(() => true);
    (fs as any).readFileSync = vi.fn(() => JSON.stringify({
      name: 'test',
      dependencies: {
        react: '18.0.0',
        next: '14.0.0',
        stripe: '12.0.0',
      },
      devDependencies: {
        express: '4.18.0',
      },
    }));
    (childProcess as any).exec = vi.fn((cmd, opts, cb) => {
      cb(null, { stdout: '', stderr: '' });
    });
  });

  it('should detect Node.js project with frameworks', async () => {
    (fs as any).existsSync = vi.fn((p) => p.includes('package.json'));

    const techStack = await detectTechStack('/tmp/test');
    
    expect(techStack.language).toBe('nodejs');
    expect(techStack.frameworks).toContain('React');
    expect(techStack.frameworks).toContain('Next.js');
    expect(techStack.frameworks).toContain('Express');
  });

  it('should detect payments integration', async () => {
    (fs as any).existsSync = vi.fn((p) => p.includes('package.json'));

    const techStack = await detectTechStack('/tmp/test');
    
    expect(techStack.hasPayments).toBe(true);
  });

  it('should detect package manager', async () => {
    (fs as any).existsSync = vi.fn((p) => 
      p.includes('package.json') || p.includes('yarn.lock')
    );

    const techStack = await detectTechStack('/tmp/test');
    
    expect(techStack.packageManager).toBe('yarn');
  });

  it('should handle missing package.json', async () => {
    (fs as any).existsSync = vi.fn(() => false);

    const techStack = await detectTechStack('/tmp/test');
    
    expect(techStack.language).toBe('unknown');
    expect(techStack.frameworks).toHaveLength(0);
  });
});
