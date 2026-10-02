#!/usr/bin/env npx ts-node
/**
 * Generate AUDIT-COVERAGE.md from audit-domains.ts
 */

import { generateCoverageMarkdown } from '../src/config/audit-domains';
import * as fs from 'fs';
import * as path from 'path';

const outputPath = path.join(__dirname, '..', 'AUDIT-COVERAGE.md');

console.log('Generating audit coverage documentation...');

const markdown = generateCoverageMarkdown();

fs.writeFileSync(outputPath, markdown);

console.log(`Generated: ${outputPath}`);

// Print summary
const lines = markdown.split('\n');
console.log('\nSummary:');
console.log(lines.slice(4, 9).join('\n'));