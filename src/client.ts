// Temporal Client for Application Audit

import { Connection, Client } from '@temporalio/client';
import { applicationAudit, p0ApprovalSignal, statusQuery, findingsQuery } from './workflows';
import type { AuditInput, AuditResult, AuditStatus, Finding } from './types';

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'start':
      await startAudit(args[1], args.slice(2));
      break;
    case 'status':
      await getAuditStatus(args[1]);
      break;
    case 'findings':
      await getAuditFindings(args[1]);
      break;
    case 'approve':
      await approveP0Findings(args[1], true);
      break;
    case 'reject':
      await approveP0Findings(args[1], false);
      break;
    case 'watch':
      await watchAudit(args[1]);
      break;
    default:
      printUsage();
  }
}

async function getClient(): Promise<Client> {
  const connection = await Connection.connect({
    address: 'localhost:7233',
  });

  return new Client({ connection });
}

async function startAudit(repoUrl: string, options: string[]) {
  const client = await getClient();

  // Parse options
  const input: AuditInput = {
    repoUrl,
    frameworks: [],
  };

  for (let i = 0; i < options.length; i++) {
    if (options[i] === '--frameworks' && options[i + 1]) {
      input.frameworks = options[i + 1].split(',').map(f => f.trim()) as any;
      i++;
    }
    if (options[i] === '--scope' && options[i + 1]) {
      input.scope = options[i + 1] as any;
      i++;
    }
    if (options[i] === '--skip-approval') {
      input.skipApproval = true;
    }
    if (options[i] === '--output' && options[i + 1]) {
      input.outputDir = options[i + 1];
      i++;
    }
  }

  // Start workflow
  const workflowId = `audit-${repoUrl.replace(/[^a-zA-Z0-9]/g, '-')}-${Date.now()}`;

  const handle = await client.workflow.start(applicationAudit, {
    taskQueue: 'audit',
    workflowId,
    args: [input],
  });

  console.log(`✓ Started audit workflow`);
  console.log(`  Workflow ID: ${workflowId}`);
  console.log(`  Repository: ${repoUrl}`);
  console.log(`  Frameworks: ${input.frameworks?.join(', ') || 'OWASP-ASVS'}`);
  console.log(``);
  console.log(`Watch progress:`);
  console.log(`  npm run workflow -- watch ${workflowId}`);
  console.log(``);
  console.log(`View in Temporal UI:`);
  console.log(`  http://localhost:8233/namespaces/default/workflows/${workflowId}`);
}

async function getAuditStatus(workflowId: string) {
  const client = await getClient();
  const handle = client.workflow.getHandle(workflowId);

  const status = await handle.query(statusQuery);

  console.log(`Audit Status: ${status}`);
}

async function getAuditFindings(workflowId: string) {
  const client = await getClient();
  const handle = client.workflow.getHandle(workflowId);

  const findings = await handle.query(findingsQuery);

  console.log(`Total Findings: ${findings.length}`);
  console.log(``);

  const bySeverity = {
    P0: findings.filter((f: Finding) => f.severity === 'P0'),
    P1: findings.filter((f: Finding) => f.severity === 'P1'),
    P2: findings.filter((f: Finding) => f.severity === 'P2'),
    P3: findings.filter((f: Finding) => f.severity === 'P3'),
  };

  for (const [severity, items] of Object.entries(bySeverity)) {
    if (items.length > 0) {
      console.log(`${severity} (${items.length}):`);
      items.forEach((f: Finding) => {
        console.log(`  - ${f.id}: ${f.title}`);
      });
      console.log(``);
    }
  }
}

async function approveP0Findings(workflowId: string, approved: boolean) {
  const client = await getClient();
  const handle = client.workflow.getHandle(workflowId);

  await handle.signal(p0ApprovalSignal, approved);

  console.log(`✓ P0 findings ${approved ? 'approved' : 'rejected'}`);
}

async function watchAudit(workflowId: string) {
  const client = await getClient();
  const handle = client.workflow.getHandle(workflowId);

  let lastStatus = '';

  while (true) {
    try {
      const status = await handle.query(statusQuery);

      if (status !== lastStatus) {
        console.log(`[${new Date().toISOString()}] Phase: ${status}`);
        lastStatus = status;
      }

      if (status === 'completed' || status === 'failed') {
        console.log(``);
        console.log(`✓ Audit ${status}`);

        if (status === 'completed') {
          const result = await handle.result() as AuditResult;
          console.log(`  Report: ${result.reportPath}`);
          console.log(`  Evidence: ${result.evidencePath}`);
          console.log(`  Duration: ${(result.duration / 1000).toFixed(1)}s`);
          console.log(`  Findings: ${result.findings.length}`);
        }

        break;
      }

      // Wait 2 seconds before checking again
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error: ${error}`);
      break;
    }
  }
}

function printUsage() {
  console.log(`Usage: npm run workflow -- <command> [options]

Commands:
  start <repo-url>            Start a new audit
    --frameworks <list>       Compliance frameworks (comma-separated)
    --scope <type>            Audit scope (full, security, compliance)
    --skip-approval           Skip P0 approval
    --output <dir>            Output directory for reports

  status <workflow-id>        Get audit status
  findings <workflow-id>      List all findings
  approve <workflow-id>       Approve P0 findings
  reject <workflow-id>        Reject P0 findings
  watch <workflow-id>         Watch audit progress

Examples:
  npm run workflow -- start vannifr/event-ticketing --frameworks GDPR,PCI-DSS
  npm run workflow -- watch audit-vannifr-event-ticketing-1234567890
  npm run workflow -- approve audit-vannifr-event-ticketing-1234567890
`);
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});