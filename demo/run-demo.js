#!/usr/bin/env node
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const ROOT = path.resolve(__dirname, '..');
const { Connection, Client } = require(path.join(ROOT, 'node_modules/@temporalio/client'));

const APPS = ['vulnerable-app', 'clean-app'];
const OWNER = 'audit-demo';
const TEMPORAL_PORT = Number(process.env.DEMO_TEMPORAL_PORT || 7233);
const UI_PORT = Number(process.env.DEMO_UI_PORT || 8233);
const RUN_TIMEOUT_MS = Number(process.env.DEMO_RUN_TIMEOUT_MS || 600000);

const children = [];
let workDir;

function log(msg) {
  console.log(`[demo] ${msg}`);
}

function portFree(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, '127.0.0.1');
  });
}

function waitFor(predicate, timeoutMs, label) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        if (await predicate()) return resolve();
      } catch (_) {}
      if (Date.now() - start > timeoutMs) return reject(new Error(`timeout waiting for ${label}`));
      setTimeout(tick, 500);
    };
    tick();
  });
}

function start(cmd, args, opts, logFile) {
  const out = fs.openSync(logFile, 'a');
  const child = spawn(cmd, args, { ...opts, detached: true, stdio: ['ignore', out, out] });
  children.push(child);
  return child;
}

function cleanup() {
  for (const child of children) {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch (_) {}
  }
  if (workDir && !process.env.DEMO_KEEP_WORKDIR) {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

function buildFixtures(fixtureRoot) {
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: 'demo',
    GIT_AUTHOR_EMAIL: 'demo@example.org',
    GIT_COMMITTER_NAME: 'demo',
    GIT_COMMITTER_EMAIL: 'demo@example.org',
  };
  for (const app of APPS) {
    const dest = path.join(fixtureRoot, app);
    fs.cpSync(path.join(__dirname, app), dest, { recursive: true });
    const git = (...a) => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', ...a], { cwd: dest, env, stdio: 'pipe' });
    git('init', '-q', '-b', 'main');
    git('add', '-A');
    git('commit', '-q', '-m', 'demo fixture');
  }
}

function loadExpected() {
  const md = fs.readFileSync(path.join(__dirname, 'EXPECTED.md'), 'utf-8');
  const m = md.match(/```json\n([\s\S]*?)\n```/);
  if (!m) throw new Error('EXPECTED.md bevat geen json-blok');
  return JSON.parse(m[1]);
}

function findingText(f) {
  const ev = (f.evidence || []).map((e) => `${e.file || ''} ${e.content || ''} ${e.type || ''}`).join(' ');
  return `${f.title || ''} ${f.description || ''} ${f.category || ''} ${ev}`;
}

function findingFiles(f) {
  return (f.evidence || []).map((e) => e.file || '').filter(Boolean);
}

function score(app, findings, expected) {
  const rows = [];
  for (const d of expected) {
    const re = new RegExp(d.match, 'i');
    const catRe = d.category ? new RegExp(d.category, 'i') : null;
    const hits = findings.filter((f) => {
      if (!re.test(findingText(f))) return false;
      if (catRe && !catRe.test(f.category || '')) return false;
      if (!d.file) return true;
      return findingFiles(f).some((p) => p.endsWith(d.file));
    });
    rows.push({
      id: d.id,
      expectedSeverity: d.severity,
      found: hits.length > 0,
      severityOk: hits.some((f) => f.severity === d.severity),
      reported: hits.map((f) => f.severity).sort().join(',') || '-',
    });
  }
  return rows;
}

async function main() {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditflow-demo-'));
  const fixtureRoot = path.join(workDir, 'fixtures');
  fs.mkdirSync(fixtureRoot);
  const reportDir = path.join(workDir, 'reports');
  fs.mkdirSync(reportDir);

  for (const tool of ['git', 'node', 'temporal', 'gitleaks', 'semgrep']) {
    try {
      execFileSync('sh', ['-c', `command -v ${tool}`], { stdio: 'pipe' });
    } catch (_) {
      throw new Error(`vereiste tool ontbreekt: ${tool}`);
    }
  }
  if (!(await portFree(TEMPORAL_PORT))) throw new Error(`poort ${TEMPORAL_PORT} is bezet`);
  if (!(await portFree(UI_PORT))) throw new Error(`poort ${UI_PORT} is bezet`);

  log('fixtures bouwen');
  buildFixtures(fixtureRoot);

  log(`temporal dev-server starten (grpc ${TEMPORAL_PORT}, ui ${UI_PORT})`);
  start('temporal', ['server', 'start-dev', '--headless', '--ip', '127.0.0.1', '--port', String(TEMPORAL_PORT), '--ui-port', String(UI_PORT)], { cwd: workDir }, path.join(workDir, 'temporal.log'));
  await waitFor(async () => !(await portFree(TEMPORAL_PORT)), 60000, 'temporal server');
  await new Promise((r) => setTimeout(r, 3000));

  const gitEnv = { GIT_CONFIG_COUNT: String(APPS.length) };
  APPS.forEach((app, i) => {
    gitEnv[`GIT_CONFIG_KEY_${i}`] = `url.file://${path.join(fixtureRoot, app)}.insteadOf`;
    gitEnv[`GIT_CONFIG_VALUE_${i}`] = `https://github.com/${OWNER}/${app}`;
  });

  log('worker starten (taskqueue audit)');
  const workerLog = path.join(workDir, 'worker.log');
  start('npx', ['ts-node', 'src/worker.ts'], { cwd: ROOT, env: { ...process.env, ...gitEnv, TEMPORAL_ADDRESS: `localhost:${TEMPORAL_PORT}` } }, workerLog);
  await waitFor(() => fs.existsSync(workerLog) && /Worker configured/.test(fs.readFileSync(workerLog, 'utf-8')), 90000, 'worker');

  const connection = await Connection.connect({ address: `localhost:${TEMPORAL_PORT}` });
  const client = new Client({ connection });
  const expected = loadExpected();
  const stamp = Date.now();
  const results = {};

  for (const app of APPS) {
    const workflowId = `demo-${app}-${stamp}`;
    log(`audit starten: ${app} (${workflowId})`);
    const handle = await client.workflow.start('applicationAudit', {
      taskQueue: 'audit',
      workflowId,
      args: [{ repoUrl: `https://github.com/${OWNER}/${app}`, skipApproval: true, outputDir: path.join(reportDir, app) }],
      workflowExecutionTimeout: RUN_TIMEOUT_MS,
    });
    try {
      results[app] = { ok: true, result: await handle.result() };
    } catch (err) {
      results[app] = { ok: false, error: String(err && err.cause && err.cause.message ? err.cause.message : err) };
    }
  }

  let failed = false;
  const lines = [];
  for (const app of APPS) {
    const r = results[app];
    if (!r.ok) {
      failed = true;
      lines.push(`${app}: audit mislukt: ${r.error}`);
      continue;
    }
    const findings = r.result.findings || [];
    const bySev = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
    lines.push(`${app}: ${findings.length} bevindingen ${JSON.stringify(bySev)}; rapport ${r.result.reportPath}`);
    if (app === 'clean-app') {
      const fp = findings.length;
      lines.push(`  vals-positieven: ${fp}`);
      for (const f of findings) lines.push(`    ${f.severity} ${f.title}`);
      if (fp > 0) failed = true;
    } else {
      const rows = score(app, findings, expected[app]);
      const found = rows.filter((x) => x.found).length;
      const sev = rows.filter((x) => x.found && x.severityOk).length;
      lines.push(`  recall: ${found}/${rows.length} gevonden, ${sev}/${rows.length} met juiste ernst`);
      for (const x of rows) lines.push(`    ${x.id} gevonden=${x.found ? 'ja' : 'NEE'} verwacht=${x.expectedSeverity} gerapporteerd=${x.reported}`);
      if (found < rows.length) failed = true;
    }
  }
  console.log('\n' + lines.join('\n'));
  fs.writeFileSync(path.join(__dirname, 'last-run.json'), JSON.stringify(results, null, 2));
  await connection.close();
  return failed ? 1 : 0;
}

let exiting = false;
function finish(code) {
  if (exiting) return;
  exiting = true;
  cleanup();
  process.exit(code);
}
process.on('SIGINT', () => finish(130));
process.on('SIGTERM', () => finish(143));

main().then(finish, (err) => {
  console.error(`[demo] fout: ${err.message}`);
  finish(2);
});
