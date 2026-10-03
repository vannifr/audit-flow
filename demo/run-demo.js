#!/usr/bin/env node
const { spawn, execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { PLANTED_SECRETS, score, summarize, gate, table } = require('./score');

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

function makeWritable(dir) {
  let entries = [];
  try {
    fs.chmodSync(dir, 0o700);
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) makeWritable(path.join(dir, entry.name));
  }
}

function cleanup() {
  for (const child of children) {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch (_) {}
  }
  if (workDir && !process.env.DEMO_KEEP_WORKDIR) {
    makeWritable(workDir);
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

function listFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

function verifyBundles(evidenceRoot, pubKeyPath) {
  const checks = [];
  if (!fs.existsSync(evidenceRoot)) return checks;
  for (const entry of fs.readdirSync(evidenceRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(evidenceRoot, entry.name);
    const run = spawnSync('npx', ['ts-node', 'src/cli/verify-evidence.ts', '--pubkey', pubKeyPath, dir], { cwd: ROOT, encoding: 'utf-8' });
    checks.push({ name: entry.name, exit: run.status === null ? 2 : run.status });
  }
  return checks;
}

function sweepSecrets(roots) {
  const leaks = [];
  for (const root of roots) {
    const files = fs.existsSync(root) && fs.statSync(root).isFile() ? [root] : listFiles(root);
    for (const file of files) {
      const text = fs.readFileSync(file).toString('latin1');
      if (PLANTED_SECRETS.some((value) => text.includes(value))) leaks.push({ file });
    }
  }
  return leaks;
}

async function main() {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tessera-demo-'));
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

  const keyPath = path.join(workDir, 'keys', 'ed25519.pem');
  execFileSync('npx', ['ts-node', 'src/cli/evidence-keygen.ts', keyPath], { cwd: ROOT, stdio: 'pipe' });
  const pubKeyPath = `${keyPath}.pub`;

  log('worker starten (taskqueue audit)');
  const workerLog = path.join(workDir, 'worker.log');
  start('npx', ['ts-node', 'src/worker.ts'], { cwd: ROOT, env: { ...process.env, ...gitEnv, TEMPORAL_ADDRESS: `localhost:${TEMPORAL_PORT}`, TESSERA_EVIDENCE_ROOT: path.join(workDir, 'evidence'), TESSERA_SIGNING_KEY: keyPath, TESSERA_REQUIRE_SIGNATURE: '1' } }, workerLog);
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
  let rows = [];
  let cleanResult = null;
  for (const app of APPS) {
    const r = results[app];
    if (!r.ok) {
      failed = true;
      lines.push(`${app}: audit mislukt: ${r.error}`);
      continue;
    }
    const findings = r.result.findings || [];
    const bySev = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
    lines.push(`${app}: ${findings.length} bevindingen ${JSON.stringify(bySev)}; outcome ${r.result.outcome}; rapport ${r.result.reportPath}`);
    if (app === 'clean-app') {
      cleanResult = r.result;
      lines.push(`  vals-positieven: ${findings.length}`);
      for (const f of findings) lines.push(`    ${f.severity} ${f.title}`);
    } else {
      rows = score(findings, expected[app]);
      lines.push(table(rows));
    }
  }

  const bundleChecks = verifyBundles(path.join(workDir, 'evidence'), pubKeyPath);
  const leaks = sweepSecrets([path.join(workDir, 'evidence'), reportDir, workerLog]);
  const verdict = gate({ rows, cleanResult, bundleChecks, leaks });
  const s = summarize(rows);
  lines.push('');
  lines.push(`evidence-bundels geverifieerd: ${bundleChecks.length} (${bundleChecks.filter((b) => b.exit === 0).length} ok)`);
  lines.push(`secret-sweep: ${leaks.length === 0 ? 'schoon' : `${leaks.length} bestand(en) met geplante waarde`}`);
  lines.push(`recall ruim ${s.broad}/${s.total}, strikt ${s.strict}/${s.total}`);
  lines.push(`release-gate: ${verdict.pass ? 'GESLAAGD' : 'GEFAALD'}`);
  for (const f of verdict.failures) lines.push(`  - ${f}`);
  if (!verdict.pass) failed = true;
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
