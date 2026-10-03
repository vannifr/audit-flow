const PLANTED_SECRETS = [
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'f3a9c1d27b8e4056a1d9e2c47b3f8a60e5d4c3b2',
  'admin1234',
];
const REQUIRED_DEPENDENCY_DEFECTS = ['D05', 'D06', 'D07'];
const MIN_STRICT_RECALL = 8;

function findingText(f) {
  const ev = (f.evidence || []).map((e) => `${e.file || ''} ${e.content || ''} ${e.type || ''}`).join(' ');
  return `${f.title || ''} ${f.description || ''} ${f.category || ''} ${ev}`;
}

function evidenceFits(e, defect) {
  if (!defect.file) return true;
  if (!(e.file || '').endsWith(defect.file)) return false;
  if (defect.line === undefined || defect.line === null) return true;
  if (e.line === undefined || e.line === null) return true;
  return e.line === defect.line;
}

function candidates(findings, defect) {
  const re = new RegExp(defect.match, 'i');
  const catRe = defect.category ? new RegExp(defect.category, 'i') : null;
  const out = [];
  findings.forEach((f, index) => {
    if (!re.test(findingText(f))) return;
    if (catRe && !catRe.test(f.category || '')) return;
    if (!(f.evidence || []).some((e) => evidenceFits(e, defect)) && defect.file) return;
    out.push(index);
  });
  return out;
}

function broadCandidates(findings, defect) {
  const re = new RegExp(defect.match, 'i');
  const catRe = defect.category ? new RegExp(defect.category, 'i') : null;
  const out = [];
  findings.forEach((f, index) => {
    if (!re.test(findingText(f))) return;
    if (catRe && !catRe.test(f.category || '')) return;
    if (defect.file && !(f.evidence || []).some((e) => (e.file || '').endsWith(defect.file))) return;
    out.push(index);
  });
  return out;
}

function assign(candidateLists) {
  const owner = new Map();
  const tryAssign = (d, seen) => {
    for (const f of candidateLists[d]) {
      if (seen.has(f)) continue;
      seen.add(f);
      if (!owner.has(f) || tryAssign(owner.get(f), seen)) {
        owner.set(f, d);
        return true;
      }
    }
    return false;
  };
  for (let d = 0; d < candidateLists.length; d += 1) tryAssign(d, new Set());
  const byDefect = new Map();
  for (const [f, d] of owner) byDefect.set(d, f);
  return byDefect;
}

function score(findings, expected) {
  const strictLists = expected.map((d) => candidates(findings, d));
  const broadLists = expected.map((d) => broadCandidates(findings, d));
  const assigned = assign(strictLists);
  return expected.map((d, i) => {
    const hit = assigned.get(i);
    const broad = broadLists[i];
    return {
      id: d.id,
      expectedSeverity: d.severity,
      broadFound: broad.length > 0,
      broadSeverityOk: broad.some((f) => findings[f].severity === d.severity),
      strictFound: hit !== undefined,
      strictSeverityOk: hit !== undefined && findings[hit].severity === d.severity,
      assignedTo: hit === undefined ? '-' : `${findings[hit].id || `#${hit}`} ${findings[hit].severity}`,
      reported: broad.map((f) => findings[f].severity).sort().join(',') || '-',
    };
  });
}

function summarize(rows) {
  return {
    total: rows.length,
    strict: rows.filter((r) => r.strictFound).length,
    strictSeverity: rows.filter((r) => r.strictSeverityOk).length,
    broad: rows.filter((r) => r.broadFound).length,
    broadSeverity: rows.filter((r) => r.broadSeverityOk).length,
  };
}

function gate({ rows, cleanResult, bundleChecks, leaks }) {
  const failures = [];
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const id of REQUIRED_DEPENDENCY_DEFECTS) {
    const row = byId.get(id);
    if (!row || !row.strictFound) failures.push(`${id} niet gevonden`);
  }
  const s = summarize(rows);
  if (s.strict < MIN_STRICT_RECALL) failures.push(`strikte recall ${s.strict}/${s.total} is lager dan ${MIN_STRICT_RECALL}`);
  if (!cleanResult || cleanResult.outcome !== 'complete') {
    failures.push(`clean-app outcome is ${cleanResult ? cleanResult.outcome : 'onbekend'}, verwacht complete`);
  }
  if (cleanResult && (cleanResult.findings || []).length > 0) failures.push(`clean-app heeft ${cleanResult.findings.length} bevindingen`);
  if (bundleChecks.length === 0) failures.push('geen evidence-bundel gevonden');
  for (const b of bundleChecks) if (b.exit !== 0) failures.push(`evidence-bundel ${b.name} faalt verificatie (exit ${b.exit})`);
  for (const l of leaks) failures.push(`geheime waarde in ${l.file}`);
  return { pass: failures.length === 0, failures };
}

function table(rows) {
  const s = summarize(rows);
  const pad = (v, n) => String(v).padEnd(n);
  const out = [`${pad('defect', 7)}${pad('ruim', 6)}${pad('strikt', 8)}${pad('verwacht', 10)}${pad('toegewezen', 14)}`];
  for (const r of rows) {
    out.push(`${pad(r.id, 7)}${pad(r.broadFound ? 'ja' : 'NEE', 6)}${pad(r.strictFound ? 'ja' : 'NEE', 8)}${pad(r.expectedSeverity, 10)}${pad(r.assignedTo, 14)}`);
  }
  out.push(`ruime recall: ${s.broad}/${s.total} (juiste ernst ${s.broadSeverity})`);
  out.push(`strikte recall: ${s.strict}/${s.total} (juiste ernst ${s.strictSeverity})`);
  return out.join('\n');
}

module.exports = { PLANTED_SECRETS, REQUIRED_DEPENDENCY_DEFECTS, MIN_STRICT_RECALL, score, summarize, gate, table, findingText };
