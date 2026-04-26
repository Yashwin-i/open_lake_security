/* ============================================================
   OpenLake Security — app.js
   ============================================================ */

// ---- State ----
let currentData   = null;
let allFindings   = [];
let scanHistory   = [];

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('sf-date').textContent = new Date().getFullYear();
  startClock();
  loadLatestScan();
  loadScanHistory();
  mermaid.initialize({ startOnLoad: false, theme: 'dark', themeVariables: { primaryColor: '#00d4ff', background: '#0d1225', edgeLabelBackground: '#111827' } });
});

// ---- Live Clock ----
function startClock() {
  function tick() {
    const now = new Date();
    const hh  = String(now.getHours()).padStart(2, '0');
    const mm  = String(now.getMinutes()).padStart(2, '0');
    const ss  = String(now.getSeconds()).padStart(2, '0');
    const el  = document.getElementById('live-clock');
    if (el) el.textContent = `${hh}:${mm}:${ss}`;
  }
  tick();
  setInterval(tick, 1000);
}

// ---- Navigation ----
const panels = ['home','findings','attacks','threatmap','datalake','ai'];
const panelTitles = {
  home:      'Home',
  findings:  'Findings',
  attacks:   'Attack Simulation',
  threatmap: 'Threat Map',
  datalake:  'Data Lake',
  ai:        'AI Assistant',
};

function navigate(id) {
  panels.forEach(p => {
    document.getElementById(`panel-${p}`).classList.remove('active');
    document.querySelector(`[data-panel="${p}"]`).classList.remove('active');
  });
  document.getElementById(`panel-${id}`).classList.add('active');
  document.querySelector(`[data-panel="${id}"]`).classList.add('active');
  document.getElementById('topbar-title').textContent = panelTitles[id];

  if (id === 'datalake') loadScanHistory();
  if (id === 'threatmap' && currentData) renderThreatMap(currentData.threat_model);
}

// ---- Scan ----
async function startScan() {
  const url   = document.getElementById('repo-url').value.trim();
  const btn   = document.getElementById('scan-btn');
  const label = document.getElementById('scan-btn-label');
  const log   = document.getElementById('scan-log');

  if (!url.startsWith('http')) {
    showAlert('Please enter a valid HTTP/HTTPS GitHub URL.', 'error');
    return;
  }

  btn.disabled = true;
  label.innerHTML = '<span class="spinner"></span> Scanning…';
  log.classList.add('visible');
  log.innerHTML = '';

  const steps = [
    ['info', '→ Initiating scan pipeline…'],
    ['info', '→ Cloning repository from GitHub…'],
    ['info', '→ Running Bandit SAST analysis…'],
    ['info', '→ Running Semgrep advanced analysis…'],
    ['info', '→ Auto-generating Dockerfile if needed…'],
    ['info', '→ Building Docker sandbox image…'],
    ['info', '→ Fuzzing — SQL injection probe…'],
    ['info', '→ Fuzzing — massive payload test…'],
    ['info', '→ Generating AI remediation plan…'],
    ['info', '→ Building threat model diagram…'],
    ['info', '→ Persisting results to data lake…'],
  ];

  let stepIdx = 0;
  const logInterval = setInterval(() => {
    if (stepIdx < steps.length) {
      appendLog(log, steps[stepIdx][0], steps[stepIdx][1]);
      stepIdx++;
    }
  }, 2800);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo_url: url }),
    });

    clearInterval(logInterval);

    if (!res.ok) {
      const err = await res.json();
      appendLog(log, 'error', `Error: ${err.detail}`);
      return;
    }

    const data = await res.json();
    appendLog(log, 'ok', `✓ Scan complete for "${data.project}"`);

    // Warn about any skipped scanner modules
    const errs = data.pipeline_errors || [];
    if (errs.length > 0) {
      errs.forEach(e => appendLog(log, 'warn', `⚠ Skipped — ${e}`));
    } else {
      appendLog(log, 'ok', '✓ All pipeline modules completed successfully.');
    }
    appendLog(log, 'ok', '✓ Results saved to data lake.');

    currentData = data;
    populateDashboard(data);
    loadScanHistory();

  } catch (e) {
    clearInterval(logInterval);
    appendLog(log, 'error', `Fetch error: ${e.message}`);
  } finally {
    btn.disabled = false;
    label.textContent = 'Run Scan';
  }
}

function appendLog(container, type, msg) {
  const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-time">${now}</span><span class="log-msg ${type}">${msg}</span>`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

// ---- Load Latest Scan ----
async function loadLatestScan() {
  try {
    const res = await fetch('/api/scans/latest');
    if (!res.ok) return;
    const data = await res.json();
    currentData = data;
    populateDashboard(data);
  } catch (_) {}
}

// ---- Populate Dashboard from Data ----
function populateDashboard(data) {
  const metrics = data.metrics || {};
  const basic    = metrics.basic_issues    || 0;
  const advanced = metrics.advanced_issues || 0;
  const fuzz     = metrics.fuzz_crashes    || 0;
  const total    = basic + advanced + fuzz;

  // — Home metrics —
  document.getElementById('home-metrics-placeholder').style.display = 'none';
  document.getElementById('home-metrics').style.display = 'block';
  animateCount('m-total',    total);
  animateCount('m-basic',    basic);
  animateCount('m-advanced', advanced);
  animateCount('m-fuzz',     fuzz);

  // — Pipeline errors alert on Home panel —
  const existingPipelineAlert = document.getElementById('pipeline-alert');
  if (existingPipelineAlert) existingPipelineAlert.remove();
  const errs = data.pipeline_errors || [];
  if (errs.length > 0) {
    const alertEl = document.createElement('div');
    alertEl.id = 'pipeline-alert';
    alertEl.className = 'alert alert-error';
    alertEl.style.marginBottom = '16px';
    alertEl.innerHTML = `<span class="alert-icon">⚠</span><span><strong>Some scanners were skipped:</strong> ${errs.map(e => `<code style="font-family:inherit">${e}</code>`).join(' · ')}<br/><small style="opacity:.7">Results above are from completed modules only. Install missing tools and re-scan for full coverage.</small></span>`;
    document.getElementById('home-metrics').before(alertEl);
  }

  // — Last scan banner —
  const banner = document.getElementById('last-scan-banner');
  banner.classList.add('visible');
  document.getElementById('lsb-project').textContent = data.project || 'Unknown';
  document.getElementById('lsb-date').textContent    = fmtDate(data.scan_date);
  document.getElementById('lsb-total').textContent   = `${total} issue${total !== 1 ? 's' : ''}`;
  const pill = document.getElementById('lsb-pill');
  pill.textContent = total === 0 ? 'Clean' : total < 5 ? 'Low Risk' : total < 15 ? 'Medium Risk' : 'High Risk';
  pill.className = 'lsb-pill ' + (total === 0 ? 'safe' : total < 5 ? 'warn' : 'danger');

  // — Topbar meta — project name only; clock is live separately
  document.getElementById('topbar-meta').innerHTML =
    `<span class="status-dot"></span>${data.project || 'Unknown'} — ${fmtDate(data.scan_date)} &nbsp;<span id="live-clock" style="font-variant-numeric:tabular-nums;opacity:.7"></span>`;

  // — Findings —
  buildFindings(data);

  // — Attacks —
  buildAttacks(data);

  // badge
  const badge = document.getElementById('badge-findings');
  badge.textContent = total;
  badge.classList.toggle('visible', total > 0);
}

// ---- Animate Counter ----
function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const duration = 900;
  const start    = performance.now();
  const from     = parseInt(el.textContent) || 0;
  function tick(now) {
    const p = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (target - from) * ease);
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ---- Build Findings Table ----
function buildFindings(data) {
  allFindings = (data.remediation_plan || []).map(r => ({
    severity: (r.severity || 'UNKNOWN').toUpperCase(),
    source:   detectSource(r.issue),
    file:     r.file   || '—',
    line:     r.line   || '—',
    issue:    r.issue  || '—',
    action:   r.action || '—',
  }));

  renderFindingsTable(allFindings);

  const wrapper = document.getElementById('findings-table-wrapper');
  const empty   = document.getElementById('findings-empty');
  if (allFindings.length > 0) {
    wrapper.style.display = 'block';
    empty.style.display   = 'none';
  }
}

function detectSource(issue) {
  if (!issue) return 'UNKNOWN';
  if (issue.includes('[SAST]'))     return 'SAST';
  if (issue.includes('[ADVANCED]')) return 'ADVANCED';
  if (issue.includes('[FUZZ]'))     return 'FUZZ';
  return 'SAST';
}

function filterFindings() {
  const sev    = document.getElementById('filter-severity').value.toUpperCase();
  const src    = document.getElementById('filter-source').value.toUpperCase();
  const search = document.getElementById('search-findings').value.toLowerCase();

  const filtered = allFindings.filter(f => {
    const matchSev = !sev || f.severity === sev;
    const matchSrc = !src || f.source === src;
    const matchStr = !search || f.file.toLowerCase().includes(search) || f.issue.toLowerCase().includes(search);
    return matchSev && matchSrc && matchStr;
  });

  renderFindingsTable(filtered);
}

function renderFindingsTable(rows) {
  const tbody = document.getElementById('findings-tbody');
  document.getElementById('findings-count').textContent = `${rows.length} finding${rows.length !== 1 ? 's' : ''}`;

  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--text-muted)">No findings match the current filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(f => `
    <tr>
      <td><span class="severity-pill ${sevClass(f.severity)}">${f.severity}</span></td>
      <td><span class="source-tag ${srcClass(f.source)}">${f.source}</span></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.file)}">${esc(shortPath(f.file))}</td>
      <td>${f.line === 0 || f.line === '0' ? 'N/A' : f.line}</td>
      <td style="max-width:260px;white-space:normal;line-height:1.5">${esc(stripTag(f.issue))}</td>
      <td style="max-width:220px;white-space:normal;line-height:1.5;color:var(--text-secondary)">${esc(f.action)}</td>
    </tr>
  `).join('');
}

function sevClass(s) {
  const m = { CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low' };
  return m[s] || 'sev-unknown';
}

function srcClass(s) {
  const m = { SAST: 'src-sast', ADVANCED: 'src-advanced', FUZZ: 'src-fuzz' };
  return m[s] || 'src-sast';
}

function stripTag(s) { return (s || '').replace(/^\[(SAST|ADVANCED|FUZZ)\]\s*/, ''); }
function shortPath(p) { return p.replace(/^(temp_scan_zone|temp_test_[^/]+)\//, ''); }
function esc(s)       { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ---- Build Attacks Panel ----
function buildAttacks(data) {
  const fuzz = (data.raw_scans || {}).fuzzing || {};
  const hasError = !!fuzz.error;

  // Docker error banner
  const dockerErr = document.getElementById('fuzz-docker-error');
  const dockerErrMsg = document.getElementById('fuzz-docker-error-msg');
  if (hasError && fuzz.error) {
    dockerErr.style.display = 'flex';
    dockerErrMsg.textContent = fuzz.error;
  } else {
    dockerErr.style.display = 'none';
  }

  // If we have an error AND no attack results, show empty panel
  const hasResults = !fuzz.error || fuzz.attack_results;
  document.getElementById('attacks-empty').style.display  = !hasResults ? 'block' : 'none';
  document.getElementById('attacks-content').style.display = hasResults ? 'block' : 'none';

  if (!hasResults) return;

  // Auto-Dockerfile notice
  document.getElementById('autodockerfile-notice').style.display =
    fuzz.auto_generated_dockerfile ? 'flex' : 'none';

  const sqliOk   = fuzz.sql_injection_detected === true;
  const xssOk    = fuzz.xss_detected === true;
  const ptOk     = fuzz.path_traversal_detected === true;
  const authOk   = fuzz.auth_bypass_detected === true;
  const crashed  = (fuzz.crashes || 0) > 0;

  // Summary strip
  document.getElementById('as-sqli').textContent = sqliOk  ? 'VULN' : (hasError ? '—' : 'SAFE');
  document.getElementById('as-xss').textContent  = xssOk   ? 'VULN' : (hasError ? '—' : 'SAFE');
  document.getElementById('as-pt').textContent   = ptOk    ? 'VULN' : (hasError ? '—' : 'SAFE');
  document.getElementById('as-misc').textContent = (authOk || crashed) ? 'VULN' : (hasError ? '—' : 'SAFE');

  // ── Attack A: SQL Injection ──────────────────────────────
  _setAttack('sqli', sqliOk);
  if (sqliOk) {
    const d = fuzz.sqli_details || {};
    document.getElementById('sqli-endpoint').textContent = d.endpoint || '—';
    document.getElementById('sqli-method').textContent   = d.method   || '—';
    document.getElementById('sqli-payload').textContent  = d.payload  || "' OR '1'='1";
    document.getElementById('sqli-snippet').textContent  = typeof d.snippet === 'object'
      ? JSON.stringify(d.snippet, null, 2) : (d.snippet || '—');
  }

  // ── Attack B: XSS ────────────────────────────────────────
  _setAttack('xss', xssOk);
  if (xssOk) {
    const d = fuzz.xss_details || {};
    document.getElementById('xss-endpoint').textContent = d.endpoint || '—';
    document.getElementById('xss-param').textContent    = d.param    || '—';
    document.getElementById('xss-payload').textContent  = d.payload  || '—';
  }

  // ── Attack C: Path Traversal ─────────────────────────────
  _setAttack('pt', ptOk);
  if (ptOk) {
    const d = fuzz.path_traversal_details || {};
    document.getElementById('pt-endpoint').textContent = d.endpoint || '—';
    document.getElementById('pt-param').textContent    = d.param    || '—';
    const snippet = document.getElementById('pt-snippet');
    if (snippet) snippet.textContent = d.snippet || '—';
  }

  // ── Attack D: Auth Bypass ────────────────────────────────
  _setAttack('auth', authOk);

  // ── Attack E: Crash / DoS ────────────────────────────────
  _setAttack('payload', crashed);

  // ── Full Attack Log table ────────────────────────────────
  const logRows = fuzz.attack_results || [];
  const tbody = document.getElementById('attack-log-tbody');
  if (logRows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-muted)">No attack log entries — Docker was unavailable or scan did not run.</td></tr>`;
  } else {
    tbody.innerHTML = logRows.map(r => {
      const isVuln = (r.status || '').toUpperCase().includes('VULN') || (r.status || '').toUpperCase().includes('CRASH') || (r.status || '').toUpperCase().includes('CONFIRM') || (r.status || '').toUpperCase().includes('POSSIBLE');
      const statusColor = isVuln ? 'sev-critical' : 'sev-low';
      return `<tr>
        <td><span class="severity-pill ${statusColor}">${esc(r.attack || '—')}</span></td>
        <td>${esc(r.method || r.headers ? JSON.stringify(r.headers) : '—')}</td>
        <td style="font-family:'JetBrains Mono',monospace">${esc(r.endpoint || r.payload_size || '—')}</td>
        <td style="max-width:160px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(r.payload||'')}">${esc(r.payload || r.payload_size || '—')}</td>
        <td><span class="severity-pill ${statusColor}">${esc(r.status || '—')}</span></td>
      </tr>`;
    }).join('');
  }
}

function _setAttack(id, isVulnerable) {
  const badge  = document.getElementById(`${id}-badge`);
  const secure = document.getElementById(`${id}-secure`);
  const body   = document.getElementById(`${id}-body`);
  if (!badge) return;
  badge.textContent = isVulnerable ? 'VULNERABLE' : 'SECURE';
  badge.className   = `status-badge ${isVulnerable ? 'vulnerable' : 'secure'}`;
  if (secure) secure.style.display = isVulnerable ? 'none' : 'flex';
  if (body)   body.style.display   = isVulnerable ? 'grid' : 'none';
}

// ---- Threat Map ----
function renderThreatMap(diagram) {
  const empty   = document.getElementById('threatmap-empty');
  const content = document.getElementById('threatmap-content');
  const el      = document.getElementById('mermaid-diagram');

  if (!diagram) {
    empty.style.display   = 'block';
    content.style.display = 'none';
    return;
  }

  empty.style.display   = 'none';
  content.style.display = 'block';
  el.removeAttribute('data-processed');
  el.textContent = diagram;
  mermaid.run({ nodes: [el] });
}

// ---- Data Lake ----
async function loadScanHistory() {
  try {
    const res  = await fetch('/api/scans');
    if (!res.ok) return;
    scanHistory = await res.json();
    renderScanList();
  } catch (_) {}
}

function renderScanList() {
  const container = document.getElementById('scan-list');
  if (scanHistory.length === 0) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">◫</div><p>No scans found in the data lake.</p></div>`;
    return;
  }

  container.innerHTML = scanHistory.map((s, i) => `
    <div class="scan-list-item" onclick="selectScan('${s.filename}', ${i})" id="sli-${i}">
      <span style="font-size:16px">📄</span>
      <span class="scan-filename">${s.filename}</span>
      <span class="scan-created">${fmtDate(s.created)}</span>
    </div>
  `).join('');
}

async function selectScan(filename, idx) {
  // highlight
  document.querySelectorAll('.scan-list-item').forEach(el => el.classList.remove('selected'));
  const el = document.getElementById(`sli-${idx}`);
  if (el) el.classList.add('selected');

  document.getElementById('dl-hint').style.display = 'none';
  const viewer = document.getElementById('json-viewer');
  viewer.classList.add('visible');
  viewer.textContent = 'Loading…';

  try {
    const res  = await fetch(`/api/scans/${filename}`);
    const data = await res.json();
    viewer.textContent = JSON.stringify(data, null, 2);

    // Switch active data
    currentData = data;
    populateDashboard(data);
  } catch (e) {
    viewer.textContent = `Error: ${e.message}`;
  }
}

// ---- Helpers ----
function fmtDate(str) {
  if (!str) return '—';
  try { return new Date(str).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }); }
  catch (_) { return str; }
}

function showAlert(msg, type) {
  const existing = document.getElementById('temp-alert');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'temp-alert';
  div.className = `alert alert-${type}`;
  div.innerHTML = `<span class="alert-icon">${type === 'error' ? '⚠' : 'ℹ'}</span><span>${msg}</span>`;
  document.querySelector('.scan-hero').prepend(div);
  setTimeout(() => div.remove(), 5000);
}

// ============================================================
// AI Assistant Logic
// ============================================================

async function checkKBStatus() {
  try {
    const res = await fetch('/api/ai/status');
    const data = await res.json();
    const statusEl = document.getElementById('kb-status');
    if (data.db_populated) {
      statusEl.innerHTML = `<span style="color: #4ade80;">✅ Ready — ${data.chunks} chunks loaded</span>`;
    } else {
      statusEl.innerHTML = `<span style="color: #fbbf24;">⚠️ Knowledge base is empty. Please build it first.</span>`;
    }
  } catch (e) {
    console.error(e);
  }
}

async function buildKB() {
  const btn = document.getElementById('btn-build-kb');
  const statusEl = document.getElementById('kb-status');
  btn.disabled = true;
  btn.textContent = "Building... (this might take a while)";
  statusEl.textContent = "Fetching and embedding sources...";
  
  try {
    await fetch('/api/ai/build', {method: 'POST'});
    await checkKBStatus();
  } catch (e) {
    statusEl.textContent = `Error: ${e.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Build / Rebuild Knowledge Base";
  }
}

async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  
  input.value = '';
  const history = document.getElementById('chat-history');
  
  const userDiv = document.createElement('div');
  userDiv.style.alignSelf = 'flex-end';
  userDiv.style.background = '#2563eb';
  userDiv.style.color = '#fff';
  userDiv.style.padding = '10px 14px';
  userDiv.style.borderRadius = '14px 14px 0 14px';
  userDiv.style.maxWidth = '80%';
  userDiv.textContent = msg;
  history.appendChild(userDiv);
  history.scrollTop = history.scrollHeight;
  
  const aiDiv = document.createElement('div');
  aiDiv.style.alignSelf = 'flex-start';
  aiDiv.style.background = '#1e293b';
  aiDiv.style.color = '#fff';
  aiDiv.style.padding = '10px 14px';
  aiDiv.style.borderRadius = '14px 14px 14px 0';
  aiDiv.style.maxWidth = '80%';
  aiDiv.style.lineHeight = '1.5';
  aiDiv.textContent = 'Thinking...';
  history.appendChild(aiDiv);
  history.scrollTop = history.scrollHeight;
  
  try {
    const res = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg})
    });
    
    if (!res.ok) {
      const err = await res.json();
      aiDiv.textContent = `Error: ${err.detail || res.statusText}`;
      return;
    }
    
    aiDiv.textContent = '';
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, {stream: true});
      aiDiv.textContent += chunk;
      history.scrollTop = history.scrollHeight;
    }
  } catch (e) {
    aiDiv.textContent = `Error: ${e.message}`;
  }
}

document.addEventListener('DOMContentLoaded', checkKBStatus);
