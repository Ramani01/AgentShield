"""
AgentShield Security Observability Web UI (HTML/CSS/JS Single-Page Application).

Renders a local, read-only security observability interface served by FastAPI.
Includes glassmorphic dark styling, safe HTML escaping, 8 tabbed views, and live API binding.
"""

def get_dashboard_html() -> str:
    """Returns self-contained single-page HTML/CSS/JS dashboard interface."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield Security Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-card: rgba(18, 26, 43, 0.75);
      --bg-card-hover: rgba(28, 39, 64, 0.85);
      --border-card: rgba(255, 255, 255, 0.08);
      --border-highlight: rgba(99, 102, 241, 0.3);
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-indigo: #6366f1;
      --accent-cyan: #06b6d4;
      --pass-green: #10b981;
      --pass-bg: rgba(16, 185, 129, 0.15);
      --fail-red: #f43f5e;
      --fail-bg: rgba(244, 63, 94, 0.15);
      --review-amber: #f59e0b;
      --review-bg: rgba(245, 158, 11, 0.15);
      --error-purple: #a855f7;
      --error-bg: rgba(168, 85, 247, 0.15);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.08) 0px, transparent 50%);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: rgba(13, 19, 33, 0.8);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-card);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .brand-icon {
      font-size: 1.75rem;
    }
    .brand-title {
      font-family: 'Outfit', sans-serif;
      font-size: 1.4rem;
      font-weight: 700;
      background: linear-gradient(135deg, #818cf8 0%, #38bdf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-badge {
      font-size: 0.75rem;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      background: rgba(99, 102, 241, 0.2);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    select, button {
      font-family: 'Inter', sans-serif;
      background: var(--bg-card);
      color: var(--text-primary);
      border: 1px solid var(--border-card);
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      font-size: 0.875rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    select:hover, button:hover {
      border-color: var(--border-highlight);
      background: var(--bg-card-hover);
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent-indigo), #4f46e5);
      border: none;
      font-weight: 500;
    }
    .btn-primary:hover {
      opacity: 0.9;
    }

    .nav-tabs {
      background: rgba(13, 19, 33, 0.6);
      border-bottom: 1px solid var(--border-card);
      padding: 0 2rem;
      display: flex;
      gap: 0.5rem;
      overflow-x: auto;
    }
    .nav-tab {
      padding: 0.85rem 1.2rem;
      color: var(--text-secondary);
      font-size: 0.9rem;
      font-weight: 500;
      border-bottom: 2px solid transparent;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .nav-tab:hover {
      color: var(--text-primary);
    }
    .nav-tab.active {
      color: #818cf8;
      border-bottom-color: #818cf8;
    }

    main {
      flex: 1;
      padding: 2rem;
      max-width: 1400px;
      width: 100%;
      margin: 0 auto;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .grid-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }

    .card {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-card);
      border-radius: 0.75rem;
      padding: 1.25rem;
      transition: transform 0.2s, border-color 0.2s;
    }
    .card:hover {
      transform: translateY(-2px);
      border-color: var(--border-highlight);
    }

    .card-title {
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }
    .card-value {
      font-family: 'Outfit', sans-serif;
      font-size: 1.8rem;
      font-weight: 700;
    }
    .card-sub {
      font-size: 0.8rem;
      color: var(--text-secondary);
      margin-top: 0.3rem;
    }

    /* Status Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.65rem;
      border-radius: 0.375rem;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .badge-PASS, .badge-ALLOW { background: var(--pass-bg); color: var(--pass-green); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-FAIL, .badge-DENY { background: var(--fail-bg); color: var(--fail-red); border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge-REVIEW, .badge-ISOLATE { background: var(--review-bg); color: var(--review-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-ERROR { background: var(--error-bg); color: var(--error-purple); border: 1px solid rgba(168, 85, 247, 0.3); }
    .badge-NOT_EVALUATED { background: rgba(100, 116, 139, 0.15); color: var(--text-muted); border: 1px solid rgba(100, 116, 139, 0.3); }

    /* Tables */
    .table-container {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: 0.75rem;
      overflow: hidden;
      margin-bottom: 2rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.875rem;
    }
    th {
      background: rgba(15, 23, 42, 0.8);
      padding: 0.85rem 1.25rem;
      font-weight: 600;
      color: var(--text-secondary);
      border-bottom: 1px solid var(--border-card);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }
    td {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-card);
      color: var(--text-primary);
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    .code-font {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
    }

    /* Notice Banner */
    .banner {
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 0.5rem;
      padding: 0.85rem 1.25rem;
      margin-bottom: 1.5rem;
      font-size: 0.85rem;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    /* Modal Drawer */
    .modal-overlay {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      z-index: 200;
      justify-content: center;
      align-items: center;
    }
    .modal-overlay.active { display: flex; }
    .modal {
      background: #0f172a;
      border: 1px solid var(--border-highlight);
      border-radius: 0.75rem;
      width: 90%;
      max-width: 700px;
      max-height: 85vh;
      overflow-y: auto;
      padding: 1.5rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-card);
    }
    .modal-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 1.25rem;
      cursor: pointer;
    }
    pre {
      background: #090d16;
      border: 1px solid var(--border-card);
      padding: 1rem;
      border-radius: 0.5rem;
      overflow-x: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #38bdf8;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="brand-icon">🛡️</span>
      <span class="brand-title">AgentShield</span>
      <span class="brand-badge">Read-Only Observability</span>
    </div>
    <div class="header-actions">
      <label for="tenantSelect" style="font-size:0.8rem; color:var(--text-muted)">Tenant:</label>
      <select id="tenantSelect" onchange="refreshCurrentTab()">
        <option value="default">default</option>
        <option value="tenant_a">tenant_a</option>
        <option value="tenant_b">tenant_b</option>
      </select>
      <button onclick="refreshCurrentTab()" class="btn-primary">🔄 Refresh</button>
    </div>
  </header>

  <nav class="nav-tabs">
    <div class="nav-tab active" onclick="switchTab('overview')">📊 Overview</div>
    <div class="nav-tab" onclick="switchTab('controls')">🛡️ Controls Matrix</div>
    <div class="nav-tab" onclick="switchTab('findings')">⚠️ Findings</div>
    <div class="nav-tab" onclick="switchTab('benchmark')">⚡ Benchmark</div>
    <div class="nav-tab" onclick="switchTab('tools')">🔧 Tool Governance</div>
    <div class="nav-tab" onclick="switchTab('checkpoints')">💾 Checkpoints</div>
    <div class="nav-tab" onclick="switchTab('audit')">📜 Audit Activity</div>
    <div class="nav-tab" onclick="switchTab('evaluations')">⏳ History</div>
  </nav>

  <main>
    <div class="banner">
      <span>ℹ️</span>
      <div>
        <strong>Local Read-Only Security Observability</strong> — Displays security decisions produced by AgentShield's evaluation pipeline, benchmark runner, and governance components.
      </div>
    </div>

    <!-- TAB 1: OVERVIEW -->
    <div id="tab-overview" class="tab-content active">
      <div class="grid-cards">
        <div class="card">
          <div class="card-title">Overall Security Posture</div>
          <div id="ov-decision" class="card-value">-</div>
          <div id="ov-status" class="card-sub">-</div>
        </div>
        <div class="card">
          <div class="card-title">Controls Evaluated</div>
          <div id="ov-controls" class="card-value">13 / 13</div>
          <div id="ov-controls-sub" class="card-sub">Pass: 0 | Review: 0 | Fail: 0</div>
        </div>
        <div class="card">
          <div class="card-title">Security Findings</div>
          <div id="ov-findings" class="card-value">0</div>
          <div class="card-sub">Active Security Findings</div>
        </div>
        <div class="card">
          <div class="card-title">Benchmark Pass Rate</div>
          <div id="ov-benchmark" class="card-value">100%</div>
          <div id="ov-corpus" class="card-sub">Corpus v1.0.0 (68 Cases)</div>
        </div>
      </div>

      <h3 style="margin-bottom: 1rem;">Latest Evaluation Breakdown</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Control Name</th>
              <th>Category</th>
              <th>Status</th>
              <th>Decision</th>
              <th>Severity</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="overview-controls-body">
            <!-- Rendered dynamically -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 2: CONTROLS MATRIX -->
    <div id="tab-controls" class="tab-content">
      <h3 style="margin-bottom: 1rem;">AgentShield 13 Security Controls Matrix</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Name</th>
              <th>Category</th>
              <th>Status</th>
              <th>Decision</th>
              <th>Severity</th>
              <th>Last Evaluated</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody id="controls-matrix-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: FINDINGS -->
    <div id="tab-findings" class="tab-content">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1rem;">
        <h3>Security Findings</h3>
        <div style="display:flex; gap:0.5rem;">
          <select id="filterSeverity" onchange="loadFindings()">
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Finding ID</th>
              <th>Control</th>
              <th>Severity</th>
              <th>Title</th>
              <th>Description</th>
              <th>Decision</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: BENCHMARK -->
    <div id="tab-benchmark" class="tab-content">
      <div class="grid-cards">
        <div class="card">
          <div class="card-title">Benchmark Pass Rate</div>
          <div id="bench-pass-rate" class="card-value">100.0%</div>
          <div class="card-sub">Measured on Local Fixtures</div>
        </div>
        <div class="card">
          <div class="card-title">Corpus Version</div>
          <div id="bench-version" class="card-value">1.0.0</div>
          <div class="card-sub">AgentShield Evaluation Corpus</div>
        </div>
        <div class="card">
          <div class="card-title">Total Cases</div>
          <div id="bench-cases" class="card-value">68</div>
          <div id="bench-cases-sub" class="card-sub">Passed: 68 | Failed: 0</div>
        </div>
        <div class="card">
          <div class="card-title">Candidate Discrepancies</div>
          <div id="bench-discrepancies" class="card-value">FP: 0 | FN: 0</div>
          <div class="card-sub">Benchmark-Relative Findings</div>
        </div>
      </div>

      <h3 style="margin-bottom: 1rem;">Category Coverage</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Category Name</th>
              <th>Total Cases</th>
              <th>Passed</th>
              <th>Failed</th>
              <th>Coverage Status</th>
            </tr>
          </thead>
          <tbody id="benchmark-categories-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 5: TOOL GOVERNANCE -->
    <div id="tab-tools" class="tab-content">
      <h3 style="margin-bottom: 1rem;">Tool-Change Governance (Phase 14)</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Tool ID</th>
              <th>Name</th>
              <th>Version</th>
              <th>Baseline Fingerprint</th>
              <th>Current Fingerprint</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody id="tools-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 6: CHECKPOINTS -->
    <div id="tab-checkpoints" class="tab-content">
      <h3 style="margin-bottom: 1rem;">Security Checkpoints (Phase 15)</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Checkpoint ID</th>
              <th>Created By</th>
              <th>Status</th>
              <th>State Fingerprint</th>
              <th>Baselines</th>
              <th>Created At</th>
            </tr>
          </thead>
          <tbody id="checkpoints-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 7: AUDIT ACTIVITY -->
    <div id="tab-audit" class="tab-content">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1rem;">
        <h3>Audit Activity Log (Phase 6)</h3>
        <div id="audit-integrity-badge"></div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Event Type</th>
              <th>Tenant</th>
              <th>Hash Signature</th>
              <th>Previous Hash</th>
            </tr>
          </thead>
          <tbody id="audit-body"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 8: EVALUATIONS -->
    <div id="tab-evaluations" class="tab-content">
      <h3 style="margin-bottom: 1rem;">Historical Evaluations</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Evaluation ID</th>
              <th>Timestamp</th>
              <th>Scope</th>
              <th>Status</th>
              <th>Decision</th>
              <th>Findings</th>
              <th>Fingerprint</th>
            </tr>
          </thead>
          <tbody id="evaluations-body"></tbody>
        </table>
      </div>
    </div>
  </main>

  <!-- MODAL DRAWER FOR CONTROL DETAIL -->
  <div id="modalOverlay" class="modal-overlay" onclick="closeModal(event)">
    <div class="modal" onclick="event.stopPropagation()">
      <div class="modal-header">
        <h3 id="modalTitle">Control Detail</h3>
        <button class="modal-close" onclick="closeModalDirect()">✕</button>
      </div>
      <div id="modalBody">
        <!-- Rendered dynamically -->
      </div>
    </div>
  </div>

  <script>
    let currentTab = 'overview';

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function switchTab(tabId) {
      currentTab = tabId;
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      event.target.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');

      refreshCurrentTab();
    }

    function refreshCurrentTab() {
      const tenant = document.getElementById('tenantSelect').value;
      if (currentTab === 'overview') loadOverview(tenant);
      else if (currentTab === 'controls') loadControls(tenant);
      else if (currentTab === 'findings') loadFindings(tenant);
      else if (currentTab === 'benchmark') loadBenchmark();
      else if (currentTab === 'tools') loadTools(tenant);
      else if (currentTab === 'checkpoints') loadCheckpoints(tenant);
      else if (currentTab === 'audit') loadAudit(tenant);
      else if (currentTab === 'evaluations') loadEvaluations(tenant);
    }

    async function fetchApi(url) {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } catch (e) {
        console.error("API error:", e);
        return null;
      }
    }

    async function loadOverview(tenant) {
      const data = await fetchApi(`/api/dashboard/overview?tenant_id=${tenant}`);
      if (!data) return;

      document.getElementById('ov-decision').innerHTML = `<span class="badge badge-${escapeHtml(data.overall_decision)}">${escapeHtml(data.overall_decision)}</span>`;
      document.getElementById('ov-status').innerText = `Status: ${data.status}`;
      document.getElementById('ov-controls-sub').innerText = `Pass: ${data.passed_controls} | Review: ${data.review_controls} | Fail: ${data.failed_controls}`;
      document.getElementById('ov-findings').innerText = data.findings_count;
      document.getElementById('ov-benchmark').innerText = `${data.benchmark_pass_rate}%`;
      document.getElementById('ov-corpus').innerText = `Corpus v${data.corpus_version} (Pass Rate)`;

      const controls = await fetchApi(`/api/dashboard/controls?tenant_id=${tenant}`);
      if (!controls) return;

      let html = '';
      controls.slice(0, 6).forEach(c => {
        html += `<tr>
          <td class="code-font">${escapeHtml(c.control_id)}</td>
          <td>${escapeHtml(c.control_name)}</td>
          <td>${escapeHtml(c.category)}</td>
          <td><span class="badge badge-${escapeHtml(c.latest_status)}">${escapeHtml(c.latest_status)}</span></td>
          <td><span class="badge badge-${escapeHtml(c.latest_decision)}">${escapeHtml(c.latest_decision)}</span></td>
          <td>${escapeHtml(c.severity)}</td>
          <td><button onclick="inspectControl('${escapeHtml(c.control_id)}')">Inspect</button></td>
        </tr>`;
      });
      document.getElementById('overview-controls-body').innerHTML = html;
    }

    async function loadControls(tenant) {
      const controls = await fetchApi(`/api/dashboard/controls?tenant_id=${tenant}`);
      if (!controls) return;

      let html = '';
      controls.forEach(c => {
        html += `<tr>
          <td class="code-font">${escapeHtml(c.control_id)}</td>
          <td><strong>${escapeHtml(c.control_name)}</strong></td>
          <td>${escapeHtml(c.category)}</td>
          <td><span class="badge badge-${escapeHtml(c.latest_status)}">${escapeHtml(c.latest_status)}</span></td>
          <td><span class="badge badge-${escapeHtml(c.latest_decision)}">${escapeHtml(c.latest_decision)}</span></td>
          <td>${escapeHtml(c.severity)}</td>
          <td>${new Date(c.last_evaluated_at * 1000).toLocaleTimeString()}</td>
          <td><button onclick="inspectControl('${escapeHtml(c.control_id)}')">Inspect</button></td>
        </tr>`;
      });
      document.getElementById('controls-matrix-body').innerHTML = html;
    }

    async function inspectControl(controlId) {
      const tenant = document.getElementById('tenantSelect').value;
      const detail = await fetchApi(`/api/dashboard/controls/${controlId}?tenant_id=${tenant}`);
      if (!detail) return;

      document.getElementById('modalTitle').innerText = `${detail.control_id}: ${detail.control_name}`;
      let html = `
        <div style="margin-bottom: 1rem;">
          <p style="color:var(--text-secondary); margin-bottom:0.5rem;">${escapeHtml(detail.description)}</p>
          <div style="display:flex; gap:0.5rem; margin-bottom:1rem;">
            <span class="badge badge-${escapeHtml(detail.latest_status)}">${escapeHtml(detail.latest_status)}</span>
            <span class="badge badge-${escapeHtml(detail.latest_decision)}">${escapeHtml(detail.latest_decision)}</span>
            <span class="badge badge-${escapeHtml(detail.severity)}">${escapeHtml(detail.severity)}</span>
          </div>
          <p><strong>Reason:</strong> ${escapeHtml(detail.reason)}</p>
        </div>
        <h4 style="margin-bottom:0.5rem;">Evidence (Sanitized)</h4>
        <pre>${escapeHtml(JSON.stringify(detail.evidence, null, 2))}</pre>
      `;
      document.getElementById('modalBody').innerHTML = html;
      document.getElementById('modalOverlay').classList.add('active');
    }

    function closeModal(event) {
      document.getElementById('modalOverlay').classList.remove('active');
    }
    function closeModalDirect() {
      document.getElementById('modalOverlay').classList.remove('active');
    }

    async function loadFindings(tenant) {
      const tenantVal = tenant || document.getElementById('tenantSelect').value;
      const sev = document.getElementById('filterSeverity').value;
      let url = `/api/dashboard/findings?tenant_id=${tenantVal}`;
      if (sev) url += `&severity=${sev}`;

      const findings = await fetchApi(url);
      if (!findings) return;

      let html = '';
      if (findings.length === 0) {
        html = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted)">No active findings matching filters</td></tr>`;
      } else {
        findings.forEach(f => {
          html += `<tr>
            <td class="code-font">${escapeHtml(f.finding_id.substring(0, 8))}...</td>
            <td class="code-font">${escapeHtml(f.control_id)}</td>
            <td><span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
            <td><strong>${escapeHtml(f.title)}</strong></td>
            <td>${escapeHtml(f.description)}</td>
            <td><span class="badge badge-${escapeHtml(f.decision)}">${escapeHtml(f.decision)}</span></td>
            <td>${new Date(f.timestamp * 1000).toLocaleTimeString()}</td>
          </tr>`;
        });
      }
      document.getElementById('findings-body').innerHTML = html;
    }

    async function loadBenchmark() {
      const summary = await fetchApi(`/api/dashboard/benchmark`);
      if (summary) {
        document.getElementById('bench-pass-rate').innerText = `${summary.pass_rate}%`;
        document.getElementById('bench-version').innerText = summary.corpus_version;
        document.getElementById('bench-cases').innerText = summary.total_cases;
        document.getElementById('bench-cases-sub').innerText = `Passed: ${summary.passed_cases} | Failed: ${summary.failed_cases}`;
        document.getElementById('bench-discrepancies').innerText = `FP: ${summary.false_positive_candidates} | FN: ${summary.false_negative_candidates}`;
      }

      const categories = await fetchApi(`/api/dashboard/benchmark/categories`);
      if (!categories) return;

      let html = '';
      categories.forEach(cat => {
        html += `<tr>
          <td><strong>${escapeHtml(cat.category_name)}</strong></td>
          <td>${cat.total_cases}</td>
          <td><span style="color:var(--pass-green)">${cat.passed_cases}</span></td>
          <td><span style="color:${cat.failed_cases > 0 ? 'var(--fail-red)' : 'var(--text-muted)'}">${cat.failed_cases}</span></td>
          <td><span class="badge badge-PASS">${escapeHtml(cat.coverage_status)}</span></td>
        </tr>`;
      });
      document.getElementById('benchmark-categories-body').innerHTML = html;
    }

    async function loadTools(tenant) {
      const tools = await fetchApi(`/api/dashboard/tools?tenant_id=${tenant}`);
      if (!tools) return;

      let html = '';
      if (tools.length === 0) {
        html = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted)">No registered tools</td></tr>`;
      } else {
        tools.forEach(t => {
          html += `<tr>
            <td class="code-font">${escapeHtml(t.tool_id)}</td>
            <td>${escapeHtml(t.name)}</td>
            <td>${escapeHtml(t.version)}</td>
            <td class="code-font">${escapeHtml(t.baseline_fingerprint.substring(0, 10))}...</td>
            <td class="code-font">${escapeHtml(t.current_fingerprint.substring(0, 10))}...</td>
            <td><span class="badge badge-${t.status === 'UNCHANGED' ? 'PASS' : 'REVIEW'}">${escapeHtml(t.status)}</span></td>
            <td>${escapeHtml(t.severity)}</td>
            <td><span class="badge badge-${escapeHtml(t.decision)}">${escapeHtml(t.decision)}</span></td>
          </tr>`;
        });
      }
      document.getElementById('tools-body').innerHTML = html;
    }

    async function loadCheckpoints(tenant) {
      const chks = await fetchApi(`/api/dashboard/checkpoints?tenant_id=${tenant}`);
      if (!chks) return;

      let html = '';
      if (chks.length === 0) {
        html = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted)">No security checkpoints recorded</td></tr>`;
      } else {
        chks.forEach(c => {
          html += `<tr>
            <td class="code-font">${escapeHtml(c.checkpoint_id)}</td>
            <td>${escapeHtml(c.created_by)}</td>
            <td><span class="badge badge-${c.status === 'ACTIVE' ? 'PASS' : 'REVIEW'}">${escapeHtml(c.status)}</span></td>
            <td class="code-font">${escapeHtml(c.state_fingerprint.substring(0, 12))}...</td>
            <td>${c.tool_baseline_count} tools</td>
            <td>${new Date(c.created_at * 1000).toLocaleTimeString()}</td>
          </tr>`;
        });
      }
      document.getElementById('checkpoints-body').innerHTML = html;
    }

    async function loadAudit(tenant) {
      const summary = await fetchApi(`/api/dashboard/audit?tenant_id=${tenant}`);
      if (!summary) return;

      const integrity = summary.integrity;
      document.getElementById('audit-integrity-badge').innerHTML = integrity.valid
        ? `<span class="badge badge-PASS">Integrity Verified (${integrity.entries_checked} Entries)</span>`
        : `<span class="badge badge-FAIL">Chain Tampered!</span>`;

      let html = '';
      if (summary.events.length === 0) {
        html = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted)">No audit events recorded</td></tr>`;
      } else {
        summary.events.reverse().forEach(e => {
          html += `<tr>
            <td>${new Date(e.timestamp * 1000).toLocaleTimeString()}</td>
            <td><strong>${escapeHtml(e.event_type)}</strong></td>
            <td>${escapeHtml(e.tenant_id)}</td>
            <td class="code-font">${escapeHtml(e.hash ? e.hash.substring(0, 12) + '...' : '-')}</td>
            <td class="code-font">${escapeHtml(e.prev_hash ? e.prev_hash.substring(0, 12) + '...' : '-')}</td>
          </tr>`;
        });
      }
      document.getElementById('audit-body').innerHTML = html;
    }

    async function loadEvaluations(tenant) {
      const evals = await fetchApi(`/api/dashboard/evaluations?tenant_id=${tenant}`);
      if (!evals) return;

      let html = '';
      if (evals.length === 0) {
        html = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted)">No historical evaluation runs recorded</td></tr>`;
      } else {
        evals.reverse().forEach(e => {
          html += `<tr>
            <td class="code-font">${escapeHtml(e.evaluation_id)}</td>
            <td>${new Date(e.evaluated_at * 1000).toLocaleTimeString()}</td>
            <td>${escapeHtml(e.scope)}</td>
            <td><span class="badge badge-${escapeHtml(e.status)}">${escapeHtml(e.status)}</span></td>
            <td><span class="badge badge-${escapeHtml(e.overall_decision)}">${escapeHtml(e.overall_decision)}</span></td>
            <td>${e.findings_count}</td>
            <td class="code-font">${escapeHtml(e.evaluation_fingerprint ? e.evaluation_fingerprint.substring(0, 12) + '...' : '-')}</td>
          </tr>`;
        });
      }
      document.getElementById('evaluations-body').innerHTML = html;
    }

    // Initial load
    refreshCurrentTab();
  </script>
</body>
</html>
"""
