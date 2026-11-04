/* ============================================================
   Network AI | Threat Defense — dashboard.js
   All API calls, chart rendering, page navigation, form handling
   ============================================================ */

'use strict';

const API_BASE = '';

/* ═══════════════════════════════════════════════════════════
   GLOBALS
═══════════════════════════════════════════════════════════ */
let trafficChart = null;
let severityChart = null;
let dashboardInterval = null;
let trafficInterval = null;
let currentAlertPage = 1;
const ALERTS_PER_PAGE = 8;
let allAlerts = [];
let filteredAlerts = [];

/* ═══════════════════════════════════════════════════════════
   SAMPLE DATA (used when API unavailable / for demo)
═══════════════════════════════════════════════════════════ */
const SAMPLE_NORMAL = {
  duration:0, protocol_type:'tcp', service:'http', flag:'SF',
  src_bytes:215, dst_bytes:45076, land:0, wrong_fragment:0, urgent:0,
  hot:0, num_failed_logins:0, logged_in:1, num_compromised:0, root_shell:0,
  su_attempted:0, num_root:0, num_file_creations:0, num_shells:0,
  num_access_files:0, num_outbound_cmds:0, is_host_login:0, is_guest_login:0,
  count:1, srv_count:1, serror_rate:0, srv_serror_rate:0, rerror_rate:0,
  srv_rerror_rate:0, same_srv_rate:1, diff_srv_rate:0, srv_diff_host_rate:0,
  dst_host_count:255, dst_host_srv_count:11, dst_host_same_srv_rate:0.04,
  dst_host_diff_srv_rate:0.06, dst_host_same_src_port_rate:0,
  dst_host_srv_diff_host_rate:0, dst_host_serror_rate:0,
  dst_host_srv_serror_rate:0, dst_host_rerror_rate:0, dst_host_srv_rerror_rate:0
};

const SAMPLE_ATTACK = {
  duration:0, protocol_type:'tcp', service:'private', flag:'REJ',
  src_bytes:0, dst_bytes:0, land:0, wrong_fragment:0, urgent:0,
  hot:0, num_failed_logins:0, logged_in:0, num_compromised:0, root_shell:0,
  su_attempted:0, num_root:0, num_file_creations:0, num_shells:0,
  num_access_files:0, num_outbound_cmds:0, is_host_login:0, is_guest_login:0,
  count:229, srv_count:10, serror_rate:0, srv_serror_rate:0, rerror_rate:1,
  srv_rerror_rate:1, same_srv_rate:0.04, diff_srv_rate:0.06, srv_diff_host_rate:0,
  dst_host_count:255, dst_host_srv_count:10, dst_host_same_srv_rate:0.04,
  dst_host_diff_srv_rate:0.06, dst_host_same_src_port_rate:0,
  dst_host_srv_diff_host_rate:0, dst_host_serror_rate:0,
  dst_host_srv_serror_rate:0, dst_host_rerror_rate:1, dst_host_srv_rerror_rate:1
};

/* ═══════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
═══════════════════════════════════════════════════════════ */
const TOAST_ICONS = {
  success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  error:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
  warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
};

function showToast(type, title, message, duration = 4000) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${TOAST_ICONS[type]}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      ${message ? `<div class="toast-msg">${message}</div>` : ''}
    </div>
    <button class="toast-close" onclick="dismissToast(this.parentElement)">×</button>`;
  container.appendChild(toast);
  setTimeout(() => dismissToast(toast), duration);
}

function dismissToast(el) {
  if (!el || !el.parentElement) return;
  el.classList.add('fade-out');
  setTimeout(() => el.remove(), 300);
}

/* ═══════════════════════════════════════════════════════════
   NAVIGATION
═══════════════════════════════════════════════════════════ */
function navigate(page) {
  // Hide all pages
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  // Show target
  const section = document.getElementById(`page-${page}`);
  if (section) section.classList.add('active');
  const navItem = document.querySelector(`[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');

  // Update topbar title
  const titles = {
    dashboard: 'Dashboard', monitor: 'Live Network Monitoring',
    traffic: 'Traffic Investigation', agent: 'AI SOC Agent',
    detection: 'Detection Lab', alerts: 'Alerts',
    reports: 'Reports', performance: 'Model Performance',
    settings: 'Settings'
  };
  const el = document.getElementById('topbarTitle');
  if (el) el.textContent = titles[page] || 'Dashboard';

  // Clear auto-refresh intervals on leave
  if (page !== 'dashboard' && dashboardInterval) {
    clearInterval(dashboardInterval); dashboardInterval = null;
  }
  if (page !== 'traffic' && trafficInterval) {
    clearInterval(trafficInterval); trafficInterval = null;
  }
  if (page !== 'monitor' && liveMonitorPollInterval) {
    clearInterval(liveMonitorPollInterval); liveMonitorPollInterval = null;
  }

  // Load page data
  if (page === 'dashboard')   initDashboard();
  if (page === 'monitor')     initMonitorPage();
  if (page === 'traffic')     initTraffic();
  if (page === 'agent')       initAgentPage();
  if (page === 'alerts')      initAlerts();
  if (page === 'performance') loadModelPerformance();
  if (page === 'reports')     loadReportStats();
}

/* ═══════════════════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════════════════ */
function initDashboard() {
  loadDashboard();
  if (!dashboardInterval) {
    dashboardInterval = setInterval(loadDashboard, 60000);
  }
}

async function loadDashboard() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    updateMetricCards(data);
    updateCharts(data);
    loadRecentAlerts();
    updateModelStatusCard(data.model_info);
  } catch (err) {
    // Use synthetic demo data when API unavailable
    const demo = generateDemoStats();
    updateMetricCards(demo);
    updateCharts(demo);
    loadRecentAlerts();
  }
}

function generateDemoStats() {
  const now = Date.now();
  const hours = Array.from({length: 24}, (_, i) => {
    const t = new Date(now - (23 - i) * 3600000);
    return t.getHours().toString().padStart(2,'0') + ':00';
  });
  return {
    total_predictions: 18472,
    attacks_detected: 3241,
    active_alerts: 12,
    model_accuracy: 99.2,
    traffic_labels: hours,
    traffic_normal: hours.map(() => Math.floor(Math.random()*600 + 200)),
    traffic_attack: hours.map(() => Math.floor(Math.random()*80)),
    severity_counts: { critical: 4, high: 8, medium: 23, low: 41 },
    model_info: { type: 'Random Forest', features: 41, status: 'Loaded', version: '2.1.0' }
  };
}

function updateMetricCards(data) {
  const safe = (v, fb = '—') => (v !== undefined && v !== null) ? v : fb;
  const preds = data.total_predictions ?? 0;
  const attacks = data.attacks_detected ?? data.total_attacks ?? 0;
  const alerts = data.active_alerts ?? data.open_alerts ?? data.total_alerts ?? 0;
  const acc = data.model_accuracy ?? (data.accuracy ? (data.accuracy * 100).toFixed(1) : 77.3);
  setText('metricPredictions', safe(preds).toLocaleString());
  setText('metricAttacks',     safe(attacks).toLocaleString());
  setText('metricAlerts',      safe(alerts));
  setText('metricAccuracy',    safe(acc) + (acc !== '—' ? '%' : ''));
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function updateCharts(data) {
  // Traffic Line Chart
  const tCtx = document.getElementById('trafficChart');
  if (tCtx) {
    const labels = data.traffic_labels || generateTimeLabels();
    const normal = data.traffic_normal || labels.map(() => Math.floor(Math.random()*500+100));
    const attack = data.traffic_attack || labels.map(() => Math.floor(Math.random()*60));

    if (trafficChart) trafficChart.destroy();
    trafficChart = new Chart(tCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Normal Traffic',
            data: normal,
            borderColor: '#2DD4BF',
            backgroundColor: 'rgba(45,212,191,.08)',
            borderWidth: 2,
            fill: true,
            tension: .4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: '#2DD4BF'
          },
          {
            label: 'Attack Traffic',
            data: attack,
            borderColor: '#EF4444',
            backgroundColor: 'rgba(239,68,68,.08)',
            borderWidth: 2,
            fill: true,
            tension: .4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: '#EF4444'
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#94A3B8', font: { family: 'Inter', size: 12 }, usePointStyle: true } },
          tooltip: { backgroundColor: '#111A2E', borderColor: '#1E2D4A', borderWidth: 1,
            titleColor: '#F1F5F9', bodyColor: '#94A3B8', padding: 10 }
        },
        scales: {
          x: { grid: { color: 'rgba(30,45,74,.5)' }, ticks: { color: '#94A3B8', font: { size: 11 }, maxTicksLimit: 8 } },
          y: { grid: { color: 'rgba(30,45,74,.5)' }, ticks: { color: '#94A3B8', font: { size: 11 } }, beginAtZero: true }
        }
      }
    });
  }

  // Severity Doughnut
  const sCtx = document.getElementById('severityChart');
  if (sCtx) {
    const sc = data.severity_counts || data.severity_distribution || { critical:4, high:8, medium:23, low:41 };
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [sc.critical||0, sc.high||0, sc.medium||0, sc.low||0],
          backgroundColor: ['rgba(239,68,68,.85)', 'rgba(249,115,22,.85)', 'rgba(234,179,8,.85)', 'rgba(59,130,246,.85)'],
          borderColor: ['#EF4444','#F97316','#EAB308','#3B82F6'],
          borderWidth: 2,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '70%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94A3B8', font: { family: 'Inter', size: 12 }, padding: 16, usePointStyle: true } },
          tooltip: { backgroundColor: '#111A2E', borderColor: '#1E2D4A', borderWidth: 1,
            titleColor: '#F1F5F9', bodyColor: '#94A3B8', padding: 10 }
        }
      }
    });
  }
}

function generateTimeLabels() {
  const now = new Date();
  return Array.from({length: 24}, (_, i) => {
    const t = new Date(now - (23 - i) * 3600000);
    return t.getHours().toString().padStart(2,'0') + ':00';
  });
}

function updateModelStatusCard(info) {
  const defaults = { type: 'Random Forest', features: 41, status: 'Loaded', version: '2.1.0' };
  const mi = info || defaults;
  setText('msModelType',    mi.type || defaults.type);
  setText('msFeatures',     mi.features || defaults.features);
  setText('msModelVersion', mi.version || defaults.version);
  setText('msModelStatus',  mi.status || defaults.status);
}

async function loadRecentAlerts() {
  const tbody = document.getElementById('recentAlertsBody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="5"><div class="spinner-wrap"><div class="spinner"></div></div></td></tr>`;
  try {
    const res = await fetch(`${API_BASE}/api/alerts?limit=5`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    renderRecentAlerts(tbody, data.alerts || data);
  } catch {
    renderRecentAlerts(tbody, getDemoAlerts().slice(0, 5));
  }
}

function renderRecentAlerts(tbody, alerts) {
  if (!alerts || !alerts.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><p>No recent alerts</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="text-muted" style="font-size:11px">${a.id || a.alert_id || '—'}</span></td>
      <td>${a.time || a.timestamp || new Date().toLocaleTimeString()}</td>
      <td><span class="badge badge-${(a.severity||'medium').toLowerCase()}">${a.severity||'Medium'}</span></td>
      <td>${a.title || a.description || 'Unknown Alert'}</td>
      <td><span class="badge badge-${(a.status||'open').toLowerCase()}">${a.status||'Open'}</span></td>
    </tr>`).join('');
}

/* ═══════════════════════════════════════════════════════════
   TRAFFIC ANALYSIS
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   TRAFFIC ANALYSIS & CSV INVESTIGATION MODULE
═══════════════════════════════════════════════════════════ */
let taAttackChart = null;
let taSeverityChart = null;
let taProtocolChart = null;
let taIpChart = null;
let currentAnalysisId = null;
let currentAnalysisData = null;
let currentAnalysisRecords = [];
let currentTaPage = 1;
let selectedTrafficFile = null;
let taSearchDebounceTimer = null;

function initTraffic() {
  setupTrafficDropZone();
  loadTrafficHistory();
}

function setupTrafficDropZone() {
  const dropZone = document.getElementById('trafficDropZone');
  if (!dropZone || dropZone._bound) return;
  dropZone._bound = true;

  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      processSelectedFile(files[0]);
    }
  }, false);
}

function handleTrafficFileSelect(input) {
  if (input.files && input.files[0]) {
    processSelectedFile(input.files[0]);
  }
}

function processSelectedFile(file) {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    showToast('error', 'Invalid File Type', 'Please upload a CSV (.csv) file.');
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    showToast('error', 'File Too Large', 'Maximum file size is 10 MB.');
    return;
  }

  selectedTrafficFile = file;
  document.getElementById('trafficSelectedFilename').textContent = file.name;
  document.getElementById('trafficSelectedFilesize').textContent = formatBytes(file.size);
  document.getElementById('trafficFileBar').classList.remove('hidden');
}

function clearTrafficFileSelection() {
  selectedTrafficFile = null;
  const input = document.getElementById('trafficFileInput');
  if (input) input.value = '';
  document.getElementById('trafficFileBar').classList.add('hidden');
}

async function executeTrafficUpload() {
  if (!selectedTrafficFile) {
    showToast('warning', 'No File Selected', 'Please select or drag-and-drop a CSV file first.');
    return;
  }

  const formData = new FormData();
  formData.append('file', selectedTrafficFile);

  const loader = document.getElementById('trafficUploadLoading');
  const fileBar = document.getElementById('trafficFileBar');
  loader.classList.remove('hidden');
  fileBar.classList.add('hidden');

  try {
    const res = await fetch(`${API_BASE}/api/traffic/upload`, {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    loader.classList.add('hidden');

    if (!res.ok) {
      const msg = data.details?.file || data.message || 'CSV upload failed';
      showToast('error', 'Analysis Failed', msg);
      fileBar.classList.remove('hidden');
      return;
    }

    showToast('success', 'Analysis Completed', `Processed ${data.total_rows} connection records successfully.`);
    clearTrafficFileSelection();
    displayAnalysisResults(data);
    loadTrafficHistory();
  } catch (err) {
    loader.classList.add('hidden');
    fileBar.classList.remove('hidden');
    showToast('error', 'Network Error', 'Failed to communicate with analysis server.');
  }
}

async function loadSampleTraffic(sampleType) {
  const loader = document.getElementById('trafficUploadLoading');
  const loaderTitle = document.getElementById('trafficLoadingTitle');
  const loaderSub = document.getElementById('trafficLoadingSub');

  loaderTitle.textContent = `Loading Demo Dataset: ${sampleType.toUpperCase()} (500 records)...`;
  loaderSub.textContent = 'Running model inference and extracting threat vectors...';
  loader.classList.remove('hidden');

  try {
    const res = await fetch(`${API_BASE}/api/traffic/load-sample/${sampleType}`, {
      method: 'POST',
    });
    const data = await res.json();
    loader.classList.add('hidden');

    if (!res.ok) {
      showToast('error', 'Sample Error', data.message || 'Failed to load demo dataset');
      return;
    }

    showToast('success', 'Demo Loaded', `Evaluated 500 ${sampleType} records via Random Forest pipeline.`);
    displayAnalysisResults(data);
    loadTrafficHistory();
  } catch (err) {
    loader.classList.add('hidden');
    showToast('error', 'Network Error', 'Could not load demo dataset.');
  }
}

async function loadTrafficHistory() {
  const tbody = document.getElementById('taHistoryTableBody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/traffic/history`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    const history = data.history || [];
    renderTrafficHistory(history);

    // If no analysis is currently displayed but history exists, load the latest
    if (!currentAnalysisId && history.length > 0) {
      loadAnalysisDetails(history[0].id);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><p>No analysis history available</p></div></td></tr>`;
  }
}

function renderTrafficHistory(history) {
  const tbody = document.getElementById('taHistoryTableBody');
  if (!tbody) return;

  if (!history || history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><p>No previous uploads recorded yet. Upload a CSV to start.</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = history.map(h => {
    const isCurrent = h.id === currentAnalysisId;
    const activeBadge = isCurrent ? `<span class="tag" style="background:rgba(45,212,191,.15);color:var(--success)">ACTIVE</span>` : '';
    const gtBadge = h.has_ground_truth
      ? `<span class="badge badge-normal" style="font-size:10px">Validated</span>`
      : `<span style="color:var(--text-secondary);font-size:11px">Unlabeled</span>`;

    return `
      <tr style="${isCurrent ? 'background:rgba(56,189,248,.04)' : ''}">
        <td class="font-mono" style="font-size:11px">#${h.id}</td>
        <td>
          <div style="font-weight:600;display:flex;align-items:center;gap:6px">
            ${h.filename} ${activeBadge}
          </div>
        </td>
        <td style="font-size:12px;color:var(--text-secondary)">${new Date(h.timestamp).toLocaleString()}</td>
        <td class="font-mono">${h.total_rows.toLocaleString()}</td>
        <td><span class="badge badge-safe">${h.normal_count}</span></td>
        <td><span class="badge badge-attack">${h.attack_count}</span></td>
        <td><span class="badge badge-suspicious">${h.suspicious_count}</span></td>
        <td>${gtBadge}</td>
        <td style="text-align:right">
          <div style="display:inline-flex;gap:6px">
            <button class="btn btn-secondary btn-sm" onclick="loadAnalysisDetails(${h.id})" title="View Dashboard">
              Inspect
            </button>
            <a class="btn btn-secondary btn-sm" href="${API_BASE}/api/traffic/export/${h.id}" title="Download Results CSV">
              Results CSV
            </a>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function loadAnalysisDetails(analysisId, page = 1) {
  currentAnalysisId = analysisId;
  currentTaPage = page;

  const status = document.getElementById('taFilterStatus')?.value || 'all';
  const severity = document.getElementById('taFilterSeverity')?.value || 'all';
  const protocol = document.getElementById('taFilterProtocol')?.value || 'all';
  const search = document.getElementById('taSearchInput')?.value || '';

  const params = new URLSearchParams({
    page: page,
    per_page: 25,
    status: status,
    severity: severity,
    protocol: protocol,
    search: search,
  });

  const tbody = document.getElementById('taRecordsTableBody');
  if (tbody) showTableLoading(tbody, 11);

  try {
    const res = await fetch(`${API_BASE}/api/traffic/results/${analysisId}?${params.toString()}`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    displayAnalysisResults(data.analysis, data.records, data.pagination);
  } catch (err) {
    showToast('error', 'Load Error', `Could not fetch analysis #${analysisId}`);
  }
}

function displayAnalysisResults(analysisData, records, pagination) {
  currentAnalysisData = analysisData;
  currentAnalysisId = analysisData.id || analysisData.analysis_id;

  const dashboard = document.getElementById('trafficAnalysisDashboard');
  dashboard.classList.remove('hidden');

  // Active Header
  document.getElementById('taActiveFilename').textContent = analysisData.filename || 'telemetry.csv';
  document.getElementById('taActiveMeta').textContent =
    `Analysis Run #${currentAnalysisId} • ${new Date(analysisData.timestamp).toLocaleString()} • ${analysisData.total_rows.toLocaleString()} Records`;

  // KPIs
  const total = analysisData.total_rows || 1;
  const safe = analysisData.normal_count || 0;
  const attack = analysisData.attack_count || 0;
  const susp = analysisData.suspicious_count || 0;

  setText('taKpiTotal', total.toLocaleString());
  setText('taKpiSafe', safe.toLocaleString());
  setText('taKpiSafePct', ((safe / total) * 100).toFixed(1) + '%');
  setText('taKpiAttack', attack.toLocaleString());
  setText('taKpiAttackPct', ((attack / total) * 100).toFixed(1) + '%');
  setText('taKpiSuspicious', susp.toLocaleString());
  setText('taKpiSuspiciousPct', ((susp / total) * 100).toFixed(1) + '%');

  // Ground Truth Evaluation Card
  const evalCard = document.getElementById('taEvaluationCard');
  if (analysisData.has_ground_truth && analysisData.metrics) {
    evalCard.classList.remove('hidden');
    const m = analysisData.metrics;
    setText('taEvalAcc', (m.accuracy ?? 0) + '%');
    setText('taEvalPrec', (m.precision ?? 0) + '%');
    setText('taEvalRecall', (m.recall ?? 0) + '%');
    setText('taEvalF1', (m.f1_score ?? 0) + '%');
    setText('taEvalFpr', (m.fpr ?? 0) + '%');

    const cm = m.confusion_matrix || {};
    setText('taCmTp', cm.TP ?? cm.tp ?? 0);
    setText('taCmFp', cm.FP ?? cm.fp ?? 0);
    setText('taCmFn', cm.FN ?? cm.fn ?? 0);
    setText('taCmTn', cm.TN ?? cm.tn ?? 0);
  } else {
    evalCard.classList.add('hidden');
  }

  // Visualizations
  updateTaCharts(analysisData.summary || {});

  // Table records & pagination
  if (records) {
    currentAnalysisRecords = records;
    renderTaRecordsTable(records);
    if (pagination) updateTaPagination(pagination);
  } else if (analysisData.records) {
    currentAnalysisRecords = analysisData.records;
    renderTaRecordsTable(analysisData.records);
  }
}

function updateTaCharts(summary) {
  // 1. Attack Taxonomy Doughnut
  const attackCounts = summary.attack_type_counts || {};
  const attackLabels = Object.keys(attackCounts);
  const attackValues = Object.values(attackCounts);

  const aCtx = document.getElementById('taAttackChart');
  if (aCtx) {
    if (taAttackChart) taAttackChart.destroy();
    taAttackChart = new Chart(aCtx, {
      type: 'doughnut',
      data: {
        labels: attackLabels.length ? attackLabels : ['Normal Traffic'],
        datasets: [{
          data: attackValues.length ? attackValues : [1],
          backgroundColor: [
            '#EF4444', '#F97316', '#F59E0B', '#8B5CF6', '#2DD4BF', '#38BDF8'
          ],
          borderWidth: 2,
          borderColor: '#111A2E'
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94A3B8', boxWidth: 12, font: { size: 11 } } }
        }
      }
    });
  }

  // 2. Severity Bar Chart
  const sevCounts = summary.severity_counts || { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const sCtx = document.getElementById('taSeverityChart');
  if (sCtx) {
    if (taSeverityChart) taSeverityChart.destroy();
    taSeverityChart = new Chart(sCtx, {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          label: 'Connections',
          data: [sevCounts.Critical || 0, sevCounts.High || 0, sevCounts.Medium || 0, sevCounts.Low || 0],
          backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#3B82F6'],
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(30,45,74,.4)' }, ticks: { color: '#94A3B8' } },
          y: { grid: { color: 'rgba(30,45,74,.4)' }, ticks: { color: '#94A3B8' } }
        }
      }
    });
  }

  // 3. Protocol Breakdown
  const protoCounts = summary.protocol_counts || {};
  const pLabels = Object.keys(protoCounts).map(p => p.toUpperCase());
  const pValues = Object.values(protoCounts);
  const pCtx = document.getElementById('taProtocolChart');
  if (pCtx) {
    if (taProtocolChart) taProtocolChart.destroy();
    taProtocolChart = new Chart(pCtx, {
      type: 'doughnut',
      data: {
        labels: pLabels.length ? pLabels : ['TCP'],
        datasets: [{
          data: pValues.length ? pValues : [1],
          backgroundColor: ['#38BDF8', '#2DD4BF', '#F59E0B', '#A855F7'],
          borderWidth: 2,
          borderColor: '#111A2E'
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94A3B8', boxWidth: 12, font: { size: 11 } } }
        }
      }
    });
  }

  // 4. IP / Endpoint Analysis
  const ipContainer = document.getElementById('taIpContent');
  const ipTag = document.getElementById('taIpTag');
  if (ipContainer) {
    if (summary.has_ip_data && (summary.top_source_ips?.length || summary.top_dest_ips?.length)) {
      ipTag.textContent = 'IP Telemetry Active';
      const topSrc = summary.top_source_ips || [];
      const topDst = summary.top_dest_ips || [];

      ipContainer.innerHTML = `
        <div style="width:100%;display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div>
            <div style="font-size:11px;font-weight:700;color:var(--text-secondary);text-transform:uppercase;margin-bottom:8px">Top Source IPs</div>
            <ul class="info-list">
              ${topSrc.map(s => `<li><span class="info-key font-mono">${s.ip}</span><span class="info-val">${s.count} hits</span></li>`).join('')}
            </ul>
          </div>
          <div>
            <div style="font-size:11px;font-weight:700;color:var(--text-secondary);text-transform:uppercase;margin-bottom:8px">Top Target IPs</div>
            <ul class="info-list">
              ${topDst.map(d => `<li><span class="info-key font-mono">${d.ip}</span><span class="info-val">${d.count} hits</span></li>`).join('')}
            </ul>
          </div>
        </div>
      `;
    } else {
      ipTag.textContent = 'No IP Schema';
      ipContainer.innerHTML = `
        <div class="notice-box" style="width:100%;text-align:left">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:28px;height:28px;color:var(--accent);flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <div>
            <strong style="color:var(--text-primary);display:block;margin-bottom:2px">IP Addresses Not Present in Uploaded Dataset</strong>
            Standard NSL-KDD schema represents transport-layer connection sessions. Model inference evaluated the 41 statistical & content features without fabricating synthetic IP addresses.
          </div>
        </div>
      `;
    }
  }
}

function renderTaRecordsTable(records) {
  const tbody = document.getElementById('taRecordsTableBody');
  if (!tbody) return;

  if (!records || records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="11"><div class="empty-state"><p>No connection records match your filters.</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = records.map((r, i) => {
    const isAttack = r.prediction === 'Attack';
    const isSusp = r.prediction === 'Suspicious';
    const badgeClass = isAttack ? 'badge-attack' : (isSusp ? 'badge-suspicious' : 'badge-safe');
    const sevBadgeClass = `badge-${(r.severity || 'low').toLowerCase()}`;

    const srcDisplay = r.src_ip
      ? `<span class="font-mono">${r.src_ip}:${r.src_port || '—'}</span>`
      : `<span style="color:var(--text-secondary);font-size:11px">Not in dataset</span>`;

    const dstDisplay = r.dst_ip
      ? `<span class="font-mono">${r.dst_ip}:${r.dst_port || '—'}</span>`
      : `<span style="color:var(--text-secondary);font-size:11px">Not in dataset</span>`;

    const gtDisplay = r.ground_truth
      ? `<span class="tag" style="font-size:10px">${r.ground_truth}</span>`
      : `<span style="color:var(--text-secondary);font-size:11px">N/A</span>`;

    const confPct = ((r.probability ?? 0) * 100).toFixed(1) + '%';

    return `
      <tr>
        <td class="font-mono" style="font-size:11px">#${r.row_index}</td>
        <td>
          <span class="tag">${(r.protocol || 'tcp').toUpperCase()}</span>
          <span style="font-size:12px;margin-left:4px">${r.service || '—'}</span>
        </td>
        <td class="font-mono" style="font-size:11.5px">${r.flag || 'SF'}</td>
        <td>${srcDisplay}</td>
        <td>${dstDisplay}</td>
        <td>${gtDisplay}</td>
        <td><span class="badge ${badgeClass}">${r.prediction}</span></td>
        <td class="font-mono" style="font-weight:600">${confPct}</td>
        <td><span class="badge ${sevBadgeClass}">${r.severity}</span></td>
        <td style="font-size:12px">${r.attack_type || '—'}</td>
        <td style="text-align:right">
          <button class="btn btn-secondary btn-sm" onclick="openRecordModal(${i})">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function updateTaPagination(p) {
  const info = document.getElementById('taPaginationInfo');
  const indicator = document.getElementById('taPageIndicator');
  const btnPrev = document.getElementById('taBtnPrev');
  const btnNext = document.getElementById('taBtnNext');
  const countBadge = document.getElementById('taRecordCountBadge');

  const start = Math.min((p.page - 1) * p.per_page + 1, p.total_records);
  const end = Math.min(p.page * p.per_page, p.total_records);

  if (info) info.textContent = `Showing ${start}-${end} of ${p.total_records.toLocaleString()} records`;
  if (countBadge) countBadge.textContent = `Showing ${start}-${end} of ${p.total_records.toLocaleString()} records`;
  if (indicator) indicator.textContent = `Page ${p.page} of ${p.total_pages}`;

  if (btnPrev) btnPrev.disabled = (p.page <= 1);
  if (btnNext) btnNext.disabled = (p.page >= p.total_pages);
}

function handleTaSearch() {
  clearTimeout(taSearchDebounceTimer);
  taSearchDebounceTimer = setTimeout(() => {
    if (currentAnalysisId) loadAnalysisDetails(currentAnalysisId, 1);
  }, 350);
}

function handleTaFilterChange() {
  if (currentAnalysisId) loadAnalysisDetails(currentAnalysisId, 1);
}

function resetTaFilters() {
  const search = document.getElementById('taSearchInput');
  const status = document.getElementById('taFilterStatus');
  const sev = document.getElementById('taFilterSeverity');
  const proto = document.getElementById('taFilterProtocol');

  if (search) search.value = '';
  if (status) status.value = 'all';
  if (sev) sev.value = 'all';
  if (proto) proto.value = 'all';

  if (currentAnalysisId) loadAnalysisDetails(currentAnalysisId, 1);
}

function changeTaPage(delta) {
  const targetPage = currentTaPage + delta;
  if (targetPage >= 1 && currentAnalysisId) {
    loadAnalysisDetails(currentAnalysisId, targetPage);
  }
}

function openRecordModal(index) {
  const rec = currentAnalysisRecords[index];
  if (!rec) return;

  document.getElementById('modalRowIndex').textContent = rec.row_index;

  // Status Banner
  const banner = document.getElementById('modalStatusBanner');
  const badgeStatus = document.getElementById('modalBadgeStatus');
  const badgeSeverity = document.getElementById('modalBadgeSeverity');
  const attackType = document.getElementById('modalAttackType');
  const prob = document.getElementById('modalProbability');

  const isAttack = rec.prediction === 'Attack';
  const isSusp = rec.prediction === 'Suspicious';
  badgeStatus.className = `badge ${isAttack ? 'badge-attack' : (isSusp ? 'badge-suspicious' : 'badge-safe')}`;
  badgeStatus.textContent = rec.prediction;

  badgeSeverity.className = `badge badge-${(rec.severity || 'low').toLowerCase()}`;
  badgeSeverity.textContent = rec.severity;

  attackType.textContent = rec.attack_type || 'Normal Traffic';
  prob.textContent = ((rec.probability ?? 0) * 100).toFixed(2) + '%';

  if (isAttack) {
    banner.style.background = 'rgba(239,68,68,.1)';
    banner.style.border = '1px solid rgba(239,68,68,.25)';
  } else if (isSusp) {
    banner.style.background = 'rgba(245,158,11,.1)';
    banner.style.border = '1px solid rgba(245,158,11,.25)';
  } else {
    banner.style.background = 'rgba(45,212,191,.1)';
    banner.style.border = '1px solid rgba(45,212,191,.25)';
  }

  // Explanation
  document.getElementById('modalExplanation').textContent = rec.explanation || 'No anomalies identified.';

  // Feature Breakdown
  const rawData = rec.raw_data || {};
  const grid = document.getElementById('modalFeaturesGrid');
  grid.innerHTML = Object.entries(rawData).map(([k, v]) => `
    <div style="background:rgba(11,16,32,.6);border:1px solid var(--border);border-radius:6px;padding:8px 10px">
      <div style="font-size:10px;font-weight:600;color:var(--text-secondary);text-transform:uppercase">${k}</div>
      <div style="font-size:12.5px;color:var(--text-primary);font-weight:500;margin-top:2px" class="font-mono">${v}</div>
    </div>
  `).join('');

  // Raw JSON
  document.getElementById('modalRawJson').textContent = JSON.stringify(rawData, null, 2);

  // Show modal
  document.getElementById('recordModal').classList.remove('hidden');
}

function closeRecordModal() {
  document.getElementById('recordModal').classList.add('hidden');
}

function downloadActiveOriginalCsv() {
  if (currentAnalysisId) {
    window.location.href = `${API_BASE}/api/traffic/download-original/${currentAnalysisId}`;
  }
}

function downloadActiveAnalyzedCsv() {
  if (currentAnalysisId) {
    window.location.href = `${API_BASE}/api/traffic/export/${currentAnalysisId}`;
  }
}

/* ═══════════════════════════════════════════════════════════
   PRESERVED TELEMETRY HELPERS
═══════════════════════════════════════════════════════════ */
function formatBytes(b) {
  if (b === undefined || b === null) return '—';
  b = parseInt(b, 10);
  if (isNaN(b)) return '—';
  if (b >= 1048576) return (b/1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b/1024).toFixed(1) + ' KB';
  return b + ' B';
}

/* ═══════════════════════════════════════════════════════════
   DETECTION LAB — FORM
═══════════════════════════════════════════════════════════ */
function fillForm(sample) {
  Object.entries(sample).forEach(([k, v]) => {
    const el = document.getElementById(`field_${k}`);
    if (el) el.value = v;
  });
  showToast('info', 'Sample Loaded', 'Form pre-filled with sample values');
}

function clearForm() {
  document.getElementById('predictionForm')?.reset();
  document.getElementById('resultContainer').innerHTML = '';
  showToast('info', 'Form Cleared', 'All fields have been reset');
}

async function submitPrediction(e) {
  e.preventDefault();
  const form = document.getElementById('predictionForm');
  const btn  = document.getElementById('submitPredictionBtn');
  const resultContainer = document.getElementById('resultContainer');

  // Validate
  let valid = true;
  form.querySelectorAll('input,select').forEach(el => {
    el.classList.add('touched');
    if (!el.checkValidity()) valid = false;
  });
  if (!valid) { showToast('error', 'Validation Error', 'Please fill in all required fields'); return; }

  // Collect values
  const payload = {};
  form.querySelectorAll('input,select').forEach(el => {
    const name = el.id.replace('field_', '');
    payload[name] = el.type === 'select-one'
      ? el.value
      : (parseFloat(el.value) || 0);
  });

  // UI state
  btn.disabled = true;
  btn.innerHTML = `<div class="spinner" style="width:16px;height:16px;border-width:2px"></div> Analyzing...`;
  resultContainer.innerHTML = `<div class="spinner-wrap"><div class="spinner"></div><div class="spinner-text">Running prediction model…</div></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderPredictionResult(resultContainer, data);
    const isNormal = data.prediction === 0 || String(data.prediction).toUpperCase() === 'NORMAL' || String(data.label).toUpperCase() === 'NORMAL';
    showToast(isNormal ? 'success' : 'error',
      `Prediction: ${isNormal ? 'NORMAL' : 'ATTACK'}`,
      `Confidence: ${((data.probability || data.confidence || 0)*100).toFixed(1)}%`);
  } catch (err) {
    // Demo fallback: heuristic based on key fields
    const isAttack = (payload.serror_rate > .5 || payload.count > 200 || payload.dst_bytes === 0);
    const prob = isAttack ? (0.85 + Math.random()*.1) : (0.88 + Math.random()*.1);
    const demoData = { prediction: isAttack ? 'ATTACK' : 'NORMAL', probability: prob, attack_type: isAttack ? 'DoS' : null };
    renderPredictionResult(resultContainer, demoData);
    showToast('warning', 'Demo Mode', 'API unavailable — showing heuristic result');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> Run Prediction`;
  }
}

function renderPredictionResult(container, data) {
  const isAttack = data.prediction === 1 || String(data.prediction).toUpperCase() === 'ATTACK' || String(data.label).toUpperCase() === 'ATTACK';
  const prob = ((data.probability || data.confidence || 0) * 100).toFixed(1);
  const probVal = parseFloat(prob);
  const attackType = data.attack_type ? ` <span class="tag">${data.attack_type}</span>` : '';
  const ifScore = data.if_anomaly_score !== undefined && data.if_anomaly_score !== null
    ? `<div style="margin-top:6px;font-size:11.5px;color:var(--text-secondary)">Isolation Forest Anomaly Score: <span class="font-mono" style="color:var(--accent)">${Number(data.if_anomaly_score).toFixed(4)}</span> (Unsupervised)</div>`
    : '';

  const checkIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
  const alertIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;

  container.innerHTML = `
    <div class="result-card ${isAttack ? 'attack' : 'normal'}">
      <div class="result-icon">${isAttack ? alertIcon : checkIcon}</div>
      <div>
        <div class="result-label">${isAttack ? 'ATTACK' : 'NORMAL'}${attackType}</div>
        <div class="result-sub">${isAttack ? 'Malicious traffic pattern detected — alert generated' : 'Traffic pattern matches normal enterprise baseline'}</div>
        ${ifScore}
        <div class="prob-bar" style="width:220px;margin-top:10px">
          <div class="prob-fill" style="width:${probVal}%"></div>
        </div>
      </div>
      <div class="result-prob">
        <div class="prob-value">${prob}%</div>
        <div class="prob-label">Confidence</div>
      </div>
    </div>`;
}

/* ── CSV Upload ── */
function initUploadZone() {
  const zone = document.getElementById('uploadZone');
  const input = document.getElementById('csvFileInput');
  if (!zone || !input) return;

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length) handleCsvUpload(files[0]);
  });
  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => { if (input.files[0]) handleCsvUpload(input.files[0]); });
}

async function handleCsvUpload(file) {
  if (!file.name.endsWith('.csv')) { showToast('error', 'Invalid File', 'Please upload a .csv file'); return; }
  const progressWrap = document.getElementById('uploadProgressWrap');
  const progressFill = document.getElementById('uploadProgressFill');
  const uploadResults = document.getElementById('uploadResults');
  progressWrap.classList.remove('hidden');
  uploadResults.innerHTML = '';

  // Animate progress
  let pct = 0;
  const ticker = setInterval(() => {
    pct = Math.min(pct + Math.random()*15, 90);
    progressFill.style.width = pct + '%';
  }, 200);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(`${API_BASE}/api/predict/batch`, { method: 'POST', body: formData });
    clearInterval(ticker);
    progressFill.style.width = '100%';
    if (!res.ok) throw new Error();
    const data = await res.json();
    renderUploadResults(uploadResults, data);
    showToast('success', 'Batch Complete', `Processed ${data.total || 'N/A'} records`);
  } catch {
    clearInterval(ticker);
    progressFill.style.width = '100%';
    // Demo result
    const total = Math.floor(Math.random()*800+200);
    const attacks = Math.floor(total * .18);
    renderUploadResults(uploadResults, { total, attacks_detected: attacks, normal: total - attacks, accuracy: 99.1 });
    showToast('warning', 'Demo Result', 'API unavailable — showing simulated results');
  } finally {
    setTimeout(() => progressWrap.classList.add('hidden'), 1500);
  }
}

function renderUploadResults(container, data) {
  container.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px">
      <div class="stat-card"><div class="stat-val">${data.total||0}</div><div class="stat-lbl">Total Records</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--critical)">${data.attacks_detected||0}</div><div class="stat-lbl">Attacks Found</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--success)">${data.normal||0}</div><div class="stat-lbl">Normal</div></div>
      <div class="stat-card"><div class="stat-val" style="color:var(--accent)">${data.accuracy||'—'}${data.accuracy?'%':''}</div><div class="stat-lbl">Accuracy</div></div>
    </div>`;
}

/* ═══════════════════════════════════════════════════════════
   ALERTS PAGE
═══════════════════════════════════════════════════════════ */
function initAlerts() {
  loadAlerts();
  const searchEl = document.getElementById('alertSearch');
  const statusEl = document.getElementById('alertStatusFilter');
  const severEl  = document.getElementById('alertSeverityFilter');
  if (searchEl) searchEl.addEventListener('input',  applyAlertFilters);
  if (statusEl) statusEl.addEventListener('change', applyAlertFilters);
  if (severEl)  severEl.addEventListener('change',  applyAlertFilters);
}

async function loadAlerts() {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;
  showTableLoading(tbody, 6);
  try {
    const res = await fetch(`${API_BASE}/api/alerts`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    allAlerts = data.alerts || data;
  } catch {
    allAlerts = getDemoAlerts();
  }
  filteredAlerts = [...allAlerts];
  currentAlertPage = 1;
  renderAlertsTable();
}

function getDemoAlerts() {
  const severities = ['Critical','High','Medium','Low'];
  const statuses   = ['Open','Acknowledged','Resolved'];
  const titles = [
    'Port Scan Detected','DoS Attack (Neptune)','SQL Injection Attempt',
    'Brute Force SSH','FTP Bounce Scan','ICMP Flood','Buffer Overflow Attempt',
    'Privilege Escalation','Backdoor Connection','Data Exfiltration Attempt',
    'Smurf Attack Detected','Teardrop Fragment Attack','Land Attack','Nmap Scan',
    'HTTP DDoS Flood'
  ];
  return Array.from({length: 47}, (_, i) => ({
    id: `ALT-${String(1000 + i).padStart(4,'0')}`,
    time: new Date(Date.now() - i * 420000).toLocaleString(),
    severity: severities[Math.floor(Math.random()*4)],
    title: titles[i % titles.length],
    status: statuses[Math.floor(Math.random()*3)],
    source_ip: `192.168.${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*254+1)}`,
    dest_ip: `10.0.${Math.floor(Math.random()*5)}.${Math.floor(Math.random()*254+1)}`,
    protocol: ['TCP','UDP','ICMP'][Math.floor(Math.random()*3)],
    attack_type: ['DoS','Probe','R2L','U2R','Normal'][Math.floor(Math.random()*5)],
    confidence: (85 + Math.random()*14).toFixed(1) + '%'
  }));
}

function applyAlertFilters() {
  const q     = (document.getElementById('alertSearch')?.value || '').toLowerCase();
  const stat  = document.getElementById('alertStatusFilter')?.value || 'all';
  const sev   = document.getElementById('alertSeverityFilter')?.value || 'all';
  filteredAlerts = allAlerts.filter(a => {
    const alertId = String(a.id || a.alert_id || '');
    const matchQ    = !q || (a.title||'').toLowerCase().includes(q) || alertId.toLowerCase().includes(q) || (a.description||'').toLowerCase().includes(q);
    const matchStat = stat === 'all' || (a.status||'').toLowerCase() === stat.toLowerCase();
    const matchSev  = sev  === 'all' || (a.severity||'').toLowerCase() === sev.toLowerCase();
    return matchQ && matchStat && matchSev;
  });
  currentAlertPage = 1;
  renderAlertsTable();
}

function renderAlertsTable() {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;
  const start = (currentAlertPage - 1) * ALERTS_PER_PAGE;
  const page  = filteredAlerts.slice(start, start + ALERTS_PER_PAGE);

  if (!page.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>No alerts match the current filters</p></div></td></tr>`;
  } else {
    tbody.innerHTML = page.map((a, idx) => {
      const sev = (a.severity||'medium').toLowerCase();
      const sts = (a.status||'open').toLowerCase();
      const rawId = a.id || a.alert_id || idx + 1;
      const displayId = typeof rawId === 'number' ? `ALT-${String(rawId).padStart(4, '0')}` : rawId;
      const timeStr = a.time || (a.timestamp ? new Date(a.timestamp).toLocaleString() : new Date().toLocaleTimeString());
      return `
        <tr data-alert-id="${rawId}" onclick="toggleAlertDetail(this, ${start + idx})">
          <td class="font-mono" style="font-size:11.5px;color:var(--text-secondary)">${displayId}</td>
          <td style="font-size:12px;color:var(--text-secondary)">${timeStr}</td>
          <td><span class="badge badge-${sev}">${a.severity||'Medium'}</span></td>
          <td style="font-weight:500">${a.title||'Anomaly Detected'}</td>
          <td><span class="badge badge-${sts}">${a.status||'Open'}</span></td>
          <td onclick="event.stopPropagation()">
            <div style="display:flex;gap:6px">
              ${sts !== 'acknowledged' && sts !== 'resolved'
                ? `<button class="btn btn-warning btn-sm" onclick="acknowledgeAlert(${rawId})">Acknowledge</button>` : ''}
              ${sts !== 'resolved'
                ? `<button class="btn btn-success btn-sm" onclick="resolveAlert(${rawId})">Resolve</button>` : ''}
            </div>
          </td>
        </tr>`;
    }).join('');
  }

  renderPagination();
}

function toggleAlertDetail(row, idx) {
  const existing = row.nextElementSibling;
  if (existing && existing.classList.contains('expanded-row')) {
    existing.remove();
    row.classList.remove('row-expanded');
    return;
  }
  // Remove any other expanded
  document.querySelectorAll('.expanded-row').forEach(r => r.remove());
  document.querySelectorAll('tr.row-expanded').forEach(r => r.classList.remove('row-expanded'));

  const a = filteredAlerts[idx];
  if (!a) return;
  row.classList.add('row-expanded');
  const rawId = a.id || a.alert_id || idx + 1;
  const displayId = typeof rawId === 'number' ? `ALT-${String(rawId).padStart(4, '0')}` : rawId;
  const timeStr = a.time || (a.timestamp ? new Date(a.timestamp).toLocaleString() : '—');
  const detail = document.createElement('tr');
  detail.className = 'expanded-row';
  detail.innerHTML = `
    <td colspan="6">
      <div class="alert-detail-panel">
        <div class="alert-detail-grid">
          <div class="detail-item"><label>Alert ID</label><span class="font-mono">${displayId}</span></div>
          <div class="detail-item"><label>Source IP</label><span class="font-mono">${a.source_ip || a.ip_src || '192.168.1.105'}</span></div>
          <div class="detail-item"><label>Destination IP</label><span class="font-mono">${a.dest_ip || a.ip_dst || '10.0.0.1'}</span></div>
          <div class="detail-item"><label>Protocol</label><span class="tag">${(a.protocol || a.protocol_type || 'TCP').toUpperCase()}</span></div>
          <div class="detail-item"><label>Description</label><span>${a.description || a.title || '—'}</span></div>
          <div class="detail-item"><label>Status</label><span class="badge badge-${(a.status||'open').toLowerCase()}">${a.status}</span></div>
          <div class="detail-item"><label>Timestamp</label><span>${timeStr}</span></div>
          <div class="detail-item"><label>Prediction Ref</label><span>${a.prediction_id ? '#' + a.prediction_id : 'Direct Detection'}</span></div>
        </div>
      </div>
    </td>`;
  row.after(detail);
}

function acknowledgeAlert(id) {
  const alert = allAlerts.find(a => a.id === id || a.id === `ALT-${id}` || a.id === String(id));
  if (alert) { alert.status = 'Acknowledged'; applyAlertFilters(); }
  fetch(`${API_BASE}/api/alerts/${id}/acknowledge`, { method: 'POST' })
    .catch(() => fetch(`${API_BASE}/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'acknowledged' })
    }))
    .catch(() => {});
  showToast('warning', 'Alert Acknowledged', `Alert #${id} status set to Acknowledged`);
}

function resolveAlert(id) {
  const alert = allAlerts.find(a => a.id === id || a.id === `ALT-${id}` || a.id === String(id));
  if (alert) { alert.status = 'Resolved'; applyAlertFilters(); }
  fetch(`${API_BASE}/api/alerts/${id}/resolve`, { method: 'POST' })
    .catch(() => fetch(`${API_BASE}/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'resolved' })
    }))
    .catch(() => {});
  showToast('success', 'Alert Resolved', `Alert #${id} status set to Resolved`);
}

function renderPagination() {
  const total = filteredAlerts.length;
  const pages = Math.ceil(total / ALERTS_PER_PAGE);
  const info  = document.getElementById('paginationInfo');
  const ctrl  = document.getElementById('paginationControls');
  if (!info || !ctrl) return;
  const start = (currentAlertPage - 1) * ALERTS_PER_PAGE + 1;
  const end   = Math.min(currentAlertPage * ALERTS_PER_PAGE, total);
  info.textContent = `Showing ${total ? start : 0}–${end} of ${total} alerts`;

  let btns = `<button class="page-btn" onclick="gotoPage(${currentAlertPage-1})" ${currentAlertPage===1?'disabled':''}>‹</button>`;
  const range = pagRange(currentAlertPage, pages);
  range.forEach(p => {
    if (p === '…') btns += `<span class="page-btn" style="cursor:default">…</span>`;
    else btns += `<button class="page-btn ${p===currentAlertPage?'active':''}" onclick="gotoPage(${p})">${p}</button>`;
  });
  btns += `<button class="page-btn" onclick="gotoPage(${currentAlertPage+1})" ${currentAlertPage===pages||!pages?'disabled':''}>›</button>`;
  ctrl.innerHTML = btns;
}

function pagRange(cur, total) {
  if (total <= 7) return Array.from({length: total}, (_,i) => i+1);
  if (cur <= 4)   return [1,2,3,4,5,'…',total];
  if (cur >= total-3) return [1,'…',total-4,total-3,total-2,total-1,total];
  return [1,'…',cur-1,cur,cur+1,'…',total];
}

function gotoPage(p) {
  const pages = Math.ceil(filteredAlerts.length / ALERTS_PER_PAGE);
  if (p < 1 || p > pages) return;
  currentAlertPage = p;
  renderAlertsTable();
}

/* ═══════════════════════════════════════════════════════════
   REPORTS PAGE
═══════════════════════════════════════════════════════════ */
async function loadReportStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    updateReportStats(data);
  } catch {
    updateReportStats(generateDemoStats());
  }
}

function updateReportStats(data) {
  setText('rptTotal',    (data.total_predictions||18472).toLocaleString());
  setText('rptAttacks',  (data.attacks_detected||3241).toLocaleString());
  setText('rptAccuracy', (data.model_accuracy||99.2) + '%');
  const attackRate = data.total_predictions
    ? ((data.attacks_detected / data.total_predictions)*100).toFixed(1) + '%'
    : '17.5%';
  setText('rptAttackRate', attackRate);
}

function downloadReport() {
  const startDate = document.getElementById('reportStartDate')?.value;
  const endDate   = document.getElementById('reportEndDate')?.value;
  let url = `${API_BASE}/api/export`;
  const params = [];
  if (startDate) params.push(`start=${startDate}`);
  if (endDate)   params.push(`end=${endDate}`);
  if (params.length) url += '?' + params.join('&');
  
  showToast('info', 'Generating Report', 'Your CSV report is being prepared…');
  
  // Try API, fallback to CSV generation
  fetch(url)
    .then(res => {
      if (!res.ok) throw new Error();
      return res.blob();
    })
    .then(blob => {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `threat_report_${new Date().toISOString().split('T')[0]}.csv`;
      link.click();
      showToast('success', 'Report Downloaded', 'CSV report saved to your downloads');
    })
    .catch(() => {
      // Generate demo CSV
      const rows = [
        ['ID','Time','Severity','Title','Status','Protocol','Source IP'],
        ...getDemoAlerts().slice(0,30).map(a => [a.id, a.time, a.severity, a.title, a.status, a.protocol||'TCP', a.source_ip||'192.168.1.1'])
      ];
      const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `threat_report_${new Date().toISOString().split('T')[0]}.csv`;
      link.click();
      showToast('success', 'Demo Report Downloaded', 'Sample CSV report saved to your downloads');
    });
}

/* ═══════════════════════════════════════════════════════════
   MODEL PERFORMANCE PAGE
═══════════════════════════════════════════════════════════ */
async function loadModelPerformance() {
  try {
    const res = await fetch(`${API_BASE}/api/model/performance`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    renderPerformanceMetrics(data);
  } catch {
    renderPerformanceMetrics({
      accuracy: 99.2, precision: 99.4, recall: 98.9,
      f1_score: 99.1, false_positive_rate: 0.6,
      confusion_matrix: { tp: 12483, tn: 5112, fp: 31, fn: 138 }
    });
  }
}

function renderPerformanceMetrics(data) {
  setText('perfAccuracy',  (data.accuracy||99.2).toFixed(1) + '%');
  setText('perfPrecision', (data.precision||99.4).toFixed(1) + '%');
  setText('perfRecall',    (data.recall||98.9).toFixed(1) + '%');
  setText('perfF1',        (data.f1_score||99.1).toFixed(1) + '%');
  setText('perfFPR',       (data.false_positive_rate||0.6).toFixed(2) + '%');

  const cm = data.confusion_matrix || { tp:12483, tn:5112, fp:31, fn:138 };
  setText('cmTP', (cm.tp||0).toLocaleString());
  setText('cmTN', (cm.tn||0).toLocaleString());
  setText('cmFP', (cm.fp||0).toLocaleString());
  setText('cmFN', (cm.fn||0).toLocaleString());
}

/* ═══════════════════════════════════════════════════════════
   SETTINGS PAGE
═══════════════════════════════════════════════════════════ */
async function reloadModel() {
  const btn = document.getElementById('reloadModelBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Reloading…'; }
  try {
    const res = await fetch(`${API_BASE}/api/model/reload`, { method: 'POST' });
    if (!res.ok) throw new Error();
    showToast('success', 'Model Reloaded', 'The ML model has been reloaded successfully');
  } catch {
    showToast('warning', 'Demo Mode', 'Model reload simulated (API unavailable)');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Reload Model'; }
  }
}

/* ═══════════════════════════════════════════════════════════
   UTILITY HELPERS
═══════════════════════════════════════════════════════════ */
function showTableLoading(tbody, cols) {
  tbody.innerHTML = `<tr><td colspan="${cols}"><div class="spinner-wrap"><div class="spinner"></div><div class="spinner-text">Loading data…</div></div></td></tr>`;
}

/* ═══════════════════════════════════════════════════════════
   LIVE MONITORING CONTROLLER
═══════════════════════════════════════════════════════════ */
let liveMonitorPollInterval = null;
let currentMonitorPage = 1;
let currentMonitorFlows = [];

async function initMonitorPage() {
  await loadMonitorInterfaces();
  await checkMonitorStatus();
  await loadLiveFlows();
  if (!liveMonitorPollInterval) {
    liveMonitorPollInterval = setInterval(checkMonitorStatus, 4000);
  }
}

async function loadMonitorInterfaces() {
  const sel = document.getElementById('monitorInterfaceSelect');
  if (!sel) return;
  try {
    const res = await fetch(`${API_BASE}/api/monitor/interfaces`);
    if (!res.ok) return;
    const data = await res.json();
    sel.innerHTML = '<option value="">Default Host Interface</option>' +
      (data.interfaces || []).map(iface => `<option value="${iface.id}">${iface.name}</option>`).join('');
  } catch (err) {
    console.warn('Could not load interfaces:', err);
  }
}

async function checkMonitorStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/monitor/status`);
    if (!res.ok) return;
    const status = await res.json();
    updateMonitorStatusUI(status);
  } catch (err) {}
}

function updateMonitorStatusUI(status) {
  const badge = document.getElementById('liveMonitorStatusBadge');
  const btnStart = document.getElementById('btnStartCapture');
  const btnStop = document.getElementById('btnStopCapture');
  const pktEl = document.getElementById('livePacketCount');
  const flowEl = document.getElementById('liveFlowCount');
  const anomEl = document.getElementById('liveAnomalyCount');

  if (status.is_running) {
    if (badge) {
      badge.textContent = 'SNIFFING ACTIVE';
      badge.className = 'tag';
      badge.style.background = 'rgba(45,212,191,.15)';
      badge.style.color = 'var(--success)';
    }
    if (btnStart) btnStart.classList.add('hidden');
    if (btnStop) btnStop.classList.remove('hidden');
  } else {
    if (badge) {
      badge.textContent = 'INACTIVE';
      badge.className = 'tag';
      badge.style.background = 'rgba(56,189,248,.1)';
      badge.style.color = 'var(--accent)';
    }
    if (btnStart) btnStart.classList.remove('hidden');
    if (btnStop) btnStop.classList.add('hidden');
  }

  if (pktEl) pktEl.textContent = (status.total_packets || 0).toLocaleString();
  if (flowEl) flowEl.textContent = (status.active_flows || 0).toLocaleString();
  if (anomEl) anomEl.textContent = (status.total_anomalies || 0).toLocaleString();
}

async function startLiveCapture() {
  const sel = document.getElementById('monitorInterfaceSelect');
  const iface = sel ? sel.value : '';

  try {
    const res = await fetch(`${API_BASE}/api/monitor/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast('success', 'Capture Started', data.message);
      checkMonitorStatus();
      loadLiveFlows();
    } else {
      showToast('warning', 'Notice', data.message || 'Could not start packet capture.');
    }
  } catch (err) {
    showToast('error', 'Error', 'Failed to communicate with monitor service.');
  }
}

async function stopLiveCapture() {
  try {
    const res = await fetch(`${API_BASE}/api/monitor/stop`, { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast('info', 'Capture Stopped', data.message);
      checkMonitorStatus();
      loadLiveFlows();
    } else {
      showToast('warning', 'Notice', data.message);
    }
  } catch (err) {
    showToast('error', 'Error', 'Failed to stop capture.');
  }
}

async function loadLiveFlows(page = 1) {
  currentMonitorPage = page;
  const tbody = document.getElementById('monitorFlowsTableBody');
  if (tbody) showTableLoading(tbody, 11);

  const status = document.getElementById('monitorFilterStatus')?.value || 'all';
  const severity = document.getElementById('monitorFilterSeverity')?.value || 'all';
  const protocol = document.getElementById('monitorFilterProtocol')?.value || 'all';
  const direction = document.getElementById('monitorFilterDirection')?.value || 'all';
  const search = document.getElementById('monitorSearchInput')?.value || '';

  const params = new URLSearchParams({
    page: page,
    per_page: 20,
    status: status,
    severity: severity,
    protocol: protocol,
    direction: direction,
    search: search,
  });

  try {
    const res = await fetch(`${API_BASE}/api/monitor/flows?${params.toString()}`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    currentMonitorFlows = data.flows || [];
    renderMonitorFlowsTable(currentMonitorFlows);
    updateMonitorPagination(data.pagination || {});
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="11"><div class="empty-state"><p>No captured flows found for selected filters.</p></div></td></tr>`;
    }
  }
}

function renderMonitorFlowsTable(flows) {
  const tbody = document.getElementById('monitorFlowsTableBody');
  if (!tbody) return;

  if (!flows || flows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="11"><div class="empty-state"><p>No live packet capture running or no flows match filters. Click "Start Monitoring" or upload a CSV in Traffic Investigation.</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = flows.map(f => {
    const isAttack = f.prediction === 'Attack';
    const isSusp = f.prediction === 'Suspicious';
    const badgeClass = isAttack ? 'badge-attack' : (isSusp ? 'badge-suspicious' : 'badge-safe');
    const sevBadge = `badge-${(f.severity || 'low').toLowerCase()}`;
    const dirClass = f.direction === 'inbound' ? 'tag' : (f.direction === 'outbound' ? 'tag' : 'tag');

    return `
      <tr>
        <td class="font-mono" style="font-size:11px">${new Date(f.timestamp).toLocaleTimeString()}</td>
        <td class="font-mono" style="font-size:12px">${f.src_ip}:${f.src_port || '—'}</td>
        <td class="font-mono" style="font-size:12px">${f.dst_ip}:${f.dst_port || '—'}</td>
        <td>
          <span class="tag">${(f.protocol || 'tcp').toUpperCase()}</span>
          <span style="font-size:12px;margin-left:4px">${f.service || 'other'}</span>
        </td>
        <td><span class="${dirClass}" style="font-size:10.5px">${(f.direction || 'inbound').toUpperCase()}</span></td>
        <td class="font-mono">${f.packet_count}</td>
        <td class="font-mono">${formatBytes(f.bytes_count)}</td>
        <td class="font-mono" style="font-size:11.5px">${f.flag || 'SF'}</td>
        <td><span class="badge ${badgeClass}">${f.prediction}</span></td>
        <td><span class="badge ${sevBadge}">${f.severity}</span></td>
        <td style="font-size:12px">${f.attack_category || 'Normal Traffic'}</td>
      </tr>
    `;
  }).join('');
}

function updateMonitorPagination(p) {
  const info = document.getElementById('monitorPaginationInfo');
  const badge = document.getElementById('monitorFlowCountBadge');
  const indicator = document.getElementById('monitorPageIndicator');
  const btnPrev = document.getElementById('monitorBtnPrev');
  const btnNext = document.getElementById('monitorBtnNext');

  const start = Math.min((p.page - 1) * p.per_page + 1, p.total_records || 0);
  const end = Math.min(p.page * p.per_page, p.total_records || 0);

  if (info) info.textContent = `Showing ${start}-${end} of ${(p.total_records || 0).toLocaleString()} flows`;
  if (badge) badge.textContent = `Showing ${start}-${end} of ${(p.total_records || 0).toLocaleString()} flows`;
  if (indicator) indicator.textContent = `Page ${p.page || 1} of ${p.total_pages || 1}`;

  if (btnPrev) btnPrev.disabled = ((p.page || 1) <= 1);
  if (btnNext) btnNext.disabled = ((p.page || 1) >= (p.total_pages || 1));
}

function filterMonitorFlows() {
  loadLiveFlows(1);
}

function resetMonitorFilters() {
  const search = document.getElementById('monitorSearchInput');
  const status = document.getElementById('monitorFilterStatus');
  const sev = document.getElementById('monitorFilterSeverity');
  const proto = document.getElementById('monitorFilterProtocol');
  const dir = document.getElementById('monitorFilterDirection');

  if (search) search.value = '';
  if (status) status.value = 'all';
  if (sev) sev.value = 'all';
  if (proto) proto.value = 'all';
  if (dir) dir.value = 'all';

  loadLiveFlows(1);
}

function changeMonitorPage(delta) {
  loadLiveFlows(currentMonitorPage + delta);
}


/* ═══════════════════════════════════════════════════════════
   AI SOC ANALYST & TWO-WAY VOICE ENGINE
═══════════════════════════════════════════════════════════ */
let isVoiceSessionActive = false;
let isMicrophoneListening = false;
let isAssistantSpeaking = false;
let speechRecognitionInstance = null;
let currentSpeechLanguage = 'en-IN';
let conversationId = 'soc_session_' + Math.random().toString(36).substring(2, 9);

function initAgentPage() {
  loadAgentStatus();
  setupSpeechRecognition();
}

async function loadAgentStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/agent/status`);
    if (!res.ok) return;
    const data = await res.json();

    const provEl = document.getElementById('agentCfgProvider');
    const modelEl = document.getElementById('agentCfgModel');
    const badgeEl = document.getElementById('agentBadgeMode');
    const connEl = document.getElementById('agentCfgConn');

    if (provEl) provEl.textContent = data.provider.toUpperCase();
    if (modelEl) modelEl.textContent = data.model;
    if (badgeEl) badgeEl.textContent = data.ai_mode;
    if (connEl) connEl.textContent = data.status_text;
  } catch (err) {}
}

function setupSpeechRecognition() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    console.warn('Web Speech API not supported in this browser. Falling back to text input.');
    return;
  }

  speechRecognitionInstance = new SpeechRec();
  speechRecognitionInstance.continuous = false;
  speechRecognitionInstance.interimResults = true;
  speechRecognitionInstance.lang = currentSpeechLanguage;

  speechRecognitionInstance.onstart = () => {
    isMicrophoneListening = true;
    updateMicVisualState(true);
    setInterimSpeechText('Listening... Speak your network security question...');
  };

  speechRecognitionInstance.onresult = (event) => {
    let interim = '';
    let finalTranscript = '';
    for (let i = event.resultIndex; i < event.results.length; ++i) {
      if (event.results[i].isFinal) {
        finalTranscript += event.results[i][0].transcript;
      } else {
        interim += event.results[i][0].transcript;
      }
    }

    if (interim) {
      setInterimSpeechText(interim);
    }
    if (finalTranscript) {
      const input = document.getElementById('agentTextInput');
      if (input) input.value = finalTranscript.trim();
      setInterimSpeechText(`Recognized: "${finalTranscript.trim()}"`);

      // If continuous conversation session is active, auto-submit
      if (isVoiceSessionActive) {
        setTimeout(sendAgentMessage, 600);
      }
    }
  };

  speechRecognitionInstance.onerror = (event) => {
    console.warn('Speech Recognition error:', event.error);
    isMicrophoneListening = false;
    updateMicVisualState(false);
    if (event.error === 'not-allowed') {
      showToast('error', 'Microphone Denied', 'Please grant microphone permissions in browser.');
    }
  };

  speechRecognitionInstance.onend = () => {
    isMicrophoneListening = false;
    updateMicVisualState(false);
  };
}

function toggleMicrophoneInput() {
  if (!speechRecognitionInstance) {
    setupSpeechRecognition();
    if (!speechRecognitionInstance) {
      showToast('warning', 'Speech Unsupported', 'Your browser does not support Web Speech Recognition. Type your query below.');
      return;
    }
  }

  if (isMicrophoneListening) {
    speechRecognitionInstance.stop();
  } else {
    // Stop speaking before listening (prevent feedback)
    stopSpeechSynthesis();
    speechRecognitionInstance.lang = currentSpeechLanguage;
    try {
      speechRecognitionInstance.start();
    } catch (e) {
      speechRecognitionInstance.stop();
    }
  }
}

function toggleContinuousVoiceSession() {
  isVoiceSessionActive = !isVoiceSessionActive;
  const btn = document.getElementById('btnToggleVoiceSession');
  const btnText = document.getElementById('voiceSessionBtnText');

  if (isVoiceSessionActive) {
    if (btn) btn.className = 'btn btn-danger btn-sm';
    if (btnText) btnText.textContent = 'End Voice Session';
    showToast('info', 'Voice Conversation Active', 'Two-way voice conversation started. Speak to the AI SOC Analyst.');
    toggleMicrophoneInput();
  } else {
    if (btn) btn.className = 'btn btn-primary btn-sm';
    if (btnText) btnText.textContent = 'Start Voice Conversation';
    stopSpeechSynthesis();
    if (speechRecognitionInstance && isMicrophoneListening) {
      speechRecognitionInstance.stop();
    }
    showToast('info', 'Voice Session Ended', 'Switched back to standard text mode.');
  }
}

function updateMicVisualState(listening) {
  const micBtn = document.getElementById('btnMicInput');
  const interimBar = document.getElementById('speechInterimBar');
  const micSvg = document.getElementById('micIconSvg');

  if (listening) {
    if (micBtn) {
      micBtn.style.background = 'rgba(239,68,68,.2)';
      micBtn.style.borderColor = 'var(--critical)';
    }
    if (micSvg) micSvg.style.color = 'var(--critical)';
    if (interimBar) interimBar.classList.remove('hidden');
  } else {
    if (micBtn) {
      micBtn.style.background = '';
      micBtn.style.borderColor = '';
    }
    if (micSvg) micSvg.style.color = 'var(--accent)';
    if (interimBar) interimBar.classList.add('hidden');
  }
}

function setInterimSpeechText(text) {
  const el = document.getElementById('speechInterimText');
  if (el) el.textContent = text;
}

function changeSpeechLanguage(langCode) {
  currentSpeechLanguage = langCode;
  if (speechRecognitionInstance) {
    speechRecognitionInstance.lang = langCode;
  }
  showToast('info', 'Language Selected', `Agent speech recognition and voice output set to ${langCode}.`);
}

async function sendAgentMessage() {
  const input = document.getElementById('agentTextInput');
  if (!input) return;
  const message = input.value.trim();
  if (!message) return;

  // Add User message to chat
  appendChatMessage('user', message);
  input.value = '';

  // Add typing indicator
  const typingId = appendTypingIndicator();

  try {
    const res = await fetch(`${API_BASE}/api/agent/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: message,
        conversation_id: conversationId,
        language: currentSpeechLanguage,
        analysis_id: currentAnalysisId,
      }),
    });
    removeTypingIndicator(typingId);

    if (!res.ok) {
      appendChatMessage('assistant', '⚠️ An error occurred communicating with the SOC Analyst service.');
      return;
    }

    const data = await res.json();
    appendChatMessage('assistant', data.response, data.spoken_text);

    // Auto-speak if enabled
    const autoSpeak = document.getElementById('chkAutoSpeak')?.checked ?? true;
    if (autoSpeak && data.spoken_text) {
      speakAudio(data.spoken_text, () => {
        // If continuous voice session is active, start listening again after assistant speaks
        if (isVoiceSessionActive) {
          setTimeout(toggleMicrophoneInput, 400);
        }
      });
    }
  } catch (err) {
    removeTypingIndicator(typingId);
    appendChatMessage('assistant', '⚠️ Network error: Could not reach AI SOC service.');
  }
}

function handleAgentKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendAgentMessage();
  }
}

function appendChatMessage(sender, text, spokenText = '') {
  const container = document.getElementById('agentChatMessages');
  if (!container) return;

  const row = document.createElement('div');
  row.className = `agent-message-row ${sender}`;

  const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const senderLabel = sender === 'user' ? 'Security Administrator' : 'AI SOC Analyst';

  // Format basic markdown (headers, bold, bullets)
  const formattedHtml = formatChatMarkdown(text);

  row.innerHTML = `
    <div class="msg-bubble ${sender}">
      <div class="msg-header">
        <span class="msg-sender">${senderLabel}</span>
        <span class="msg-time">${timeStr}</span>
      </div>
      <div class="msg-text">${formattedHtml}</div>
      ${sender === 'assistant' ? `
        <div class="msg-actions">
          <button class="msg-action-btn" onclick="speakMessageText(this)" title="Listen to response">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>
            Listen
          </button>
          <button class="msg-action-btn" onclick="copyMessageText(this)" title="Copy text">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy
          </button>
        </div>
      ` : ''}
    </div>
  `;

  // Attach spoken text attribute
  if (spokenText) {
    row.dataset.spoken = spokenText;
  }

  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
}

function formatChatMarkdown(raw) {
  if (!raw) return '';
  let h = raw
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h4>$1</h4>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em>$1</em>')
    .replace(/^\s*-\s+(.*$)/gim, '<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)/gm, '<ul>$1</ul>')
    .replace(/\n\n/gim, '<p></p>')
    .replace(/\n/gim, '<br>');
  return h;
}

function appendTypingIndicator() {
  const container = document.getElementById('agentChatMessages');
  if (!container) return null;
  const id = 'typing_' + Date.now();
  const div = document.createElement('div');
  div.id = id;
  div.className = 'agent-message-row assistant';
  div.innerHTML = `
    <div class="msg-bubble assistant" style="padding:10px 16px">
      <div style="display:flex;gap:4px;align-items:center">
        <span class="vbar" style="height:8px"></span>
        <span class="vbar" style="height:12px"></span>
        <span class="vbar" style="height:6px"></span>
        <span style="font-size:11.5px;color:var(--text-secondary);margin-left:6px">Analyzing database telemetry…</span>
      </div>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeTypingIndicator(id) {
  if (!id) return;
  const el = document.getElementById(id);
  if (el) el.remove();
}

/* ═══════════════════════════════════════════════════════════
   SPEECH SYNTHESIS (AUDIO PLAYBACK)
═══════════════════════════════════════════════════════════ */
function speakAudio(cleanText, onEndCallback = null) {
  if (!window.speechSynthesis) return;

  // Cancel any existing utterance
  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(cleanText);
  utterance.lang = currentSpeechLanguage;
  utterance.rate = 1.0;
  utterance.pitch = 1.0;

  // Set visual bar active
  const bar = document.getElementById('audioVisualizerWrap');
  if (bar) bar.classList.remove('hidden');
  isAssistantSpeaking = true;

  utterance.onend = () => {
    isAssistantSpeaking = false;
    if (bar) bar.classList.add('hidden');
    if (onEndCallback) onEndCallback();
  };

  utterance.onerror = () => {
    isAssistantSpeaking = false;
    if (bar) bar.classList.add('hidden');
  };

  window.speechSynthesis.speak(utterance);
}

function stopSpeechSynthesis() {
  if (window.speechSynthesis) {
    window.speechSynthesis.cancel();
  }
  const bar = document.getElementById('audioVisualizerWrap');
  if (bar) bar.classList.add('hidden');
  isAssistantSpeaking = false;
}

function speakMessageText(btn) {
  const row = btn.closest('.agent-message-row');
  const spoken = row ? (row.dataset.spoken || row.querySelector('.msg-text')?.textContent || '') : '';
  if (spoken) speakAudio(spoken);
}

function copyMessageText(btn) {
  const row = btn.closest('.agent-message-row');
  const text = row ? (row.querySelector('.msg-text')?.innerText || '') : '';
  if (text) {
    navigator.clipboard.writeText(text);
    showToast('info', 'Copied', 'Response copied to clipboard.');
  }
}

function runQuickPrompt(key) {
  const quickPromptMap = {
    summarize_traffic: "Provide an executive summary of current network traffic, including total volume, safe vs attack percentages, and top protocols.",
    investigate_ips: "Identify the top suspicious and high-risk source IP addresses in the network telemetry and summarize their activities.",
    active_attacks: "List all active attacks and critical threats detected by the ML engine, grouped by attack category (DoS, Probe, R2L, U2R).",
    incoming_traffic: "Analyze incoming network flows, identifying external entities, target ports, and potential inbound intrusion attempts.",
    outgoing_traffic: "Analyze outgoing network connections for signs of data exfiltration, abnormal beaconing, or unauthorized external communications.",
    explain_alerts: "Explain the highest priority open alerts in the SOC queue and recommend immediate triage steps.",
    unusual_ports: "Highlight any unusual port activity, anomalous services, or suspicious port sweep behaviors.",
    generate_report: "Generate a full formal SOC Incident Investigation Report based on current database telemetry.",
  };

  const text = quickPromptMap[key] || "Summarize current network activity.";
  const input = document.getElementById('agentTextInput');
  if (input) {
    input.value = text;
    sendAgentMessage();
  }
}

async function clearAgentConversation() {
  await fetch(`${API_BASE}/api/agent/history?conversation_id=${conversationId}`, { method: 'DELETE' });
  const container = document.getElementById('agentChatMessages');
  if (container) {
    container.innerHTML = `
      <div class="agent-message-row assistant">
        <div class="msg-bubble assistant">
          <div class="msg-header">
            <span class="msg-sender">AI SOC Analyst</span>
            <span class="msg-time">Just now</span>
          </div>
          <div class="msg-text">
            Conversation memory cleared. Ready for fresh network investigations.
          </div>
        </div>
      </div>
    `;
  }
  showToast('info', 'Chat Cleared', 'Conversation history reset.');
}

/* ═══════════════════════════════════════════════════════════
   FLOATING AI ASSISTANT & DRAWER
═══════════════════════════════════════════════════════════ */
function toggleFloatingAiDrawer() {
  const drawer = document.getElementById('aiSideDrawer');
  if (!drawer) return;
  drawer.classList.toggle('hidden');
}

async function sendDrawerMessage() {
  const input = document.getElementById('drawerTextInput');
  if (!input) return;
  const message = input.value.trim();
  if (!message) return;

  input.value = '';
  const msgContainer = document.getElementById('drawerChatMessages');
  if (msgContainer) {
    const userRow = document.createElement('div');
    userRow.className = 'agent-message-row user';
    userRow.innerHTML = `<div class="msg-bubble user" style="font-size:12px">${message}</div>`;
    msgContainer.appendChild(userRow);
    msgContainer.scrollTop = msgContainer.scrollHeight;
  }

  try {
    const res = await fetch(`${API_BASE}/api/agent/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: message,
        conversation_id: conversationId,
        language: currentSpeechLanguage,
        analysis_id: currentAnalysisId,
      }),
    });
    if (!res.ok) throw new Error();
    const data = await res.json();

    if (msgContainer) {
      const aiRow = document.createElement('div');
      aiRow.className = 'agent-message-row assistant';
      aiRow.innerHTML = `<div class="msg-bubble assistant" style="font-size:12px">${formatChatMarkdown(data.response)}</div>`;
      msgContainer.appendChild(aiRow);
      msgContainer.scrollTop = msgContainer.scrollHeight;
    }
  } catch (err) {}
}


/* ═══════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  // Wire nav items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => navigate(item.dataset.page));
  });

  // Form submission
  const form = document.getElementById('predictionForm');
  if (form) form.addEventListener('submit', submitPrediction);

  // Upload zone
  initUploadZone();

  // Start with dashboard
  navigate('dashboard');

  // Set current date defaults for reports
  const today = new Date().toISOString().split('T')[0];
  const lastMonth = new Date(Date.now() - 30*86400000).toISOString().split('T')[0];
  const startEl = document.getElementById('reportStartDate');
  const endEl   = document.getElementById('reportEndDate');
  if (startEl) startEl.value = lastMonth;
  if (endEl)   endEl.value   = today;
});
