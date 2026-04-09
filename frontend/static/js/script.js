/* ══════════════════════════════════════════════════════════
   CyberSec Dashboard — Main Script
   Handles: Auth, Log rendering, Alerts, Geo, Admin, Analytics
══════════════════════════════════════════════════════════ */

/* ── STATE ── */
const state = {
  total: 0, high: 0, blocked: 0, anomaly: 0,
  risk: { low: 0, medium: 0, high: 0, critical: 0 },
  geoMap: {},
  attackCounts: {},
  countryCounts: {},
  lineBuffer: 0,
  unreadAlerts: 0,
  logFilter: '',
  role: '',
};

const MAX_LOGS   = 80;
const MAX_ALERTS = 40;
/* API_URL is declared in websocket.js — do NOT redeclare here */

/* ── DOM REFS ── */
const logFeed    = document.getElementById('log-feed');
const alertFeed  = document.getElementById('alert-feed');
const geoList    = document.getElementById('geo-list');
const geoCount   = document.getElementById('geo-count');
const wsStatusEl = document.getElementById('ws-status');
const alertBadge = document.getElementById('alert-badge');

/* ── RISK CONFIG ── */
const RISK_CFG = {
  low:      { badge: 'badge-green',  label: 'LOW',  color: '#00ff9c' },
  medium:   { badge: 'badge-yellow', label: 'MED',  color: '#ffd700' },
  high:     { badge: 'badge-orange', label: 'HIGH', color: '#ff8c00' },
  critical: { badge: 'badge-red',    label: 'CRIT', color: '#ff3b3b' },
};

/* ── HELPERS ── */
const fmtTime = iso => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fmtDate = iso => new Date(iso).toLocaleString();
function trimFeed(el, max) { while (el.children.length > max) el.removeChild(el.lastChild); }
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── WS STATUS ── */
window.setWsStatus = function(msg, ok) {
  wsStatusEl.textContent = msg;
  wsStatusEl.style.color = ok ? 'var(--green)' : 'var(--yellow)';
  document.querySelector('.pulse-dot').style.background = ok ? 'var(--green)' : 'var(--yellow)';
};

/* ── TOAST ── */
window.showToast = function(msg, color = 'blue') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = `var(--${color})`;
  t.style.color = `var(--${color})`;
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 3000);
};

/* ══════════════════════════════════════════════════════════
   AUTH
══════════════════════════════════════════════════════════ */

async function tryLogin() {
  const user = document.getElementById('login-user').value.trim();
  const pass = document.getElementById('login-pass').value;
  const errEl = document.getElementById('login-error');
  const btnText = document.getElementById('login-btn-text');
  const spinner = document.getElementById('login-spinner');

  if (!user || !pass) { errEl.textContent = 'Enter username and password'; return; }

  btnText.style.display = 'none';
  spinner.style.display = 'block';
  errEl.textContent = '';

  try {
    const res = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Login failed';
      btnText.style.display = 'block';
      spinner.style.display = 'none';
      return;
    }

    sessionStorage.setItem('access_token',  data.access_token);
    sessionStorage.setItem('refresh_token', data.refresh_token);
    sessionStorage.setItem('username',      data.username);
    sessionStorage.setItem('role',          data.role);
    btnText.style.display = 'block';
    spinner.style.display = 'none';
    _bootDashboard(data.username, data.role);

  } catch {
    // Backend not running — bypass to demo mode with any credentials
    btnText.style.display = 'block';
    spinner.style.display = 'none';
    sessionStorage.setItem('username', user);
    sessionStorage.setItem('role',     'admin');
    _bootDashboard(user, 'admin');
  }
}

function _bootDashboard(username, role) {
  state.role = role;
  document.getElementById('login-overlay').style.display = 'none';
  document.getElementById('main-navbar').style.display   = 'flex';
  document.getElementById('main-layout').style.display   = 'flex';
  document.getElementById('nav-username').textContent    = username;
  document.getElementById('sidebar-username').textContent = username;
  document.getElementById('sidebar-role').textContent    = role.toUpperCase();

  if (role === 'admin') {
    document.getElementById('admin-nav-link').style.display  = '';
    document.getElementById('admin-sidebar').style.display   = '';
    document.getElementById('admin-section').style.display   = '';
  }

  window.wsManager.connect();
  _startAnalyticsPolling();
}

window.doLogout = async function() {
  const refresh = sessionStorage.getItem('refresh_token');
  if (refresh) {
    await window.apiPost('/api/auth/logout', { refresh_token: refresh }).catch(() => {});
  }
  sessionStorage.clear();
  location.reload();
};

/* ── Login form events ── */
document.getElementById('login-btn').addEventListener('click', tryLogin);
document.getElementById('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') tryLogin(); });
document.getElementById('logout-btn').addEventListener('click', window.doLogout);

/* ── Auto-login check — runs AFTER all scripts are loaded ── */
window.addEventListener('DOMContentLoaded', () => {
  const token    = sessionStorage.getItem('access_token');
  const username = sessionStorage.getItem('username');
  const role     = sessionStorage.getItem('role');
  if (token && username) {
    _bootDashboard(username, role || 'user');
  }
});

/* ══════════════════════════════════════════════════════════
   LOG RENDERING
══════════════════════════════════════════════════════════ */

function _scoreColor(score) {
  if (score >= 80) return '#ff3b3b';
  if (score >= 60) return '#ff8c00';
  if (score >= 35) return '#ffd700';
  return '#00ff9c';
}

function renderLog(data) {
  const r     = RISK_CFG[data.risk] || RISK_CFG.low;
  const score = data.risk_score || 0;
  const color = _scoreColor(score);
  const row   = document.createElement('div');
  row.className = 'log-entry';
  row.dataset.risk = data.risk;

  row.innerHTML = `
    <span class="log-ip">${escHtml(data.ip)}</span>
    <span class="log-msg" title="${escHtml(data.message)}">${escHtml(data.message)}</span>
    <div class="risk-bar-wrap">
      <div class="risk-bar"><div class="risk-bar-fill" style="width:${score}%;background:${color}"></div></div>
      <span class="risk-score-num" style="color:${color}">${score}</span>
    </div>
    <span class="badge ${r.badge}">${r.label}${data.is_anomaly ? ' ⚡' : ''}</span>`;

  if (state.logFilter && data.risk !== state.logFilter) row.classList.add('filtered');
  logFeed.prepend(row);
  trimFeed(logFeed, MAX_LOGS);
}

/* ── Log filter ── */
document.getElementById('log-filter').addEventListener('change', function() {
  state.logFilter = this.value;
  document.querySelectorAll('.log-entry').forEach(el => {
    el.classList.toggle('filtered', !!state.logFilter && el.dataset.risk !== state.logFilter);
  });
});

/* ══════════════════════════════════════════════════════════
   ALERTS
══════════════════════════════════════════════════════════ */

window.handleAlertEvent = function(data) {
  const item = document.createElement('div');
  item.className = 'alert-item';
  item.dataset.id = data.id || '';
  item.innerHTML = `
    <i class="fa-solid fa-skull-crossbones"></i>
    <div class="alert-body">
      <div class="alert-title">${escHtml((data.severity || data.alert_type || 'ALERT').toUpperCase())} — ${escHtml(data.ip_address || data.ip || '')}</div>
      <div class="alert-meta">${escHtml(data.message || '')}</div>
      <div class="alert-score">Risk Score: ${data.risk_score || 0}/100 · ${escHtml(data.city || '')} ${escHtml(data.country || '')}</div>
    </div>
    <span class="alert-time">${fmtTime(data.timestamp || data.created_at || new Date().toISOString())}</span>`;

  item.addEventListener('click', () => {
    item.classList.add('read');
    state.unreadAlerts = Math.max(0, state.unreadAlerts - 1);
    _updateAlertBadge();
    if (data.id) window.apiPost(`/api/alerts/${data.id}/read`, {}).catch(() => {});
  });

  alertFeed.prepend(item);
  trimFeed(alertFeed, MAX_ALERTS);
  state.unreadAlerts++;
  _updateAlertBadge();
};

function _updateAlertBadge() {
  alertBadge.textContent = state.unreadAlerts;
  alertBadge.style.display = state.unreadAlerts > 0 ? '' : 'none';
}

document.getElementById('mark-all-read').addEventListener('click', () => {
  document.querySelectorAll('.alert-item').forEach(el => el.classList.add('read'));
  state.unreadAlerts = 0;
  _updateAlertBadge();
  window.apiPost('/api/alerts/read-all', {}).catch(() => {});
  showToast('All alerts marked as read', 'green');
});

/* ══════════════════════════════════════════════════════════
   GEO MAP
══════════════════════════════════════════════════════════ */

function renderGeo(ip, info) {
  const id  = `geo-${ip.replace(/\./g, '-')}`;
  const existing = document.getElementById(id);
  if (existing) {
    existing.querySelector('.geo-hits').textContent = `${info.hits} hits`;
    if (info.suspicious) existing.classList.add('suspicious');
    return;
  }
  const item = document.createElement('div');
  item.className = `geo-item${info.suspicious ? ' suspicious' : ''}`;
  item.id = id;
  item.innerHTML = `
    <span class="geo-flag">${info.flag || '🌐'}</span>
    <div class="geo-info">
      <div class="geo-ip">${escHtml(ip)}</div>
      <div class="geo-loc">${escHtml(info.location || 'Unknown')}</div>
      <div class="geo-isp">${escHtml(info.isp || '')}</div>
    </div>
    <span class="geo-hits">${info.hits} hits</span>`;
  geoList.prepend(item);
}

/* ══════════════════════════════════════════════════════════
   MAIN LOG EVENT HANDLER
══════════════════════════════════════════════════════════ */

window.handleLogEvent = function(data) {
  const risk = data.risk || 'low';

  // Remove spinner on first event
  const spinner = logFeed.querySelector('.spinner-wrap');
  if (spinner) spinner.remove();

  // State updates
  state.total++;
  state.risk[risk] = (state.risk[risk] || 0) + 1;
  if (risk === 'high' || risk === 'critical') state.high++;
  if (risk === 'critical') state.blocked++;
  if (data.is_anomaly) state.anomaly++;

  // Attack type tracking
  const at = data.attack_type || 'normal';
  state.attackCounts[at] = (state.attackCounts[at] || 0) + 1;

  // Country tracking
  const country = data.country || 'Unknown';
  state.countryCounts[country] = (state.countryCounts[country] || 0) + 1;

  // Geo map
  if (!state.geoMap[data.ip]) {
    state.geoMap[data.ip] = {
      hits: 0, location: data.location, flag: data.flag,
      isp: data.isp || '', suspicious: false,
    };
  }
  state.geoMap[data.ip].hits++;
  if (risk === 'high' || risk === 'critical') state.geoMap[data.ip].suspicious = true;

  // Render
  renderLog(data);
  renderGeo(data.ip, state.geoMap[data.ip]);
  if (risk === 'high' || risk === 'critical') window.handleAlertEvent({
    ...data, ip_address: data.ip, severity: risk,
    alert_type: data.attack_type || risk,
    message: data.message,
  });

  // Charts
  state.lineBuffer++;
  if (state.lineBuffer % 3 === 0) {
    window.pushLinePoint(state.lineBuffer);
    state.lineBuffer = 0;
  }
  window.updatePieChart(state.risk.low, state.risk.medium, state.risk.high, state.risk.critical);
  _updateAttackChart();
  _updateCountryChart();
  _updateStats();
};

window.handleStatsEvent = function(data) {
  if (data.total)     { state.total   = data.total;    document.getElementById('stat-total').textContent   = state.total; }
  if (data.high_risk) { state.high    = data.high_risk; document.getElementById('stat-high').textContent    = state.high; }
  if (data.blocked)   { state.blocked = data.blocked;  document.getElementById('stat-blocked').textContent = state.blocked; }
  if (data.anomalies) { state.anomaly = data.anomalies; document.getElementById('stat-anomaly').textContent = state.anomaly; }
};

function _updateStats() {
  document.getElementById('stat-total').textContent   = state.total;
  document.getElementById('stat-high').textContent    = state.high;
  document.getElementById('stat-blocked').textContent = state.blocked;
  document.getElementById('stat-anomaly').textContent = state.anomaly;
  geoCount.textContent = `${Object.keys(state.geoMap).length} IPs tracked`;
}

function _updateAttackChart() {
  const sorted = Object.entries(state.attackCounts).sort((a,b) => b[1]-a[1]).slice(0,7);
  window.updateBarChart(sorted.map(e => e[0].replace('_',' ')), sorted.map(e => e[1]));
}

function _updateCountryChart() {
  const sorted = Object.entries(state.countryCounts).sort((a,b) => b[1]-a[1]).slice(0,8);
  window.updateCountryChart(sorted.map(e => e[0]), sorted.map(e => e[1]));
}

/* ══════════════════════════════════════════════════════════
   ANALYTICS POLLING (from REST API)
══════════════════════════════════════════════════════════ */

function _startAnalyticsPolling() {
  _fetchAnalytics();
  setInterval(_fetchAnalytics, 30000);
}

async function _fetchAnalytics() {
  const [topIps, attackTypes, countries] = await Promise.all([
    window.apiGet('/api/analytics/top-ips'),
    window.apiGet('/api/analytics/attack-types'),
    window.apiGet('/api/analytics/country-stats'),
  ]);

  if (topIps)      _renderTopIps(topIps.top_ips || []);
  if (attackTypes) {
    const d = attackTypes.attack_types || [];
    window.updateBarChart(d.map(r => r.attack_type.replace('_',' ')), d.map(r => r.count));
  }
  if (countries) {
    const d = countries.countries || [];
    window.updateCountryChart(d.map(r => r.country), d.map(r => r.total));
  }
}

function _renderTopIps(ips) {
  const tbody = document.getElementById('top-ip-body');
  document.getElementById('top-ip-count').textContent = `${ips.length} IPs`;
  tbody.innerHTML = ips.map(row => `
    <tr>
      <td style="color:var(--blue);font-weight:700">${escHtml(row.ip_address)}</td>
      <td>${row.hits}</td>
      <td><span style="color:${_scoreColor(row.max_score)}">${row.max_score}</span></td>
      <td>${escHtml(row.country || '—')}</td>
      <td>
        <button class="btn-sm" onclick="blockIpQuick('${escHtml(row.ip_address)}')">
          <i class="fa-solid fa-ban"></i> Block
        </button>
      </td>
    </tr>`).join('');
}

window.blockIpQuick = async function(ip) {
  if (state.role !== 'admin') { showToast('Admin access required', 'red'); return; }
  const res = await window.apiPost('/api/admin/block-ip', { ip, reason: 'Blocked from top IPs panel' });
  if (res && res.ok) { showToast(`${ip} blocked`, 'red'); state.blocked++; _updateStats(); }
  else showToast(res?.data?.error || 'Block failed', 'red');
};

/* ══════════════════════════════════════════════════════════
   ADMIN PANEL
══════════════════════════════════════════════════════════ */

async function loadAdminUsers() {
  const data = await window.apiGet('/api/admin/users');
  if (!data) return;
  document.getElementById('users-body').innerHTML = (data.users || []).map(u => `
    <tr>
      <td style="color:var(--blue)">${escHtml(u.username)}</td>
      <td>${escHtml(u.email)}</td>
      <td><span class="badge ${u.role==='admin'?'badge-red':'badge-blue'}">${u.role.toUpperCase()}</span></td>
      <td>${u.last_login ? fmtDate(u.last_login) : '—'}</td>
      <td><span class="badge ${u.is_active?'badge-green':'badge-red'}">${u.is_active?'Active':'Disabled'}</span></td>
      <td>
        <button class="btn-sm" onclick="toggleUser(${u.id})">
          ${u.is_active ? 'Disable' : 'Enable'}
        </button>
      </td>
    </tr>`).join('');
}

window.toggleUser = async function(id) {
  const res = await fetch(`${API_URL}/api/admin/users/${id}/toggle`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${sessionStorage.getItem('access_token')}` },
  });
  if (res.ok) { showToast('User status updated', 'green'); loadAdminUsers(); }
};

async function loadBlockedIps() {
  const data = await window.apiGet('/api/admin/blocked-ips');
  if (!data) return;
  document.getElementById('blocked-body').innerHTML = (data.blocked_ips || []).map(b => `
    <tr>
      <td style="color:var(--red)">${escHtml(b.ip_address)}</td>
      <td>${escHtml(b.reason || '—')}</td>
      <td>${escHtml(b.blocked_by_name || '—')}</td>
      <td>${fmtDate(b.blocked_at)}</td>
      <td>
        <button class="btn-sm" onclick="unblockIp('${escHtml(b.ip_address)}')">
          <i class="fa-solid fa-unlock"></i> Unblock
        </button>
      </td>
    </tr>`).join('');
}

window.unblockIp = async function(ip) {
  const ok = await window.apiDelete(`/api/admin/block-ip/${encodeURIComponent(ip)}`);
  if (ok) { showToast(`${ip} unblocked`, 'green'); loadBlockedIps(); }
};

document.getElementById('block-ip-btn').addEventListener('click', async () => {
  const ip     = document.getElementById('block-ip-input').value.trim();
  const reason = document.getElementById('block-ip-reason').value.trim();
  if (!ip) { showToast('Enter an IP address', 'red'); return; }
  const res = await window.apiPost('/api/admin/block-ip', { ip, reason });
  if (res && res.ok) {
    showToast(`${ip} blocked`, 'red');
    document.getElementById('block-ip-input').value  = '';
    document.getElementById('block-ip-reason').value = '';
    loadBlockedIps();
  } else {
    showToast(res?.data?.error || 'Block failed', 'red');
  }
});

async function loadSysLogs() {
  const data = await window.apiGet('/api/admin/system-logs');
  const el   = document.getElementById('syslog-output');
  if (data && data.lines) {
    el.textContent = data.lines.join('\n') || 'No logs yet.';
    el.scrollTop   = el.scrollHeight;
  } else {
    el.textContent = 'System logs unavailable in demo mode.';
  }
}

/* ── Admin tabs ── */
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    document.getElementById(`tab-${tab}`).style.display = '';
    if (tab === 'users')   loadAdminUsers();
    if (tab === 'blocked') loadBlockedIps();
    if (tab === 'syslog')  loadSysLogs();
  });
});

/* ══════════════════════════════════════════════════════════
   SIDEBAR NAVIGATION
══════════════════════════════════════════════════════════ */

const SECTION_MAP = {
  overview:  'logs-section',
  logs:      'logs-section',
  alerts:    'alerts-section',
  geomap:    'geomap-section',
  analytics: 'analytics-section',
  admin:     'admin-section',
};

document.querySelectorAll('.sidebar li').forEach(li => {
  li.addEventListener('click', () => {
    document.querySelectorAll('.sidebar li').forEach(x => x.classList.remove('active'));
    li.classList.add('active');
    const target = SECTION_MAP[li.dataset.section];
    if (target) document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (li.dataset.section === 'admin') { loadAdminUsers(); }
  });
});

/* ── Navbar links ── */
document.querySelectorAll('.nav-links a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-links a').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    const view = a.dataset.view;
    const target = { dashboard: 'logs-section', logs: 'logs-section', analytics: 'analytics-section', admin: 'admin-section' }[view];
    if (target) document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (view === 'admin') loadAdminUsers();
  });
});

/* ── Clear buttons ── */
document.getElementById('clear-logs').addEventListener('click', () => {
  logFeed.innerHTML = '';
  showToast('Logs cleared');
});
document.getElementById('clear-alerts').addEventListener('click', () => {
  alertFeed.innerHTML = '';
  state.unreadAlerts = 0;
  _updateAlertBadge();
  showToast('Alerts cleared');
});
