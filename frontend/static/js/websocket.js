/* ── WEBSOCKET MANAGER ── */

const WS_URL  = 'ws://localhost:8765';
const API_URL = 'http://localhost:8000';

/* ── Demo data ── */
const _D = {
  ips: [
    '185.220.101.34','91.108.4.0','45.33.32.156','198.51.100.42',
    '203.0.113.77','104.21.45.67','176.10.99.200','62.210.105.116',
    '192.168.1.10','10.0.0.5',
  ],
  msgs: [
    'SSH brute-force attempt detected',
    'Port scan from external host',
    'Failed login: root@server',
    'SQL injection attempt blocked',
    'DDoS pattern detected',
    'Unauthorized API access',
    'Malware signature matched',
    'Normal traffic flow',
    'Firewall rule triggered',
    'C2 beacon detected',
  ],
  attacks: ['brute_force','port_scan','sql_injection','ddos','malware','unauthorized','normal'],
  risks:   ['low','low','medium','medium','high','critical'],
  locs: [
    { country: 'United States', country_code: 'US', city: 'New York',   isp: 'Cloudflare Inc.' },
    { country: 'Russia',        country_code: 'RU', city: 'Moscow',     isp: 'Rostelecom' },
    { country: 'China',         country_code: 'CN', city: 'Beijing',    isp: 'China Telecom' },
    { country: 'Germany',       country_code: 'DE', city: 'Berlin',     isp: 'Deutsche Telekom' },
    { country: 'Brazil',        country_code: 'BR', city: 'São Paulo',  isp: 'Claro S.A.' },
    { country: 'United Kingdom',country_code: 'GB', city: 'London',     isp: 'BT Group' },
    { country: 'India',         country_code: 'IN', city: 'Mumbai',     isp: 'Reliance Jio' },
    { country: 'Japan',         country_code: 'JP', city: 'Tokyo',      isp: 'NTT Communications' },
    { country: 'North Korea',   country_code: 'KP', city: 'Pyongyang',  isp: 'Star JV' },
    { country: 'Iran',          country_code: 'IR', city: 'Tehran',     isp: 'TCI' },
  ],
};

function _rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function _flagEmoji(code) {
  try { return [...code.toUpperCase()].map(c => String.fromCodePoint(c.charCodeAt(0) + 127397)).join(''); }
  catch { return '🌐'; }
}

function _demoLog() {
  const risk  = _rand(_D.risks);
  const loc   = _rand(_D.locs);
  const score = risk === 'critical' ? Math.floor(Math.random()*20)+80
              : risk === 'high'     ? Math.floor(Math.random()*20)+60
              : risk === 'medium'   ? Math.floor(Math.random()*25)+35
              :                       Math.floor(Math.random()*35);
  const attack = risk === 'low' ? 'normal' : _rand(_D.attacks.filter(a => a !== 'normal'));
  return {
    ip:           _rand(_D.ips),
    message:      _rand(_D.msgs),
    risk,
    risk_score:   score,
    attack_type:  attack,
    is_anomaly:   score > 70 && Math.random() > 0.5,
    country:      loc.country,
    country_code: loc.country_code,
    city:         loc.city,
    isp:          loc.isp,
    flag:         _flagEmoji(loc.country_code),
    location:     `${loc.city}, ${loc.country}`,
    timestamp:    new Date().toISOString(),
  };
}

/* ── API helpers ── */
window.apiGet = async function(path) {
  try {
    const token = sessionStorage.getItem('access_token');
    const res   = await fetch(API_URL + path, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (res.status === 401) {
      if (typeof window.doLogout === 'function') window.doLogout();
      return null;
    }
    return res.ok ? res.json() : null;
  } catch {
    return null; // backend offline — silently ignore
  }
};

window.apiPost = async function(path, body) {
  const token = sessionStorage.getItem('access_token');
  const res   = await fetch(API_URL + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, status: res.status, data: await res.json().catch(() => ({})) };
};

window.apiDelete = async function(path) {
  const token = sessionStorage.getItem('access_token');
  const res   = await fetch(API_URL + path, {
    method: 'DELETE',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  return res.ok;
};

/* ── WebSocket Manager ── */
class WSManager {
  constructor() {
    this.ws        = null;
    this.retries   = 0;
    this.maxRetry  = 5;
    this.demoTimer = null;
    this.connected = false;
  }

  connect() {
    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        this.connected = true;
        this.retries   = 0;
        clearInterval(this.demoTimer);
        window.setWsStatus('Live', true);
        window.showToast('WebSocket connected', 'green');
        // Subscribe to get initial data burst
        this.ws.send(JSON.stringify({ type: 'subscribe' }));
      };

      this.ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          this._dispatch(msg);
        } catch { /* ignore malformed */ }
      };

      this.ws.onclose = () => {
        this.connected = false;
        window.setWsStatus('Reconnecting…', false);
        this._retry();
      };

      this.ws.onerror = () => this.ws.close();

    } catch {
      this._startDemo();
    }
  }

  _dispatch(msg) {
    const { type, data } = msg;
    if (type === 'log')       window.handleLogEvent(data);
    else if (type === 'alert') window.handleAlertEvent(data);
    else if (type === 'init') {
      (data.logs   || []).forEach(l => window.handleLogEvent(l));
      (data.alerts || []).forEach(a => window.handleAlertEvent(a));
    }
    else if (type === 'stats') window.handleStatsEvent(data);
    else if (type === 'heartbeat') { /* keep-alive, no-op */ }
  }

  _retry() {
    if (this.retries >= this.maxRetry) { this._startDemo(); return; }
    this.retries++;
    setTimeout(() => this.connect(), 2000 * this.retries);
  }

  _startDemo() {
    window.setWsStatus('Demo Mode', false);
    window.showToast('Running in demo mode', 'blue');
    clearInterval(this.demoTimer);
    this.demoTimer = setInterval(() => window.handleLogEvent(_demoLog()), 1600);
  }

  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN)
      this.ws.send(JSON.stringify(data));
  }
}

window.wsManager = new WSManager();
