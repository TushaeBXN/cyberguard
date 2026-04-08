const { app, BrowserWindow, ipcMain, Menu, shell } = require('electron');
const { execSync } = require('child_process');
const path  = require('path');
const si    = require('systeminformation');
const store = require('./store');
const feeds = require('./feeds');

let mainWindow;
let statsInterval;
let threatInterval;
let feedRefreshInterval;
let threatCount = 0;
let cachedFeeds = [];

// ── Window ────────────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width:    1200,
    height:   780,
    minWidth: 1000,
    minHeight: 680,
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 20 },
    backgroundColor: '#f5f5f7',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    startMonitoring();
    refreshFeeds();
  });

  mainWindow.on('closed', () => {
    stopMonitoring();
    mainWindow = null;
  });

  buildMenu();
}

// ── Monitoring ────────────────────────────────────────────────────────────────

function startMonitoring() {
  // Live stats every 2 s
  statsInterval = setInterval(async () => {
    try {
      const [load, mem, nets] = await Promise.all([
        si.currentLoad(),
        si.mem(),
        si.networkStats(),
      ]);
      const net = nets[0] || {};
      mainWindow?.webContents.send('stats-update', {
        cpu:        Math.round(load.currentLoad),
        ram:        Math.round((mem.used / mem.total) * 100),
        ramUsedGB:  +(mem.used  / 1e9).toFixed(1),
        ramTotalGB: +(mem.total / 1e9).toFixed(1),
        netInKB:    Math.round((net.rx_sec || 0) / 1024),
        netOutKB:   Math.round((net.tx_sec || 0) / 1024),
        timestamp:  Date.now(),
      });
    } catch (_) {}
  }, 2000);

  // Simulated threat events (v2 will plug in real IDS)
  threatInterval = setInterval(() => {
    if (Math.random() < 0.12) emitSimulatedThreat();
  }, 10000);

  // Refresh intelligence feeds every 30 min
  feedRefreshInterval = setInterval(refreshFeeds, 30 * 60 * 1000);
}

function stopMonitoring() {
  clearInterval(statsInterval);
  clearInterval(threatInterval);
  clearInterval(feedRefreshInterval);
}

async function refreshFeeds() {
  try {
    console.log('[feeds] Fetching intelligence feeds…');
    cachedFeeds = await feeds.fetchAll();
    mainWindow?.webContents.send('feeds-updated', cachedFeeds);
    console.log(`[feeds] Got ${cachedFeeds.length} items`);
  } catch (e) {
    console.error('[feeds] Error:', e.message);
  }
}

// ── Simulated threats ─────────────────────────────────────────────────────────

const THREAT_TYPES = [
  { type: 'Port Scan',           severity: 'Medium'   },
  { type: 'Brute Force Attempt', severity: 'High'     },
  { type: 'DNS Anomaly',         severity: 'Low'      },
  { type: 'Suspicious Process',  severity: 'High'     },
  { type: 'Outbound C2 Attempt', severity: 'Critical' },
  { type: 'Malicious URL Block', severity: 'Medium'   },
  { type: 'SSH Auth Failure',    severity: 'Medium'   },
  { type: 'ARP Spoofing Probe',  severity: 'High'     },
];

function randIp() {
  return `${192 + Math.floor(Math.random() * 10)}.168.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 254) + 1}`;
}

function emitSimulatedThreat() {
  const t = THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)];
  threatCount++;
  mainWindow?.webContents.send('threat-detected', {
    id:        Date.now(),
    count:     threatCount,
    type:      t.type,
    severity:  t.severity,
    source:    randIp(),
    blocked:   true,
    timestamp: new Date().toISOString(),
  });
}

// ── IPC: System stats ─────────────────────────────────────────────────────────

ipcMain.handle('get-system-stats', async () => {
  const [load, mem, disks, nets, cpu] = await Promise.all([
    si.currentLoad(), si.mem(), si.fsSize(), si.networkStats(), si.cpu(),
  ]);
  const disk = disks.find(d => d.mount === '/') || disks[0] || {};
  const net  = nets[0] || {};
  return {
    cpu:        Math.round(load.currentLoad),
    cpuModel:   cpu.brand || 'Processor',
    cpuCores:   cpu.cores  || 0,
    ram:        Math.round((mem.used / mem.total) * 100),
    ramUsedGB:  +(mem.used  / 1e9).toFixed(1),
    ramTotalGB: +(mem.total / 1e9).toFixed(1),
    disk:       disk.size ? Math.round((disk.used / disk.size) * 100) : 0,
    diskUsedGB: disk.used  ? Math.round(disk.used  / 1e9) : 0,
    diskTotalGB:disk.size  ? Math.round(disk.size  / 1e9) : 0,
    netInKB:    Math.round((net.rx_sec || 0) / 1024),
    netOutKB:   Math.round((net.tx_sec || 0) / 1024),
  };
});

// ── IPC: Security checks ──────────────────────────────────────────────────────

ipcMain.handle('get-security-checks', () => {
  const run = cmd => { try { return execSync(cmd, { timeout: 5000 }).toString().trim(); } catch { return ''; } };
  const checks = [];

  const fw = run('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null');
  checks.push({ id: 'firewall', name: 'Firewall', icon: 'firewall',
    status: fw.includes('enabled') ? 'pass' : 'fail',
    detail: fw.includes('enabled') ? 'Enabled — blocking unsolicited connections' : 'Disabled — your Mac is exposed to the network',
    fix: 'System Settings → Network → Firewall' });

  const fv = run('fdesetup status 2>/dev/null');
  checks.push({ id: 'filevault', name: 'FileVault Encryption', icon: 'lock',
    status: fv.includes('On') ? 'pass' : 'warn',
    detail: fv.includes('On') ? 'Disk encryption is active' : 'Disk is unencrypted — data is readable if the device is lost',
    fix: 'System Settings → Privacy & Security → FileVault' });

  const sip = run('csrutil status 2>/dev/null');
  checks.push({ id: 'sip', name: 'System Integrity Protection', icon: 'shield',
    status: sip.includes('enabled') ? 'pass' : 'warn',
    detail: sip.includes('enabled') ? 'SIP is protecting system files' : 'SIP is disabled — system files are modifiable',
    fix: 'Re-enable from macOS Recovery (hold Power on Apple Silicon)' });

  const gk = run('spctl --status 2>/dev/null');
  checks.push({ id: 'gatekeeper', name: 'Gatekeeper', icon: 'gatekeeper',
    status: gk.includes('enabled') ? 'pass' : 'warn',
    detail: gk.includes('enabled') ? 'Only verified apps are allowed' : 'Unverified apps can run freely',
    fix: 'System Settings → Privacy & Security' });

  const au = run('defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null');
  checks.push({ id: 'updates', name: 'Automatic Updates', icon: 'refresh',
    status: au === '1' ? 'pass' : 'warn',
    detail: au === '1' ? 'macOS checks for security updates automatically' : 'Auto-updates are off — patches must be applied manually',
    fix: 'System Settings → General → Software Update' });

  const sl = run('defaults read com.apple.screensaver idleTime 2>/dev/null');
  const idle = parseInt(sl, 10) || 0;
  checks.push({ id: 'screenlock', name: 'Screen Lock', icon: 'screenlock',
    status: idle > 0 && idle <= 300 ? 'pass' : 'warn',
    detail: idle > 0 ? `Screen locks after ${Math.round(idle / 60)} min of inactivity` : 'Screen never locks automatically',
    fix: 'System Settings → Lock Screen' });

  return checks;
});

// ── IPC: Network devices ──────────────────────────────────────────────────────

ipcMain.handle('get-network-devices', () => {
  try {
    const raw = execSync('arp -a 2>/dev/null', { timeout: 5000 }).toString();
    return raw.split('\n')
      .filter(l => l.includes('at') && !l.includes('incomplete') && !l.includes('(0.0.0.0)'))
      .map(l => {
        const m = l.match(/^(\S+)\s+\(([^)]+)\)\s+at\s+(\S+)/);
        if (!m) return null;
        return { hostname: m[1] === '?' ? 'Unknown Device' : m[1].replace(/\.$/, ''), ip: m[2], mac: m[3], status: 'online' };
      })
      .filter(Boolean)
      .slice(0, 25);
  } catch { return []; }
});

// ── IPC: Processes ────────────────────────────────────────────────────────────

ipcMain.handle('get-processes', async () => {
  const SUSPICIOUS = ['xmrig','miner','coinminer','cryptominer','keylogger','backdoor','netcat','ncat','reverse_shell'];
  try {
    const { list } = await si.processes();
    return list.sort((a, b) => b.cpu - a.cpu).slice(0, 40).map(p => ({
      pid:  p.pid, name: p.name,
      cpu:  +p.cpu.toFixed(1), mem: +p.mem.toFixed(1), user: p.user || '—',
      suspicious: SUSPICIOUS.some(s => p.name.toLowerCase().includes(s)),
    }));
  } catch { return []; }
});

// ── IPC: Intelligence feeds ───────────────────────────────────────────────────

ipcMain.handle('get-feeds', () => cachedFeeds);
ipcMain.handle('refresh-feeds', async () => { await refreshFeeds(); return cachedFeeds; });

// ── IPC: Credentials ─────────────────────────────────────────────────────────

ipcMain.handle('cred-get-masked', () => store.getMasked());
ipcMain.handle('cred-configured', () => store.getConfiguredKeys());
ipcMain.handle('cred-set', (_, key, value) => { store.set(key, value); return true; });
ipcMain.handle('cred-delete', (_, key) => { store.delete(key); return true; });

// ── IPC: Test API connections ─────────────────────────────────────────────────

ipcMain.handle('cred-test', async (_, service) => {
  const key = store.get(service);
  if (!key) return { ok: false, msg: 'No API key configured' };

  try {
    if (service === 'virustotal') {
      const r = await fetchJSON(`https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8`, { 'x-apikey': key });
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'abuseipdb') {
      const r = await fetchJSON('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', { 'Key': key, 'Accept': 'application/json' });
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'shodan') {
      const r = await fetchJSON(`https://api.shodan.io/api-info?key=${key}`, {});
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'hibp') {
      // HIBP requires a real email to test — just validate key length
      return key.length >= 20 ? { ok: true, msg: 'Key saved (test with a scan)' } : { ok: false, msg: 'Key looks too short' };
    }
    return { ok: false, msg: 'Unknown service' };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
});

// ── IPC: App info ─────────────────────────────────────────────────────────────

ipcMain.handle('get-version', () => app.getVersion());
ipcMain.handle('open-url', (_, url) => shell.openExternal(url));
ipcMain.handle('check-for-updates', () => {
  if (app.isPackaged) {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.checkForUpdates();
  }
  return app.getVersion();
});

// ── Fetch helper (main process — no CORS) ────────────────────────────────────

function fetchJSON(url, headers) {
  const https = require('https');
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

// ── App lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  store.init(app.getPath('userData'));
  createWindow();

  // Auto-updater (only when packaged)
  if (app.isPackaged) {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.checkForUpdatesAndNotify();
    autoUpdater.on('update-available',  () => mainWindow?.webContents.send('update-available'));
    autoUpdater.on('update-downloaded', () => mainWindow?.webContents.send('update-downloaded'));
  }
});

app.on('window-all-closed', () => {
  stopMonitoring();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ── Menu ──────────────────────────────────────────────────────────────────────

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'CyberGuard', submenu: [
      { label: 'About CyberGuard', role: 'about' },
      { type: 'separator' },
      { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
      { type: 'separator' },
      { role: 'quit' },
    ]},
    { label: 'View', submenu: [
      { role: 'reload' }, { role: 'toggleDevTools' },
      { type: 'separator' },
      { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
      { type: 'separator' }, { role: 'togglefullscreen' },
    ]},
    { label: 'Window', submenu: [
      { role: 'minimize' }, { role: 'zoom' }, { type: 'separator' }, { role: 'front' },
    ]},
  ]));
}
