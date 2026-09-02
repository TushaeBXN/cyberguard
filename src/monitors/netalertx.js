/**
 * netalertx.js — NetAlertX local network integration for CyberGuard AI
 *
 * Polls a local NetAlertX instance (Docker or bare-metal) for:
 *   • New/unknown devices appearing on the LAN
 *   • Devices going offline unexpectedly (potential takedown / ARP spoofing)
 *   • Rogue device detection (MAC not in known-good list)
 *
 * SCAN BOUNDARY ENFORCED: this module only reads from a local NetAlertX
 * API endpoint (127.0.0.1 or a configured LAN IP). No traffic is sent
 * outside the local network. If the configured host is non-RFC-1918,
 * the monitor refuses to start.
 *
 * Setup:
 *   1. Run NetAlertX locally: docker run -d --net=host jokobsk/netalertx
 *   2. Set NETALERTX_HOST in environment (default: http://127.0.0.1:20211)
 *   3. CyberGuard AI will auto-load this monitor on startup.
 *
 * NetAlertX API docs: https://github.com/netalertx/NetAlertX/blob/main/docs/API.md
 */

'use strict';

const http  = require('http');
const https = require('https');
const net   = require('net');

// ── Configuration ─────────────────────────────────────────────────────────
const NETALERTX_HOST = process.env.NETALERTX_HOST || 'http://127.0.0.1:20211';
const POLL_INTERVAL_MS = parseInt(process.env.NETALERTX_POLL_MS || '30000', 10);
const ROGUE_ALERT_THRESHOLD = 1; // alert immediately on any unknown device

// ── RFC-1918 + loopback enforcement ──────────────────────────────────────
const LOCAL_RANGES = [
  { start: ip2long('10.0.0.0'),    end: ip2long('10.255.255.255')   },
  { start: ip2long('172.16.0.0'),  end: ip2long('172.31.255.255')   },
  { start: ip2long('192.168.0.0'), end: ip2long('192.168.255.255')  },
  { start: ip2long('127.0.0.0'),   end: ip2long('127.255.255.255')  },
];

function ip2long(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function isLocalIp(ipStr) {
  try {
    if (!net.isIPv4(ipStr)) return ipStr === 'localhost' || ipStr === '::1';
    const n = ip2long(ipStr);
    return LOCAL_RANGES.some(r => n >= r.start && n <= r.end);
  } catch (_) { return false; }
}

function extractHost(urlStr) {
  try {
    return new URL(urlStr).hostname;
  } catch (_) { return urlStr; }
}

// ── State ─────────────────────────────────────────────────────────────────
let knownDevices  = new Map();  // mac → {ip, name, lastSeen, trusted}
let trustedMACs   = new Set();  // populated from /api/devices on first poll
let alertCallback = null;       // set by start()
let pollTimer     = null;

// ── HTTP helper (no npm deps) ─────────────────────────────────────────────
function fetchJSON(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// ── NetAlertX API wrappers ─────────────────────────────────────────────────

async function fetchDevices() {
  // NetAlertX REST API: GET /api/devices returns list of known devices
  const url = `${NETALERTX_HOST}/api/devices`;
  const data = await fetchJSON(url);
  // Response is either data.data (array) or data directly
  return Array.isArray(data) ? data : (data.data || data.devices || []);
}

async function fetchAlerts() {
  // GET /api/notifications returns recent unread alerts
  try {
    const url = `${NETALERTX_HOST}/api/notifications`;
    const data = await fetchJSON(url);
    return Array.isArray(data) ? data : (data.data || []);
  } catch (_) {
    return [];
  }
}

// ── Device change detection ───────────────────────────────────────────────

function classifyDevice(device) {
  const mac  = (device.dev_MAC  || device.MAC  || '').toUpperCase();
  const ip   = device.dev_LastIP || device.IP  || '';
  const name = device.dev_Name  || device.Name || 'Unknown';
  const isNew        = !knownDevices.has(mac);
  const isTrusted    = trustedMACs.has(mac);
  const isOnline     = device.dev_PresentLastScan === 1 || device.Status === 'online';

  return { mac, ip, name, isNew, isTrusted, isOnline };
}

function emit(severity, title, detail, metadata = {}) {
  if (alertCallback) {
    alertCallback({ source: 'netalertx', severity, title, detail, metadata, ts: Date.now() });
  }
}

// ── Poll cycle ────────────────────────────────────────────────────────────

async function poll() {
  let devices;
  try {
    devices = await fetchDevices();
  } catch (err) {
    // NetAlertX not reachable — not an error state, just not running
    return;
  }

  const currentMACs = new Set();

  for (const raw of devices) {
    const d = classifyDevice(raw);
    if (!d.mac) continue;
    currentMACs.add(d.mac);

    if (d.isNew) {
      // First poll: populate known-device map without alerting
      if (knownDevices.size === 0 && devices.length > 1) {
        knownDevices.set(d.mac, { ip: d.ip, name: d.name, lastSeen: Date.now(), trusted: d.isTrusted });
        if (d.isTrusted) trustedMACs.add(d.mac);
        continue;
      }

      // Subsequent polls: new MAC = possible rogue device
      knownDevices.set(d.mac, { ip: d.ip, name: d.name, lastSeen: Date.now(), trusted: false });

      const severity = d.isTrusted ? 'low' : 'high';
      emit(severity, `New device on LAN: ${d.name || d.mac}`,
        `MAC ${d.mac} (${d.ip}) appeared on the network. ${d.isTrusted ? 'Trusted device.' : 'NOT in trusted list — possible rogue device.'}`,
        { mac: d.mac, ip: d.ip, name: d.name, trusted: d.isTrusted }
      );
    } else {
      // Update last-seen
      const entry = knownDevices.get(d.mac);
      if (entry) { entry.lastSeen = Date.now(); entry.ip = d.ip; }
    }
  }

  // Check for devices that disappeared (possible ARP spoofing / takedown)
  for (const [mac, info] of knownDevices.entries()) {
    if (!currentMACs.has(mac)) {
      const ageMin = (Date.now() - info.lastSeen) / 60000;
      if (ageMin < 5) {  // only alert if recently seen (< 5 min)
        emit('medium', `Device went offline: ${info.name || mac}`,
          `MAC ${mac} (${info.ip}) was online and has disappeared. Possible disconnect, ARP spoofing, or network issue.`,
          { mac, ip: info.ip, name: info.name }
        );
      }
      knownDevices.delete(mac);
    }
  }

  // Pull NetAlertX's own alert queue and forward high-severity ones
  const natAlerts = await fetchAlerts();
  for (const a of natAlerts) {
    const text = a.alert_Text || a.text || '';
    const level = (a.alert_Level || a.level || '').toLowerCase();
    if (level === 'critical' || level === 'high' || text.toLowerCase().includes('rogue')) {
      emit(level === 'critical' ? 'critical' : 'high',
        `NetAlertX: ${a.alert_Name || a.name || 'Alert'}`,
        text,
        { source_alert_id: a.alert_id || a.id }
      );
    }
  }
}

// ── Public interface ──────────────────────────────────────────────────────

/**
 * Start the NetAlertX monitor.
 * @param {Function} onAlert - callback(alert) called for each new threat
 * @returns {boolean} true if started, false if refused (non-local host)
 */
function start(onAlert) {
  const host = extractHost(NETALERTX_HOST);
  if (!isLocalIp(host)) {
    console.error(`[NetAlertX] REFUSED: configured host '${host}' is not RFC-1918/loopback.`);
    console.error('  Scanning cannot leave your network. Set NETALERTX_HOST to a local address.');
    return false;
  }

  alertCallback = onAlert;
  console.log(`[NetAlertX] Monitor started — polling ${NETALERTX_HOST} every ${POLL_INTERVAL_MS / 1000}s`);

  // Immediate first poll to seed known-device map
  poll().catch(() => {});

  pollTimer = setInterval(() => poll().catch(() => {}), POLL_INTERVAL_MS);
  return true;
}

function stop() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  alertCallback = null;
  console.log('[NetAlertX] Monitor stopped.');
}

/** Add a MAC to the trusted list at runtime (permission control). */
function trustDevice(mac) {
  const normalized = mac.toUpperCase();
  trustedMACs.add(normalized);
  const entry = knownDevices.get(normalized);
  if (entry) entry.trusted = true;
}

/** Remove trust from a device. */
function distrustDevice(mac) {
  trustedMACs.delete(mac.toUpperCase());
}

/** Return current device snapshot for CyberGuard UI. */
function getDevices() {
  return Array.from(knownDevices.entries()).map(([mac, info]) => ({
    mac, ...info, trusted: trustedMACs.has(mac),
  }));
}

module.exports = { start, stop, trustDevice, distrustDevice, getDevices };
