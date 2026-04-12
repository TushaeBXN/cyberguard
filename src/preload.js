const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberguard', {
  // System
  getSystemStats:    () => ipcRenderer.invoke('get-system-stats'),
  getSecurityChecks: () => ipcRenderer.invoke('get-security-checks'),
  getNetworkDevices: () => ipcRenderer.invoke('get-network-devices'),
  getProcesses:      () => ipcRenderer.invoke('get-processes'),
  getVersion:        () => ipcRenderer.invoke('get-version'),
  checkForUpdates:   () => ipcRenderer.invoke('check-for-updates'),
  openUrl:           (url) => ipcRenderer.invoke('open-url', url),

  // Live monitoring data
  getConnections: () => ipcRenderer.invoke('get-connections'),
  getPorts:       () => ipcRenderer.invoke('get-ports'),

  // Intelligence feeds
  getFeeds:     () => ipcRenderer.invoke('get-feeds'),
  refreshFeeds: () => ipcRenderer.invoke('refresh-feeds'),

  // Credentials (encrypted, local only)
  credGetMasked:  ()         => ipcRenderer.invoke('cred-get-masked'),
  credConfigured: ()         => ipcRenderer.invoke('cred-configured'),
  credSet:        (key, val) => ipcRenderer.invoke('cred-set', key, val),
  credDelete:     (key)      => ipcRenderer.invoke('cred-delete', key),
  credTest:       (service)  => ipcRenderer.invoke('cred-test', service),

  // Scanners (real — results from actual APIs)
  scanIP:             (ip)       => ipcRenderer.invoke('scan-ip', ip),
  scanURL:            (url)      => ipcRenderer.invoke('scan-url', url),
  scanFile:           ()         => ipcRenderer.invoke('scan-file'),
  checkEmailBreach:   (email)    => ipcRenderer.invoke('check-email-breach', email),
  checkPasswordBreach:(password) => ipcRenderer.invoke('check-password-breach', password),

  // Real-time push events from main process
  onStatsUpdate:       (cb) => ipcRenderer.on('stats-update',        (_, d) => cb(d)),
  onThreatDetected:    (cb) => ipcRenderer.on('threat-detected',     (_, d) => cb(d)),
  onFeedsUpdated:      (cb) => ipcRenderer.on('feeds-updated',       (_, d) => cb(d)),
  onConnectionsUpdate: (cb) => ipcRenderer.on('connections-update',  (_, d) => cb(d)),
  onPortsUpdate:       (cb) => ipcRenderer.on('ports-update',        (_, d) => cb(d)),
  onUpdateAvailable:   (cb) => ipcRenderer.on('update-available',    ()     => cb()),
  onUpdateDownloaded:  (cb) => ipcRenderer.on('update-downloaded',   ()     => cb()),

  off: (channel) => ipcRenderer.removeAllListeners(channel),
});
