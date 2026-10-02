const { app, BrowserWindow, WebContentsView, ipcMain, session, safeStorage } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const TOOLBAR_HEIGHT = 112;
const SYNC_INTERVAL_MS = 2500;
const profileName = sanitizeProfile(readArgument('profile') || process.env.SHARED_BROWSER_PROFILE || 'default');
app.setPath('userData', path.join(app.getPath('appData'), 'Shared Browser', profileName));

let mainWindow;
let browserSession;
let config;
let syncTimer;
let syncRunning = false;
let cookiePushTimer;
let activeTabId;
let nextTabId = 1;
let settingsOpen = false;
const tabs = new Map();

function logFatal(error) {
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    fs.appendFileSync(path.join(app.getPath('userData'), 'startup-errors.log'), `${new Date().toISOString()} ${error?.stack || error}\n`);
  } catch { }
}

process.on('uncaughtException', error => { logFatal(error); app.quit(); });
process.on('unhandledRejection', error => logFatal(error));

function readArgument(name) {
  const prefix = `--${name}=`;
  return process.argv.find(value => value.startsWith(prefix))?.slice(prefix.length);
}

function sanitizeProfile(value) {
  const result = String(value).trim().replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 64);
  return result || 'default';
}

function defaultSnapshot() {
  return {
    revision: 0,
    updatedAt: new Date(0).toISOString(),
    settings: {
      homePage: 'https://example.com/',
      primaryDeviceId: '',
      autoShareCookies: true,
      proxy: { enabled: false, host: '127.0.0.1', port: 8899, allowedPorts: '80,443', bypassList: 'localhost;127.0.0.1' }
    },
    profiles: [],
    bookmarks: []
  };
}

function defaultConfig() {
  return {
    serverUrl: 'http://127.0.0.1:8787',
    deviceId: crypto.randomUUID().replaceAll('-', ''),
    deviceName: profileName,
    networkMode: 'direct',
    secrets: { deviceToken: '', enrollmentToken: '', cache: defaultSnapshot() }
  };
}

function configPath() {
  return path.join(app.getPath('userData'), 'client-config.json');
}

function encrypt(value) {
  const text = JSON.stringify(value);
  if (safeStorage.isEncryptionAvailable()) return `safe:${safeStorage.encryptString(text).toString('base64')}`;
  return `plain:${Buffer.from(text, 'utf8').toString('base64')}`;
}

function decrypt(value, fallback) {
  try {
    if (typeof value !== 'string') return fallback;
    if (value.startsWith('safe:')) return JSON.parse(safeStorage.decryptString(Buffer.from(value.slice(5), 'base64')));
    if (value.startsWith('plain:')) return JSON.parse(Buffer.from(value.slice(6), 'base64').toString('utf8'));
  } catch { }
  return fallback;
}

function loadConfig() {
  const fresh = defaultConfig();
  try {
    const disk = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    const secrets = decrypt(disk.protected, fresh.secrets);
    return {
      serverUrl: validServerUrl(disk.serverUrl) ? disk.serverUrl.replace(/\/$/, '') : fresh.serverUrl,
      deviceId: /^[a-f0-9]{32}$/i.test(disk.deviceId || '') ? disk.deviceId.toLowerCase() : fresh.deviceId,
      deviceName: String(disk.deviceName || profileName).slice(0, 80),
      networkMode: disk.networkMode === 'managed' ? 'managed' : 'direct',
      secrets: {
        deviceToken: String(secrets?.deviceToken || ''),
        enrollmentToken: String(secrets?.enrollmentToken || ''),
        cache: normalizeSnapshot(secrets?.cache)
      }
    };
  } catch {
    return fresh;
  }
}

function saveConfig() {
  fs.mkdirSync(app.getPath('userData'), { recursive: true });
  const disk = {
    serverUrl: config.serverUrl,
    deviceId: config.deviceId,
    deviceName: config.deviceName,
    networkMode: config.networkMode,
    protected: encrypt(config.secrets)
  };
  const target = configPath();
  const temporary = `${target}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(disk, null, 2));
  fs.renameSync(temporary, target);
}

function normalizeSnapshot(input) {
  const fallback = defaultSnapshot();
  if (!input || typeof input !== 'object') return fallback;
  input.settings ||= fallback.settings;
  input.settings.proxy ||= fallback.settings.proxy;
  input.profiles = Array.isArray(input.profiles) ? input.profiles : [];
  input.bookmarks = Array.isArray(input.bookmarks) ? input.bookmarks : [];
  input.revision = Number(input.revision) || 0;
  return input;
}

function validServerUrl(value) {
  try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; }
}

function send(channel, value) {
  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) mainWindow.webContents.send(channel, value);
}

function status(text, error = false) {
  send('browser:status', {
    text,
    error,
    route: config?.networkMode === 'managed' ? 'Server IP' : 'Client IP'
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 850,
    minHeight: 560,
    title: `Shared Browser — ${profileName}`,
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('resize', layoutActiveView);
  mainWindow.on('closed', () => {
    clearInterval(syncTimer);
    clearTimeout(cookiePushTimer);
    for (const tab of tabs.values()) {
      if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
    }
    tabs.clear();
    mainWindow = undefined;
  });
  mainWindow.webContents.once('did-finish-load', () => {
    publishAll();
    if (!config.secrets.deviceToken && !config.secrets.enrollmentToken) send('browser:show-settings');
  });
}

function layoutActiveView() {
  const tab = tabs.get(activeTabId);
  if (!tab || !mainWindow || mainWindow.isDestroyed()) return;
  const [width, height] = mainWindow.getContentSize();
  tab.view.setBounds({ x: 0, y: TOOLBAR_HEIGHT, width, height: Math.max(0, height - TOOLBAR_HEIGHT) });
}

function publishAll() {
  publishTabs();
  publishNavigationState();
  status(config?.secrets.deviceToken ? `Synced r${config.secrets.cache.revision}` : 'Not enrolled', !config?.secrets.deviceToken);
}

function publishTabs() {
  send('browser:tabs', [...tabs.values()].map(tab => ({ id: tab.id, title: tab.title, active: tab.id === activeTabId })));
}

function publishNavigationState() {
  const tab = tabs.get(activeTabId);
  send('browser:state', {
    url: tab?.view.webContents.getURL() || '',
    canGoBack: tab?.view.webContents.navigationHistory.canGoBack() || false,
    canGoForward: tab?.view.webContents.navigationHistory.canGoForward() || false
  });
}

function normalizeAddress(value) {
  let text = String(value || '').trim();
  if (!text.includes('://')) text = `https://${text}`;
  const url = new URL(text);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Enter a valid HTTP or HTTPS address.');
  return url.toString();
}

async function addTab(url) {
  const id = nextTabId++;
  const view = new WebContentsView({
    webPreferences: {
      session: browserSession,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    }
  });
  const tab = { id, title: 'New tab', view };
  tabs.set(id, tab);
  view.webContents.setWindowOpenHandler(details => {
    addTab(details.url).catch(error => status(error.message, true));
    return { action: 'deny' };
  });
  view.webContents.on('page-title-updated', (event, title) => {
    event.preventDefault();
    tab.title = shortTitle(title);
    publishTabs();
  });
  for (const eventName of ['did-navigate', 'did-navigate-in-page']) {
    view.webContents.on(eventName, () => {
      if (activeTabId === id) publishNavigationState();
    });
  }
  view.webContents.on('did-finish-load', async () => {
    if (activeTabId === id) publishNavigationState();
    await pushCurrentDomain(view.webContents.getURL());
  });
  view.webContents.on('did-fail-load', (_, code, description, failedUrl, isMainFrame) => {
    if (isMainFrame && code !== -3) status(`Page failed: ${description} (${failedUrl})`, true);
  });
  await selectTab(id);
  await applyAllCookies();
  view.webContents.loadURL(normalizeAddress(url || config.secrets.cache.settings.homePage)).catch(error => status(error.message, true));
  return id;
}

async function selectTab(id) {
  const next = tabs.get(Number(id));
  if (!next || !mainWindow) return;
  const current = tabs.get(activeTabId);
  if (current) mainWindow.contentView.removeChildView(current.view);
  activeTabId = next.id;
  if (!settingsOpen) mainWindow.contentView.addChildView(next.view);
  layoutActiveView();
  publishTabs();
  publishNavigationState();
  next.view.webContents.focus();
}

async function closeTab(id) {
  const numericId = Number(id);
  const tab = tabs.get(numericId);
  if (!tab) return;
  const ids = [...tabs.keys()];
  const index = ids.indexOf(numericId);
  if (mainWindow) mainWindow.contentView.removeChildView(tab.view);
  tabs.delete(numericId);
  if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
  if (activeTabId === numericId) activeTabId = undefined;
  if (tabs.size === 0) await addTab(config.secrets.cache.settings.homePage);
  else if (!activeTabId) await selectTab(ids[index - 1] || ids[index + 1] || [...tabs.keys()][0]);
  publishTabs();
}

function shortTitle(value) {
  const title = String(value || 'New tab').trim() || 'New tab';
  return title.length > 28 ? `${title.slice(0, 28)}…` : title;
}

function apiUrl(pathname) {
  return `${config.serverUrl.replace(/\/$/, '')}${pathname}`;
}

async function api(pathname, options = {}, useDevice = true) {
  const headers = { accept: 'application/json', ...(options.headers || {}) };
  if (options.body && !headers['content-type']) headers['content-type'] = 'application/json';
  if (useDevice) {
    headers.authorization = `Bearer ${config.secrets.deviceToken}`;
    headers['x-device-id'] = config.deviceId;
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(apiUrl(pathname), { ...options, headers, signal: controller.signal });
    const text = await response.text();
    if (!response.ok) throw new Error(response.status === 401 ? 'This browser is unauthorized or revoked.' : `Server returned ${response.status}${text ? `: ${text}` : ''}`);
    return text ? JSON.parse(text) : undefined;
  } finally {
    clearTimeout(timeout);
  }
}

async function ensureEnrolled() {
  if (config.secrets.deviceToken) return;
  if (!config.secrets.enrollmentToken) throw new Error('Open Settings and enter the management server administrator token.');
  const result = await api('/api/client/enroll', {
    method: 'POST',
    headers: { authorization: `Bearer ${config.secrets.enrollmentToken}` },
    body: JSON.stringify({ deviceId: config.deviceId, deviceName: config.deviceName })
  }, false);
  config.secrets.deviceId = result.deviceId;
  config.deviceId = result.deviceId;
  config.secrets.deviceToken = result.deviceToken;
  config.secrets.enrollmentToken = '';
  saveConfig();
}

async function pullSnapshot(notify = false) {
  if (!config.secrets.deviceToken || syncRunning) return;
  syncRunning = true;
  try {
    const snapshot = normalizeSnapshot(await api(`/api/client/snapshot?deviceName=${encodeURIComponent(config.deviceName)}`));
    const changed = snapshot.revision !== config.secrets.cache.revision;
    config.secrets.cache = snapshot;
    saveConfig();
    if (changed) {
      await applyAllCookies();
      if (!isPrimary()) tabs.get(activeTabId)?.view.webContents.reload();
    }
    status(`${notify ? 'Synchronization complete — ' : ''}Synced r${snapshot.revision}`);
    publishTabs();
    publishNavigationState();
  } catch (error) {
    status(`Offline cache — ${error.message}`, true);
    if (/unauthorized|revoked/i.test(error.message)) send('browser:show-settings');
  } finally {
    syncRunning = false;
  }
}

function isPrimary() {
  const settings = config.secrets.cache.settings;
  return (settings.autoShareCookies && !settings.primaryDeviceId) || settings.primaryDeviceId?.toLowerCase() === config.deviceId.toLowerCase();
}

function domainMatches(host, domain) {
  const a = String(host || '').replace(/^\./, '').toLowerCase();
  const b = String(domain || '').replace(/^\./, '').toLowerCase();
  return a === b || a.endsWith(`.${b}`);
}

function findProfile(host) {
  return config.secrets.cache.profiles
    .filter(profile => profile.enabled && domainMatches(host, profile.domain))
    .sort((a, b) => b.domain.length - a.domain.length)[0];
}

function electronSameSite(value) {
  if (value === 'Strict') return 'strict';
  if (value === 'None') return 'no_restriction';
  return 'lax';
}

function serverSameSite(value) {
  if (value === 'strict') return 'Strict';
  if (value === 'no_restriction') return 'None';
  return 'Lax';
}

async function applyAllCookies() {
  for (const profile of config.secrets.cache.profiles.filter(item => item.enabled)) {
    for (const cookie of profile.cookies || []) {
      const domain = String(cookie.domain || profile.domain).replace(/^\./, '');
      const cookiePath = String(cookie.path || '/');
      try {
        await browserSession.cookies.set({
          url: `${cookie.secure ? 'https' : 'http'}://${domain}${cookiePath.startsWith('/') ? cookiePath : `/${cookiePath}`}`,
          name: cookie.name,
          value: cookie.value,
          domain,
          path: cookiePath,
          secure: Boolean(cookie.secure),
          httpOnly: Boolean(cookie.httpOnly),
          sameSite: electronSameSite(cookie.sameSite)
        });
      } catch { }
    }
  }
}

function validCookie(cookie) {
  return cookie.name && !/[\s;=]/.test(cookie.name) && !/[\r\n;]/.test(cookie.value || '') && cookie.domain;
}

function toSharedCookie(cookie) {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: String(cookie.domain).replace(/^\./, ''),
    path: cookie.path || '/',
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: serverSameSite(cookie.sameSite)
  };
}

async function pushCurrentDomain(pageUrl) {
  if (!isPrimary() || !config.secrets.deviceToken) return;
  let page;
  try { page = new URL(pageUrl); } catch { return; }
  if (!['http:', 'https:'].includes(page.protocol)) return;
  const profile = findProfile(page.hostname);
  if (!profile && !config.secrets.cache.settings.autoShareCookies) return;
  try {
    const cookies = (await browserSession.cookies.get({ url: page.toString() }))
      .filter(cookie => validCookie(cookie) && domainMatches(page.hostname, cookie.domain))
      .slice(0, 200)
      .map(toSharedCookie);
    await pushCookies(page.toString(), cookies);
  } catch (error) {
    status(`Cookie sync failed — ${error.message}`, true);
  }
}

async function pushAllStoredCookies() {
  if (!isPrimary() || !config.secrets.deviceToken || syncRunning) return;
  syncRunning = true;
  try {
    const cookies = (await browserSession.cookies.get({})).filter(validCookie);
    const groups = new Map();
    for (const cookie of cookies) {
      const domain = String(cookie.domain).replace(/^\./, '').toLowerCase();
      if (!groups.has(domain)) groups.set(domain, []);
      groups.get(domain).push(toSharedCookie(cookie));
    }
    for (const [domain, values] of [...groups.entries()].slice(0, 500)) {
      await pushCookies(`https://${domain}/`, values.slice(0, 200));
    }
    status(`Synced r${config.secrets.cache.revision}`);
  } catch (error) {
    status(`Cookie sync failed — ${error.message}`, true);
  } finally {
    syncRunning = false;
  }
}

async function pushCookies(pageUrl, cookies) {
  const result = await api('/api/client/sync', {
    method: 'POST',
    body: JSON.stringify({ knownRevision: config.secrets.cache.revision, pageUrl, cookies })
  });
  if (result?.snapshot) {
    config.secrets.cache = normalizeSnapshot(result.snapshot);
    saveConfig();
  }
}

function scheduleCookiePush() {
  if (!isPrimary()) return;
  clearTimeout(cookiePushTimer);
  cookiePushTimer = setTimeout(() => pushAllStoredCookies(), 900);
}

async function configureProxy() {
  const proxy = config.secrets.cache.settings.proxy;
  if (config.networkMode !== 'managed') {
    await browserSession.setProxy({ mode: 'direct' });
    return;
  }
  if (!proxy?.enabled) throw new Error('Managed proxy is selected, but it is disabled on the server. Choose Direct mode or enable it in the dashboard.');
  const host = String(proxy.host).includes(':') && !String(proxy.host).startsWith('[') ? `[${proxy.host}]` : proxy.host;
  await browserSession.setProxy({
    mode: 'fixed_servers',
    proxyRules: `http://${host}:${proxy.port}`,
    proxyBypassRules: String(proxy.bypassList || '').split(';').filter(Boolean).join(',')
  });
}

async function startClient() {
  try {
    await ensureEnrolled();
    await pullSnapshot(false);
    await configureProxy();
    browserSession.cookies.on('changed', scheduleCookiePush);
    if (tabs.size === 0) await addTab(config.secrets.cache.settings.homePage);
    await pushAllStoredCookies();
    syncTimer = setInterval(() => pullSnapshot(false), SYNC_INTERVAL_MS);
  } catch (error) {
    status(error.message, true);
    if (tabs.size === 0) await addTab(config.secrets.cache.settings.homePage);
    send('browser:show-settings');
  }
}

function publicConfig() {
  const backend = safeStorage.isEncryptionAvailable() && process.platform === 'linux' ? safeStorage.getSelectedStorageBackend() : undefined;
  return {
    profileName,
    serverUrl: config.serverUrl,
    deviceName: config.deviceName,
    enrolled: Boolean(config.secrets.deviceToken),
    networkMode: config.networkMode,
    revision: config.secrets.cache.revision,
    proxy: config.secrets.cache.settings.proxy,
    secureStorage: safeStorage.isEncryptionAvailable() && backend !== 'basic_text'
  };
}

function registerIpc() {
  ipcMain.handle('browser:bootstrap', () => ({ config: publicConfig(), tabs: [...tabs.values()].map(tab => ({ id: tab.id, title: tab.title, active: tab.id === activeTabId })) }));
  ipcMain.handle('browser:navigate', (_, url) => tabs.get(activeTabId)?.view.webContents.loadURL(normalizeAddress(url)));
  ipcMain.handle('browser:back', () => { const web = tabs.get(activeTabId)?.view.webContents; if (web?.navigationHistory.canGoBack()) web.navigationHistory.goBack(); });
  ipcMain.handle('browser:forward', () => { const web = tabs.get(activeTabId)?.view.webContents; if (web?.navigationHistory.canGoForward()) web.navigationHistory.goForward(); });
  ipcMain.handle('browser:reload', () => tabs.get(activeTabId)?.view.webContents.reload());
  ipcMain.handle('browser:new-tab', (_, url) => addTab(url || config.secrets.cache.settings.homePage));
  ipcMain.handle('browser:select-tab', (_, id) => selectTab(id));
  ipcMain.handle('browser:close-tab', (_, id) => closeTab(id));
  ipcMain.handle('browser:sync-now', async () => {
    if (isPrimary()) await pushAllStoredCookies();
    await pullSnapshot(true);
  });
  ipcMain.handle('browser:settings-open', (_, open) => {
    settingsOpen = Boolean(open);
    const tab = tabs.get(activeTabId);
    if (!tab || !mainWindow || mainWindow.isDestroyed()) return;
    try { mainWindow.contentView.removeChildView(tab.view); } catch { }
    if (!settingsOpen) {
      mainWindow.contentView.addChildView(tab.view);
      layoutActiveView();
    }
  });
  ipcMain.handle('browser:save-settings', (_, input) => {
    if (!validServerUrl(input.serverUrl)) throw new Error('Server URL must begin with http:// or https://.');
    const deviceName = String(input.deviceName || '').trim();
    if (!deviceName || deviceName.length > 80) throw new Error('Device name must be between 1 and 80 characters.');
    const serverUrl = String(input.serverUrl).trim().replace(/\/$/, '');
    if (serverUrl !== config.serverUrl) {
      config.secrets.deviceToken = '';
      config.secrets.cache = defaultSnapshot();
    }
    config.serverUrl = serverUrl;
    config.deviceName = deviceName;
    config.networkMode = input.networkMode === 'managed' ? 'managed' : 'direct';
    if (String(input.enrollmentToken || '').trim()) config.secrets.enrollmentToken = String(input.enrollmentToken).trim();
    if (!config.secrets.deviceToken && !config.secrets.enrollmentToken) throw new Error('An enrollment token is required for a new browser or server.');
    saveConfig();
    app.relaunch({ args: process.argv.slice(1) });
    app.exit(0);
    return true;
  });
}

app.on('login', (event, webContents, details, authInfo, callback) => {
  if (!authInfo.isProxy || config?.networkMode !== 'managed' || !config?.secrets.deviceToken) return;
  event.preventDefault();
  callback(config.deviceId, config.secrets.deviceToken);
});

app.whenReady().then(async () => {
  config = loadConfig();
  browserSession = session.fromPartition('persist:shared-browser');
  registerIpc();
  createWindow();
  await startClient();
  app.on('activate', () => { if (!mainWindow) createWindow(); });
}).catch(error => {
  logFatal(error);
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
