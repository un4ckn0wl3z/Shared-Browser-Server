const { app, BrowserWindow, WebContentsView, Menu, clipboard, ipcMain, net, session, safeStorage, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const TOOLBAR_HEIGHT = 112;
const SYNC_INTERVAL_MS = 2500;
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;
const RELEASE_REPOSITORY = 'un4ckn0wl3z/Shared-Browser-Server';
// electron-updater downloads through this partition (its NET_SESSION_NAME); it gets the same proxy as
// the browser so update checks never bypass Managed or Strict privacy routing.
const UPDATER_PARTITION = 'electron-updater';
const profileName = sanitizeProfile(readArgument('profile') || process.env.SHARED_BROWSER_PROFILE || 'default');
app.setPath('userData', path.join(app.getPath('appData'), 'Shared Browser', profileName));
if (readStrictPrivacySetting()) app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp');

let mainWindow;
let browserSession;
let config;
let syncTimer;
let serverQueue = Promise.resolve();
let pullPending = false;
let pushPending = false;
let cookiePushTimer;
let appliedCookies = new Map();
let autoUpdater;
let updateTimer;
let updateState = { state: 'idle', currentVersion: app.getVersion() };
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
      homePage: '',
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
    strictPrivacy: false,
    secrets: { deviceToken: '', enrollmentToken: '', cache: defaultSnapshot() }
  };
}

function configPath() {
  return path.join(app.getPath('userData'), 'client-config.json');
}

function readStrictPrivacySetting() {
  try { return JSON.parse(fs.readFileSync(configPath(), 'utf8')).strictPrivacy === true; } catch { return false; }
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
      strictPrivacy: disk.strictPrivacy === true,
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
    strictPrivacy: config.strictPrivacy,
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
  if (input.settings.homePage === 'https://example.com/' || input.settings.homePage === 'https://example.com') input.settings.homePage = '';
  if (typeof input.settings.homePage !== 'string') input.settings.homePage = fallback.settings.homePage;
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
    route: config?.networkMode === 'managed' ? `Server IP${config.strictPrivacy ? ' • Strict' : ''}` : 'Client IP'
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 850,
    minHeight: 560,
    title: `Shared Browser ${app.getVersion()} — ${profileName}`,
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.on('page-title-updated', event => event.preventDefault());
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (handleShortcut(input, mainWindow.webContents)) event.preventDefault();
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('resize', layoutActiveView);
  mainWindow.on('closed', () => {
    clearInterval(syncTimer);
    clearInterval(updateTimer);
    clearTimeout(cookiePushTimer);
    for (const tab of tabs.values()) {
      if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
    }
    tabs.clear();
    mainWindow = undefined;
    for (const popup of BrowserWindow.getAllWindows()) popup.close();
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
  const currentUrl = tab?.view.webContents.getURL() || '';
  send('browser:state', {
    url: currentUrl === 'about:blank' ? '' : currentUrl,
    loading: tab?.view.webContents.isLoading() || false,
    canGoBack: tab?.view.webContents.navigationHistory.canGoBack() || false,
    canGoForward: tab?.view.webContents.navigationHistory.canGoForward() || false
  });
}

function normalizeAddress(value) {
  let text = String(value || '').trim();
  if (!text || text.toLowerCase() === 'about:blank') return 'about:blank';
  if (!text.includes('://')) text = `https://${text}`;
  const url = new URL(text);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Enter a valid HTTP or HTTPS address.');
  return url.toString();
}

async function addTab(url, details) {
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
  configurePageContents(view.webContents);
  view.webContents.on('page-title-updated', (event, title) => {
    event.preventDefault();
    tab.title = shortTitle(title);
    publishTabs();
  });
  for (const eventName of ['did-navigate', 'did-navigate-in-page', 'did-start-loading', 'did-stop-loading']) {
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
  view.webContents.loadURL(normalizeAddress(url || config.secrets.cache.settings.homePage), loadOptions(details)).catch(error => status(error.message, true));
  return id;
}

// Keeps the referrer and form body when a page opens a link or submits a form into a new tab.
function loadOptions(details) {
  const options = {};
  if (details?.referrer?.url) options.httpReferrer = details.referrer;
  if (details?.postBody?.data?.length) {
    const { contentType, boundary } = details.postBody;
    options.postData = details.postBody.data;
    options.extraHeaders = `Content-Type: ${contentType}${boundary ? `; boundary=${boundary}` : ''}`;
  }
  return options;
}

// Shared by tabs and popup windows so every page gets the same popup, menu, and shortcut handling.
function configurePageContents(webContents) {
  webContents.setWindowOpenHandler(details => {
    // Real popups (window.open with features) must stay attached to their opener for
    // sign-in, OAuth, and approval flows that report back through window.opener.
    if (details.disposition === 'new-window') {
      return { action: 'allow', overrideBrowserWindowOptions: { width: 960, height: 720, autoHideMenuBar: true, backgroundColor: '#ffffff' } };
    }
    addTab(details.url, details).catch(error => status(error.message, true));
    return { action: 'deny' };
  });
  webContents.on('did-create-window', window => {
    window.setMenuBarVisibility(false);
    configurePageContents(window.webContents);
  });
  webContents.on('context-menu', (_, params) => showContextMenu(webContents, params));
  webContents.on('before-input-event', (event, input) => {
    if (handleShortcut(input, webContents)) event.preventDefault();
  });
}

function showContextMenu(webContents, params) {
  const template = [];
  if (params.linkURL && /^https?:/i.test(params.linkURL)) {
    template.push(
      { label: 'Open link in new tab', click: () => addTab(params.linkURL, { referrer: { url: params.pageURL, policy: 'strict-origin-when-cross-origin' } }).catch(error => status(error.message, true)) },
      { label: 'Copy link address', click: () => clipboard.writeText(params.linkURL) },
      { type: 'separator' }
    );
  }
  if (params.mediaType === 'image' && /^https?:/i.test(params.srcURL)) {
    template.push(
      { label: 'Open image in new tab', click: () => addTab(params.srcURL).catch(error => status(error.message, true)) },
      { label: 'Copy image address', click: () => clipboard.writeText(params.srcURL) },
      { type: 'separator' }
    );
  }
  if (params.isEditable) {
    template.push(
      { label: 'Undo', role: 'undo', enabled: params.editFlags.canUndo },
      { label: 'Redo', role: 'redo', enabled: params.editFlags.canRedo },
      { type: 'separator' },
      { label: 'Cut', role: 'cut', enabled: params.editFlags.canCut },
      { label: 'Copy', role: 'copy', enabled: params.editFlags.canCopy },
      { label: 'Paste', role: 'paste', enabled: params.editFlags.canPaste },
      { label: 'Select all', role: 'selectAll', enabled: params.editFlags.canSelectAll },
      { type: 'separator' }
    );
  } else if (params.selectionText.trim()) {
    template.push({ label: 'Copy', role: 'copy' }, { type: 'separator' });
  }
  template.push(
    { label: 'Back', enabled: webContents.navigationHistory.canGoBack(), click: () => webContents.navigationHistory.goBack() },
    { label: 'Forward', enabled: webContents.navigationHistory.canGoForward(), click: () => webContents.navigationHistory.goForward() },
    { label: 'Reload', click: () => webContents.reload() },
    { type: 'separator' },
    { label: 'Inspect', click: () => webContents.inspectElement(params.x, params.y) }
  );
  Menu.buildFromTemplate(template).popup({ window: BrowserWindow.fromWebContents(webContents) || mainWindow });
}

function handleShortcut(input, source) {
  if (input.type !== 'keyDown') return false;
  const mac = process.platform === 'darwin';
  const command = mac ? input.meta : input.control;
  const key = input.key.toLowerCase();
  const isPopup = source && !source.isDestroyed() && source !== mainWindow?.webContents && ![...tabs.values()].some(tab => tab.view.webContents === source);
  const web = isPopup ? source : tabs.get(activeTabId)?.view.webContents;
  const run = action => { Promise.resolve().then(action).catch(error => status(error.message, true)); return true; };
  if (command && !input.alt && key === 'w') {
    return run(() => isPopup ? BrowserWindow.fromWebContents(source)?.close() : closeTab(activeTabId));
  }
  if (isPopup) return false;
  if (command && !input.shift && !input.alt && key === 't') return run(() => addTab(config.secrets.cache.settings.homePage));
  if ((command && key === 'l') || (input.alt && key === 'd' && !mac)) {
    return run(() => { mainWindow?.webContents.focus(); send('browser:focus-address'); });
  }
  if (input.control && key === 'tab') {
    const ids = [...tabs.keys()];
    const index = ids.indexOf(activeTabId);
    return run(() => selectTab(ids[(index + (input.shift ? -1 : 1) + ids.length) % ids.length]));
  }
  if (!web || web.isDestroyed()) return false;
  if ((command && key === 'r') || key === 'f5') return run(() => input.shift || (key === 'f5' && command) ? web.reloadIgnoringCache() : web.reload());
  if ((input.alt && !command && key === 'arrowleft') || (mac && command && key === '[')) return run(() => web.navigationHistory.canGoBack() && web.navigationHistory.goBack());
  if ((input.alt && !command && key === 'arrowright') || (mac && command && key === ']')) return run(() => web.navigationHistory.canGoForward() && web.navigationHistory.goForward());
  if (key === 'f12' || (command && input.shift && key === 'i')) return run(() => web.toggleDevTools());
  if (command && (key === '=' || key === '+')) return run(() => web.setZoomLevel(Math.min(web.getZoomLevel() + 0.5, 5)));
  if (command && key === '-') return run(() => web.setZoomLevel(Math.max(web.getZoomLevel() - 0.5, -5)));
  if (command && key === '0') return run(() => web.setZoomLevel(0));
  return false;
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

// All server traffic runs one request at a time so a slow snapshot pull can never land after a
// newer cookie push and roll the local cache (and the live session cookies) back.
function serialized(task) {
  const run = serverQueue.then(task, task);
  serverQueue = run.catch(() => { });
  return run;
}

async function pullSnapshot(notify = false) {
  if (!config.secrets.deviceToken || pullPending) return;
  pullPending = true;
  return serialized(async () => {
    pullPending = false;
    try {
      const snapshot = normalizeSnapshot(await api(`/api/client/snapshot?deviceName=${encodeURIComponent(config.deviceName)}`));
      const changed = snapshot.revision !== config.secrets.cache.revision;
      config.secrets.cache = snapshot;
      saveConfig();
      // Cookies are installed in place. Reloading the page here would wipe whatever the user is in
      // the middle of (an open dialog, a half-filled form, a deployment approval).
      if (changed) await applyAllCookies();
      status(`${notify ? 'Synchronization complete — ' : ''}Synced r${snapshot.revision}`);
      publishTabs();
      publishNavigationState();
    } catch (error) {
      status(`Offline cache — ${error.message}`, true);
      if (/unauthorized|revoked/i.test(error.message)) send('browser:show-settings');
    }
  });
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

function normalizedDomain(value) {
  return String(value || '').replace(/^\./, '').toLowerCase();
}

function cookieKey(cookie, fallbackDomain) {
  return `${cookie.name}\n${normalizedDomain(cookie.domain || fallbackDomain)}\n${cookie.path || '/'}`;
}

// The primary browser is the source of truth: it only receives cookies it does not have yet, so a
// stale server copy can never overwrite a session cookie the site has just rotated. Other browsers
// only install cookies whose shared value actually changed, so their own session state is left alone.
async function applyAllCookies() {
  const primary = isPrimary();
  const local = primary ? new Set((await browserSession.cookies.get({})).map(cookie => cookieKey(cookie))) : undefined;
  const shared = new Map();
  for (const profile of config.secrets.cache.profiles.filter(item => item.enabled)) {
    for (const cookie of profile.cookies || []) {
      const key = cookieKey(cookie, profile.domain);
      shared.set(key, cookie.value);
      if (primary ? local.has(key) : appliedCookies.get(key) === cookie.value) continue;
      try { await setSharedCookie(cookie, profile.domain); } catch { }
    }
  }
  appliedCookies = shared;
}

async function setSharedCookie(cookie, profileDomain) {
  const domain = normalizedDomain(cookie.domain || profileDomain);
  const hostPrefix = cookie.name.startsWith('__Host-');
  const secure = Boolean(cookie.secure) || hostPrefix || cookie.name.startsWith('__Secure-');
  const rawPath = String(cookie.path || '/');
  const cookiePath = hostPrefix ? '/' : rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
  const url = `${secure ? 'https' : 'http'}://${domain}${cookiePath}`;
  // The server does not record whether a cookie was host-only. Reuse the scope of the local copy
  // when there is one so the site does not end up with two same-named cookies; __Host- cookies
  // must always be host-only or Chromium rejects them.
  const existing = (await browserSession.cookies.get({ url, name: cookie.name }))
    .filter(item => normalizedDomain(item.domain) === domain && item.path === cookiePath);
  const hostOnly = hostPrefix || existing.some(item => item.hostOnly);
  const sameSite = electronSameSite(cookie.sameSite);
  await browserSession.cookies.set({
    url,
    name: cookie.name,
    value: cookie.value,
    ...(hostOnly ? {} : { domain }),
    path: cookiePath,
    secure,
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: sameSite === 'no_restriction' && !secure ? 'lax' : sameSite,
    ...(existing[0]?.expirationDate ? { expirationDate: existing[0].expirationDate } : {})
  });
}

// When a site writes a cookie that also exists in the other scope (host-only vs. domain), drop the
// other copy. Otherwise both are sent and the site may read the stale one, which breaks CSRF checks
// on form submissions such as GitHub's "Approve and deploy".
async function removeDuplicateCookie(cookie) {
  const domain = normalizedDomain(cookie.domain);
  const url = `https://${domain}${cookie.path || '/'}`;
  const affected = await browserSession.cookies.get({ url, name: cookie.name });
  const duplicates = affected.filter(item => normalizedDomain(item.domain) === domain && item.path === cookie.path && Boolean(item.hostOnly) !== Boolean(cookie.hostOnly));
  if (!duplicates.length) return;
  await browserSession.cookies.remove(url, cookie.name);
  for (const keep of affected.filter(item => !duplicates.includes(item))) {
    try { await browserSession.cookies.set(cookieDetails(keep)); } catch { }
  }
}

function cookieDetails(cookie) {
  const domain = normalizedDomain(cookie.domain);
  return {
    url: `${cookie.secure ? 'https' : 'http'}://${domain}${cookie.path || '/'}`,
    name: cookie.name,
    value: cookie.value,
    ...(cookie.hostOnly ? {} : { domain }),
    path: cookie.path || '/',
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: cookie.sameSite,
    ...(cookie.session || !cookie.expirationDate ? {} : { expirationDate: cookie.expirationDate })
  };
}

function onCookieChanged(_event, cookie, _cause, removed) {
  if (!removed) removeDuplicateCookie(cookie).catch(() => { });
  scheduleCookiePush();
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
  return serialized(async () => {
    try {
      const cookies = (await browserSession.cookies.get({ url: page.toString() }))
        .filter(cookie => validCookie(cookie) && domainMatches(page.hostname, cookie.domain))
        .slice(0, 200)
        .map(toSharedCookie);
      await pushCookies(page.toString(), cookies);
    } catch (error) {
      status(`Cookie sync failed — ${error.message}`, true);
    }
  });
}

async function pushAllStoredCookies() {
  if (!isPrimary() || !config.secrets.deviceToken || pushPending) return;
  pushPending = true;
  return serialized(async () => {
    pushPending = false;
    try {
      const cookies = (await browserSession.cookies.get({})).filter(validCookie);
      const groups = new Map();
      for (const cookie of cookies) {
        const domain = normalizedDomain(cookie.domain);
        if (!groups.has(domain)) groups.set(domain, []);
        groups.get(domain).push(toSharedCookie(cookie));
      }
      for (const [domain, values] of [...groups.entries()].slice(0, 500)) {
        await pushCookies(`https://${domain}/`, values.slice(0, 200));
      }
      status(`Synced r${config.secrets.cache.revision}`);
    } catch (error) {
      status(`Cookie sync failed — ${error.message}`, true);
    }
  });
}

async function pushCookies(pageUrl, cookies) {
  const result = await api('/api/client/sync', {
    method: 'POST',
    body: JSON.stringify({ knownRevision: config.secrets.cache.revision, pageUrl, cookies })
  });
  if (result?.snapshot) {
    config.secrets.cache = normalizeSnapshot(result.snapshot);
    saveConfig();
    for (const profile of config.secrets.cache.profiles) {
      for (const cookie of profile.cookies || []) appliedCookies.set(cookieKey(cookie, profile.domain), cookie.value);
    }
  }
}

function scheduleCookiePush() {
  if (!isPrimary()) return;
  clearTimeout(cookiePushTimer);
  cookiePushTimer = setTimeout(() => pushAllStoredCookies(), 900);
}

async function configureProxy() {
  const proxy = config.secrets.cache.settings.proxy;
  if (config.strictPrivacy && config.networkMode !== 'managed') {
    await blockBrowserTraffic();
    throw new Error('Strict privacy requires Managed proxy mode. Direct browsing is blocked.');
  }
  if (config.networkMode !== 'managed') {
    await setProxy({ mode: 'direct' });
    return;
  }
  if (!proxy?.enabled) {
    if (config.strictPrivacy) await blockBrowserTraffic();
    throw new Error(config.strictPrivacy
      ? 'Strict privacy is blocking browsing because the managed proxy is disabled on the server.'
      : 'Managed proxy is selected, but it is disabled on the server. Choose Direct mode or enable it in the dashboard.');
  }
  const host = String(proxy.host).includes(':') && !String(proxy.host).startsWith('[') ? `[${proxy.host}]` : proxy.host;
  await setProxy({
    mode: 'fixed_servers',
    proxyRules: `http://${host}:${proxy.port}`,
    proxyBypassRules: config.strictPrivacy ? '<-loopback>' : String(proxy.bypassList || '').split(';').filter(Boolean).join(',')
  });
  if (config.strictPrivacy) {
    const route = await browserSession.resolveProxy('https://example.com/');
    if (routeIsDirect(route)) {
      await blockBrowserTraffic();
      throw new Error('Strict privacy blocked browsing because Chromium resolved a direct route.');
    }
  }
}

async function setProxy(proxyConfig) {
  await Promise.all([browserSession, session.fromPartition(UPDATER_PARTITION, { cache: false })].map(item => item.setProxy(proxyConfig)));
}

async function blockBrowserTraffic() {
  await setProxy({
    mode: 'fixed_servers',
    proxyRules: 'http://127.0.0.1:1',
    proxyBypassRules: '<-loopback>'
  });
}

function configurePrivacyPermissions() {
  if (!config.strictPrivacy) return;
  // Copy buttons and fullscreen video do not expose anything about the network or device.
  const harmless = new Set(['clipboard-sanitized-write', 'fullscreen']);
  browserSession.setPermissionCheckHandler((_webContents, permission) => harmless.has(permission));
  browserSession.setPermissionRequestHandler((_webContents, permission, callback) => callback(harmless.has(permission)));
}

function routeIsDirect(value) {
  return !value || /(^|;)\s*DIRECT\s*(;|$)/i.test(value);
}

async function privacyCheck() {
  const externalRoute = await browserSession.resolveProxy('https://example.com/');
  const loopbackRoute = await browserSession.resolveProxy('http://127.0.0.1/');
  const webRtcPolicy = app.commandLine.getSwitchValue('force-webrtc-ip-handling-policy');
  const ok = config.strictPrivacy
    && !routeIsDirect(externalRoute)
    && !routeIsDirect(loopbackRoute)
    && webRtcPolicy === 'disable_non_proxied_udp';
  return {
    ok,
    strictPrivacy: config.strictPrivacy,
    externalRoute,
    loopbackRoute,
    webRtcPolicy: webRtcPolicy || 'default'
  };
}

async function startClient() {
  try {
    if (config.strictPrivacy) await blockBrowserTraffic();
    await ensureEnrolled();
    await pullSnapshot(false);
    await configureProxy();
    await applyAllCookies();
    browserSession.cookies.on('changed', onCookieChanged);
    if (tabs.size === 0) await addTab(config.secrets.cache.settings.homePage);
    await pushAllStoredCookies();
    syncTimer = setInterval(() => pullSnapshot(false), SYNC_INTERVAL_MS);
  } catch (error) {
    status(error.message, true);
    try { await applyAllCookies(); } catch { }
    if (tabs.size === 0) await addTab(config.secrets.cache.settings.homePage);
    send('browser:show-settings');
  }
}

function proxyLogin(authInfo, callback) {
  if (authInfo.isProxy && config?.networkMode === 'managed' && config?.secrets.deviceToken) callback(config.deviceId, config.secrets.deviceToken);
  else callback();
}

// Windows (NSIS) and Linux AppImage builds download and install updates themselves. Other builds,
// including the unsigned macOS DMG that Squirrel.Mac refuses to update, link to the release page.
function installsUpdates() {
  return app.isPackaged && (process.platform === 'win32' || (process.platform === 'linux' && Boolean(process.env.APPIMAGE)));
}

function publishUpdate(patch) {
  updateState = { ...updateState, ...patch };
  send('browser:update', updateState);
}

function setupUpdater() {
  if (!installsUpdates()) return;
  ({ autoUpdater } = require('electron-updater'));
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on('login', proxyLogin);
  autoUpdater.on('checking-for-update', () => publishUpdate({ state: 'checking', error: '' }));
  autoUpdater.on('update-not-available', () => publishUpdate({ state: 'current' }));
  autoUpdater.on('update-available', info => publishUpdate({ state: 'downloading', version: info.version, percent: 0 }));
  autoUpdater.on('download-progress', progress => publishUpdate({ state: 'downloading', percent: Math.round(progress.percent) }));
  autoUpdater.on('update-downloaded', info => publishUpdate({ state: 'ready', version: info.version }));
  autoUpdater.on('error', error => publishUpdate({ state: 'error', error: shortError(error) }));
}

function scheduleUpdateChecks() {
  setTimeout(() => checkForUpdates(), 8000);
  updateTimer = setInterval(() => checkForUpdates(), UPDATE_CHECK_INTERVAL_MS);
}

async function checkForUpdates() {
  if (!app.isPackaged) {
    publishUpdate({ state: 'error', error: 'Updates are only available in installed builds.' });
    return updateState;
  }
  if (['checking', 'downloading', 'ready'].includes(updateState.state)) return updateState;
  publishUpdate({ state: 'checking', error: '' });
  try {
    if (autoUpdater) {
      const result = await autoUpdater.checkForUpdates();
      if (!result?.isUpdateAvailable && updateState.state === 'checking') publishUpdate({ state: 'current' });
    } else {
      const release = await latestRelease();
      const version = release.tag.replace(/^v/i, '');
      publishUpdate(newerVersion(version, app.getVersion()) ? { state: 'available', version, url: release.url } : { state: 'current' });
    }
  } catch (error) {
    publishUpdate({ state: 'error', error: shortError(error) });
  }
  return updateState;
}

// github.com answers /releases/latest with a redirect to the newest tag. Unlike the REST API it is
// not limited to 60 requests an hour per IP, which many clients behind one office NAT would exceed.
function latestRelease() {
  return new Promise((resolve, reject) => {
    const request = net.request({ url: `https://github.com/${RELEASE_REPOSITORY}/releases/latest`, redirect: 'manual', session: session.fromPartition(UPDATER_PARTITION, { cache: false }) });
    const finish = (error, value) => { clearTimeout(timeout); if (error) reject(error); else resolve(value); };
    const timeout = setTimeout(() => { request.abort(); finish(new Error('Update check timed out.')); }, 20000);
    request.on('login', proxyLogin);
    request.on('redirect', (_status, _method, location) => {
      request.abort();
      const tag = /\/releases\/tag\/([^/?#]+)/.exec(location)?.[1];
      if (tag) finish(undefined, { tag: decodeURIComponent(tag), url: location });
      else finish(new Error('No published release was found.'));
    });
    request.on('response', response => finish(new Error(`GitHub returned ${response.statusCode}`)));
    request.on('error', error => finish(error));
    request.end();
  });
}

function shortError(error) {
  const line = String(error?.message || error).split('\n')[0].trim();
  return line.length > 180 ? `${line.slice(0, 180)}…` : line;
}

function newerVersion(candidate, current) {
  const parse = value => String(value).split('-')[0].split('.').map(part => Number(part) || 0);
  const [a, b] = [parse(candidate), parse(current)];
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) > (b[index] || 0);
  }
  return false;
}

function installUpdate() {
  if (updateState.state === 'ready' && autoUpdater) autoUpdater.quitAndInstall();
  else if (updateState.state === 'available' && updateState.url?.startsWith('https://github.com/')) shell.openExternal(updateState.url);
}

function publicConfig() {
  const backend = safeStorage.isEncryptionAvailable() && process.platform === 'linux' ? safeStorage.getSelectedStorageBackend() : undefined;
  return {
    profileName,
    version: app.getVersion(),
    serverUrl: config.serverUrl,
    deviceName: config.deviceName,
    enrolled: Boolean(config.secrets.deviceToken),
    networkMode: config.networkMode,
    strictPrivacy: config.strictPrivacy,
    revision: config.secrets.cache.revision,
    proxy: config.secrets.cache.settings.proxy,
    secureStorage: safeStorage.isEncryptionAvailable() && backend !== 'basic_text'
  };
}

function registerIpc() {
  ipcMain.handle('browser:check-updates', checkForUpdates);
  ipcMain.handle('browser:install-update', installUpdate);
  ipcMain.handle('browser:bootstrap', () => ({ config: publicConfig(), update: updateState, tabs: [...tabs.values()].map(tab => ({ id: tab.id, title: tab.title, active: tab.id === activeTabId })) }));
  ipcMain.handle('browser:navigate', (_, url) => tabs.get(activeTabId)?.view.webContents.loadURL(normalizeAddress(url)));
  ipcMain.handle('browser:back', () => { const web = tabs.get(activeTabId)?.view.webContents; if (web?.navigationHistory.canGoBack()) web.navigationHistory.goBack(); });
  ipcMain.handle('browser:forward', () => { const web = tabs.get(activeTabId)?.view.webContents; if (web?.navigationHistory.canGoForward()) web.navigationHistory.goForward(); });
  ipcMain.handle('browser:reload', () => tabs.get(activeTabId)?.view.webContents.reload());
  ipcMain.handle('browser:stop', () => tabs.get(activeTabId)?.view.webContents.stop());
  ipcMain.handle('browser:new-tab', (_, url) => addTab(url || config.secrets.cache.settings.homePage));
  ipcMain.handle('browser:select-tab', (_, id) => selectTab(id));
  ipcMain.handle('browser:close-tab', (_, id) => closeTab(id));
  ipcMain.handle('browser:sync-now', async () => {
    if (isPrimary()) await pushAllStoredCookies();
    await pullSnapshot(true);
  });
  ipcMain.handle('browser:privacy-check', privacyCheck);
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
    const networkMode = input.networkMode === 'managed' ? 'managed' : 'direct';
    const strictPrivacy = input.strictPrivacy === true;
    if (strictPrivacy && networkMode !== 'managed') throw new Error('Strict privacy requires Managed proxy mode.');
    if (strictPrivacy && !config.secrets.cache.settings.proxy?.enabled) throw new Error('Enable the managed proxy in the server dashboard before turning on Strict privacy.');
    if (serverUrl !== config.serverUrl) {
      config.secrets.deviceToken = '';
      config.secrets.cache = defaultSnapshot();
    }
    config.serverUrl = serverUrl;
    config.deviceName = deviceName;
    config.networkMode = networkMode;
    config.strictPrivacy = strictPrivacy;
    if (String(input.enrollmentToken || '').trim()) config.secrets.enrollmentToken = String(input.enrollmentToken).trim();
    if (!config.secrets.deviceToken && !config.secrets.enrollmentToken) throw new Error('An enrollment token is required for a new browser or server.');
    saveConfig();
    app.relaunch({ args: process.argv.slice(1) });
    app.exit(0);
    return true;
  });
}

// Sites such as Google and GitHub treat an "Electron/x" user agent as an unsupported or embedded
// browser and degrade or block sign-in and form flows, so present the plain Chromium user agent.
function browserUserAgent() {
  const name = app.getName().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return app.userAgentFallback.replace(new RegExp(`\\s(?:Electron|${name})/\\S+`, 'g'), '');
}

// Shortcuts are handled per page in handleShortcut. macOS still needs an Edit menu for copy and
// paste; elsewhere the default menu is removed so its Ctrl+R/devtools items cannot hit the toolbar.
function applicationMenu() {
  if (process.platform !== 'darwin') return null;
  return Menu.buildFromTemplate([{ role: 'appMenu' }, { role: 'editMenu' }]);
}

app.on('login', (event, webContents, details, authInfo, callback) => {
  if (!authInfo.isProxy || config?.networkMode !== 'managed' || !config?.secrets.deviceToken) return;
  event.preventDefault();
  proxyLogin(authInfo, callback);
});

app.whenReady().then(async () => {
  config = loadConfig();
  app.userAgentFallback = browserUserAgent();
  Menu.setApplicationMenu(applicationMenu());
  browserSession = session.fromPartition('persist:shared-browser');
  browserSession.setUserAgent(app.userAgentFallback);
  configurePrivacyPermissions();
  registerIpc();
  setupUpdater();
  createWindow();
  await startClient();
  scheduleUpdateChecks();
  app.on('activate', () => { if (!mainWindow) createWindow(); });
}).catch(error => {
  logFatal(error);
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
