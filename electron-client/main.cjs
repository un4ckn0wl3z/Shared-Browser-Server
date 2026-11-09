const { app, BrowserWindow, WebContentsView, Menu, clipboard, ipcMain, net, screen, session, safeStorage, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const TOOLBAR_HEIGHT = 112;
const SYNC_INTERVAL_MS = 2500;
const MAX_SYNC_BACKOFF_MS = 60 * 1000;
const MAX_COOKIES_PER_DOMAIN = 200;
const MAX_CLOSED_TABS = 25;
// The server ignores expiry shifts smaller than a day, so the client does not re-push them either.
const EXPIRY_BUCKET_SECONDS = 24 * 60 * 60;
const DEFAULT_SEARCH_URL = 'https://duckduckgo.com/?q=%s';
// While the server can push changes over Server-Sent Events, polling is only a slow safety net.
const EVENTS_POLL_INTERVAL_MS = 30 * 1000;
const EVENTS_IDLE_TIMEOUT_MS = 70 * 1000;
const MAX_RESTORED_TABS = 30;
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
let syncFailures = 0;
let authPrompted = false;
let serverQueue = Promise.resolve();
let pullPending = false;
let pushPending = false;
let cookiePushTimer;
// key -> { name, domain, path, value, applied }. `applied` is false for entries seeded from the offline
// cache at startup: they are only used to notice cookies that were removed from the vault meanwhile.
let appliedCookies = new Map();
// Cookie domain -> signature of the cookie list last published by this (primary) browser.
let pushedDomains = new Map();
let wasPrimary = false;
let watchingCookies = false;
let eventsConnected = false;
let eventsController;
let sessionSaveTimer;
let quitting = false;
const closedTabs = [];
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
      searchUrl: DEFAULT_SEARCH_URL,
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
    window: undefined,
    secrets: { deviceToken: '', enrollmentToken: '', cache: defaultSnapshot(), session: { tabs: [], active: 0 } }
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
      window: normalizeWindowState(disk.window),
      secrets: {
        deviceToken: String(secrets?.deviceToken || ''),
        enrollmentToken: String(secrets?.enrollmentToken || ''),
        cache: normalizeSnapshot(secrets?.cache),
        session: {
          tabs: Array.isArray(secrets?.session?.tabs) ? secrets.session.tabs.filter(url => /^https?:\/\//i.test(String(url))).slice(0, MAX_RESTORED_TABS) : [],
          active: Number(secrets?.session?.active) || 0
        }
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
    window: config.window,
    // Open tab addresses can contain tokens, so they are encrypted along with the device credentials.
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
  if (typeof input.settings.searchUrl !== 'string') input.settings.searchUrl = fallback.settings.searchUrl;
  input.settings.proxy ||= fallback.settings.proxy;
  input.profiles = Array.isArray(input.profiles) ? input.profiles : [];
  input.bookmarks = Array.isArray(input.bookmarks) ? input.bookmarks.filter(item => item && /^https?:\/\//i.test(item.url || '')) : [];
  input.revision = Number(input.revision) || 0;
  return input;
}

function normalizeWindowState(value) {
  if (!value || typeof value !== 'object') return undefined;
  const bounds = ['x', 'y', 'width', 'height'].map(key => Number(value[key]));
  if (bounds.some(number => !Number.isFinite(number))) return undefined;
  const [x, y, width, height] = bounds;
  return { x, y, width: Math.max(850, width), height: Math.max(560, height), maximized: value.maximized === true };
}

// Saved bounds are only reused while they still overlap a connected display.
function savedBounds() {
  const saved = config.window;
  if (!saved) return {};
  const visible = screen.getAllDisplays().some(({ workArea: area }) =>
    saved.x < area.x + area.width - 80 && saved.x + saved.width > area.x + 80 && saved.y < area.y + area.height - 40 && saved.y + saved.height > area.y);
  return visible ? { x: saved.x, y: saved.y, width: saved.width, height: saved.height } : { width: saved.width, height: saved.height };
}

function captureSessionState() {
  if (!config) return;
  if (mainWindow && !mainWindow.isDestroyed()) {
    config.window = { ...mainWindow.getNormalBounds(), maximized: mainWindow.isMaximized() };
  }
  const ordered = [...tabs.values()];
  const urls = [];
  let active = 0;
  for (const tab of ordered) {
    const url = tab.view.webContents.isDestroyed() ? '' : tab.view.webContents.getURL();
    if (!/^https?:\/\//i.test(url)) continue;
    if (tab.id === activeTabId) active = urls.length;
    urls.push(url);
  }
  config.secrets.session = { tabs: urls.slice(0, MAX_RESTORED_TABS), active };
}

function saveSessionState() {
  clearTimeout(sessionSaveTimer);
  try {
    captureSessionState();
    saveConfig();
  } catch (error) { logFatal(error); }
}

function scheduleSessionSave() {
  clearTimeout(sessionSaveTimer);
  sessionSaveTimer = setTimeout(saveSessionState, 5000);
}

// Reopens the tabs from the last session, or the shared home page when there were none.
async function openInitialTabs() {
  if (tabs.size > 0) return;
  const { tabs: urls, active } = config.secrets.session;
  if (!urls.length) {
    await addTab(config.secrets.cache.settings.homePage);
    return;
  }
  const ids = [];
  for (const url of urls) ids.push(await addTab(url));
  await selectTab(ids[Math.min(Math.max(active, 0), ids.length - 1)]);
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
    ...savedBounds(),
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
  if (config.window?.maximized) mainWindow.maximize();
  mainWindow.on('resize', () => { layoutActiveView(); scheduleSessionSave(); });
  mainWindow.on('move', scheduleSessionSave);
  mainWindow.on('close', () => { quitting = true; saveSessionState(); });
  mainWindow.on('closed', () => {
    eventsController?.abort();
    clearTimeout(sessionSaveTimer);
    clearTimeout(syncTimer);
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

function tabSummaries() {
  return [...tabs.values()].map(tab => ({
    id: tab.id,
    title: tab.title,
    url: tab.view.webContents.isDestroyed() ? '' : tab.view.webContents.getURL(),
    loading: !tab.view.webContents.isDestroyed() && tab.view.webContents.isLoading(),
    active: tab.id === activeTabId
  }));
}

function publishTabs() {
  send('browser:tabs', tabSummaries());
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

// Turns address-bar text into a URL: full http(s) URLs pass through, bare host names get https://
// (http:// for localhost and IP addresses), and anything else becomes a search when one is configured.
function normalizeAddress(value) {
  const text = String(value || '').trim();
  if (!text || text.toLowerCase() === 'about:blank') return 'about:blank';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const url = new URL(text);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS addresses can be opened.');
    return url.toString();
  }
  const local = /^(localhost|\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:.]+\])(:\d+)?(\/|$)/i.test(text);
  const looksLikeHost = !/\s/.test(text) && (local || /^[^/?#:]+\.[a-z][a-z0-9-]*\.?(:\d+)?([/?#]|$)/i.test(text));
  if (looksLikeHost) {
    try { return new URL(`${local ? 'http' : 'https'}://${text}`).toString(); } catch { }
  }
  const search = config?.secrets.cache.settings.searchUrl;
  if (search && search.includes('%s')) return search.replace('%s', encodeURIComponent(text));
  throw new Error('Enter a valid web address. Searching from the address bar is disabled on the server.');
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
      if (eventName === 'did-start-loading' || eventName === 'did-stop-loading') publishTabs();
      if (eventName === 'did-navigate' || eventName === 'did-navigate-in-page') scheduleSessionSave();
    });
  }
  view.webContents.on('did-finish-load', () => {
    if (activeTabId === id) publishNavigationState();
  });
  view.webContents.on('found-in-page', (_, result) => {
    if (activeTabId === id) send('browser:find-result', { active: result.activeMatchOrdinal, matches: result.matches });
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
  if (command && input.shift && !input.alt && key === 't') return run(reopenClosedTab);
  if ((command && !input.alt && key === 'f') || key === 'f3') {
    return run(() => { mainWindow?.webContents.focus(); send('browser:show-find', { next: key === 'f3', backward: input.shift }); });
  }
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
  if (current && current !== next) {
    mainWindow.contentView.removeChildView(current.view);
    if (!current.view.webContents.isDestroyed()) current.view.webContents.stopFindInPage('clearSelection');
    send('browser:find-result', { active: 0, matches: 0, reset: true });
  }
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
  const closedUrl = tab.view.webContents.isDestroyed() ? '' : tab.view.webContents.getURL();
  if (/^https?:/i.test(closedUrl)) {
    closedTabs.push(closedUrl);
    if (closedTabs.length > MAX_CLOSED_TABS) closedTabs.shift();
  }
  if (!tab.view.webContents.isDestroyed()) tab.view.webContents.close();
  if (activeTabId === numericId) activeTabId = undefined;
  if (tabs.size === 0 && !quitting) await addTab(config.secrets.cache.settings.homePage);
  else if (!activeTabId && tabs.size) await selectTab(ids[index - 1] || ids[index + 1] || [...tabs.keys()][0]);
  publishTabs();
  scheduleSessionSave();
}

async function reopenClosedTab() {
  const url = closedTabs.pop();
  if (url) await addTab(url);
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
    if (!response.ok) {
      let message = '';
      try { message = JSON.parse(text).error || ''; } catch { }
      if (response.status === 401) throw new Error(useDevice ? 'This browser is unauthorized or revoked.' : message || 'The enrollment code or token was not accepted.');
      throw new Error(message || `Server returned ${response.status}${text ? `: ${text.slice(0, 200)}` : ''}`);
    }
    return text ? JSON.parse(text) : undefined;
  } finally {
    clearTimeout(timeout);
  }
}

async function ensureEnrolled() {
  if (config.secrets.deviceToken) return;
  if (!config.secrets.enrollmentToken) throw new Error('Open Settings and enter an enrollment code from the management dashboard.');
  const result = await api('/api/client/enroll', {
    method: 'POST',
    headers: { authorization: `Bearer ${config.secrets.enrollmentToken}` },
    body: JSON.stringify({ deviceId: config.deviceId, deviceName: config.deviceName })
  }, false);
  config.deviceId = result.deviceId;
  config.secrets.deviceToken = result.deviceToken;
  config.secrets.enrollmentToken = '';
  saveConfig();
}

// Listens for "revision" events from the server and pulls right away, so a change made on the primary
// browser reaches the others within a moment instead of at the next poll.
async function listenForEvents() {
  let failures = 0;
  while (mainWindow && config.secrets.deviceToken) {
    const controller = new AbortController();
    eventsController = controller;
    let idle;
    const resetIdle = () => { clearTimeout(idle); idle = setTimeout(() => controller.abort(), EVENTS_IDLE_TIMEOUT_MS); };
    try {
      resetIdle();
      const response = await fetch(apiUrl('/api/client/events'), {
        headers: { accept: 'text/event-stream', authorization: `Bearer ${config.secrets.deviceToken}`, 'x-device-id': config.deviceId },
        signal: controller.signal
      });
      if (!response.ok || !response.body) throw Object.assign(new Error(`events ${response.status}`), { status: response.status });
      eventsConnected = true;
      failures = 0;
      scheduleSync();
      const decoder = new TextDecoder();
      let buffer = '';
      for await (const chunk of response.body) {
        resetIdle();
        buffer += decoder.decode(chunk, { stream: true });
        let end;
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const type = /^event: *(.*)$/m.exec(block)?.[1];
          const data = /^data: *(.*)$/m.exec(block)?.[1];
          if (type === 'revision' && Number(data) !== config.secrets.cache.revision) pullSnapshot(false);
        }
      }
    } catch (error) {
      failures++;
      // A revoked or unknown device is reported by the regular sync; just retry slowly.
      if (error.status === 401) failures = Math.max(failures, 5);
    } finally {
      clearTimeout(idle);
      if (eventsConnected) {
        eventsConnected = false;
        scheduleSync();
      }
    }
    if (!mainWindow) return;
    await new Promise(resolve => setTimeout(resolve, Math.min(2000 * 2 ** Math.min(failures, 5), 60000)));
  }
}

// All server traffic runs one request at a time so a slow snapshot pull can never land after a
// newer cookie push and roll the local cache (and the live session cookies) back.
function serialized(task) {
  const run = serverQueue.then(task, task);
  serverQueue = run.catch(() => { });
  return run;
}

// Returns true when the server was reachable. `since` lets the server answer 204 when nothing changed,
// so idle polling neither downloads the vault nor rewrites the encrypted local cache.
async function pullSnapshot(notify = false) {
  if (!config.secrets.deviceToken || pullPending) return false;
  pullPending = true;
  return serialized(async () => {
    pullPending = false;
    try {
      const previous = config.secrets.cache;
      const since = previous.revision > 0 && !notify ? `&since=${previous.revision}` : '';
      const response = await api(`/api/client/snapshot?deviceName=${encodeURIComponent(config.deviceName)}${since}`);
      if (response) {
        const snapshot = normalizeSnapshot(response);
        if (snapshot.revision !== previous.revision || notify) await installSnapshot(snapshot, previous);
      }
      syncFailures = 0;
      authPrompted = false;
      status(`${notify ? 'Synchronization complete — ' : ''}Synced r${config.secrets.cache.revision}`);
      return true;
    } catch (error) {
      syncFailures++;
      status(`Offline cache — ${error.message}`, true);
      // Ask once. Re-opening the dialog on every poll would reset whatever the user is typing in it.
      if (/unauthorized|revoked/i.test(error.message) && !authPrompted) {
        authPrompted = true;
        send('browser:show-settings');
      }
      return false;
    }
  });
}

async function installSnapshot(snapshot, previous) {
  config.secrets.cache = snapshot;
  saveConfig();
  // Cookies are installed in place. Reloading the page here would wipe whatever the user is in
  // the middle of (an open dialog, a half-filled form, a deployment approval).
  await applyAllCookies();
  if (JSON.stringify(previous.settings.proxy) !== JSON.stringify(snapshot.settings.proxy) && config.networkMode === 'managed') {
    try {
      await configureProxy();
      await browserSession.closeAllConnections();
    } catch (error) {
      status(error.message, true);
    }
  }
  if (JSON.stringify(previous.bookmarks) !== JSON.stringify(snapshot.bookmarks)) send('browser:bookmarks', snapshot.bookmarks);
  const primary = isPrimary();
  // A browser that has just been made primary publishes everything it holds right away.
  if (primary && !wasPrimary) {
    pushedDomains = new Map();
    setImmediate(() => pushAllStoredCookies());
  }
  wasPrimary = primary;
  publishTabs();
  publishNavigationState();
}

function scheduleSync() {
  clearTimeout(syncTimer);
  const delay = syncFailures ? Math.min(SYNC_INTERVAL_MS * 2 ** Math.min(syncFailures, 6), MAX_SYNC_BACKOFF_MS)
    : eventsConnected ? EVENTS_POLL_INTERVAL_MS : SYNC_INTERVAL_MS;
  syncTimer = setTimeout(async () => {
    try { await pullSnapshot(false); } finally { if (mainWindow) scheduleSync(); }
  }, delay);
}

function isPrimary() {
  const settings = config.secrets.cache.settings;
  return (settings.autoShareCookies && !settings.primaryDeviceId) || settings.primaryDeviceId?.toLowerCase() === config.deviceId.toLowerCase();
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
// A cookie that disappears from the vault (the primary browser signed out, or an administrator removed
// it) is deleted here too, but only while it still holds the value this browser received; a value the
// site has since rotated locally is left alone.
async function applyAllCookies() {
  const primary = isPrimary();
  const local = primary ? new Set((await browserSession.cookies.get({})).map(cookie => cookieKey(cookie))) : undefined;
  const now = Date.now() / 1000;
  const shared = new Map();
  for (const profile of config.secrets.cache.profiles.filter(item => item.enabled)) {
    for (const cookie of profile.cookies || []) {
      if (cookie.expiresAt && cookie.expiresAt < now) continue;
      const key = cookieKey(cookie, profile.domain);
      const entry = { name: cookie.name, domain: normalizedDomain(cookie.domain || profile.domain), path: cookie.path || '/', value: cookie.value, applied: true };
      shared.set(key, entry);
      const previous = appliedCookies.get(key);
      if (primary ? local.has(key) : previous?.applied && previous.value === cookie.value) continue;
      try { await setSharedCookie(cookie, profile.domain); } catch { entry.applied = false; }
    }
  }
  if (!primary) {
    for (const [key, entry] of appliedCookies) {
      if (shared.has(key)) continue;
      try { await removeSharedCookie(entry); } catch { }
    }
  }
  appliedCookies = shared;
}

async function removeSharedCookie(entry) {
  for (const scheme of ['https', 'http']) {
    const url = `${scheme}://${entry.domain}${entry.path}`;
    const matches = (await browserSession.cookies.get({ url, name: entry.name }))
      .filter(item => normalizedDomain(item.domain) === entry.domain && item.path === entry.path && item.value === entry.value);
    if (matches.length) {
      await browserSession.cookies.remove(url, entry.name);
      return;
    }
  }
}

// Remembers what the offline cache says this browser received, so a removal made on the server while
// this browser was closed is still noticed on the first pull.
function seedSyncState() {
  appliedCookies = new Map();
  pushedDomains = new Map();
  for (const profile of config.secrets.cache.profiles) {
    for (const cookie of profile.cookies || []) {
      const domain = normalizedDomain(cookie.domain || profile.domain);
      appliedCookies.set(cookieKey(cookie, profile.domain), { name: cookie.name, domain, path: cookie.path || '/', value: cookie.value, applied: false });
      if (cookie.sourceDeviceId && cookie.sourceDeviceId !== 'admin') pushedDomains.set(domain, '');
    }
  }
  wasPrimary = isPrimary();
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
    ...(cookie.expiresAt ? { expirationDate: Number(cookie.expiresAt) } : existing[0]?.expirationDate ? { expirationDate: existing[0].expirationDate } : {})
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
    sameSite: serverSameSite(cookie.sameSite),
    ...(cookie.session || !cookie.expirationDate ? {} : { expiresAt: Math.floor(cookie.expirationDate) })
  };
}

function domainSignature(cookies) {
  return JSON.stringify(cookies
    .map(cookie => [cookie.name, cookie.path, cookie.value, cookie.secure, cookie.httpOnly, cookie.sameSite, cookie.expiresAt ? Math.floor(cookie.expiresAt / EXPIRY_BUCKET_SECONDS) : 0])
    .sort((a, b) => `${a[0]}\n${a[1]}`.localeCompare(`${b[0]}\n${b[1]}`)));
}

// The primary browser publishes one complete cookie list per cookie domain, and only for domains whose
// cookies changed since the last publish. A domain whose cookies are all gone (sign-out) is published
// as an empty list so the server removes them from the vault as well.
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
      for (const domain of pushedDomains.keys()) if (!groups.has(domain)) groups.set(domain, []);
      let published = 0;
      for (const [domain, values] of groups) {
        const signature = domainSignature(values);
        if (pushedDomains.get(domain) === signature) continue;
        if (!/^[a-z0-9.-]+$/.test(domain)) continue;
        const complete = values.length <= MAX_COOKIES_PER_DOMAIN;
        await pushCookies(`https://${domain}/`, values.slice(0, MAX_COOKIES_PER_DOMAIN), complete);
        if (values.length) pushedDomains.set(domain, signature); else pushedDomains.delete(domain);
        if (++published >= 500) break;
      }
      status(`Synced r${config.secrets.cache.revision}`);
    } catch (error) {
      status(`Cookie sync failed — ${error.message}`, true);
    }
  });
}

async function pushCookies(pageUrl, cookies, complete) {
  const result = await api('/api/client/sync', {
    method: 'POST',
    body: JSON.stringify({ knownRevision: config.secrets.cache.revision, pageUrl, cookies, complete })
  });
  if (result?.snapshot && result.snapshot.revision !== config.secrets.cache.revision) {
    const previous = config.secrets.cache;
    config.secrets.cache = normalizeSnapshot(result.snapshot);
    saveConfig();
    // These values came from this browser, so they are already installed here.
    appliedCookies = new Map();
    for (const profile of config.secrets.cache.profiles) {
      for (const cookie of profile.cookies || []) {
        appliedCookies.set(cookieKey(cookie, profile.domain), { name: cookie.name, domain: normalizedDomain(cookie.domain || profile.domain), path: cookie.path || '/', value: cookie.value, applied: true });
      }
    }
    if (JSON.stringify(previous.bookmarks) !== JSON.stringify(config.secrets.cache.bookmarks)) send('browser:bookmarks', config.secrets.cache.bookmarks);
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
    proxyRules: `${proxy.tls ? 'https' : 'http'}://${host}:${proxy.port}`,
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

function certificateSha256(certificate) {
  try { return new crypto.X509Certificate(certificate.data).fingerprint256.replaceAll(':', '').toLowerCase(); } catch { return ''; }
}

// The management server advertises the SHA-256 of its proxy certificate over the authenticated API, so
// a self-signed proxy certificate is trusted exactly when it matches. Anything else, including a site
// that happens to share the proxy's host name, gets Chromium's normal verification.
function verifyCertificate(request, callback) {
  const proxy = config?.secrets.cache.settings.proxy;
  const pinned = String(proxy?.certificateSha256 || '').toLowerCase();
  const host = String(proxy?.host || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (config?.networkMode === 'managed' && proxy?.tls && pinned && request.hostname.replace(/^\[|\]$/g, '').toLowerCase() === host
    && certificateSha256(request.certificate) === pinned) {
    callback(0);
    return;
  }
  callback(-3);
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
    seedSyncState();
    if (config.strictPrivacy) await blockBrowserTraffic();
    await ensureEnrolled();
    await pullSnapshot(false);
    await configureProxy();
    await applyAllCookies();
    watchCookies();
    await openInitialTabs();
    wasPrimary = isPrimary();
    await pushAllStoredCookies();
    scheduleSync();
    listenForEvents();
  } catch (error) {
    status(error.message, true);
    try { await applyAllCookies(); } catch { }
    await openInitialTabs();
    send('browser:show-settings');
    // Keep retrying in the background (for example when the server was briefly unreachable at startup).
    if (config.secrets.deviceToken) {
      watchCookies();
      syncFailures = Math.max(syncFailures, 1);
      scheduleSync();
      listenForEvents();
    }
  }
}

function watchCookies() {
  if (watchingCookies) return;
  watchingCookies = true;
  browserSession.cookies.on('changed', onCookieChanged);
}

function showBookmarksMenu(position) {
  const bookmarks = config.secrets.cache.bookmarks;
  const open = (url, event) => {
    const newTab = Boolean(event?.ctrlKey || event?.metaKey || event?.shiftKey);
    const web = tabs.get(activeTabId)?.view.webContents;
    if (newTab || !web || web.isDestroyed()) addTab(url).catch(error => status(error.message, true));
    else web.loadURL(normalizeAddress(url)).catch(error => status(error.message, true));
  };
  const template = bookmarks.length
    ? bookmarks.map(item => ({ label: String(item.title || item.url).slice(0, 80).replace(/&/g, '&&'), toolTip: item.url, click: (_item, _window, event) => open(item.url, event) }))
    : [{ label: 'No shared bookmarks yet', enabled: false }];
  template.push(
    { type: 'separator' },
    { label: 'Hold Ctrl (⌘) or Shift to open in a new tab', enabled: false },
    { label: 'Manage bookmarks in the dashboard…', enabled: validServerUrl(config.serverUrl), click: () => shell.openExternal(config.serverUrl) }
  );
  Menu.buildFromTemplate(template).popup({
    window: mainWindow,
    x: Math.round(Number(position?.x) || 0),
    y: Math.round(Number(position?.y) || TOOLBAR_HEIGHT)
  });
}

function activeWebContents() {
  const web = tabs.get(activeTabId)?.view.webContents;
  return web && !web.isDestroyed() ? web : undefined;
}

function configureDownloads() {
  browserSession.on('will-download', (_event, item) => {
    const name = item.getFilename();
    status(`Downloading ${name}…`);
    item.on('updated', (_e, state) => {
      if (state !== 'progressing' || item.isPaused()) return;
      const total = item.getTotalBytes();
      if (total > 0) status(`Downloading ${name} (${Math.round(item.getReceivedBytes() / total * 100)}%)…`);
    });
    item.once('done', (_e, state) => {
      if (state === 'completed') status(`Downloaded ${name}`);
      else if (state === 'interrupted') status(`Download failed: ${name}`, true);
      else status(`Download cancelled: ${name}`);
    });
  });
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
  ipcMain.handle('browser:bootstrap', () => ({ config: publicConfig(), update: updateState, tabs: tabSummaries(), bookmarks: config.secrets.cache.bookmarks }));
  ipcMain.handle('browser:show-bookmarks', (_, position) => showBookmarksMenu(position));
  ipcMain.handle('browser:reopen-tab', reopenClosedTab);
  ipcMain.handle('browser:find', (_, text, options) => {
    const web = activeWebContents();
    const query = String(text || '');
    if (!web) return;
    if (!query) {
      web.stopFindInPage('clearSelection');
      send('browser:find-result', { active: 0, matches: 0 });
      return;
    }
    // Electron's findNext means "start a new find session", which is what typing a new query needs.
    web.findInPage(query, { forward: options?.forward !== false, findNext: !options?.next, matchCase: false });
  });
  ipcMain.handle('browser:stop-find', () => {
    const web = activeWebContents();
    if (web) {
      web.stopFindInPage('keepSelection');
      web.focus();
    }
  });
  ipcMain.handle('browser:navigate', async (_, url) => {
    const target = normalizeAddress(url);
    const web = activeWebContents();
    if (!web) return addTab(target);
    // A failed or aborted load is reported through did-fail-load; only invalid input should reach the renderer.
    web.loadURL(target).catch(() => { });
  });
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
    if (!config.secrets.deviceToken && !config.secrets.enrollmentToken) throw new Error('An enrollment code is required for a new browser or server.');
    saveConfig();
    saveSessionState();
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
  for (const item of [browserSession, session.fromPartition(UPDATER_PARTITION, { cache: false })]) item.setCertificateVerifyProc(verifyCertificate);
  configurePrivacyPermissions();
  configureDownloads();
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
