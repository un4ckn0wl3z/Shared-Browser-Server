const { app, BrowserWindow, WebContentsView, Menu, Notification, clipboard, ipcMain: electronIpcMain, net, powerMonitor, screen, session, safeStorage, shell, webContents, webFrameMain } = require('electron');
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
let chromeHeight = TOOLBAR_HEIGHT;
let announcementTimer;
const closedTabs = [];
let autoUpdater;
let updateTimer;
let updateState = { state: 'idle', currentVersion: app.getVersion() };
let activeTabId;
let nextTabId = 1;
let settingsOpen = false;
// The unlock code is asked once per launch while the server requires it.
let unlocked = false;
let lockShown = false;
let unlockFailures = 0;
let unlockBlockedUntil = 0;
// Set once startup reaches the point of opening tabs, so unlocking earlier does not open pages before the proxy is set.
let initialTabsRequested = false;
// The server no longer accepts this browser's token (it was deleted or revoked); a new enrollment code reconnects it.
let deviceRejected = false;
// The minimum version the server requires while this browser is older; pages stay hidden until it updates.
let updateRequired = '';
let forcedInstallTimer;
// Outside the allowed hours set by the administrator; pages stay hidden until they start again.
let scheduleBlocked = false;
// Addresses an administrator asked to open while pages were hidden.
const pendingOpens = [];
// Downloads of this session, newest first.
const downloads = [];
let nextDownloadId = 1;
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
      primaryDeviceIds: [],
      autoShareCookies: true,
      proxy: { enabled: false, host: '127.0.0.1', port: 8899, allowedPorts: '80,443', bypassList: 'localhost;127.0.0.1' },
      clientLock: { enabled: false }
    },
    profiles: [],
    accounts: [],
    bookmarks: [],
    announcements: []
  };
}

function defaultConfig() {
  return {
    serverUrl: 'http://127.0.0.1:8787',
    deviceId: crypto.randomUUID().replaceAll('-', ''),
    deviceName: profileName,
    // New browsers send everything through the management proxy with Strict privacy until told otherwise.
    networkMode: 'managed',
    strictPrivacy: true,
    window: undefined,
    announcements: { dismissed: [], notified: [], pendingAcks: [] },
    secrets: { deviceToken: '', enrollmentToken: '', unlockFailures: 0, doneCommands: [], cache: defaultSnapshot(), session: { tabs: [], active: 0 } }
  };
}

function configPath() {
  return path.join(app.getPath('userData'), 'client-config.json');
}

// Read before the app is ready, because the WebRTC policy switch must be set at startup. A browser
// without a saved configuration starts in Strict privacy, which is the default.
function readStrictPrivacySetting() {
  try { return JSON.parse(fs.readFileSync(configPath(), 'utf8')).strictPrivacy === true; } catch { return true; }
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
      networkMode: disk.networkMode === 'managed' || disk.networkMode === 'direct' ? disk.networkMode : fresh.networkMode,
      strictPrivacy: typeof disk.strictPrivacy === 'boolean' ? disk.strictPrivacy : fresh.strictPrivacy,
      window: normalizeWindowState(disk.window),
      announcements: {
        dismissed: stringList(disk.announcements?.dismissed),
        notified: stringList(disk.announcements?.notified),
        pendingAcks: stringList(disk.announcements?.pendingAcks)
      },
      secrets: {
        deviceToken: String(secrets?.deviceToken || ''),
        enrollmentToken: String(secrets?.enrollmentToken || ''),
        unlockFailures: Math.max(0, Math.floor(Number(secrets?.unlockFailures) || 0)),
        doneCommands: stringList(secrets?.doneCommands).slice(-100),
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
    announcements: config.announcements,
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
  // Sites whose cookies this browser may update although it is not the primary browser (server 1.10+).
  input.editableDomains = stringList(input.editableDomains).map(normalizedDomain).filter(Boolean);
  // For the primary browser: sites whose account is kept up to date by editors, which it only receives.
  input.readOnlyDomains = stringList(input.readOnlyDomains).map(normalizedDomain).filter(Boolean);
  input.commands = Array.isArray(input.commands) ? input.commands.filter(item => item && typeof item.id === 'string' && typeof item.type === 'string') : [];
  const settings = input.settings;
  settings.siteFilter = settings.siteFilter && ['off', 'allow', 'block'].includes(settings.siteFilter.mode) ? { mode: settings.siteFilter.mode, domains: stringList(settings.siteFilter.domains).map(normalizedDomain) } : { mode: 'off', domains: [] };
  settings.schedule = settings.schedule && typeof settings.schedule === 'object' ? settings.schedule : { enabled: false };
  settings.dataControls = settings.dataControls && typeof settings.dataControls === 'object' ? { ...settings.dataControls, domains: stringList(settings.dataControls.domains).map(normalizedDomain) } : { domains: [] };
  // Servers before 1.4 do not send accounts; the account button then stays hidden.
  input.accounts = Array.isArray(input.accounts)
    ? input.accounts.filter(item => item && typeof item.id === 'string' && typeof item.domain === 'string')
      .map(item => ({
        id: item.id, name: String(item.name || item.domain), domain: normalizedDomain(item.domain), active: item.active === true, cookieCount: Number(item.cookieCount) || 0,
        session: ['ok', 'expiring', 'signed-out', 'empty'].includes(item.session) ? item.session : 'ok',
        expiresAt: item.expiresAt && !Number.isNaN(Date.parse(item.expiresAt)) ? item.expiresAt : null
      }))
    : [];
  input.bookmarks = Array.isArray(input.bookmarks) ? input.bookmarks.filter(item => item && /^https?:\/\//i.test(item.url || '')) : [];
  input.announcements = Array.isArray(input.announcements)
    ? input.announcements.filter(item => item && typeof item.id === 'string' && ['info', 'warning', 'critical'].includes(item.level))
      .map(item => ({ ...item, pinned: item.pinned === true, title: String(item.title || ''), message: String(item.message || ''), url: /^https?:\/\//i.test(item.url || '') ? item.url : '' }))
    : [];
  input.revision = Number(input.revision) || 0;
  return input;
}

function stringList(value) {
  return Array.isArray(value) ? value.filter(item => typeof item === 'string').slice(-500) : [];
}

// ---- Announcements ------------------------------------------------------------------------------

function visibleAnnouncements() {
  const dismissed = new Set(config.announcements.dismissed);
  const now = Date.now();
  // Pinned announcements stay on screen, even if the user dismissed them before they were pinned.
  return config.secrets.cache.announcements
    .filter(item => (item.pinned || !dismissed.has(item.id)) && !(item.expiresAt && Date.parse(item.expiresAt) <= now))
    .sort((a, b) => Number(Boolean(b.pinned)) - Number(Boolean(a.pinned)));
}

// Sends the banners to the toolbar, raises a desktop notification for new warning and critical
// announcements, and schedules a refresh for the next one that expires.
function publishAnnouncements() {
  const visible = visibleAnnouncements();
  send('browser:announcements', visible);
  const known = new Set(config.secrets.cache.announcements.map(item => item.id));
  const notified = new Set(config.announcements.notified);
  let changed = false;
  for (const item of visible) {
    if (notified.has(item.id)) continue;
    notified.add(item.id);
    changed = true;
    if (item.level !== 'info' && Notification.isSupported()) {
      const notification = new Notification({ title: item.title || 'Announcement', body: item.message || item.title, urgency: item.level === 'critical' ? 'critical' : 'normal' });
      notification.on('click', () => { if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.focus(); } });
      notification.show();
    }
  }
  // Forget ids the server no longer sends so the lists cannot grow without bound.
  const prune = list => list.filter(id => known.has(id));
  const before = JSON.stringify(config.announcements);
  config.announcements = { dismissed: prune(config.announcements.dismissed), notified: prune([...notified]), pendingAcks: config.announcements.pendingAcks };
  if (changed || before !== JSON.stringify(config.announcements)) saveConfig();
  clearTimeout(announcementTimer);
  const next = Math.min(...visible.filter(item => item.expiresAt).map(item => Date.parse(item.expiresAt) - Date.now()));
  if (Number.isFinite(next)) announcementTimer = setTimeout(publishAnnouncements, Math.max(1000, Math.min(next + 500, 2 ** 31 - 1)));
}

async function dismissAnnouncement(id) {
  const value = String(id);
  if (config.secrets.cache.announcements.some(item => item.id === value && item.pinned)) return;
  if (!config.announcements.dismissed.includes(value)) config.announcements.dismissed.push(value);
  if (!config.announcements.pendingAcks.includes(value)) config.announcements.pendingAcks.push(value);
  saveConfig();
  publishAnnouncements();
  await sendAnnouncementAcks();
}

// Tells the server which announcements were dismissed; anything that fails is retried after the next sync.
async function sendAnnouncementAcks() {
  if (!config.secrets.deviceToken || !config.announcements.pendingAcks.length) return;
  const remaining = [];
  for (const id of config.announcements.pendingAcks) {
    try { await api(`/api/client/announcements/${encodeURIComponent(id)}/ack`, { method: 'POST' }); }
    catch (error) { if (!/not found/i.test(error.message)) remaining.push(id); }
  }
  config.announcements.pendingAcks = remaining;
  saveConfig();
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
  // Nothing is open yet (for example while the unlock screen is shown): keep the saved tabs.
  if (!ordered.length) return;
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
  initialTabsRequested = true;
  if (tabs.size > 0) return;
  if (isLocked()) {
    engageLock();
    return;
  }
  if (config.secrets.deviceToken && !scheduleBlocked && !scheduleOpen()) {
    scheduleBlocked = true;
    hidePages();
    send('browser:lock', lockState());
  }
  if (updateRequired || scheduleBlocked) return;
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
  tab.view.setBounds({ x: 0, y: chromeHeight, width, height: Math.max(0, height - chromeHeight) });
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
    canGoForward: tab?.view.webContents.navigationHistory.canGoForward() || false,
    account: accountState(currentUrl),
    primary: Boolean(config.secrets.deviceToken) && !deviceRejected && isPrimary(),
    readOnly: config.secrets.cache.readOnlyDomains || [],
    editor: Boolean(config.secrets.deviceToken) && !deviceRejected && !isPrimary() ? editableDomains() : []
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
  if (pagesHidden()) return undefined;
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
  applyWebRtcPolicy(webContents);
  protectPage(webContents);
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
  const rules = dataRules(params.pageURL || webContents.getURL());
  if (params.linkURL && /^https?:/i.test(params.linkURL)) {
    template.push(
      { label: 'Open link in new tab', click: () => addTab(params.linkURL, { referrer: { url: params.pageURL, policy: 'strict-origin-when-cross-origin' } }).catch(error => status(error.message, true)) },
      ...(rules.copy ? [] : [{ label: 'Copy link address', click: () => clipboard.writeText(params.linkURL) }]),
      { type: 'separator' }
    );
  }
  if (params.mediaType === 'image' && /^https?:/i.test(params.srcURL)) {
    template.push(
      { label: 'Open image in new tab', click: () => addTab(params.srcURL).catch(error => status(error.message, true)) },
      ...(rules.copy ? [] : [{ label: 'Copy image address', click: () => clipboard.writeText(params.srcURL) }]),
      { type: 'separator' }
    );
  }
  if (params.isEditable) {
    template.push(
      { label: 'Undo', role: 'undo', enabled: params.editFlags.canUndo },
      { label: 'Redo', role: 'redo', enabled: params.editFlags.canRedo },
      { type: 'separator' },
      { label: 'Cut', role: 'cut', enabled: params.editFlags.canCut && !rules.copy },
      { label: 'Copy', role: 'copy', enabled: params.editFlags.canCopy && !rules.copy },
      { label: 'Paste', role: 'paste', enabled: params.editFlags.canPaste },
      { label: 'Select all', role: 'selectAll', enabled: params.editFlags.canSelectAll },
      { type: 'separator' }
    );
  } else if (params.selectionText.trim() && !rules.copy) {
    template.push({ label: 'Copy', role: 'copy' }, { type: 'separator' });
  }
  template.push(
    { label: 'Back', enabled: webContents.navigationHistory.canGoBack(), click: () => webContents.navigationHistory.goBack() },
    { label: 'Forward', enabled: webContents.navigationHistory.canGoForward(), click: () => webContents.navigationHistory.goForward() },
    { label: 'Reload', click: () => webContents.reload() },
    { type: 'separator' },
    { label: 'Inspect', enabled: !(rules.uploads || rules.copy || rules.downloads), click: () => webContents.inspectElement(params.x, params.y) }
  );
  Menu.buildFromTemplate(template).popup({ window: BrowserWindow.fromWebContents(webContents) || mainWindow });
}

function handleShortcut(input, source) {
  if (input.type !== 'keyDown' || pagesHidden()) return false;
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
  if (key === 'f12' || (command && input.shift && key === 'i')) {
    const rules = dataRules(web.getURL());
    return run(() => rules.uploads || rules.copy || rules.downloads ? status('Developer tools are disabled on this site by the administrator', true) : web.toggleDevTools());
  }
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
  if (!settingsOpen && !pagesHidden()) mainWindow.contentView.addChildView(next.view);
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
      if (response.status === 401) {
        if (useDevice) {
          deviceRejected = true;
          publishNavigationState();
        }
        throw Object.assign(new Error(useDevice ? 'This browser was removed or revoked on the server (unauthorized). Enter a new enrollment code in Settings to reconnect it.' : message || 'The enrollment code or token was not accepted.'), { status: 401 });
      }
      let data;
      try { data = JSON.parse(text); } catch { }
      throw Object.assign(new Error(message || `Server returned ${response.status}${text ? `: ${text.slice(0, 200)}` : ''}`), { status: response.status, data });
    }
    return text ? JSON.parse(text) : undefined;
  } finally {
    clearTimeout(timeout);
  }
}

// A newly entered enrollment code always enrolls again, even when an old device token is still stored: that
// token stops working when an administrator deletes or revokes the browser, and the code is how it reconnects.
async function ensureEnrolled() {
  if (config.secrets.deviceToken && !config.secrets.enrollmentToken) return;
  if (!config.secrets.enrollmentToken) throw new Error('Open Settings and enter an enrollment code from the management dashboard.');
  let result;
  try {
    result = await api('/api/client/enroll', {
      method: 'POST',
      headers: { authorization: `Bearer ${config.secrets.enrollmentToken}` },
      body: JSON.stringify({ deviceId: config.deviceId, deviceName: config.deviceName })
    }, false);
  } catch (error) {
    // A code the server refused is not tried again at every start; the user enters a new one.
    if (error.status === 401 || error.status === 403) {
      config.secrets.enrollmentToken = '';
      saveConfig();
    }
    throw error;
  }
  deviceRejected = false;
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
      const response = await fetch(apiUrl(`/api/client/events?${clientReport()}`), {
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
      const response = await api(`/api/client/snapshot?deviceName=${encodeURIComponent(config.deviceName)}&${clientReport()}${since}`);
      if (response) {
        const snapshot = normalizeSnapshot(response);
        if (snapshot.revision !== previous.revision || notify) await installSnapshot(snapshot, previous);
      }
      syncFailures = 0;
      authPrompted = false;
      deviceRejected = false;
      if (updateRequired) await clearUpdateRequirement();
      status(`${notify ? 'Synchronization complete — ' : ''}Synced r${config.secrets.cache.revision}`);
      return true;
    } catch (error) {
      syncFailures++;
      status(`Offline cache — ${error.message}`, true);
      if (error.status === 426) requireUpdate(error.data?.minimumVersion);
      // Ask once. Re-opening the dialog on every poll would reset whatever the user is typing in it.
      if (/unauthorized|revoked/i.test(error.message) && !authPrompted) {
        authPrompted = true;
        send('browser:show-settings');
      }
      return false;
    }
  });
}

// Lets the dashboard show each browser's version and whether it follows the required connection mode.
function clientReport() {
  return `version=${encodeURIComponent(app.getVersion())}&mode=${effectiveMode()}`;
}

async function installSnapshot(snapshot, previous) {
  const lockWasOn = Boolean(previous?.settings?.clientLock?.enabled && previous.settings.clientLock.hash);
  config.secrets.cache = snapshot;
  // Turning the unlock code on (for everyone or for this browser) locks it again, even if it was unlocked earlier in this run.
  if (!lockWasOn && clientLock()) unlocked = false;
  const modeChanged = enforceNetworkPolicy();
  saveConfig();
  if (modeChanged) {
    await applyNetworkMode();
    // Report the new mode right away instead of at the next poll.
    setTimeout(() => pullSnapshot(false), 0);
  }
  // Cookies are installed in place. Reloading the page here would wipe whatever the user is in
  // the middle of (an open dialog, a half-filled form, a deployment approval).
  await applyAllCookies();
  if (!modeChanged && JSON.stringify(previous.settings.proxy) !== JSON.stringify(snapshot.settings.proxy) && config.networkMode === 'managed') {
    try {
      await configureProxy();
      await browserSession.closeAllConnections();
    } catch (error) {
      status(error.message, true);
    }
  }
  if (JSON.stringify(previous.bookmarks) !== JSON.stringify(snapshot.bookmarks)) send('browser:bookmarks', snapshot.bookmarks);
  if (JSON.stringify(previous.announcements) !== JSON.stringify(snapshot.announcements)) publishAnnouncements();
  sendAnnouncementAcks().catch(() => { });
  const primary = isPrimary();
  // A browser that has just been made primary publishes everything it holds right away.
  if (primary && !wasPrimary) {
    pushedDomains = new Map();
    setImmediate(() => pushAllStoredCookies());
  }
  wasPrimary = primary;
  // Turning the unlock code on locks running browsers too; turning it off releases a locked one.
  if (isLocked()) engageLock();
  else if (lockShown) await releaseLock();
  await applySchedule();
  runCommands(snapshot.commands).catch(error => status(error.message, true));
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
  // Servers since 1.9 list every primary browser; older ones name a single one.
  const primaries = (Array.isArray(settings.primaryDeviceIds) && settings.primaryDeviceIds.length ? settings.primaryDeviceIds : [settings.primaryDeviceId])
    .filter(Boolean).map(id => String(id).toLowerCase());
  // Only the browser the administrator chose is primary; with none chosen, no browser shares its sign-ins.
  return primaries.includes(config.deviceId.toLowerCase());
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
      // The primary browser keeps its own cookies, except on sites whose editors are the source of the session.
      const writer = primary && !readOnlyDomain(normalizedDomain(profile.domain));
      if (writer ? local.has(key) : previous?.applied && previous.value === cookie.value) continue;
      try { await setSharedCookie(cookie, profile.domain); } catch { entry.applied = false; }
    }
  }
  {
    for (const [key, entry] of appliedCookies) {
      if (shared.has(key) || (primary && !readOnlyDomain(entry.domain))) continue;
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
function editableDomains() {
  return config.secrets.cache.editableDomains || [];
}

// The primary browser publishes every site; an editor only the sites of the accounts it may update.
function publishes() {
  return isPrimary() || editableDomains().length > 0;
}

function readOnlyDomain(domain) {
  return (config.secrets.cache.readOnlyDomains || []).some(site => domainWithin(domain, site));
}

function mayPublish(domain) {
  return isPrimary() ? !readOnlyDomain(domain) : editableDomains().some(site => domainWithin(domain, site));
}

async function pushAllStoredCookies() {
  if (!publishes() || !config.secrets.deviceToken || pushPending) return;
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
        if (!/^[a-z0-9.-]+$/.test(domain) || !mayPublish(domain)) continue;
        // An editor reports a site as empty only after it published that site itself in this run, so a
        // browser that never received a site's cookies cannot wipe them from the vault.
        if (!values.length && !isPrimary() && !pushedDomains.get(domain)) continue;
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
    if (JSON.stringify(previous.announcements) !== JSON.stringify(config.secrets.cache.announcements)) publishAnnouncements();
  }
}

function scheduleCookiePush() {
  if (!publishes()) return;
  clearTimeout(cookiePushTimer);
  cookiePushTimer = setTimeout(() => pushAllStoredCookies(), 900);
}

// ---- Unlock code --------------------------------------------------------------------------------
// The server sends only a salted PBKDF2 hash of the code, kept in the encrypted local cache, so the
// browser can be unlocked offline too. Until it is unlocked no page is shown and no tab opens.

function clientLock() {
  const lock = config.secrets.cache.settings.clientLock;
  return lock?.enabled && typeof lock.salt === 'string' && lock.salt && typeof lock.hash === 'string' && lock.hash ? lock : null;
}

function isLocked() {
  return !unlocked && Boolean(config.secrets.deviceToken) && Boolean(clientLock());
}

// Pages are hidden while the unlock screen or the update-required screen is shown.
function pagesHidden() {
  return lockShown || Boolean(updateRequired) || scheduleBlocked;
}

function hidePages() {
  const tab = tabs.get(activeTabId);
  if (tab && mainWindow && !mainWindow.isDestroyed()) {
    try { mainWindow.contentView.removeChildView(tab.view); } catch { }
  }
  for (const item of tabs.values()) if (!item.view.webContents.isDestroyed()) item.view.webContents.setAudioMuted(true);
  for (const popup of BrowserWindow.getAllWindows()) if (popup !== mainWindow) popup.close();
}

async function showPages() {
  if (pagesHidden()) return;
  for (const item of tabs.values()) if (!item.view.webContents.isDestroyed()) item.view.webContents.setAudioMuted(false);
  if (tabs.size) await selectTab(activeTabId ?? [...tabs.keys()][0]);
  else if (initialTabsRequested) await openInitialTabs();
  while (pendingOpens.length && !pagesHidden()) await addTab(pendingOpens.shift());
}

function engageLock() {
  if (lockShown) return;
  lockShown = true;
  hidePages();
  send('browser:lock', lockState());
}

async function releaseLock() {
  if (!lockShown) return;
  lockShown = false;
  send('browser:lock', lockState());
  await showPages();
}

function lockState() {
  return {
    locked: lockShown,
    deviceName: config.deviceName,
    update: updateRequired ? { version: updateRequired, current: app.getVersion() } : null,
    schedule: scheduleBlocked ? scheduleText() : null
  };
}

// ---- Required update ----------------------------------------------------------------------------
// The server answers 426 when it requires a newer browser. The browser then hides its pages, downloads
// the update and restarts into it on its own (Windows and Linux AppImage); the macOS build links to the
// release page.

function requireUpdate(version) {
  const value = String(version || '').slice(0, 20);
  if (!/^\d+\.\d+\.\d+$/.test(value) || updateRequired === value) return;
  if (!updateRequired) hidePages();
  updateRequired = value;
  send('browser:lock', lockState());
  if (updateState.state === 'ready') scheduleForcedInstall();
  else checkForUpdates().catch(() => { });
}

async function clearUpdateRequirement() {
  if (!updateRequired) return;
  updateRequired = '';
  clearTimeout(forcedInstallTimer);
  forcedInstallTimer = undefined;
  publishUpdate({ restarting: false });
  send('browser:lock', lockState());
  await showPages();
}

function scheduleForcedInstall() {
  if (!updateRequired || !autoUpdater || forcedInstallTimer) return;
  publishUpdate({ restarting: true });
  forcedInstallTimer = setTimeout(() => {
    quitting = true;
    saveSessionState();
    autoUpdater.quitAndInstall(true, true);
  }, 5000);
}

async function verifyUnlockCode(code, lock) {
  const iterations = Math.min(Math.max(Math.floor(Number(lock.iterations) || 0), 1), 5_000_000);
  const derived = await new Promise((resolve, reject) => crypto.pbkdf2(code.trim().normalize('NFC'), Buffer.from(lock.salt, 'base64'), iterations, 32, 'sha256', (error, key) => error ? reject(error) : resolve(key)));
  const expected = Buffer.from(lock.hash, 'base64');
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

function unlockDelay(failures) {
  return failures >= 5 ? Math.min(30_000 * 2 ** (failures - 5), 15 * 60_000) : 0;
}

// After five wrong codes each further attempt waits longer, up to 15 minutes; the count survives restarts.
async function unlock(code) {
  if (!lockShown) return { ok: true };
  const lock = clientLock();
  if (!lock) {
    unlocked = true;
    await releaseLock();
    return { ok: true };
  }
  const wait = unlockBlockedUntil - Date.now();
  if (wait > 0) return { ok: false, error: `Too many wrong codes. Try again in ${Math.ceil(wait / 1000)} seconds.` };
  const ok = await verifyUnlockCode(String(code || '').slice(0, 256), lock);
  if (config.secrets.deviceToken) api('/api/client/unlock-report', { method: 'POST', body: JSON.stringify({ success: ok }) }).catch(() => { });
  if (!ok) {
    unlockFailures++;
    unlockBlockedUntil = Date.now() + unlockDelay(unlockFailures);
    config.secrets.unlockFailures = unlockFailures;
    saveConfig();
    return { ok: false, error: 'Wrong unlock code.' };
  }
  unlocked = true;
  unlockFailures = 0;
  unlockBlockedUntil = 0;
  config.secrets.unlockFailures = 0;
  saveConfig();
  await releaseLock();
  return { ok: true };
}

// ---- Idle lock ----------------------------------------------------------------------------------
// With an unlock code in use, the browser locks again after a period without keyboard or mouse use, and
// optionally when the computer's screen locks or it sleeps.

function relock() {
  if (!clientLock() || !config.secrets.deviceToken) return false;
  unlocked = false;
  engageLock();
  return true;
}

function watchIdle() {
  const lockWithSystem = () => { if (unlocked && clientLock()?.lockOnSystemLock) relock(); };
  powerMonitor.on('lock-screen', lockWithSystem);
  powerMonitor.on('suspend', lockWithSystem);
  setInterval(() => {
    const lock = clientLock();
    if (!unlocked || lockShown || !lock || !(Number(lock.idleMinutes) > 0)) return;
    if (powerMonitor.getSystemIdleTime() >= Number(lock.idleMinutes) * 60) relock();
  }, 5000);
}

// ---- Allowed hours ------------------------------------------------------------------------------

const WEEKDAYS = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function minutesOf(value) {
  const match = /^(\d{2}):(\d{2})$/.exec(String(value || ''));
  return match ? Number(match[1]) * 60 + Number(match[2]) : NaN;
}

// True when the browser may be used now. Times are in the administrator's time zone, and a range such as
// 22:00-06:00 continues past midnight.
function scheduleOpen(now = new Date()) {
  const schedule = config.secrets.cache.settings.schedule;
  if (!schedule?.enabled) return true;
  const start = minutesOf(schedule.start);
  const end = minutesOf(schedule.end);
  const days = Array.isArray(schedule.days) ? schedule.days.map(Number) : [];
  if (Number.isNaN(start) || Number.isNaN(end)) return true;
  let parts;
  try {
    parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: schedule.timeZone || 'UTC', weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
      .formatToParts(now).map(part => [part.type, part.value]));
  } catch {
    return true;
  }
  const day = WEEKDAYS[parts.weekday];
  const minute = Number(parts.hour) * 60 + Number(parts.minute);
  if (start === end) return days.includes(day);
  if (start < end) return days.includes(day) && minute >= start && minute < end;
  return (days.includes(day) && minute >= start) || (days.includes((day + 6) % 7) && minute < end);
}

function scheduleText() {
  const schedule = config.secrets.cache.settings.schedule || {};
  const names = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const days = (schedule.days || []).map(day => names[day]).filter(Boolean).join(', ');
  return { days, start: schedule.start, end: schedule.end, timeZone: schedule.timeZone };
}

async function applySchedule() {
  const blocked = Boolean(config.secrets.deviceToken) && !scheduleOpen();
  if (blocked === scheduleBlocked) return;
  scheduleBlocked = blocked;
  if (blocked) hidePages();
  send('browser:lock', lockState());
  if (!blocked) await showPages();
}

// ---- Administrator actions ----------------------------------------------------------------------

async function runCommands(commands) {
  const done = new Set(config.secrets.doneCommands);
  for (const command of commands || []) {
    if (!done.has(command.id)) {
      done.add(command.id);
      config.secrets.doneCommands = [...done].slice(-100);
      saveConfig();
      try { await runCommand(command); } catch (error) { status(`Administrator action failed — ${error.message}`, true); }
    }
    // Acknowledged even when repeated, so a lost acknowledgement is retried.
    api(`/api/client/commands/${encodeURIComponent(command.id)}/ack`, { method: 'POST', body: '{}' }).catch(() => { });
  }
}

async function runCommand(command) {
  switch (command.type) {
    case 'lock':
      status(relock() ? 'Locked by the administrator' : 'The administrator asked to lock this browser, but no unlock code is set');
      break;
    case 'close-tabs':
      closedTabs.length = 0;
      config.secrets.session = { tabs: [], active: 0 };
      saveConfig();
      for (const id of [...tabs.keys()]) await closeTab(id);
      status('All tabs were closed by the administrator');
      break;
    case 'clear-site': {
      const domain = normalizedDomain(command.argument);
      if (!domain) return;
      await clearSiteCookies(domain);
      for (const [key, entry] of appliedCookies) if (domainWithin(entry.domain, domain)) appliedCookies.delete(key);
      for (const tab of tabs.values()) if (!tab.view.webContents.isDestroyed() && domainWithin(hostOf(tab.view.webContents.getURL()), domain)) tab.view.webContents.reload();
      status(`Cookies for ${domain} were cleared by the administrator`);
      break;
    }
    case 'open-url':
      if (!/^https?:\/\//i.test(command.argument)) return;
      if (pagesHidden()) pendingOpens.push(command.argument);
      else await addTab(command.argument);
      break;
    case 'switch-account': {
      const account = config.secrets.cache.accounts.find(item => item.id === command.argument);
      if (!account) throw new Error('That account is no longer shared with this browser');
      if (!account.active) await switchAccount(account.id);
      status(`The administrator switched ${account.domain} to ${account.name}`);
      break;
    }
    case 'restart':
      saveSessionState();
      app.relaunch();
      app.quit();
      break;
    default:
      break;
  }
}

// ---- Site filter --------------------------------------------------------------------------------
// Decides which sites pages may open (address bar, links, redirects, popups). Resources a page loads from
// other sites are not filtered, so allowed sites keep working.

function siteAllowed(url) {
  const host = hostOf(url);
  if (!host) return true;
  const filter = config.secrets.cache.settings.siteFilter;
  if (!filter || filter.mode === 'off') return true;
  const listed = filter.domains.some(domain => domainWithin(host, domain));
  return filter.mode === 'allow' ? listed : !listed;
}

function blockedPage(url) {
  const host = hostOf(url).replace(/[<>&"]/g, '');
  const html = `<!doctype html><meta charset="utf-8"><title>Blocked</title><body style="font:15px system-ui;margin:12vh auto;max-width:520px;color:#263246"><h1 style="font-size:22px">${host} is blocked</h1><p>Your administrator does not allow this browser to open this site.</p></body>`;
  return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
}

function filterNavigation() {
  browserSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*'] }, (details, callback) => {
    if ((details.resourceType === 'mainFrame' || details.resourceType === 'subFrame') && !siteAllowed(details.url)) {
      callback({ cancel: true });
      const web = details.webContents || (details.webContentsId ? webContents.fromId(details.webContentsId) : undefined);
      if (details.resourceType === 'mainFrame' && web && !web.isDestroyed()) setImmediate(() => web.loadURL(blockedPage(details.url)).catch(() => { }));
      status(`${hostOf(details.url)} is blocked by the administrator`, true);
      return;
    }
    callback({});
  });
}

// ---- Data controls ------------------------------------------------------------------------------
// Downloads, file uploads and copying text can be blocked on chosen sites (all sites when none are listed).
// This keeps honest users from moving data out; it is not protection against screenshots or a determined user.

function dataRules(url) {
  const controls = config.secrets.cache.settings.dataControls || {};
  const host = hostOf(url);
  const applies = host && (!controls.domains?.length || controls.domains.some(domain => domainWithin(host, domain)));
  return applies ? { downloads: Boolean(controls.blockDownloads), uploads: Boolean(controls.blockUploads), copy: Boolean(controls.blockCopy) } : { downloads: false, uploads: false, copy: false };
}

function guardScript(rules) {
  return `(() => {
  if (window.__sharedBrowserGuard) return;
  window.__sharedBrowserGuard = true;
  const stop = event => { event.preventDefault(); event.stopImmediatePropagation(); };
  if (${rules.uploads}) {
    document.addEventListener('click', event => {
      const target = event.target;
      const input = target && (target.matches?.('input[type=file]') ? target : target.control?.type === 'file' ? target.control : null);
      if (input) stop(event);
    }, true);
    for (const type of ['dragover', 'drop']) document.addEventListener(type, event => { if (event.dataTransfer && Array.from(event.dataTransfer.types || []).includes('Files')) stop(event); }, true);
    const picker = HTMLInputElement.prototype.showPicker;
    HTMLInputElement.prototype.showPicker = function () { if (this.type === 'file') throw new DOMException('File uploads are blocked by the administrator', 'NotAllowedError'); return picker.call(this); };
    if (window.showOpenFilePicker) window.showOpenFilePicker = () => Promise.reject(new DOMException('File uploads are blocked by the administrator', 'NotAllowedError'));
    if (window.showDirectoryPicker) window.showDirectoryPicker = window.showOpenFilePicker;
  }
  if (${rules.copy}) {
    for (const type of ['copy', 'cut']) document.addEventListener(type, stop, true);
    if (navigator.clipboard) {
      const refuse = () => Promise.reject(new DOMException('Copying is blocked by the administrator', 'NotAllowedError'));
      navigator.clipboard.writeText = refuse;
      navigator.clipboard.write = refuse;
    }
  }
})();`;
}

function guardFrame(frame) {
  if (!frame || frame.isDestroyed?.()) return;
  const rules = dataRules(frame.url);
  if (rules.uploads || rules.copy) frame.executeJavaScript(guardScript(rules)).catch(() => { });
}

function protectPage(web) {
  web.on('dom-ready', () => guardFrame(web.mainFrame));
  web.on('did-frame-finish-load', (_event, isMainFrame, processId, routingId) => {
    if (!isMainFrame) guardFrame(webFrameMain.fromId(processId, routingId));
  });
  // Developer tools would get around the guards, so they stay closed on protected sites.
  web.on('devtools-opened', () => {
    const rules = dataRules(web.getURL());
    if (rules.uploads || rules.copy || rules.downloads) web.closeDevTools();
  });
}

// ---- Downloads ----------------------------------------------------------------------------------

function downloadSummary(entry) {
  const { item, ...rest } = entry;
  return rest;
}

function publishDownloads() {
  send('browser:downloads', downloads.map(downloadSummary));
}

function uniqueDownloadPath(name) {
  const folder = app.getPath('downloads');
  fs.mkdirSync(folder, { recursive: true });
  const parsed = path.parse(name.replace(/[\\/:*?"<>|]/g, '_') || 'download');
  let candidate = path.join(folder, parsed.base);
  for (let index = 1; fs.existsSync(candidate) && index < 1000; index++) candidate = path.join(folder, `${parsed.name} (${index})${parsed.ext}`);
  return candidate;
}

function trackDownload(event, item, source) {
  const pageUrl = source && !source.isDestroyed() ? source.getURL() : '';
  const entry = { id: nextDownloadId++, name: item.getFilename(), url: item.getURL(), path: '', state: 'progressing', received: 0, total: item.getTotalBytes(), startedAt: Date.now(), item };
  downloads.unshift(entry);
  if (downloads.length > 100) downloads.length = 100;
  if (dataRules(pageUrl || item.getURL()).downloads) {
    event.preventDefault();
    entry.state = 'blocked';
    status(`Downloads are blocked on ${hostOf(pageUrl || item.getURL())} by the administrator`, true);
    publishDownloads();
    return;
  }
  entry.path = uniqueDownloadPath(entry.name);
  item.setSavePath(entry.path);
  status(`Downloading ${entry.name}…`);
  let lastPublish = 0;
  item.on('updated', (_event, state) => {
    entry.state = state === 'interrupted' ? 'interrupted' : item.isPaused() ? 'paused' : 'progressing';
    entry.received = item.getReceivedBytes();
    entry.total = item.getTotalBytes();
    if (Date.now() - lastPublish > 400) { lastPublish = Date.now(); publishDownloads(); }
    if (state === 'progressing' && !item.isPaused() && entry.total > 0) status(`Downloading ${entry.name} (${Math.round(entry.received / entry.total * 100)}%)…`);
  });
  item.once('done', (_event, state) => {
    entry.state = state;
    entry.received = item.getReceivedBytes();
    entry.item = undefined;
    if (state === 'completed') status(`Downloaded ${entry.name}`);
    else if (state === 'interrupted') status(`Download failed: ${entry.name}`, true);
    else status(`Download cancelled: ${entry.name}`);
    publishDownloads();
  });
  publishDownloads();
  send('browser:download-started', downloadSummary(entry));
}

function downloadAction(id, action) {
  const entry = downloads.find(item => item.id === Number(id));
  if (!entry) return;
  if (action === 'pause') entry.item?.pause();
  else if (action === 'resume' && entry.item?.canResume()) entry.item.resume();
  else if (action === 'cancel') entry.item?.cancel();
  else if (action === 'open' && entry.state === 'completed') shell.openPath(entry.path);
  else if (action === 'show' && entry.path) shell.showItemInFolder(entry.path);
  else if (action === 'remove' && !entry.item) downloads.splice(downloads.indexOf(entry), 1);
  if (action === 'pause') entry.state = 'paused';
  if (action === 'resume') entry.state = 'progressing';
  publishDownloads();
}

function clearDownloads() {
  for (let index = downloads.length - 1; index >= 0; index--) if (!downloads[index].item) downloads.splice(index, 1);
  publishDownloads();
}

// ---- Accounts -----------------------------------------------------------------------------------
// A site can have several shared accounts (session profiles with the same domain), for example two
// GitHub users. The server sends cookies only for the account this browser uses; switching asks the
// server to change that, then replaces the site's cookies here and reloads the site's tabs.

function hostOf(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.hostname.toLowerCase() : '';
  } catch {
    return '';
  }
}

function domainWithin(host, domain) {
  return Boolean(host && domain) && (host === domain || host.endsWith(`.${domain}`));
}

// The accounts of the most specific shared site that covers the URL's host.
function siteAccounts(url, accounts = config.secrets.cache.accounts) {
  const host = hostOf(url);
  const matching = accounts.filter(item => domainWithin(host, item.domain));
  const domain = matching.reduce((best, item) => item.domain.length > best.length ? item.domain : best, '');
  return { host, domain, accounts: matching.filter(item => item.domain === domain) };
}

function accountState(url) {
  const site = siteAccounts(url);
  if (!site.accounts.length) return null;
  const active = site.accounts.find(item => item.active) || site.accounts[0];
  warnExpiringSession(active);
  return { domain: site.domain, name: active.name, count: site.accounts.length, session: active.session, expiresAt: active.expiresAt };
}

function expiryText(item) {
  if (item.session === 'signed-out' || item.session === 'empty') return 'signed out';
  if (!item.expiresAt) return '';
  const date = new Date(item.expiresAt);
  return `${item.session === 'expiring' ? 'expires' : 'until'} ${date.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} ${date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
}

// A desktop notification, once per account and expiry date, when the shared sign-in expires soon.
const expiryWarned = new Set();
function warnExpiringSession(item) {
  if (item.session !== 'expiring' || !item.expiresAt) return;
  const key = `${item.id}|${item.expiresAt}`;
  if (expiryWarned.has(key)) return;
  expiryWarned.add(key);
  const when = new Date(item.expiresAt).toLocaleString();
  status(`The shared ${item.domain} sign-in (${item.name}) expires on ${when}`, true);
  if (Notification.isSupported()) new Notification({ title: `${item.domain}: shared sign-in expires soon`, body: `${item.name} expires on ${when}. Ask your administrator to sign in again on the primary browser.` }).show();
}

function accountLabel(item) {
  const detail = item.cookieCount ? `${item.cookieCount} cookie${item.cookieCount === 1 ? '' : 's'}` : 'not signed in';
  const expiry = expiryText(item);
  return `${item.session === 'expiring' ? '⏳ ' : ''}${item.name.slice(0, 60)} — ${detail}${expiry ? ` · ${expiry}` : ''}`.replace(/&/g, '&&');
}

function showAccountsMenu(position) {
  const web = activeWebContents();
  const site = siteAccounts(web?.getURL() || '');
  if (!site.accounts.length) return;
  const template = [{ label: `Accounts for ${site.domain}`, enabled: false }];
  for (const item of site.accounts) {
    template.push({
      label: accountLabel(item),
      type: 'radio',
      checked: item.active,
      click: () => { if (!item.active) switchAccount(item.id).catch(error => status(`Account switch failed — ${error.message}`, true)); }
    });
  }
  template.push({ type: 'separator' }, isPrimary()
    ? { label: 'Add another account…', click: () => send('browser:add-account', { domain: site.domain }) }
    : { label: 'Accounts are added from the primary browser', enabled: false });
  Menu.buildFromTemplate(template).popup({
    window: mainWindow,
    x: Math.round(Number(position?.x) || 0),
    y: Math.round(Number(position?.y) || chromeHeight)
  });
}

async function clearSiteCookies(domain) {
  const cookies = (await browserSession.cookies.get({})).filter(cookie => domainWithin(normalizedDomain(cookie.domain), domain));
  for (const cookie of cookies) {
    const url = `${cookie.secure ? 'https' : 'http'}://${normalizedDomain(cookie.domain)}${cookie.path || '/'}`;
    try { await browserSession.cookies.remove(url, cookie.name); } catch { }
  }
}

// Runs in the server queue, so a cookie publish cannot interleave: one queued before the switch still
// goes to the old account, and the publish triggered by clearing the cookies goes to the new one.
function changeAccount(pathname, body, pageUrl, clear) {
  return serialized(async () => {
    const snapshot = normalizeSnapshot(await api(pathname, { method: 'POST', body: JSON.stringify(body) }));
    const domain = siteAccounts(pageUrl, snapshot.accounts).domain || hostOf(pageUrl);
    if (clear) await clearSiteCookies(domain);
    for (const [key, entry] of appliedCookies) if (domainWithin(entry.domain, domain)) appliedCookies.delete(key);
    await installSnapshot(snapshot, config.secrets.cache);
    for (const tab of tabs.values()) {
      const web = tab.view.webContents;
      if (!web.isDestroyed() && domainWithin(hostOf(web.getURL()), domain)) web.reload();
    }
    publishNavigationState();
    return siteAccounts(pageUrl, snapshot.accounts).accounts.find(item => item.active);
  });
}

async function switchAccount(id) {
  const account = config.secrets.cache.accounts.find(item => item.id === id);
  if (!account) throw new Error('That account is no longer shared with this browser');
  await changeAccount(`/api/client/accounts/${encodeURIComponent(id)}/switch`, {}, `https://${account.domain}/`, true);
  status(`Using ${account.name} on ${account.domain}`);
}

// Adds an empty account and signs this browser out of the site, so the next sign-in is saved as it.
async function addAccount(name) {
  const pageUrl = activeWebContents()?.getURL() || '';
  const site = siteAccounts(pageUrl);
  if (!site.host) throw new Error('Open the site you want to add an account for first');
  if (!isPrimary()) throw new Error('Accounts are added from the primary browser');
  // The first account of a site keeps the session this browser already has.
  const account = await changeAccount('/api/client/accounts', { name, pageUrl }, pageUrl, site.accounts.length > 0);
  status(`Sign in to ${account?.domain || site.host} to save the ${account?.name || name} account`);
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
  if (!config.strictPrivacy) {
    browserSession.setPermissionCheckHandler(null);
    browserSession.setPermissionRequestHandler(null);
    return;
  }
  // Copy buttons and fullscreen video do not expose anything about the network or device.
  const harmless = new Set(['clipboard-sanitized-write', 'fullscreen']);
  browserSession.setPermissionCheckHandler((_webContents, permission) => harmless.has(permission));
  browserSession.setPermissionRequestHandler((_webContents, permission, callback) => callback(harmless.has(permission)));
}

const STRICT_WEBRTC_POLICY = 'disable_non_proxied_udp';

// Also set per page, so Strict privacy can take effect without the restart the command-line switch needs.
function applyWebRtcPolicy(webContents) {
  if (!webContents || webContents.isDestroyed() || webContents === mainWindow?.webContents) return;
  webContents.setWebRTCIPHandlingPolicy(config.strictPrivacy ? STRICT_WEBRTC_POLICY : 'default');
}

function networkPolicy() {
  const value = config.secrets.cache.settings.networkPolicy;
  return value === 'managed' || value === 'strict' ? value : 'choice';
}

function effectiveMode() {
  return config.networkMode !== 'managed' ? 'direct' : config.strictPrivacy ? 'strict' : 'managed';
}

// Applies the connection mode the administrator requires. Returns true when this browser's mode changed.
function enforceNetworkPolicy() {
  const policy = networkPolicy();
  const before = effectiveMode();
  if (policy === 'managed' || policy === 'strict') config.networkMode = 'managed';
  if (policy === 'strict') config.strictPrivacy = true;
  return effectiveMode() !== before;
}

// Switches routing, permissions and WebRTC to the current mode while the browser keeps running.
async function applyNetworkMode() {
  configurePrivacyPermissions();
  for (const contents of webContents.getAllWebContents()) applyWebRtcPolicy(contents);
  try {
    await configureProxy();
    await browserSession.closeAllConnections();
  } catch (error) {
    status(error.message, true);
  }
  send('browser:config', publicConfig());
}

// Asks the administrator's IP echo service which address websites see, over this browser's own route.
function checkPublicIp() {
  const url = config.secrets.cache.settings.ipCheckUrl;
  if (!url) return Promise.reject(new Error('The administrator has not set an IP check service.'));
  return new Promise((resolve, reject) => {
    const request = net.request({ url, session: browserSession, useSessionCookies: false });
    const timeout = setTimeout(() => { request.abort(); reject(new Error('The IP check timed out.')); }, 20000);
    const finish = (error, value) => { clearTimeout(timeout); if (error) reject(error); else resolve(value); };
    request.on('login', proxyLogin);
    request.on('response', response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').trim();
        let ip = text;
        try { ip = JSON.parse(text).ip || ''; } catch { }
        if (response.statusCode !== 200 || !/^[0-9a-f:.]+$/i.test(ip)) finish(new Error(`The IP check service answered ${response.statusCode}.`));
        else finish(undefined, { ip, mode: effectiveMode() });
      });
    });
    request.on('error', error => finish(new Error(`IP check failed: ${error.message}`)));
    request.end();
  });
}

function routeIsDirect(value) {
  return !value || /(^|;)\s*DIRECT\s*(;|$)/i.test(value);
}

async function privacyCheck() {
  const externalRoute = await browserSession.resolveProxy('https://example.com/');
  const loopbackRoute = await browserSession.resolveProxy('http://127.0.0.1/');
  const page = tabs.get(activeTabId)?.view.webContents;
  const webRtcPolicy = page && !page.isDestroyed() ? page.getWebRTCIPHandlingPolicy() : app.commandLine.getSwitchValue('force-webrtc-ip-handling-policy');
  const ok = config.strictPrivacy
    && !routeIsDirect(externalRoute)
    && !routeIsDirect(loopbackRoute)
    && webRtcPolicy === STRICT_WEBRTC_POLICY;
  return {
    ok,
    strictPrivacy: config.strictPrivacy,
    externalRoute,
    loopbackRoute,
    webRtcPolicy: webRtcPolicy || 'default'
  };
}

async function startClient() {
  // Show the unlock screen right away when the cached settings require it, before the server answers.
  if (isLocked()) engageLock();
  try {
    seedSyncState();
    if (enforceNetworkPolicy()) saveConfig();
    configurePrivacyPermissions();
    if (config.strictPrivacy) await blockBrowserTraffic();
    await ensureEnrolled();
    await pullSnapshot(false);
    await configureProxy();
    await applyAllCookies();
    watchCookies();
    await openInitialTabs();
    publishAnnouncements();
    sendAnnouncementAcks().catch(() => { });
    wasPrimary = isPrimary();
    await pushAllStoredCookies();
    scheduleSync();
    listenForEvents();
  } catch (error) {
    status(error.message, true);
    try { await applyAllCookies(); } catch { }
    await openInitialTabs();
    publishAnnouncements();
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
  const entry = item => ({ label: String(item.title || item.url).slice(0, 80).replace(/&/g, '&&'), toolTip: item.url, click: (_item, _window, event) => open(item.url, event) });
  // Bookmarks with a folder are grouped in submenus, in the order the folders first appear.
  const folders = new Map();
  const template = [];
  for (const item of bookmarks) {
    const folder = String(item.folder || '').trim();
    if (!folder) { template.push(entry(item)); continue; }
    if (!folders.has(folder)) {
      const submenu = [];
      folders.set(folder, submenu);
      template.push({ label: `📁 ${folder.slice(0, 60).replace(/&/g, '&&')}`, submenu });
    }
    folders.get(folder).push(entry(item));
  }
  if (!template.length) template.push({ label: 'No shared bookmarks yet', enabled: false });
  template.push(
    { type: 'separator' },
    { label: 'Hold Ctrl (⌘) or Shift to open in a new tab', enabled: false },
    { label: 'Manage bookmarks in the dashboard…', enabled: validServerUrl(config.serverUrl), click: () => shell.openExternal(config.serverUrl) }
  );
  Menu.buildFromTemplate(template).popup({
    window: mainWindow,
    x: Math.round(Number(position?.x) || 0),
    y: Math.round(Number(position?.y) || chromeHeight)
  });
}

function activeWebContents() {
  const web = tabs.get(activeTabId)?.view.webContents;
  return web && !web.isDestroyed() ? web : undefined;
}

function configureDownloads() {
  browserSession.on('will-download', trackDownload);
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
  autoUpdater.on('update-downloaded', info => {
    publishUpdate({ state: 'ready', version: info.version });
    if (updateRequired) scheduleForcedInstall();
  });
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
    rejected: deviceRejected,
    profileName,
    version: app.getVersion(),
    serverUrl: config.serverUrl,
    deviceName: config.deviceName,
    enrolled: Boolean(config.secrets.deviceToken),
    networkMode: config.networkMode,
    strictPrivacy: config.strictPrivacy,
    networkPolicy: networkPolicy(),
    ipCheck: Boolean(config.secrets.cache.settings.ipCheckUrl),
    revision: config.secrets.cache.revision,
    proxy: config.secrets.cache.settings.proxy,
    secureStorage: safeStorage.isEncryptionAvailable() && backend !== 'basic_text'
  };
}

// While the unlock screen is shown, only these requests from the window are answered.
const ALLOWED_WHILE_LOCKED = new Set(['browser:bootstrap', 'browser:chrome-height', 'browser:unlock', 'browser:check-updates', 'browser:install-update']);

function registerIpc() {
  const ipcMain = {
    handle: (channel, handler) => electronIpcMain.handle(channel, (...args) => {
      if (pagesHidden() && !ALLOWED_WHILE_LOCKED.has(channel)) throw new Error(updateRequired ? 'Update the browser first' : 'Unlock the browser first');
      return handler(...args);
    })
  };
  ipcMain.handle('browser:unlock', (_, code) => unlock(code));
  ipcMain.handle('browser:downloads', () => downloads.map(downloadSummary));
  ipcMain.handle('browser:download-action', (_, id, action) => downloadAction(id, String(action)));
  ipcMain.handle('browser:clear-downloads', clearDownloads);
  ipcMain.handle('browser:check-updates', checkForUpdates);
  ipcMain.handle('browser:install-update', installUpdate);
  ipcMain.handle('browser:bootstrap', () => ({ lock: lockState(), config: publicConfig(), update: updateState, tabs: tabSummaries(), bookmarks: config.secrets.cache.bookmarks, announcements: visibleAnnouncements() }));
  ipcMain.handle('browser:dismiss-announcement', (_, id) => dismissAnnouncement(id));
  ipcMain.handle('browser:open-announcement-link', (_, id) => {
    const item = config.secrets.cache.announcements.find(entry => entry.id === String(id));
    if (item?.url) return addTab(item.url);
  });
  ipcMain.handle('browser:chrome-height', (_, height) => {
    const value = Math.round(Number(height));
    if (!Number.isFinite(value)) return;
    chromeHeight = Math.min(Math.max(value, TOOLBAR_HEIGHT), 420);
    layoutActiveView();
  });
  ipcMain.handle('browser:show-bookmarks', (_, position) => showBookmarksMenu(position));
  ipcMain.handle('browser:show-accounts', (_, position) => showAccountsMenu(position));
  ipcMain.handle('browser:add-account', (_, name) => addAccount(String(name || '').trim().slice(0, 80)));
  ipcMain.handle('browser:switch-account', (_, id) => switchAccount(String(id || '')));
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
  ipcMain.handle('browser:check-ip', checkPublicIp);
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
    // A mode the administrator requires cannot be changed here.
    const policy = networkPolicy();
    const networkMode = policy === 'choice' ? (input.networkMode === 'managed' ? 'managed' : 'direct') : 'managed';
    const strictPrivacy = policy === 'strict' || input.strictPrivacy === true;
    if (strictPrivacy && networkMode !== 'managed') throw new Error('Strict privacy requires Managed proxy mode.');
    // Before the first sync the proxy settings are not known yet, so the check waits until they are.
    if (policy === 'choice' && strictPrivacy && config.secrets.cache.revision > 0 && !config.secrets.cache.settings.proxy?.enabled) throw new Error('Enable the managed proxy in the server dashboard before turning on Strict privacy.');
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
  unlockFailures = config.secrets.unlockFailures;
  unlockBlockedUntil = Date.now() + unlockDelay(unlockFailures);
  app.userAgentFallback = browserUserAgent();
  Menu.setApplicationMenu(applicationMenu());
  browserSession = session.fromPartition('persist:shared-browser');
  browserSession.setUserAgent(app.userAgentFallback);
  for (const item of [browserSession, session.fromPartition(UPDATER_PARTITION, { cache: false })]) item.setCertificateVerifyProc(verifyCertificate);
  configurePrivacyPermissions();
  configureDownloads();
  filterNavigation();
  watchIdle();
  setInterval(() => applySchedule().catch(() => { }), 20000);
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
