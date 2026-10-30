const api = window.sharedBrowser;
const element = id => document.getElementById(id);
const address = element('address');
const tabsElement = element('tabs');
const dialog = element('settings-dialog');
let currentConfig;
let loading = false;

function renderTabs(tabs) {
  tabsElement.replaceChildren(...tabs.map(tab => {
    const button = document.createElement('button');
    button.className = `tab${tab.active ? ' active' : ''}`;
    button.title = tab.title;
    const title = document.createElement('span');
    title.textContent = tab.title;
    const close = document.createElement('span');
    close.className = 'tab-close';
    close.textContent = '×';
    close.title = 'Close tab';
    close.addEventListener('click', event => { event.stopPropagation(); api.closeTab(tab.id); });
    button.append(title, close);
    button.addEventListener('click', () => api.selectTab(tab.id));
    return button;
  }));
}

function updateState(state) {
  if (document.activeElement !== address) address.value = state.url || '';
  element('back').disabled = !state.canGoBack;
  element('forward').disabled = !state.canGoForward;
  loading = Boolean(state.loading);
  const reload = element('reload');
  reload.textContent = loading ? '✕' : '↻';
  reload.title = loading ? 'Stop loading' : 'Reload';
}

function updateUpdate(value) {
  const button = element('update');
  button.hidden = !['available', 'downloading', 'ready'].includes(value.state);
  button.disabled = value.state === 'downloading';
  if (!button.hidden) button.textContent = value.state === 'ready' ? `Restart to update to v${value.version}`
    : value.state === 'downloading' ? `Downloading v${value.version}${value.percent ? ` (${value.percent}%)` : ''}…`
    : `Update to v${value.version}`;
  button.title = value.state === 'available' ? 'Open the release download page' : '';
  element('version-label').textContent = `Version ${value.currentVersion}`;
  const result = element('update-result');
  const messages = {
    checking: 'Checking for updates…',
    current: 'You are running the latest version.',
    available: `Version ${value.version} is available. Use the Update button in the toolbar to download it.`,
    downloading: `Downloading version ${value.version}…`,
    ready: `Version ${value.version} is ready. Use the toolbar button to restart, or it installs when you quit.`,
    error: `Update check failed: ${value.error}`
  };
  result.hidden = !messages[value.state];
  result.className = value.state === 'error' ? 'warning' : 'info';
  result.textContent = messages[value.state] || '';
}

function updateStatus(value) {
  const target = element('status');
  target.textContent = `${value.text} • ${value.route}${currentConfig?.version ? ` • v${currentConfig.version}` : ''}`;
  target.title = target.textContent;
  target.className = value.error ? 'status-error' : 'status-ok';
}

async function openSettings() {
  await api.setSettingsOpen(true);
  const state = await api.bootstrap();
  currentConfig = state.config;
  element('profile-label').textContent = `Profile: ${currentConfig.profileName}`;
  element('server-url').value = currentConfig.serverUrl;
  element('device-name').value = currentConfig.deviceName;
  element('enrollment-token').value = '';
  element('enrollment-token').required = !currentConfig.enrolled;
  element('enrollment-help').textContent = currentConfig.enrolled ? 'Already enrolled. Leave empty to keep the current device token.' : 'Enter the server administrator token once to enroll this browser.';
  element('network-mode').value = currentConfig.networkMode;
  element('strict-privacy').checked = currentConfig.strictPrivacy === true;
  element('privacy-warning').hidden = !currentConfig.strictPrivacy;
  element('proxy-info').textContent = currentConfig.proxy?.enabled
    ? `Managed proxy available at ${currentConfig.proxy.host}:${currentConfig.proxy.port}.`
    : 'Managed proxy is disabled on the server.';
  element('storage-warning').hidden = currentConfig.secureStorage;
  element('settings-error').textContent = '';
  if (!dialog.open) dialog.showModal();
}

function closeSettings() {
  if (dialog.open) dialog.close();
  api.setSettingsOpen(false);
}

async function navigate() {
  const target = address.value;
  address.blur();
  try { await api.navigate(target); } catch (error) { updateStatus({ text: error.message, route: '', error: true }); }
}

element('back').addEventListener('click', api.back);
element('forward').addEventListener('click', api.forward);
element('reload').addEventListener('click', () => loading ? api.stop() : api.reload());
element('go').addEventListener('click', navigate);
element('sync').addEventListener('click', api.syncNow);
element('update').addEventListener('click', api.installUpdate);
element('check-updates').addEventListener('click', api.checkForUpdates);
element('new-tab').addEventListener('click', () => api.newTab());
element('settings').addEventListener('click', openSettings);
element('settings-close').addEventListener('click', closeSettings);
element('cancel').addEventListener('click', closeSettings);
dialog.addEventListener('cancel', event => { event.preventDefault(); closeSettings(); });
address.addEventListener('keydown', event => { if (event.key === 'Enter') navigate(); });
element('strict-privacy').addEventListener('change', event => {
  if (event.target.checked) element('network-mode').value = 'managed';
  element('privacy-warning').hidden = !event.target.checked;
});
element('privacy-check').addEventListener('click', async () => {
  const output = element('privacy-result');
  output.hidden = false;
  output.textContent = 'Checking Chromium routes…';
  try {
    const result = await api.privacyCheck();
    output.className = result.ok ? 'info' : 'warning';
    output.textContent = result.ok
      ? `Passed — external: ${result.externalRoute}; loopback: ${result.loopbackRoute}; WebRTC: ${result.webRtcPolicy}.`
      : `Not protected — strict: ${result.strictPrivacy ? 'on' : 'off'}; external: ${result.externalRoute || 'none'}; loopback: ${result.loopbackRoute || 'none'}; WebRTC: ${result.webRtcPolicy}. Save and restart after enabling Strict privacy.`;
  } catch (error) {
    output.className = 'warning';
    output.textContent = `Privacy check failed: ${error.message}`;
  }
});

element('settings-form').addEventListener('submit', async event => {
  event.preventDefault();
  const error = element('settings-error');
  error.textContent = '';
  try {
    await api.saveSettings({
      serverUrl: element('server-url').value,
      deviceName: element('device-name').value,
      enrollmentToken: element('enrollment-token').value,
      networkMode: element('network-mode').value,
      strictPrivacy: element('strict-privacy').checked
    });
  } catch (failure) {
    error.textContent = failure.message;
  }
});

api.onState(updateState);
api.onTabs(renderTabs);
api.onStatus(updateStatus);
api.onShowSettings(openSettings);
api.onUpdate(updateUpdate);
api.onFocusAddress(() => { address.focus(); address.select(); });

api.bootstrap().then(state => {
  currentConfig = state.config;
  renderTabs(state.tabs);
  updateUpdate(state.update);
  if (!currentConfig.enrolled) openSettings();
});
