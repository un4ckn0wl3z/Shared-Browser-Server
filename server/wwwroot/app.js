const $ = selector => document.querySelector(selector);
let token = sessionStorage.getItem('sharedBrowserAdmin') || '';
let state = null;
// Profile ids ticked for bulk deletion; kept across re-renders so the auto-refresh does not clear them.
const selectedProfiles = new Set();

function toast(message, error = false) {
  const element = $('#toast');
  element.textContent = message;
  element.className = `show${error ? ' error' : ''}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.className = ''; }, 3200);
}

function esc(value) {
  const div = document.createElement('div');
  div.textContent = String(value ?? '');
  return div.innerHTML;
}

async function api(path, options = {}) {
  const response = await fetch(`/api/admin${path}`, {
    ...options,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(options.headers || {}) }
  });
  if (response.status === 401) {
    logout();
    throw new Error('The administrator token was rejected.');
  }
  if (response.status === 204) return null;
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.error || data?.title || `Request failed (${response.status})`);
  return data;
}

function connected(value) {
  $('#login').hidden = value;
  $('#app').hidden = !value;
  $('#connection').textContent = value ? 'Connected' : 'Disconnected';
  $('#connection').className = value ? 'badge' : 'badge off';
}

function logout() {
  sessionStorage.removeItem('sharedBrowserAdmin');
  token = '';
  state = null;
  connected(false);
}

async function load() {
  state = await api('/status');
  connected(true);
  // A display problem must not sign the administrator out; only a rejected token does (see api()).
  try {
    render();
  } catch (error) {
    console.warn(error);
    toast(`Part of the dashboard could not be shown (${error.message}). Reload the page with Ctrl+Shift+R.`, true);
  }
}

function relativeTime(value) {
  if (!value || value.startsWith('0001-')) return 'Never';
  const date = new Date(value);
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return date.toLocaleString();
}

// A form the administrator is editing is left alone when the dashboard refreshes; submitting it clears the mark.
const untouched = selector => !$(selector).dataset.dirty;

function render() {
  const settings = state.settings;
  $('#revision').textContent = state.revision;
  $('#device-count').textContent = state.devices.length;
  $('#profile-count').textContent = state.profiles.length;
  if (untouched('#settings-form')) renderSettingsForm(settings);
  renderSettingsHint(settings);
  if (untouched('#proxy-form')) renderProxyForm(settings);
  if (untouched('#lock-form')) {
    const lock = settings.clientLock || {};
    $('#lock-enabled').checked = lock.enabled === true;
    $('#lock-idle').value = lock.idleMinutes || '';
    $('#lock-system').checked = lock.lockOnSystemLock === true;
  }
  if (untouched('#notify-form')) renderNotifications();
  if (untouched('#controls-form')) renderControls();
  if (untouched('#offsite-form')) renderOffsite();
  renderStatusOnly(settings);
}

function renderSettingsForm(settings) {
  $('#home-page').value = settings.homePage;
  $('#search-url').value = settings.searchUrl || '';
  $('#auto-share-mode').value = settings.autoShareCookies === false ? 'off' : settings.autoShareScope === 'listed' ? 'listed' : 'all';
  $('#auto-share-domains').value = (settings.autoShareDomains || []).join('\n');
  updateShareSites();
  $('#allow-admin-enroll').checked = settings.allowAdminTokenEnrollment !== false;
  $('#min-version').value = settings.minimumClientVersion || '';
  const primary = $('#primary-device');
  primary.replaceChildren(new Option('Select automatically', ''));
  for (const device of state.devices.filter(item => !item.revoked)) primary.append(new Option(`${device.name} (${device.id.slice(0, 8)})`, device.id));
  primary.value = settings.primaryDeviceId || '';
}

function renderSettingsHint(settings) {
  const versions = state.devices.filter(device => !device.revoked && device.clientVersion).map(device => device.clientVersion);
  const newest = versions.reduce((best, version) => !best || versionAtLeast(version, best) ? version : best, '');
  const outdated = settings.minimumClientVersion ? state.devices.filter(device => !device.revoked && !(device.clientVersion && versionAtLeast(device.clientVersion, settings.minimumClientVersion))).length : 0;
  $('#min-version-hint').textContent = `Older browsers stop syncing and can only download the update through the proxy. Browsers 1.6 and newer install it and restart on their own.${newest ? ` Newest version in use: ${newest}.` : ''}${outdated ? ` ${outdated} browser(s) still need to update.` : ''}`;
}

function renderProxyForm(settings) {
  const proxy = settings.proxy || {};
  $('#proxy-enabled').checked = proxy.enabled === true;
  $('#proxy-host').value = proxy.host || '127.0.0.1';
  $('#proxy-port').value = proxy.port || 8899;
  $('#proxy-ports').value = proxy.allowedPorts || '80,443';
  $('#proxy-bypass').value = proxy.bypassList || '';
  $('#proxy-tls').checked = proxy.tls === true;
  $('#network-policy').value = settings.networkPolicy || 'strict';
  $('#ip-check-url').value = settings.ipCheckUrl || '';
  $('#egress-family').value = proxy.egressAddressFamily || 'any';
  $('#egress-source').value = proxy.egressSourceAddress || '';
  $('#limit-connections').value = proxy.maxConnectionsPerDevice || '';
  $('#limit-quota').value = proxy.monthlyQuotaGb || '';
  $('#limit-rate').value = proxy.rateLimitMbps || '';
  $('#record-destinations').checked = proxy.recordDestinations !== false;
  updatePolicyWarning();
}

function renderStatusOnly(settings) {
  const proxy = settings.proxy || {};
  const runtime = state.proxy || {};
  const lock = settings.clientLock || {};
  $('#lock-state').textContent = lock.enabled ? 'On' : 'Off';
  $('#lock-state').className = lock.enabled ? 'badge' : 'badge off';
  $('#lock-code').placeholder = lock.hash ? 'Leave empty to keep the current code' : 'Choose an unlock code';
  $('#lock-hint').textContent = `4 to 128 characters. Only a hash is stored; the code itself cannot be shown again.${lock.changedAt ? ` Last changed ${new Date(lock.changedAt).toLocaleString()}.` : ''}`;
  $('#proxy-fingerprint').textContent = proxy.tls && proxy.certificateSha256
    ? `Certificate SHA-256 (${runtime.certificateSource === 'operator' ? 'operator supplied' : 'generated by the server'}): ${proxy.certificateSha256.match(/.{1,2}/g).join(':')}`
    : '';
  $('#proxy-state').textContent = runtime.listening ? 'Running' : proxy.enabled ? 'Starting' : 'Disabled';
  $('#proxy-runtime').textContent = runtime.listening ? 'Listening' : 'Stopped';
  $('#proxy-runtime').className = runtime.listening ? 'badge' : 'badge off';
  $('#proxy-details').textContent = runtime.listening
    ? `${runtime.bindAddress}:${runtime.port} · ${runtime.activeConnections} active · ${runtime.totalConnections} total connection(s)`
    : runtime.lastError || 'Each enrolled browser authenticates with its own device token.';

  renderDevices();
  // Forget selections for profiles that no longer exist (deleted elsewhere or by a restore).
  const existing = new Set(state.profiles.map(profile => profile.id));
  for (const id of [...selectedProfiles]) if (!existing.has(id)) selectedProfiles.delete(id);
  renderProfiles();
  updateBulkBar();
  if (untouched('#bookmarks-form')) renderBookmarks();
  renderCodes();
  renderAnnouncements();
  renderBackups();
  renderAudit();
}

const POLICY_MIN_VERSION = '1.3.0';
const LOCK_MIN_VERSION = '1.5.0';

function versionAtLeast(version, minimum) {
  const parse = value => String(value || '0').split('-')[0].split('.').map(part => Number(part) || 0);
  const [a, b] = [parse(version), parse(minimum)];
  for (let index = 0; index < 3; index++) if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) > (b[index] || 0);
  return true;
}

function updatePolicyWarning() {
  $('#policy-warning').hidden = $('#network-policy').value === 'choice' || $('#proxy-enabled').checked;
}

// Explains, per browser, whether it follows the required connection mode.
function complianceNote(device) {
  const minimum = state.settings.minimumClientVersion;
  if (minimum && !device.revoked && !(device.clientVersion && versionAtLeast(device.clientVersion, minimum))) {
    return `<span class="pill warn" title="Below the minimum browser version ${minimum}: cannot sync until it updates">UPDATE REQUIRED</span>`;
  }
  if (state.settings.clientLock?.enabled && !device.revoked && !(device.clientVersion && versionAtLeast(device.clientVersion, LOCK_MIN_VERSION))) {
    return `<span class="pill warn" title="Browsers before ${LOCK_MIN_VERSION} do not ask for the unlock code">UPDATE NEEDED</span>`;
  }
  const policy = state.settings.networkPolicy || 'strict';
  if (policy === 'choice' || device.revoked) return '';
  if (!device.clientVersion || !versionAtLeast(device.clientVersion, POLICY_MIN_VERSION)) return `<span class="pill warn" title="Browsers before ${POLICY_MIN_VERSION} ignore the required connection mode">UPDATE NEEDED</span>`;
  const ok = policy === 'strict' ? device.networkMode === 'strict' : device.networkMode === 'managed' || device.networkMode === 'strict';
  return ok ? '' : '<span class="pill warn" title="Not yet reported in the required mode">PENDING</span>';
}

function usageCell(device) {
  const usage = device.usage || {};
  const total = (usage.bytesUp || 0) + (usage.bytesDown || 0);
  const quota = usage.quotaBytes || 0;
  const percent = quota ? Math.min(100, Math.round(total / quota * 100)) : 0;
  const limits = usage.limits || {};
  const limitText = [
    limits.maxConnections ? `max ${limits.maxConnections} open` : '',
    limits.rateLimitMbps ? `${limits.rateLimitMbps} Mbps` : ''
  ].filter(Boolean).join(' · ');
  const hosts = (usage.topHosts || []).map(entry => `<li>${esc(entry.host)} <small>${esc(formatBytes(entry.bytes))} · ${entry.connections} conn.</small></li>`).join('');
  return `<div class="usage"><span>↑ ${esc(formatBytes(usage.bytesUp || 0))} · ↓ ${esc(formatBytes(usage.bytesDown || 0))}</span>`
    + `<small>${usage.activeConnections || 0} open now · ${usage.connections || 0} this month${limitText ? ` · ${esc(limitText)}` : ''}</small>`
    + (quota ? `<div class="meter${percent >= 100 ? ' full' : ''}" title="${percent}% of ${esc(formatBytes(quota))}"><span style="width:${percent}%"></span></div><small>${percent}% of ${esc(formatBytes(quota))}</small>` : '')
    + (hosts ? `<details><summary>Top sites</summary><ol>${hosts}</ol></details>` : '')
    + '</div>';
}

function renderDevices() {
  const body = $('#devices');
  body.replaceChildren();
  if (!state.devices.length) {
    body.innerHTML = '<tr><td colspan="9" class="empty">No browsers enrolled</td></tr>';
    paginate('devices', [], null);
    return;
  }
  const modes = { direct: 'Direct', managed: 'Managed', strict: 'Strict' };
  for (const device of paginate('devices', state.devices, device => `${device.name} ${device.id} ${device.clientVersion} ${device.networkMode}`)) {
    const row = document.createElement('tr');
    row.innerHTML = `<td>${esc(device.name)}${device.primary ? '<span class="pill">PRIMARY</span>' : ''}<br><code>${esc(device.id.slice(0, 12))}…</code></td>`
      + `<td>${device.clientVersion ? `v${esc(device.clientVersion)}` : '<small>unknown</small>'}${device.networkMode ? ` <span class="pill mode">${esc(modes[device.networkMode] || device.networkMode)}</span>` : ''} ${complianceNote(device)}</td>`
      + `<td title="${esc(device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : '')}">${device.live ? '<span class="pill">LIVE</span> ' : ''}${esc(device.live ? 'Connected' : relativeTime(device.lastSeenAt))}</td>`
      + `<td>${usageCell(device)}</td>`
      + `<td>${device.revoked ? 'Revoked' : 'Active'}</td>`
      + `<td><button class="${device.revoked ? 'secondary' : 'danger'} toggle">${device.revoked ? 'Restore' : 'Revoke'}</button></td>`
      + '<td><button class="secondary limits" title="Proxy limits for this browser">Limits</button></td>'
      + '<td><button class="secondary actions-button" title="Settings and actions for this browser">Manage</button></td>'
      + '<td><button class="ghost delete" title="Remove this browser from the list">Delete</button></td>';
    row.querySelector('.toggle').onclick = async () => {
      if (!device.revoked && !confirm(`Revoke ${device.name}? It can no longer sync or use the proxy, and its open proxy connections are closed.`)) return;
      try {
        await api(`/devices/${device.id}/${device.revoked ? 'restore' : 'revoke'}`, { method: 'POST', body: '{}' });
        await load();
        toast('Device status updated');
      } catch (error) { toast(error.message, true); }
    };
    row.querySelector('.delete').onclick = async () => {
      if (!confirm(`Delete ${device.name}? The browser must be enrolled again with a new enrollment code to reconnect.`)) return;
      try {
        await api(`/devices/${device.id}`, { method: 'DELETE' });
        await load();
        toast('Device deleted');
      } catch (error) { toast(error.message, true); }
    };
    row.querySelector('.limits').onclick = () => toggleLimitsEditor(row, device);
    row.querySelector('.actions-button').onclick = () => toggleDevicePanel(row, device);
    if (device.pendingCommands?.length) row.children[4].insertAdjacentHTML('beforeend', `<br><span class="pending">${device.pendingCommands.length} action(s) waiting</span>`);
    body.append(row);
  }
}

const COMMAND_LABELS = { lock: 'Lock now', 'close-tabs': 'Close all tabs', 'clear-site': 'Clear cookies for a site', restart: 'Restart browser', 'open-url': 'Open a page', 'switch-account': 'Switch account' };

function toggleDevicePanel(row, device) {
  if (row.nextElementSibling?.classList.contains('device-row')) {
    row.nextElementSibling.remove();
    return;
  }
  const filter = device.siteFilter;
  const panel = document.createElement('tr');
  panel.className = 'limits-row device-row';
  panel.innerHTML = `<td colspan="9"><div class="device-panel">
    <strong>Actions for ${esc(device.name)}</strong>
    <div class="buttons">
      <button type="button" class="secondary" data-command="lock"${state.settings.clientLock?.enabled ? '' : ' disabled title="Turn on the unlock code first"'}>Lock now</button>
      <button type="button" class="secondary" data-command="close-tabs">Close all tabs</button>
      <button type="button" class="secondary" data-command="restart">Restart browser</button>
      <label>Page to open<input name="openUrl" type="url" placeholder="https://example.com/"></label><button type="button" class="secondary" data-command="open-url">Open</button>
      <label>Site<input name="clearSite" placeholder="github.com"></label><button type="button" class="danger" data-command="clear-site">Clear cookies</button>
    </div>
    ${(device.accounts || []).length ? `<div class="account-pick"><strong>Accounts</strong>${device.accounts.map(site => `<label>${esc(site.domain)}<select data-site="${esc(site.domain)}">${site.options.map(option => `<option value="${esc(option.id)}"${option.id === site.activeId ? ' selected' : ''}>${esc(option.name)}</option>`).join('')}</select></label><button type="button" class="secondary" data-switch="${esc(site.domain)}">Switch</button>`).join('')}</div>` : ''}
    <div class="pending">${(device.pendingCommands || []).map(command => `${esc(COMMAND_LABELS[command.type] || command.type)}${command.argument ? ` (${esc(command.argument)})` : ''} — waiting <button type="button" class="ghost" data-cancel="${esc(command.id)}">Cancel</button>`).join('<br>')}</div>
    <form class="limits-form device-settings"><strong>Settings for this browser</strong>
      <label>Home page<input name="homePage" type="url" placeholder="Shared home page"></label>
      <label>Site filter<select name="filterMode"><option value="">Same as all browsers</option><option value="off">Any site</option><option value="allow">Only the sites listed</option><option value="block">Every site except those listed</option></select></label>
      <label>Sites<input name="filterDomains" placeholder="github.com, gitlab.com"></label>
      <label class="check"><input name="scheduleExempt" type="checkbox">Can be used outside the allowed hours</label>
      <button>Save settings</button><button type="button" class="ghost cancel">Close</button>
    </form>
    <small class="hint">Actions run the next time the browser connects (within a second or two when it is online), once. Clearing cookies on the primary browser also removes that site's session from the vault.</small>
  </div></td>`;
  const form = panel.querySelector('form');
  form.elements.homePage.value = device.homePage || '';
  form.elements.filterMode.value = filter ? filter.mode : '';
  form.elements.filterDomains.value = filter ? filter.domains.join(', ') : '';
  form.elements.scheduleExempt.checked = device.scheduleExempt === true;
  form.querySelector('.cancel').onclick = () => panel.remove();
  form.onsubmit = async event => {
    event.preventDefault();
    const mode = form.elements.filterMode.value;
    try {
      await api(`/devices/${device.id}/settings`, {
        method: 'PUT',
        body: JSON.stringify({ homePage: form.elements.homePage.value, siteFilter: mode ? { mode, domains: lines(form.elements.filterDomains.value) } : null, scheduleExempt: form.elements.scheduleExempt.checked })
      });
      await load();
      toast(`Settings saved for ${device.name}`);
    } catch (error) { toast(error.message, true); }
  };
  for (const button of panel.querySelectorAll('[data-command]')) {
    button.onclick = async () => {
      const type = button.dataset.command;
      const argument = type === 'open-url' ? panel.querySelector('[name=openUrl]').value : type === 'clear-site' ? panel.querySelector('[name=clearSite]').value : '';
      if ((type === 'restart' || type === 'close-tabs' || type === 'clear-site') && !confirm(`${COMMAND_LABELS[type]} on ${device.name}?`)) return;
      try {
        await api(`/devices/${device.id}/commands`, { method: 'POST', body: JSON.stringify({ type, argument }) });
        await load();
        toast(`${COMMAND_LABELS[type]} sent to ${device.name}`);
      } catch (error) { toast(error.message, true); }
    };
  }
  for (const button of panel.querySelectorAll('[data-switch]')) {
    button.onclick = async () => {
      const select = panel.querySelector(`select[data-site="${CSS.escape(button.dataset.switch)}"]`);
      const name = select.selectedOptions[0]?.textContent;
      try {
        await api(`/devices/${device.id}/commands`, { method: 'POST', body: JSON.stringify({ type: 'switch-account', argument: select.value }) });
        await load();
        toast(`${device.name} switches ${button.dataset.switch} to ${name}`);
      } catch (error) { toast(error.message, true); }
    };
  }
  for (const button of panel.querySelectorAll('[data-cancel]')) {
    button.onclick = async () => {
      try {
        await api(`/devices/${device.id}/commands/${button.dataset.cancel}`, { method: 'DELETE' });
        await load();
        toast('Action cancelled');
      } catch (error) { toast(error.message, true); }
    };
  }
  row.after(panel);
}

function toggleLimitsEditor(row, device) {
  if (row.nextElementSibling?.classList.contains('limits-row')) {
    row.nextElementSibling.remove();
    return;
  }
  const proxy = state.settings.proxy || {};
  const overrides = device.limitOverrides || {};
  const fallback = value => value ? String(value) : 'unlimited';
  const editor = document.createElement('tr');
  editor.className = 'limits-row';
  editor.innerHTML = `<td colspan="9"><form class="limits-form"><label>Open connections<input name="maxConnections" type="number" min="0" step="1" placeholder="default (${esc(fallback(proxy.maxConnectionsPerDevice))})"></label>`
    + `<label>Data per month (GB)<input name="monthlyQuotaGb" type="number" min="0" step="0.1" placeholder="default (${esc(fallback(proxy.monthlyQuotaGb))})"></label>`
    + `<label>Speed (Mbps)<input name="rateLimitMbps" type="number" min="0" step="0.1" placeholder="default (${esc(fallback(proxy.rateLimitMbps))})"></label>`
    + '<button>Save limits</button><button type="button" class="ghost cancel">Close</button><small class="hint">Empty uses the default; 0 means unlimited for this browser.</small></form></td>';
  const form = editor.querySelector('form');
  for (const name of ['maxConnections', 'monthlyQuotaGb', 'rateLimitMbps']) form.elements[name].value = overrides[name] ?? '';
  form.querySelector('.cancel').onclick = () => editor.remove();
  form.onsubmit = async event => {
    event.preventDefault();
    const value = name => form.elements[name].value === '' ? null : Number(form.elements[name].value);
    try {
      await api(`/devices/${device.id}/limits`, { method: 'PUT', body: JSON.stringify({ maxConnections: value('maxConnections'), monthlyQuotaGb: value('monthlyQuotaGb'), rateLimitMbps: value('rateLimitMbps') }) });
      await load();
      toast(`Limits saved for ${device.name}`);
    } catch (error) { toast(error.message, true); }
  };
  row.after(editor);
}

function healthBadge(profile) {
  const health = profile.health || {};
  if (!profile.enabled) return '';
  const days = health.expiresAt ? (Date.parse(health.expiresAt) - Date.now()) / 86400000 : null;
  const left = days === null ? '' : days >= 1 ? `${Math.floor(days)} d` : `${Math.max(0, Math.round(days * 24))} h`;
  const text = {
    ok: health.expiresAt ? `signed in · ${left} left` : 'signed in',
    expiring: `expires in ${left}`,
    'signed-out': 'signed out',
    empty: 'no cookies'
  }[health.state];
  return text ? ` · <em class="health ${esc(health.state)}" title="${esc(health.expiresAt ? `Sign-in expires ${new Date(health.expiresAt).toLocaleString()}` : '')}">${esc(text)}</em>` : '';
}

function renderProfiles() {
  const container = $('#profiles');
  container.replaceChildren();
  if (!state.profiles.length) {
    container.innerHTML = '<p class="empty">No shared profiles yet.</p>';
    paginate('profiles', [], null);
    return;
  }
  // Accounts of the same site sit together, in the order browsers fall back to them.
  const order = new Map(state.profiles.map((profile, index) => [profile.id, index]));
  const sorted = [...state.profiles].sort((a, b) => a.domain.localeCompare(b.domain) || order.get(a.id) - order.get(b.id));
  for (const profile of paginate('profiles', sorted, profile => `${profile.domain} ${profile.name} ${(profile.usedBy || []).join(' ')}`, 20)) {
    const element = document.createElement('div');
    element.className = `profile${selectedProfiles.has(profile.id) ? ' selected' : ''}`;
    element.innerHTML = `<label class="pick"><input type="checkbox" aria-label="Select ${esc(profile.domain)}"${selectedProfiles.has(profile.id) ? ' checked' : ''}><div><strong>${profile.enabled ? '●' : '○'} ${esc(profile.name)}</strong><span>${esc(profile.domain)} · ${profile.cookieCount} cookie(s)${profile.enabled ? '' : ' · disabled'}${profile.listed === false ? ' · <em class="unlisted" title="Not on the list of shared sites: the primary browser no longer updates it">not on the sharing list</em>' : ''}${healthBadge(profile)}${profile.accounts > 1 ? ` · account of ${profile.accounts} · ${profile.usedBy?.length ? `used by ${esc(profile.usedBy.join(', '))}` : 'used by no browser'}` : ''}</span></div></label><button class="secondary">Edit</button>`;
    element.querySelector('input').onchange = event => {
      if (event.target.checked) selectedProfiles.add(profile.id); else selectedProfiles.delete(profile.id);
      element.classList.toggle('selected', event.target.checked);
      updateBulkBar();
    };
    element.querySelector('button').onclick = () => edit(profile);
    container.append(element);
  }
}

function updateBulkBar() {
  const total = state?.profiles.length || 0;
  const count = selectedProfiles.size;
  const button = $('#delete-selected');
  button.disabled = count === 0;
  button.textContent = count ? `Delete selected (${count})` : 'Delete selected';
  $('#purge-profiles').disabled = total === 0;
  $('#select-unlisted').hidden = !state?.profiles.some(profile => profile.listed === false);
  const all = $('#select-all-profiles');
  all.disabled = total === 0;
  all.checked = total > 0 && count === total;
  all.indeterminate = count > 0 && count < total;
}

async function deleteProfiles(ids) {
  const result = await api('/profiles/delete', { method: 'POST', body: JSON.stringify({ ids }) });
  for (const id of ids) selectedProfiles.delete(id);
  return result;
}

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const lines = value => value.split(/[\s,]+/).filter(Boolean);

function renderNotifications() {
  const notify = state.notifications || {};
  $('#notify-discord').value = notify.discordWebhookUrl || '';
  $('#notify-telegram-token').value = notify.telegramBotToken || '';
  $('#notify-telegram-chat').value = notify.telegramChatId || '';
  $('#notify-line-token').value = notify.lineChannelToken || '';
  $('#notify-line-to').value = notify.lineTo || '';
  $('#notify-offline').value = notify.offlineMinutes || 30;
  $('#notify-expiry').value = notify.expiryWarningDays || 3;
  const enabled = new Set(notify.events || []);
  const groups = new Map();
  for (const kind of notify.catalog || []) {
    if (!groups.has(kind.group)) groups.set(kind.group, []);
    groups.get(kind.group).push(kind);
  }
  $('#notify-events').replaceChildren(...[...groups].map(([group, kinds]) => {
    const box = document.createElement('div');
    box.className = 'event-group';
    box.innerHTML = `<strong>${esc(group)}</strong>` + kinds.map(kind => `<label class="check"><input type="checkbox" value="${esc(kind.key)}"${enabled.has(kind.key) ? ' checked' : ''}>${esc(kind.title)}</label>`).join('');
    return box;
  }));
}

function renderControls() {
  const settings = state.settings;
  const filter = settings.siteFilter || { mode: 'off', domains: [] };
  $('#filter-mode').value = filter.mode;
  $('#filter-domains').value = (filter.domains || []).join('\n');
  const schedule = settings.schedule || {};
  $('#schedule-enabled').checked = schedule.enabled === true;
  $('#schedule-start').value = schedule.start || '09:00';
  $('#schedule-end').value = schedule.end || '18:00';
  $('#schedule-zone').value = schedule.timeZone || 'Asia/Bangkok';
  const days = new Set(schedule.days || [1, 2, 3, 4, 5]);
  $('#schedule-days').replaceChildren(...DAY_NAMES.map((name, index) => {
    const label = document.createElement('label');
    label.className = 'check';
    label.innerHTML = `<input type="checkbox" value="${index}"${days.has(index) ? ' checked' : ''}>${name}`;
    return label;
  }));
  const controls = settings.dataControls || {};
  $('#block-downloads').checked = controls.blockDownloads === true;
  $('#block-uploads').checked = controls.blockUploads === true;
  $('#block-copy').checked = controls.blockCopy === true;
  $('#block-domains').value = (controls.domains || []).join('\n');
}

function renderOffsite() {
  const offsite = state.offsiteBackup || {};
  $('#offsite-enabled').checked = offsite.enabled === true;
  $('#offsite-endpoint').value = offsite.endpoint || '';
  $('#offsite-region').value = offsite.region || '';
  $('#offsite-bucket').value = offsite.bucket || '';
  $('#offsite-prefix').value = offsite.prefix ?? 'shared-browser/';
  $('#offsite-key').value = offsite.accessKeyId || '';
  $('#offsite-secret').value = offsite.secretAccessKey || '';
  $('#offsite-status').textContent = offsite.lastError
    ? `Last upload failed: ${offsite.lastError}`
    : offsite.lastUploadAt ? `Last uploaded ${offsite.lastUploadName} on ${new Date(offsite.lastUploadAt).toLocaleString()}.` : offsite.enabled ? 'Nothing uploaded yet.' : '';
  $('#offsite-status').className = offsite.lastError ? 'warning-text' : 'hint';
}

function controlsPayload() {
  return {
    siteFilter: { mode: $('#filter-mode').value, domains: lines($('#filter-domains').value) },
    schedule: {
      enabled: $('#schedule-enabled').checked,
      days: [...document.querySelectorAll('#schedule-days input:checked')].map(input => Number(input.value)),
      start: $('#schedule-start').value,
      end: $('#schedule-end').value,
      timeZone: $('#schedule-zone').value.trim()
    },
    dataControls: { blockDownloads: $('#block-downloads').checked, blockUploads: $('#block-uploads').checked, blockCopy: $('#block-copy').checked, domains: lines($('#block-domains').value) }
  };
}

function updateShareSites() {
  $('#auto-share-sites').hidden = $('#auto-share-mode').value !== 'listed';
}

function settingsPayload(proxy) {
  return {
    homePage: $('#home-page').value,
    searchUrl: $('#search-url').value,
    primaryDeviceId: $('#primary-device').value,
    autoShareCookies: $('#auto-share-mode').value !== 'off',
    autoShareScope: $('#auto-share-mode').value === 'listed' ? 'listed' : 'all',
    autoShareDomains: $('#auto-share-domains').value.split(/[\s,]+/).filter(Boolean),
    allowAdminTokenEnrollment: $('#allow-admin-enroll').checked,
    minimumClientVersion: $('#min-version').value.trim(),
    networkPolicy: $('#network-policy').value,
    ipCheckUrl: $('#ip-check-url').value,
    ...controlsPayload(),
    proxy: proxy || state.settings.proxy
  };
}

function cookieMeta(cookie) {
  const parts = [];
  if (cookie.expiresAt) parts.push(`expires ${new Date(cookie.expiresAt * 1000).toLocaleString()}`);
  else if (cookie.name) parts.push('session cookie');
  if (cookie.sourceDeviceId === 'admin') parts.push('added in dashboard');
  else if (cookie.sourceDeviceId) {
    const device = state.devices.find(item => item.id === cookie.sourceDeviceId);
    parts.push(`from ${device ? device.name : cookie.sourceDeviceId.slice(0, 8)}`);
  }
  if (cookie.updatedAt) parts.push(`updated ${relativeTime(cookie.updatedAt)}`);
  return parts.join(' · ');
}

function cookieRow(cookie = {}) {
  const row = $('#cookie-template').content.firstElementChild.cloneNode(true);
  row.querySelector('.cookie-name').value = cookie.name || '';
  row.querySelector('.cookie-value').placeholder = cookie.hasValue ? 'Unchanged — type to replace' : 'Secret value';
  row.querySelector('.cookie-domain').value = cookie.domain || '';
  row.querySelector('.cookie-path').value = cookie.path || '/';
  row.querySelector('.cookie-secure').checked = cookie.secure !== false;
  row.querySelector('.cookie-http').checked = cookie.httpOnly !== false;
  row.querySelector('.cookie-same').value = cookie.sameSite || 'Lax';
  row.querySelector('.cookie-meta').textContent = cookieMeta(cookie);
  row.dataset.stored = cookie.hasValue ? 'true' : '';
  row.querySelector('.remove').onclick = () => row.remove();
  return row;
}

function edit(profile = null) {
  $('#editor').hidden = false;
  $('#editor-title').textContent = profile ? 'Edit profile' : 'New profile';
  $('#profile-id').value = profile?.id || '';
  $('#profile-name').value = profile?.name || '';
  $('#profile-domain').value = profile?.domain || '';
  $('#profile-session-cookie').value = profile?.sessionCookie || '';
  $('#profile-enabled').checked = profile?.enabled !== false;
  $('#delete-profile').hidden = !profile;
  const shareAll = profile?.shareWithAllDevices !== false;
  $('#share-all').checked = shareAll;
  $('#share-some').checked = !shareAll;
  const allowed = new Set(profile?.allowedDeviceIds || []);
  $('#share-devices').replaceChildren(...state.devices.map(device => {
    const label = document.createElement('label');
    label.className = 'check';
    label.innerHTML = `<input type="checkbox" value="${esc(device.id)}"${allowed.has(device.id) ? ' checked' : ''}>${esc(device.name)}${device.revoked ? ' (revoked)' : ''}`;
    return label;
  }));
  updateShareDevices();
  $('#cookies').replaceChildren(...(profile?.cookies?.length ? profile.cookies : [{}]).map(cookieRow));
  $('#editor').scrollIntoView({ behavior: 'smooth' });
}

function bookmarkRow(bookmark = {}) {
  const row = $('#bookmark-template').content.firstElementChild.cloneNode(true);
  row.querySelector('.bookmark-title').value = bookmark.title || '';
  row.querySelector('.bookmark-folder').value = bookmark.folder || '';
  row.querySelector('.bookmark-url').value = bookmark.url || '';
  row.querySelector('.remove').onclick = () => row.remove();
  row.querySelector('.move-up').onclick = () => { if (row.previousElementSibling) row.parentElement.insertBefore(row, row.previousElementSibling); };
  return row;
}

function renderAnnouncementDevices() {
  const container = $('#announcement-devices');
  const selected = new Set([...container.querySelectorAll('input:checked')].map(input => input.value));
  container.replaceChildren(...state.devices.filter(device => !device.revoked).map(device => {
    const label = document.createElement('label');
    label.className = 'check';
    label.innerHTML = `<input type="checkbox" value="${esc(device.id)}"${selected.has(device.id) ? ' checked' : ''}>${esc(device.name)}`;
    return label;
  }));
  updateAnnouncementDevices();
}

function updateAnnouncementDevices() {
  const some = $('#announcement-some').checked;
  for (const input of document.querySelectorAll('#announcement-devices input')) input.disabled = !some;
  $('#announcement-devices').style.opacity = some ? '1' : '.5';
}

function renderAnnouncements() {
  renderAnnouncementDevices();
  const container = $('#announcements');
  container.replaceChildren(...paginate('announcements', state.announcements || [], null, 10).map(item => {
    const element = document.createElement('article');
    element.className = `announcement ${item.level}${item.expired ? ' expired' : ''}${item.pinned ? ' pinned' : ''}`;
    const audience = item.shareWithAllDevices ? 'all browsers' : item.recipients.join(', ') || 'no active browsers';
    const read = item.acknowledgedBy.map(entry => entry.name);
    const expiry = item.expired ? 'expired' : item.expiresAt ? `expires ${relativeFuture(item.expiresAt)}` : 'no expiry';
    element.innerHTML = `<header><div>${item.pinned ? '<span class="pin-mark" title="Pinned">📌</span>' : ''}<span class="level ${esc(item.level)}">${esc(item.level.toUpperCase())}</span><strong></strong></div><div class="actions"><button class="secondary pin" type="button">${item.pinned ? 'Unpin' : 'Pin'}</button><button class="ghost delete" type="button">Delete</button></div></header>`
      + `<p></p>${item.url ? `<small>Link: <a target="_blank" rel="noopener noreferrer"></a></small>` : ''}`
      + `<small>Sent ${esc(relativeTime(item.createdAt))} to ${esc(audience)} · ${esc(expiry)} · ${item.pinned ? 'pinned: cannot be dismissed' : `dismissed by ${read.length} of ${item.recipients.length}${read.length ? ` (${esc(read.join(', '))})` : ''}`}</small>`;
    element.querySelector('strong').textContent = item.title || '(no title)';
    element.querySelector('p').textContent = item.message;
    const link = element.querySelector('a');
    if (link) { link.href = item.url; link.textContent = item.url; }
    element.querySelector('.pin').onclick = async () => {
      try {
        await api(`/announcements/${item.id}/pin`, { method: 'PUT', body: JSON.stringify({ pinned: !item.pinned }) });
        await load();
        toast(item.pinned ? 'Announcement unpinned: browsers can dismiss it again' : 'Announcement pinned: browsers always show it');
      } catch (error) { toast(error.message, true); }
    };
    element.querySelector('.delete').onclick = async () => {
      if (!confirm('Delete this announcement? Browsers remove its banner.')) return;
      try {
        await api(`/announcements/${item.id}`, { method: 'DELETE' });
        await load();
        toast('Announcement deleted');
      } catch (error) { toast(error.message, true); }
    };
    return element;
  }));
  if (!container.children.length) container.innerHTML = '<p class="empty">No announcements yet.</p>';
}

function updateShareDevices() {
  const some = $('#share-some').checked;
  for (const input of document.querySelectorAll('#share-devices input')) input.disabled = !some;
  $('#share-devices').style.opacity = some ? '1' : '.5';
}

function renderCodes() {
  const container = $('#codes');
  const now = Date.now();
  // Show active codes, plus codes used or revoked in the last day so a new enrollment is easy to confirm.
  const codes = (state.enrollmentCodes || []).filter(code => code.active || now - new Date(code.usedAt || code.createdAt).getTime() < 86400000);
  container.replaceChildren(...codes.map(code => {
    const row = document.createElement('div');
    row.className = 'code-row';
    const status = code.active ? `expires ${relativeFuture(code.expiresAt)}`
      : code.usedAt ? `used by ${esc(code.usedBy || 'a browser')} ${esc(relativeTime(code.usedAt))}`
      : code.revoked ? 'revoked' : 'expired';
    row.innerHTML = `<div>${esc(code.label || 'Enrollment code')}<small>${status}</small></div>${code.active ? '<button class="ghost">Revoke</button>' : ''}`;
    row.querySelector('button')?.addEventListener('click', async () => {
      try {
        await api(`/enrollment-codes/${code.id}`, { method: 'DELETE' });
        await load();
        toast('Enrollment code revoked');
      } catch (error) { toast(error.message, true); }
    });
    return row;
  }));
}

function relativeFuture(value) {
  const minutes = Math.round((new Date(value).getTime() - Date.now()) / 60000);
  if (minutes < 1) return 'in under a minute';
  if (minutes < 120) return `in ${minutes} min`;
  if (minutes < 2880) return `in ${Math.round(minutes / 60)} h`;
  return `in ${Math.round(minutes / 1440)} days`;
}

// Decimal units, matching the monthly quota, which is set in GB.
function formatBytes(value) {
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let size = value;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) { size /= 1000; unit++; }
  return unit === 0 ? `${size} B` : `${size.toFixed(size < 10 ? 2 : 1)} ${units[unit]}`;
}

function renderBackups() {
  const body = $('#backups');
  body.replaceChildren();
  const policy = state.backupPolicy;
  if (policy) {
    const oldest = state.backups?.length ? new Date(state.backups[state.backups.length - 1].createdAt).toLocaleString() : '';
    $('#backup-policy').textContent = `Keeps the newest ${policy.keep} backups and deletes older ones automatically. An automatic backup is saved at most every ${policy.intervalMinutes} minutes while the vault changes, so a quiet vault keeps backups for longer.${oldest ? ` Oldest kept: ${oldest}.` : ''} Change with SHARED_BROWSER_BACKUP_KEEP and SHARED_BROWSER_BACKUP_INTERVAL_MINUTES.`;
  }
  if (!state.backups?.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No backups yet</td></tr>';
    paginate('backups', [], null);
    selectedBackups.clear();
    updateBackupBar();
    return;
  }
  const existing = new Set(state.backups.map(backup => backup.name));
  for (const name of [...selectedBackups]) if (!existing.has(name)) selectedBackups.delete(name);
  for (const backup of paginate('backups', state.backups, null, 20)) {
    const row = document.createElement('tr');
    row.innerHTML = `<td><input type="checkbox" class="pick-backup" aria-label="Select ${esc(backup.name)}"${selectedBackups.has(backup.name) ? ' checked' : ''}></td><td><code>${esc(backup.name)}</code></td><td>${esc(new Date(backup.createdAt).toLocaleString())}</td><td>${esc(formatBytes(backup.size))}</td><td class="actions"><button class="secondary">Restore</button><button class="danger">Delete</button></td>`;
    row.querySelector('.pick-backup').onchange = event => {
      if (event.target.checked) selectedBackups.add(backup.name); else selectedBackups.delete(backup.name);
      updateBackupBar();
    };
    row.querySelector('.danger').onclick = async () => {
      if (!confirm(`Delete ${backup.name}? It cannot be restored afterwards.`)) return;
      try {
        await api(`/backups/${encodeURIComponent(backup.name)}`, { method: 'DELETE' });
        await load();
        toast(`Deleted ${backup.name}`);
      } catch (error) { toast(error.message, true); }
    };
    row.querySelector('.secondary').onclick = async () => {
      if (!confirm(`Restore ${backup.name}? The current vault is backed up first, then replaced. Browsers pick up the restored vault on their next sync.`)) return;
      try {
        const result = await api(`/backups/${encodeURIComponent(backup.name)}/restore`, { method: 'POST', body: '{}' });
        await load();
        toast(`Restored — ${result.result}`);
      } catch (error) { toast(error.message, true); }
    };
    body.append(row);
  }
  updateBackupBar();
}

const selectedBackups = new Set();

function updateBackupBar() {
  const total = state?.backups?.length || 0;
  const count = selectedBackups.size;
  $('#delete-backups').disabled = count === 0;
  $('#delete-backups').textContent = count ? `Delete selected (${count})` : 'Delete selected';
  $('#purge-backups').disabled = total === 0;
  const all = $('#select-all-backups');
  all.disabled = total === 0;
  all.checked = total > 0 && count === total;
  all.indeterminate = count > 0 && count < total;
}

// ---- Pagination ----
// Long lists show one page at a time; the page, page size and search survive the automatic refresh.
const pagers = {};

function paginate(key, items, match, defaultSize = 20) {
  const pager = pagers[key] ||= { page: 1, size: defaultSize, query: '' };
  const query = pager.query.trim().toLowerCase();
  const filtered = query && match ? items.filter(item => match(item).toLowerCase().includes(query)) : items;
  const pages = Math.max(1, Math.ceil(filtered.length / pager.size));
  pager.page = Math.min(Math.max(1, pager.page), pages);
  const start = (pager.page - 1) * pager.size;
  renderPager(key, filtered.length, items.length, pages);
  return filtered.slice(start, start + pager.size);
}

const pagerRenderers = {};

function renderPager(key, shown, total, pages) {
  const container = $(`#${key}-pager`);
  if (!container) return;
  const pager = pagers[key];
  // The search box is created once so typing in it is never interrupted by a refresh.
  if (container.dataset.search && !container.querySelector('input')) {
    const input = document.createElement('input');
    input.type = 'search';
    input.placeholder = container.dataset.search;
    input.oninput = () => { pager.query = input.value; pager.page = 1; pagerRenderers[key]?.(); };
    container.prepend(input);
  }
  let nav = container.querySelector('.nav');
  if (!nav) {
    nav = document.createElement('div');
    nav.className = 'nav';
    container.append(nav);
  }
  container.hidden = total <= 10 && !pager.query;
  const first = shown ? (pager.page - 1) * pager.size + 1 : 0;
  const last = Math.min(shown, pager.page * pager.size);
  nav.innerHTML = `<span>${first}–${last} of ${shown}${shown !== total ? ` (filtered from ${total})` : ''}</span>`
    + `<button type="button" class="secondary" data-go="first" title="First page"${pager.page <= 1 ? ' disabled' : ''}>«</button>`
    + `<button type="button" class="secondary" data-go="prev" title="Previous page"${pager.page <= 1 ? ' disabled' : ''}>‹</button>`
    + `<span>Page ${pager.page} of ${pages}</span>`
    + `<button type="button" class="secondary" data-go="next" title="Next page"${pager.page >= pages ? ' disabled' : ''}>›</button>`
    + `<button type="button" class="secondary" data-go="last" title="Last page"${pager.page >= pages ? ' disabled' : ''}>»</button>`
    + `<select title="Rows per page">${[10, 20, 50, 100].map(size => `<option value="${size}"${size === pager.size ? ' selected' : ''}>${size} / page</option>`).join('')}</select>`;
  for (const button of nav.querySelectorAll('[data-go]')) {
    button.onclick = () => {
      pager.page = { first: 1, prev: pager.page - 1, next: pager.page + 1, last: pages }[button.dataset.go];
      pagerRenderers[key]?.();
    };
  }
  nav.querySelector('select').onchange = event => { pager.size = Number(event.target.value); pager.page = 1; pagerRenderers[key]?.(); };
}

function renderAudit() {
  const body = $('#audit');
  body.replaceChildren();
  if (!state.audit?.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No activity recorded yet</td></tr>';
    paginate('audit', [], null);
    return;
  }
  for (const entry of paginate('audit', state.audit, entry => `${entry.actor} ${entry.action} ${entry.target} ${entry.details} ${entry.ip}`, 25)) {
    const row = document.createElement('tr');
    row.innerHTML = `<td title="${esc(new Date(entry.at).toLocaleString())}">${esc(relativeTime(entry.at))}</td><td>${esc(entry.actor)}</td><td><code>${esc(entry.action)}</code></td><td>${esc(entry.target)}</td><td class="details">${esc(entry.details)}</td><td>${esc(entry.ip)}</td>`;
    body.append(row);
  }
  if (!body.children.length) body.innerHTML = '<tr><td colspan="6" class="empty">No matching activity</td></tr>';
}

function renderBookmarks() {
  const container = $('#bookmarks');
  container.replaceChildren(...(state.bookmarks || []).map(bookmarkRow));
  if (!container.children.length) container.innerHTML = '<p class="empty">No shared bookmarks yet.</p>';
}

$('#login-form').onsubmit = async event => {
  event.preventDefault();
  token = $('#token').value.trim();
  try {
    await load();
    sessionStorage.setItem('sharedBrowserAdmin', token);
    $('#token').value = '';
    toast('Connected');
  } catch (error) {
    token = '';
    toast(error.message, true);
  }
};

$('#lock-show').onchange = event => { $('#lock-code').type = event.target.checked ? 'text' : 'password'; };
$('#lock-form').onsubmit = async event => {
  event.preventDefault();
  const enabled = $('#lock-enabled').checked;
  const code = $('#lock-code').value.trim();
  if (code && code.length < 4) return toast('The unlock code must be at least 4 characters', true);
  if (enabled && !code && !state.settings.clientLock?.hash) return toast('Enter an unlock code', true);
  try {
    await api('/client-lock', { method: 'PUT', body: JSON.stringify({ enabled, code, idleMinutes: Number($('#lock-idle').value) || 0, lockOnSystemLock: $('#lock-system').checked }) });
    $('#lock-code').value = '';
    await load();
    toast(enabled ? (code ? 'Unlock code saved. Browsers ask for it from now on' : 'Unlock code turned on') : 'Unlock code turned off');
  } catch (error) { toast(error.message, true); }
};

$('#notify-form').onsubmit = async event => {
  event.preventDefault();
  try {
    await api('/notifications', {
      method: 'PUT',
      body: JSON.stringify({
        discordWebhookUrl: $('#notify-discord').value,
        telegramBotToken: $('#notify-telegram-token').value,
        telegramChatId: $('#notify-telegram-chat').value,
        lineChannelToken: $('#notify-line-token').value,
        lineTo: $('#notify-line-to').value,
        events: [...document.querySelectorAll('#notify-events input:checked')].map(input => input.value),
        offlineMinutes: Number($('#notify-offline').value) || 30,
        expiryWarningDays: Number($('#notify-expiry').value) || 3
      })
    });
    await load();
    toast('Notifications saved');
  } catch (error) { toast(error.message, true); }
};

$('#notify-test').onclick = async () => {
  try {
    const result = await api('/notifications/test', { method: 'POST', body: '{}' });
    const failed = result.results.filter(item => !item.ok);
    toast(failed.length ? `Failed: ${failed.map(item => `${item.channel} (${item.error})`).join(', ')}` : `Test sent to ${result.results.map(item => item.channel).join(', ')}`, failed.length > 0);
  } catch (error) { toast(error.message, true); }
};

$('#controls-form').onsubmit = async event => {
  event.preventDefault();
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(settingsPayload()) });
    await load();
    toast('Browsing controls saved');
  } catch (error) { toast(error.message, true); }
};

$('#offsite-form').onsubmit = async event => {
  event.preventDefault();
  if ($('#offsite-enabled').checked && ['#offsite-endpoint', '#offsite-bucket', '#offsite-key', '#offsite-secret'].some(selector => !$(selector).value.trim())) {
    return toast('Enter the endpoint, bucket, access key and secret key', true);
  }
  try {
    await api('/offsite-backup', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: $('#offsite-enabled').checked,
        endpoint: $('#offsite-endpoint').value,
        region: $('#offsite-region').value,
        bucket: $('#offsite-bucket').value,
        prefix: $('#offsite-prefix').value,
        accessKeyId: $('#offsite-key').value,
        secretAccessKey: $('#offsite-secret').value
      })
    });
    await load();
    toast('Offsite backup saved');
  } catch (error) { toast(error.message, true); }
};

$('#offsite-upload').onclick = async () => {
  try {
    const result = await api('/offsite-backup/upload', { method: 'POST', body: '{}' });
    await load();
    toast(`Uploaded ${result.name}`);
  } catch (error) {
    await load().catch(() => { });
    toast(error.message, true);
  }
};

$('#settings-form').onsubmit = async event => {
  event.preventDefault();
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(settingsPayload()) });
    await load();
    toast('Shared settings saved');
  } catch (error) { toast(error.message, true); }
};

$('#proxy-form').onsubmit = async event => {
  event.preventDefault();
  const proxy = {
    enabled: $('#proxy-enabled').checked,
    host: $('#proxy-host').value,
    port: Number($('#proxy-port').value),
    allowedPorts: $('#proxy-ports').value,
    bypassList: $('#proxy-bypass').value,
    tls: $('#proxy-tls').checked,
    egressAddressFamily: $('#egress-family').value,
    egressSourceAddress: $('#egress-source').value,
    maxConnectionsPerDevice: Number($('#limit-connections').value) || 0,
    monthlyQuotaGb: Number($('#limit-quota').value) || 0,
    rateLimitMbps: Number($('#limit-rate').value) || 0,
    recordDestinations: $('#record-destinations').checked
  };
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(settingsPayload(proxy)) });
    await new Promise(resolve => setTimeout(resolve, 900));
    await load();
    toast('Proxy settings saved; browsers apply them automatically');
  } catch (error) { toast(error.message, true); }
};

$('#bookmarks-form').onsubmit = async event => {
  event.preventDefault();
  const bookmarks = [...document.querySelectorAll('.bookmark')].map(row => ({
    title: row.querySelector('.bookmark-title').value,
    folder: row.querySelector('.bookmark-folder').value,
    url: row.querySelector('.bookmark-url').value
  }));
  try {
    await api('/bookmarks', { method: 'PUT', body: JSON.stringify(bookmarks) });
    await load();
    toast('Bookmarks saved');
  } catch (error) { toast(error.message, true); }
};

$('#add-bookmark').onclick = () => {
  const container = $('#bookmarks');
  container.querySelector('.empty')?.remove();
  const row = bookmarkRow();
  container.append(row);
  $('#bookmarks-form').dataset.dirty = 'true';
  row.querySelector('.bookmark-url').focus();
};

$('#refresh').onclick = () => load().catch(error => toast(error.message, true));
$('#network-policy').onchange = updatePolicyWarning;
$('#proxy-enabled').onchange = updatePolicyWarning;

$('#check-egress').onclick = async () => {
  const output = $('#egress-result');
  output.textContent = 'Checking…';
  try {
    const result = await api('/egress-ip', { method: 'POST', body: '{}' });
    output.textContent = `Websites see ${result.ip}`;
  } catch (error) {
    output.textContent = '';
    toast(error.message, true);
  }
};

$('#auto-share-mode').onchange = updateShareSites;
$('#select-unlisted').onclick = () => {
  for (const profile of state.profiles) if (profile.listed === false) selectedProfiles.add(profile.id);
  renderProfiles();
  updateBulkBar();
};

$('#select-all-backups').onchange = event => {
  selectedBackups.clear();
  if (event.target.checked) for (const backup of state.backups || []) selectedBackups.add(backup.name);
  renderBackups();
};
$('#delete-backups').onclick = async () => {
  const names = [...selectedBackups];
  if (!names.length || !confirm(`Delete ${names.length} backup(s)? They cannot be restored afterwards.`)) return;
  try {
    const result = await api('/backups/delete', { method: 'POST', body: JSON.stringify({ names }) });
    selectedBackups.clear();
    await load();
    toast(`Deleted ${result.deleted} backup(s)`);
  } catch (error) { toast(error.message, true); }
};
$('#purge-backups').onclick = async () => {
  const total = state.backups?.length || 0;
  if (!total) return;
  const typed = prompt(`Delete all ${total} backup(s)? Nothing can be restored from them afterwards, and the next backup is taken when the vault changes.\n\nType PURGE to confirm.`);
  if (typed === null) return;
  if (typed.trim() !== 'PURGE') return toast('Nothing deleted: type PURGE to confirm', true);
  try {
    const result = await api('/backups/purge', { method: 'POST', body: JSON.stringify({ confirm: true }) });
    selectedBackups.clear();
    await load();
    toast(`Deleted all ${result.deleted} backup(s)`);
  } catch (error) { toast(error.message, true); }
};

$('#select-all-profiles').onchange = event => {
  selectedProfiles.clear();
  if (event.target.checked) for (const profile of state.profiles) selectedProfiles.add(profile.id);
  renderProfiles();
  updateBulkBar();
};

$('#delete-selected').onclick = async () => {
  const ids = [...selectedProfiles];
  if (!ids.length) return;
  const domains = state.profiles.filter(profile => selectedProfiles.has(profile.id)).map(profile => profile.domain);
  const preview = domains.slice(0, 8).join('\n') + (domains.length > 8 ? `\n…and ${domains.length - 8} more` : '');
  if (!confirm(`Delete ${ids.length} profile(s)?\n\n${preview}\n\nOther browsers remove these cookies. A backup of the vault is saved first.`)) return;
  try {
    const result = await deleteProfiles(ids);
    $('#editor').hidden = true;
    await load();
    toast(`Deleted ${result.deleted} profile(s). Backup: ${result.backup}`);
  } catch (error) { toast(error.message, true); }
};

$('#purge-profiles').onclick = async () => {
  const total = state.profiles.length;
  if (!total) return;
  const typed = prompt(`Purge all ${total} profile(s) and their cookies from the vault?\n\nOther browsers remove these cookies. A backup of the vault is saved first and can be restored under Vault backups.\n\nType PURGE to confirm.`);
  if (typed === null) return;
  if (typed.trim() !== 'PURGE') {
    toast('Nothing was deleted: type PURGE to confirm', true);
    return;
  }
  try {
    const result = await api('/profiles/purge', { method: 'POST', body: JSON.stringify({ confirm: true }) });
    selectedProfiles.clear();
    $('#editor').hidden = true;
    await load();
    toast(`Purged ${result.deleted} profile(s). Backup: ${result.backup}`);
  } catch (error) { toast(error.message, true); }
};
$('#share-all').onchange = updateShareDevices;
$('#announcement-all').onchange = updateAnnouncementDevices;
$('#announcement-some').onchange = updateAnnouncementDevices;

$('#announcement-form').onsubmit = async event => {
  event.preventDefault();
  const expiry = $('#announcement-expiry').value;
  try {
    await api('/announcements', {
      method: 'POST',
      body: JSON.stringify({
        title: $('#announcement-title').value,
        message: $('#announcement-message').value,
        level: $('#announcement-level').value,
        url: $('#announcement-url').value,
        expiresInMinutes: expiry ? Number(expiry) : null,
        shareWithAllDevices: $('#announcement-all').checked,
        allowedDeviceIds: [...document.querySelectorAll('#announcement-devices input:checked')].map(input => input.value),
        pinned: $('#announcement-pinned').checked
      })
    });
    for (const id of ['#announcement-title', '#announcement-message', '#announcement-url']) $(id).value = '';
    $('#announcement-pinned').checked = false;
    await load();
    toast('Announcement sent');
  } catch (error) { toast(error.message, true); }
};
$('#share-some').onchange = updateShareDevices;

$('#code-form').onsubmit = async event => {
  event.preventDefault();
  try {
    const code = await api('/enrollment-codes', { method: 'POST', body: JSON.stringify({ label: $('#code-label').value, ttlMinutes: Number($('#code-ttl').value) }) });
    $('#code-value').textContent = code.code;
    $('#code-result').hidden = false;
    $('#code-label').value = '';
    await load();
  } catch (error) { toast(error.message, true); }
};

$('#copy-code').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('#code-value').textContent);
    toast('Enrollment code copied');
  } catch { toast('Select the code and copy it manually', true); }
};

$('#export').onclick = async () => {
  try {
    const response = await fetch('/api/admin/export', { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) throw new Error(`Export failed (${response.status})`);
    const name = /filename="?([^";]+)/.exec(response.headers.get('content-disposition') || '')?.[1] || 'shared-browser-vault.json';
    const link = document.createElement('a');
    link.href = URL.createObjectURL(await response.blob());
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    toast('Vault exported. Keep it with the matching data key.');
  } catch (error) { toast(error.message, true); }
};

$('#import-file').onchange = async event => {
  const file = event.target.files[0];
  event.target.value = '';
  if (!file || !confirm(`Import ${file.name}? The current vault is backed up first, then replaced, including enrolled browsers and their tokens.`)) return;
  try {
    const result = await api('/import', { method: 'POST', body: await file.text() });
    await load();
    toast(`Imported — ${result.result}`);
  } catch (error) { toast(error.message, true); }
};
$('#new-profile').onclick = () => edit();
$('#close-editor').onclick = () => { $('#editor').hidden = true; };
$('#add-cookie').onclick = () => $('#cookies').append(cookieRow());

$('#profile-form').onsubmit = async event => {
  event.preventDefault();
  const id = $('#profile-id').value;
  const domain = $('#profile-domain').value;
  const rows = [...document.querySelectorAll('.cookie')];
  const cookies = rows.map(row => ({
    name: row.querySelector('.cookie-name').value,
    value: row.querySelector('.cookie-value').value,
    domain: row.querySelector('.cookie-domain').value || domain,
    path: row.querySelector('.cookie-path').value,
    secure: row.querySelector('.cookie-secure').checked,
    httpOnly: row.querySelector('.cookie-http').checked,
    sameSite: row.querySelector('.cookie-same').value
  }));
  const missing = rows.find(row => !row.dataset.stored && !row.querySelector('.cookie-value').value);
  if (missing) {
    toast('Enter a value for every new cookie', true);
    missing.querySelector('.cookie-value').focus();
    return;
  }
  try {
    await api(id ? `/profiles/${id}` : '/profiles', {
      method: id ? 'PUT' : 'POST',
      body: JSON.stringify({
        id,
        name: $('#profile-name').value,
        sessionCookie: $('#profile-session-cookie').value.trim(),
        domain,
        enabled: $('#profile-enabled').checked,
        shareWithAllDevices: $('#share-all').checked,
        allowedDeviceIds: [...document.querySelectorAll('#share-devices input:checked')].map(input => input.value),
        cookies
      })
    });
    $('#editor').hidden = true;
    await load();
    toast('Shared profile saved');
  } catch (error) { toast(error.message, true); }
};

$('#delete-profile').onclick = async () => {
  const id = $('#profile-id').value;
  if (!id || !confirm('Delete this shared profile? If automatic sharing is on, the primary browser recreates it the next time it visits the domain. Disable the profile instead to stop sharing.')) return;
  try {
    await api(`/profiles/${id}`, { method: 'DELETE' });
    $('#editor').hidden = true;
    await load();
    toast('Profile deleted');
  } catch (error) { toast(error.message, true); }
};

document.addEventListener('submit', event => { delete event.target.dataset.dirty; }, true);
document.addEventListener('input', event => {
  const form = event.target.closest?.('form');
  if (form && form.id !== 'login-form') form.dataset.dirty = 'true';
});
document.addEventListener('click', event => {
  if (event.target.matches?.('.bookmark .remove, .bookmark .move-up')) $('#bookmarks-form').dataset.dirty = 'true';
});

Object.assign(pagerRenderers, { audit: renderAudit, devices: renderDevices, profiles: () => { renderProfiles(); updateBulkBar(); }, announcements: renderAnnouncements, backups: renderBackups });

// Keep "last seen" and proxy counters current while the dashboard is open, but never re-render while
// the administrator is typing in a form.
setInterval(() => {
  if (!state || document.hidden) return;
  // Forms being edited are kept as they are (see render), so only focus and open editors pause the refresh.
  if (document.activeElement?.closest('form') || document.querySelector('.limits-row') || !$('#editor').hidden) return;
  load().catch(() => { });
}, 15000);

// api() already signs out when the token is rejected; other errors (server restarting, network) keep the session.
if (token) load().catch(error => { if (token) toast(error.message, true); });
