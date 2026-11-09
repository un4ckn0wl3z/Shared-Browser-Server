const $ = selector => document.querySelector(selector);
let token = sessionStorage.getItem('sharedBrowserAdmin') || '';
let state = null;

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
  render();
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

function render() {
  for (const form of document.querySelectorAll('form[data-dirty]')) delete form.dataset.dirty;
  const settings = state.settings;
  $('#revision').textContent = state.revision;
  $('#device-count').textContent = state.devices.length;
  $('#profile-count').textContent = state.profiles.length;
  $('#home-page').value = settings.homePage;
  $('#search-url').value = settings.searchUrl || '';
  $('#auto-share').checked = settings.autoShareCookies !== false;

  const proxy = settings.proxy || {};
  const runtime = state.proxy || {};
  $('#proxy-enabled').checked = proxy.enabled === true;
  $('#proxy-host').value = proxy.host || '127.0.0.1';
  $('#proxy-port').value = proxy.port || 8899;
  $('#proxy-ports').value = proxy.allowedPorts || '80,443';
  $('#proxy-bypass').value = proxy.bypassList || '';
  $('#proxy-state').textContent = runtime.listening ? 'Running' : proxy.enabled ? 'Starting' : 'Disabled';
  $('#proxy-runtime').textContent = runtime.listening ? 'Listening' : 'Stopped';
  $('#proxy-runtime').className = runtime.listening ? 'badge' : 'badge off';
  $('#proxy-details').textContent = runtime.listening
    ? `${runtime.bindAddress}:${runtime.port} · ${runtime.activeConnections} active · ${runtime.totalConnections} total connection(s)`
    : runtime.lastError || 'Each enrolled browser authenticates with its own device token.';

  const primary = $('#primary-device');
  primary.replaceChildren(new Option('Select automatically', ''));
  for (const device of state.devices.filter(item => !item.revoked)) primary.append(new Option(`${device.name} (${device.id.slice(0, 8)})`, device.id));
  primary.value = settings.primaryDeviceId || '';

  renderDevices();
  renderProfiles();
  renderBookmarks();
}

function renderDevices() {
  const body = $('#devices');
  body.replaceChildren();
  if (!state.devices.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No browsers enrolled</td></tr>';
    return;
  }
  for (const device of state.devices) {
    const row = document.createElement('tr');
    row.innerHTML = `<td>${esc(device.name)}${device.primary ? '<span class="pill">PRIMARY</span>' : ''}</td>`
      + `<td><code>${esc(device.id.slice(0, 12))}…</code></td>`
      + `<td title="${esc(device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : '')}">${esc(relativeTime(device.lastSeenAt))}</td>`
      + `<td>${device.revoked ? 'Revoked' : 'Active'}</td>`
      + `<td><button class="${device.revoked ? 'secondary' : 'danger'} toggle">${device.revoked ? 'Restore' : 'Revoke'}</button></td>`
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
      if (!confirm(`Delete ${device.name}? The browser must be enrolled again with the administrator token to reconnect.`)) return;
      try {
        await api(`/devices/${device.id}`, { method: 'DELETE' });
        await load();
        toast('Device deleted');
      } catch (error) { toast(error.message, true); }
    };
    body.append(row);
  }
}

function renderProfiles() {
  const container = $('#profiles');
  container.replaceChildren();
  if (!state.profiles.length) {
    container.innerHTML = '<p class="empty">No shared profiles yet.</p>';
    return;
  }
  for (const profile of [...state.profiles].sort((a, b) => a.domain.localeCompare(b.domain))) {
    const element = document.createElement('div');
    element.className = 'profile';
    element.innerHTML = `<div><strong>${profile.enabled ? '●' : '○'} ${esc(profile.name)}</strong><span>${esc(profile.domain)} · ${profile.cookieCount} cookie(s)${profile.enabled ? '' : ' · disabled'}</span></div><button class="secondary">Edit</button>`;
    element.querySelector('button').onclick = () => edit(profile);
    container.append(element);
  }
}

function settingsPayload(proxy) {
  return {
    homePage: $('#home-page').value,
    searchUrl: $('#search-url').value,
    primaryDeviceId: $('#primary-device').value,
    autoShareCookies: $('#auto-share').checked,
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
  $('#profile-enabled').checked = profile?.enabled !== false;
  $('#delete-profile').hidden = !profile;
  $('#cookies').replaceChildren(...(profile?.cookies?.length ? profile.cookies : [{}]).map(cookieRow));
  $('#editor').scrollIntoView({ behavior: 'smooth' });
}

function bookmarkRow(bookmark = {}) {
  const row = $('#bookmark-template').content.firstElementChild.cloneNode(true);
  row.querySelector('.bookmark-title').value = bookmark.title || '';
  row.querySelector('.bookmark-url').value = bookmark.url || '';
  row.querySelector('.remove').onclick = () => row.remove();
  row.querySelector('.move-up').onclick = () => { if (row.previousElementSibling) row.parentElement.insertBefore(row, row.previousElementSibling); };
  return row;
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
    bypassList: $('#proxy-bypass').value
  };
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(settingsPayload(proxy)) });
    await new Promise(resolve => setTimeout(resolve, 900));
    await load();
    toast('Proxy settings saved; Electron browsers in Managed mode switch automatically');
  } catch (error) { toast(error.message, true); }
};

$('#bookmarks-form').onsubmit = async event => {
  event.preventDefault();
  const bookmarks = [...document.querySelectorAll('.bookmark')].map(row => ({
    title: row.querySelector('.bookmark-title').value,
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
      body: JSON.stringify({ id, name: $('#profile-name').value, domain, enabled: $('#profile-enabled').checked, cookies })
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

document.addEventListener('input', event => {
  const form = event.target.closest?.('form');
  if (form && form.id !== 'login-form') form.dataset.dirty = 'true';
});
document.addEventListener('click', event => {
  if (event.target.matches?.('.bookmark .remove, .bookmark .move-up')) $('#bookmarks-form').dataset.dirty = 'true';
});

// Keep "last seen" and proxy counters current while the dashboard is open, but never re-render while
// the administrator is typing in a form.
setInterval(() => {
  if (!state || document.hidden) return;
  if (document.activeElement?.closest('form') || document.querySelector('form[data-dirty]') || !$('#editor').hidden) return;
  load().catch(() => { });
}, 15000);

if (token) load().catch(() => logout());
