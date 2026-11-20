import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { ADMIN_TOKEN, randomDeviceId, startCapture, startServer, waitFor } from './lib/harness.mjs';

describe('dashboard', () => {
  let server;
  let browser;
  let page;
  const errors = [];

  before(async () => {
    server = await startServer();
    const { chromium } = await import('playwright');
    // CI installs Playwright's Chromium; elsewhere CHROMIUM_PATH can point at an existing build.
    browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
    page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    const device = await server.enroll(randomDeviceId(), 'WB1');
    await server.device(device, '/sync', 'POST', { pageUrl: 'https://dash.example/', complete: true, cookies: [{ name: 's', value: '1', domain: 'dash.example', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' }] });
  });
  after(async () => {
    await browser?.close();
    await server?.stop();
  });

  test('signs in with the administrator token', async () => {
    await page.goto(server.url);
    await page.fill('#token', ADMIN_TOKEN);
    await page.click('#login-form button');
    await page.waitForSelector('#app:not([hidden])');
    await waitFor(async () => (await page.textContent('#devices')).includes('WB1'), { message: 'device list' });
  });

  test('creates an enrollment code that a browser can use once', async () => {
    await page.fill('#code-label', 'Front desk');
    await page.selectOption('#code-ttl', '60');
    await page.click('#code-form button');
    await page.waitForSelector('#code-result:not([hidden])');
    const code = (await page.textContent('#code-value')).trim();
    assert.match(code, /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    await waitFor(async () => (await page.textContent('#codes')).includes('Front desk'), { message: 'code listed' });
    await server.enroll(randomDeviceId(), 'WB2', code);
    await page.click('#refresh');
    await waitFor(async () => /used by WB2/.test(await page.textContent('#codes')), { message: 'code marked used' });
  });

  test('limits a profile to selected browsers', async () => {
    await page.click('.profile button');
    await page.check('#share-some');
    await page.check('#share-devices label:has-text("WB1") input');
    await page.click('#profile-form .actions button');
    await waitFor(async () => {
      const profile = await server.profile('dash.example');
      return profile && !profile.shareWithAllDevices && profile.allowedDeviceIds.length === 1;
    }, { message: 'profile restricted' });
    assert.equal((await server.profile('dash.example')).cookies.length, 1);
  });

  test('turns on proxy TLS and shows the pinned fingerprint', async () => {
    await page.check('#proxy-enabled');
    await page.fill('#proxy-port', String(server.proxyPort));
    await page.check('#proxy-tls');
    await page.click('#proxy-form > button');
    await waitFor(async () => /Proxy settings saved/.test(await page.textContent('#toast')), { message: 'proxy saved' });
    await waitFor(async () => /Certificate SHA-256/.test(await page.textContent('#proxy-fingerprint')), { message: 'fingerprint shown' });
  });

  test('sends an announcement and lists it', async () => {
    await page.fill('#announcement-title', 'Dashboard notice');
    await page.fill('#announcement-message', 'Hello browsers');
    await page.selectOption('#announcement-level', 'critical');
    await page.click('#announcement-form > button');
    await waitFor(async () => (await page.textContent('#announcements')).includes('Dashboard notice'), { message: 'announcement listed' });
    assert.match(await page.textContent('#announcements'), /dismissed by 0 of \d/);
    assert.equal((await server.status()).announcements[0].level, 'critical');
  });

  test('shares only the listed sites', async () => {
    assert.ok(await page.isHidden('#auto-share-sites'));
    await page.selectOption('#auto-share-mode', 'listed');
    assert.ok(await page.isVisible('#auto-share-sites'));
    await page.fill('#auto-share-domains', 'github.com\nhttps://gitlab.com/');
    await page.click('#settings-form > button');
    await waitFor(async () => (await server.status()).settings.autoShareScope === 'listed', { message: 'list saved' });
    assert.deepEqual((await server.status()).settings.autoShareDomains, ['github.com', 'gitlab.com']);
    // dash.example was shared before the list: it is flagged and can be selected for deletion.
    await waitFor(async () => /not on the sharing list/.test(await page.textContent('#profiles')), { message: 'unlisted flag' });
    await page.click('#select-unlisted');
    assert.equal(await page.textContent('#delete-selected'), 'Delete selected (1)');
    assert.ok(await page.isChecked('.profile:has-text("not on the sharing list") input[type=checkbox]'));
    // Clear the selection again for the bulk-delete test below.
    await page.check('#select-all-profiles');
    await page.uncheck('#select-all-profiles');
    assert.equal(await page.textContent('#delete-selected'), 'Delete selected');
    await page.selectOption('#auto-share-mode', 'all');
    await page.click('#settings-form > button');
    await waitFor(async () => (await server.status()).settings.autoShareScope === 'all', { message: 'every site again' });
  });

  test('turns the browser unlock code on, and off again', async () => {
    await page.check('#lock-enabled');
    await page.click('#lock-form button');
    await waitFor(async () => /Enter an unlock code/.test(await page.textContent('#toast')), { message: 'code required' });
    await page.fill('#lock-code', 'dash-code');
    await page.click('#lock-form button');
    await waitFor(async () => (await server.status()).settings.clientLock.enabled, { message: 'lock on' });
    await waitFor(async () => (await page.textContent('#lock-state')) === 'On', { message: 'badge on' });
    assert.equal(await page.inputValue('#lock-code'), '');
    // Browsers older than 1.5 are flagged because they do not ask for the code.
    assert.match(await page.textContent('#devices'), /UPDATE NEEDED/);
    await page.uncheck('#lock-enabled');
    await page.click('#lock-form button');
    await waitFor(async () => !(await server.status()).settings.clientLock.enabled, { message: 'lock off' });
    assert.ok((await server.status()).settings.clientLock.hash);
  });

  test('lists the accounts of a site and the browsers using them', async () => {
    // A second account for dash.example; the first one is limited to WB1, so WB2 uses the new one.
    await page.click('#new-profile');
    await page.fill('#profile-name', 'work');
    await page.fill('#profile-domain', 'dash.example');
    await page.click('#cookies .remove');
    await page.click('#profile-form .actions button');
    await waitFor(async () => /account of 2/.test(await page.textContent('#profiles')), { message: 'accounts listed' });
    assert.match(await page.textContent('.profile:has-text("work")'), /account of 2 · used by WB2/);
    assert.match(await page.textContent('.profile:has-text("dash.example · 1 cookie")'), /used by WB1/);
  });

  test('deletes selected profiles and purges the rest', async () => {
    for (const domain of ['bulk-a.example', 'bulk-b.example', 'bulk-c.example']) {
      await server.admin('/profiles', 'POST', { name: domain, domain, enabled: true, cookies: [{ name: 'c', value: '1', domain, path: '/', secure: true, httpOnly: true, sameSite: 'Lax' }] });
    }
    await page.click('#refresh');
    await waitFor(async () => (await page.locator('.profile').count()) >= 4, { message: 'profiles listed' });
    assert.ok(await page.isDisabled('#delete-selected'));
    await page.check('.profile:has-text("bulk-a.example") input[type=checkbox]');
    await page.check('.profile:has-text("bulk-b.example") input[type=checkbox]');
    assert.equal(await page.textContent('#delete-selected'), 'Delete selected (2)');
    assert.equal(await page.evaluate(() => document.getElementById('select-all-profiles').indeterminate), true);
    page.once('dialog', dialog => dialog.accept());
    await page.click('#delete-selected');
    await waitFor(async () => {
      const domains = (await server.status()).profiles.map(item => item.domain);
      return !domains.includes('bulk-a.example') && !domains.includes('bulk-b.example') && domains.includes('bulk-c.example');
    }, { message: 'selected profiles deleted' });
    await waitFor(async () => !(await page.textContent('#profiles')).includes('bulk-a.example'), { message: 'list refreshed' });
    // A purge needs PURGE typed; anything else leaves the vault alone.
    page.once('dialog', dialog => dialog.accept('purge please'));
    await page.click('#purge-profiles');
    await waitFor(async () => /type PURGE/.test(await page.textContent('#toast')), { message: 'purge refused' });
    assert.ok((await server.status()).profiles.length > 0);
    page.once('dialog', dialog => dialog.accept('PURGE'));
    await page.click('#purge-profiles');
    await waitFor(async () => (await server.status()).profiles.length === 0, { message: 'vault purged' });
    await waitFor(async () => (await page.textContent('#profiles')).includes('No shared profiles yet'), { message: 'empty list' });
    assert.ok(await page.isDisabled('#purge-profiles'));
  });

  test('connection policy, egress settings and per-browser limits', async () => {
    assert.equal(await page.inputValue('#network-policy'), 'strict');
    // The proxy was enabled above, so the warning about Strict without a proxy stays hidden.
    assert.ok(await page.isHidden('#policy-warning'));
    await page.uncheck('#proxy-enabled');
    assert.ok(await page.isVisible('#policy-warning'));
    await page.check('#proxy-enabled');
    await page.selectOption('#egress-family', 'ipv4');
    await page.fill('#limit-connections', '20');
    await page.fill('#limit-quota', '50');
    await page.fill('#limit-rate', '10');
    await page.selectOption('#network-policy', 'managed');
    await page.click('#proxy-form > button');
    await waitFor(async () => /Proxy settings saved/.test(await page.textContent('#toast')), { message: 'proxy saved' });
    await waitFor(async () => (await server.status()).settings.networkPolicy === 'managed', { message: 'policy saved' });
    const proxy = (await server.status()).settings.proxy;
    assert.deepEqual([proxy.egressAddressFamily, proxy.maxConnectionsPerDevice, proxy.monthlyQuotaGb, proxy.rateLimitMbps], ['ipv4', 20, 50, 10]);
    // Per-browser override from the browsers table.
    await page.click('#devices tr:has-text("WB1") button.limits');
    await page.fill('.limits-row input[name=maxConnections]', '3');
    await page.fill('.limits-row input[name=rateLimitMbps]', '0');
    await page.click('.limits-row button:has-text("Save limits")');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB1').limitOverrides.maxConnections === 3, { message: 'override saved' });
    const overrides = (await server.status()).devices.find(item => item.name === 'WB1').limitOverrides;
    assert.deepEqual(overrides, { maxConnections: 3, monthlyQuotaGb: null, rateLimitMbps: 0 });
    assert.ok((await page.textContent('#devices').then(() => page.locator('table:has(#devices) thead').textContent())).includes('Proxy this month'));
    assert.match(await page.textContent('#devices'), /↑ .* · ↓ /);
  });

  test('requires a minimum browser version', async () => {
    await page.fill('#min-version', '99.0.0');
    await page.click('#settings-form > button');
    await waitFor(async () => (await server.status()).settings.minimumClientVersion === '99.0.0', { message: 'minimum saved' });
    await waitFor(async () => /UPDATE REQUIRED/.test(await page.textContent('#devices')), { message: 'outdated browsers marked' });
    assert.match(await page.textContent('#min-version-hint'), /browser\(s\) still need to update/);
    await page.fill('#min-version', '');
    await page.click('#settings-form > button');
    await waitFor(async () => (await server.status()).settings.minimumClientVersion === '', { message: 'minimum cleared' });
  });

  test('notifications: save a Discord webhook, keep it secret and send a test', async () => {
    const capture = await startCapture();
    try {
      await page.fill('#notify-discord', `${capture.url}/api/webhooks/42/dashboard-secret`);
      await page.uncheck('#notify-events input[value="device.offline"]');
      await page.click('#notify-form button:not([type=button])');
      await waitFor(async () => /Notifications saved/.test(await page.textContent('#toast')), { message: 'webhook saved' });
      assert.ok(!(await server.status()).notifications.events.includes('device.offline'));
      assert.equal(await page.inputValue('#notify-discord'), '••••••••');
      await page.click('#notify-test');
      await waitFor(async () => /Test sent to Discord/.test(await page.textContent('#toast')), { message: 'test sent' });
      assert.match(JSON.parse(capture.requests[0].text).embeds[0].title, /Test notification/);
    } finally {
      await capture.close();
    }
  });

  test('browsing controls and per-browser settings and actions', async () => {
    await page.selectOption('#filter-mode', 'block');
    await page.fill('#filter-domains', 'games.example');
    await page.check('#schedule-enabled');
    await page.fill('#schedule-start', '08:00');
    await page.check('#block-copy');
    await page.click('#controls-form > button');
    await waitFor(async () => /Browsing controls saved/.test(await page.textContent('#toast')), { message: 'controls saved' });
    const settings = (await server.status()).settings;
    assert.deepEqual([settings.siteFilter.domains, settings.schedule.enabled, settings.schedule.start, settings.dataControls.blockCopy], [['games.example'], true, '08:00', true]);
    await page.selectOption('#filter-mode', 'off');
    await page.uncheck('#schedule-enabled');
    await page.uncheck('#block-copy');
    await page.click('#controls-form > button');
    await waitFor(async () => !(await server.status()).settings.schedule.enabled, { message: 'controls cleared' });
    await waitFor(async () => !(await page.isChecked('#schedule-enabled')) && (await page.textContent('#toast')) === 'Browsing controls saved', { message: 'controls form refreshed' });
    // Per-browser panel: an action and settings.
    await page.click('#devices tr:has-text("WB1") button.actions-button');
    await page.fill('.device-row [name=openUrl]', 'https://intranet.example/');
    await page.click('.device-row [data-command="open-url"]');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB1').pendingCommands.some(item => item.argument === 'https://intranet.example/'), { message: 'action sent' });
    await waitFor(async () => /1 action\(s\) waiting/.test(await page.textContent('#devices')), { message: 'pending shown' });
    await waitFor(async () => /Open a page sent to WB1/.test(await page.textContent('#toast')), { message: 'action toast' });
    await page.click('#devices tr:has-text("WB1") button.actions-button');
    await page.fill('.device-row [name=homePage]', 'https://desk.example/');
    await page.selectOption('.device-row [name=filterMode]', 'allow');
    await page.fill('.device-row [name=filterDomains]', 'desk.example, docs.example');
    await page.click('.device-row form button:not([type=button])');
    await waitFor(async () => /Settings saved for WB1/.test(await page.textContent('#toast')), { message: 'device settings saved' });
    assert.deepEqual((await server.status()).devices.find(item => item.name === 'WB1').siteFilter, { mode: 'allow', domains: ['desk.example', 'docs.example'] });
    await page.click('#devices tr:has-text("WB1") button.actions-button');
    await page.click('.device-row [data-cancel]');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB1').pendingCommands.length === 0, { message: 'action cancelled' });
  });

  test('offsite backup settings are validated', async () => {
    await page.check('#offsite-enabled');
    await page.fill('#offsite-endpoint', 'https://sgp1.digitaloceanspaces.com');
    await page.click('#offsite-form button:not([type=button])');
    await waitFor(async () => /Enter the endpoint, bucket, access key and secret key/.test(await page.textContent('#toast')), { message: 'validation shown' });
    assert.equal((await server.status()).offsiteBackup.enabled, false);
    await page.uncheck('#offsite-enabled');
  });

  test('pins an announcement, pages and searches long lists', async () => {
    await page.fill('#announcement-title', 'Pinned notice');
    await page.fill('#announcement-message', 'Read me');
    await page.check('#announcement-pinned');
    await page.click('#announcement-form > button');
    await waitFor(async () => /Announcement sent/.test(await page.textContent('#toast')), { message: 'sent' });
    assert.equal((await server.status()).announcements.find(item => item.title === 'Pinned notice').pinned, true);
    assert.match(await page.textContent('#announcements article:first-child'), /📌[\s\S]*Pinned notice[\s\S]*cannot be dismissed/);
    await page.click('#announcements article:first-child button.pin');
    await waitFor(async () => !(await server.status()).announcements.find(item => item.title === 'Pinned notice').pinned, { message: 'unpinned' });
    // Activity has more than one page: paging and search work, and survive the refresh.
    await page.selectOption('#audit-pager select', '10');
    await waitFor(async () => /Page 1 of \d+/.test(await page.textContent('#audit-pager')), { message: 'pager shown' });
    assert.equal(await page.locator('#audit tr').count(), 10);
    await page.click('#audit-pager [data-go="next"]');
    assert.match(await page.textContent('#audit-pager'), /11–20 of/);
    await page.fill('#audit-pager input', 'announcement.sent');
    await waitFor(async () => (await page.locator('#audit tr').count()) >= 1 && /filtered from/.test(await page.textContent('#audit-pager')), { message: 'search applied' });
    for (const row of await page.locator('#audit tr').allTextContents()) assert.match(row, /announcement\.sent/);
    await page.click('#refresh');
    await waitFor(async () => /filtered from/.test(await page.textContent('#audit-pager')), { message: 'search kept after refresh' });
    await page.fill('#audit-pager input', '');
    await page.selectOption('#audit-pager select', '20');
  });

  test('switches a browser to another account from its Manage panel', async () => {
    await server.admin('/profiles', 'POST', { name: 'Anuwat', domain: 'switch.example', enabled: true, cookies: [] });
    const napon = await server.admin('/profiles', 'POST', { name: 'Napon', domain: 'switch.example', enabled: true, cookies: [] });
    await page.click('#refresh');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB2').accounts.length > 0, { message: 'accounts listed' });
    await page.click('#devices tr:has-text("WB2") button.actions-button');
    await page.selectOption('.device-row select[data-site="switch.example"]', napon.id);
    await page.click('.device-row [data-switch="switch.example"]');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB2').pendingCommands.some(item => item.type === 'switch-account' && item.argument === napon.id), { message: 'switch queued' });
    await waitFor(async () => /WB2 switches switch\.example to Napon/.test(await page.textContent('#toast')), { message: 'switch toast' });
  });

  test('selects backups to delete, and purges them after typing PURGE', async () => {
    await page.click('#refresh');
    await waitFor(async () => (await page.locator('#backups .pick-backup').count()) >= 2, { message: 'backups listed' });
    const before = (await server.status()).backups.length;
    await page.check('#backups tr:nth-child(1) .pick-backup');
    assert.equal(await page.textContent('#delete-backups'), 'Delete selected (1)');
    page.once('dialog', dialog => dialog.accept());
    await page.click('#delete-backups');
    await waitFor(async () => (await server.status()).backups.length === before - 1, { message: 'one deleted' });
    page.once('dialog', dialog => dialog.accept('nope'));
    await page.click('#purge-backups');
    await waitFor(async () => /type PURGE/.test(await page.textContent('#toast')), { message: 'purge refused' });
    page.once('dialog', dialog => dialog.accept('PURGE'));
    await page.click('#purge-backups');
    await waitFor(async () => (await server.status()).backups.length === 0, { message: 'purged' });
    await waitFor(async () => /No backups yet/.test(await page.textContent('#backups')), { message: 'empty table' });
  });

  test('lists backups and the audit log', async () => {
    await server.admin('/profiles/purge', 'POST', { confirm: true }).catch(() => { });
    await server.admin('/profiles', 'POST', { name: 'Again', domain: 'again.example', enabled: true, cookies: [] });
    await server.admin('/profiles/purge', 'POST', { confirm: true });
    await page.click('#refresh');
    await waitFor(async () => (await page.locator('#backups tr').count()) >= 1 && !(await page.textContent('#backups')).includes('No backups'), { message: 'backup rows' });
    assert.match(await page.textContent('#backup-policy'), /Keeps the newest \d+ backups/);
    const count = await page.locator('#backups tr').count();
    page.once('dialog', dialog => dialog.accept());
    await page.click('#backups tr:first-child button.danger');
    await waitFor(async () => (await page.locator('#backups tr').count()) === count - 1 || /No backups/.test(await page.textContent('#backups')), { message: 'backup deleted' });
    await page.click('#refresh');
    await waitFor(async () => (await page.textContent('#audit')).includes('backup.deleted'), { message: 'deletion audited' });
    // Show the whole recent activity on one page.
    await page.selectOption('#audit-pager select', '100');
    const audit = await page.textContent('#audit');
    for (const action of ['notifications.updated', 'device.command_sent', 'device.settings_updated', 'client_lock.updated', 'enrollment_code.created', 'device.enrolled', 'profile.updated', 'settings.updated', 'announcement.sent', 'profiles.deleted', 'profiles.purged']) assert.ok(audit.includes(action), action);
  });

  test('a display error does not sign out, and a reload keeps the session', async () => {
    // Simulates a page and script from different versions: an element the script expects is missing.
    await page.evaluate(() => document.getElementById('lock-enabled').remove());
    await page.click('#refresh');
    await waitFor(async () => /Part of the dashboard could not be shown/.test(await page.textContent('#toast')), { message: 'display error reported' });
    assert.ok(await page.isVisible('#app'));
    await page.reload();
    await page.waitForSelector('#app:not([hidden])');
    await waitFor(async () => (await page.textContent('#devices')).includes('WB1'), { message: 'still signed in after reload' });
  });

  test('has no script errors', () => {
    assert.deepEqual(errors, []);
  });
});
