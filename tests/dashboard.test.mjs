import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { ADMIN_TOKEN, randomDeviceId, startServer, waitFor } from './lib/harness.mjs';

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

  test('lists backups and the audit log', async () => {
    await waitFor(async () => (await page.locator('#backups tr').count()) >= 1 && !(await page.textContent('#backups')).includes('No backups'), { message: 'backup rows' });
    const audit = await page.textContent('#audit');
    for (const action of ['enrollment_code.created', 'device.enrolled', 'profile.updated', 'settings.updated', 'announcement.sent', 'profiles.deleted', 'profiles.purged']) assert.ok(audit.includes(action), action);
  });

  test('has no script errors', () => {
    assert.deepEqual(errors, []);
  });
});
