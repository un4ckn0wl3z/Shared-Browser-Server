import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  PUBLIC_IP, launchBrowser, publicAddressAvailable, randomDeviceId, sleep, startOrigin, startServer, startSite,
  tempDir, waitFor, writeClientProfile
} from './lib/harness.mjs';

describe('Electron browsers sharing a session', () => {
  let server;
  let site;
  let home;
  let wb1;
  let wb2;
  const ids = { WB1: randomDeviceId(), WB2: randomDeviceId() };
  const deviceId = name => ids[name];

  before(async () => {
    server = await startServer();
    site = await startSite();
    home = tempDir('home');
    // Browsers enroll with one-time codes, and administrator-token enrollment is switched off.
    await server.settings({ allowAdminTokenEnrollment: false });
    for (const name of ['WB1', 'WB2']) {
      writeClientProfile(home, name, { serverUrl: server.url, deviceId: deviceId(name), credential: await server.code(name) });
    }
  });
  after(async () => {
    await wb1?.close().catch(() => { });
    await wb2?.close().catch(() => { });
    await site?.close();
    await server?.stop();
  });

  test('both browsers enroll with one-time codes', async () => {
    wb1 = await launchBrowser(home, 'WB1');
    await waitFor(async () => (await server.status()).devices.some(item => item.name === 'WB1'), { message: 'WB1 enrolled' });
    wb2 = await launchBrowser(home, 'WB2');
    await waitFor(async () => (await server.status()).devices.some(item => item.name === 'WB2'), { message: 'WB2 enrolled' });
    const codes = (await server.status()).enrollmentCodes;
    assert.ok(codes.every(code => !code.active));
  });

  test('browsers hold a live event stream', async () => {
    await waitFor(async () => (await server.status()).devices.every(item => item.live), { message: 'both browsers live' });
  });

  test('sign-in on the primary reaches the other browser with its expiry', async () => {
    await server.settings({ primaryDeviceId: deviceId('WB1') });
    await wb1.navigate(`localhost:${site.port}/login`);
    await waitFor(async () => (await wb1.cookies(site.origin)).includes('sid=secret-1'), { message: 'WB1 signed in' });
    await waitFor(async () => (await wb2.cookies(site.origin)).includes('sid=secret-1(persistent)'), { message: 'WB2 received the session' });
  });

  test('a rotated session reaches the other browser within seconds', async () => {
    const started = Date.now();
    await wb1.navigate(`${site.origin}/rotate`);
    await waitFor(async () => (await wb2.cookies(site.origin)).includes('sid=secret-2'), { message: 'rotated session', timeout: 10000, interval: 100 });
    // Polling falls back to 30 seconds while the event stream is connected, so this proves the push path.
    assert.ok(Date.now() - started < 8000, `took ${Date.now() - started} ms`);
  });

  test('sign-out on the primary removes the session everywhere', async () => {
    await wb1.navigate(`${site.origin}/logout`);
    await waitFor(async () => {
      const profile = await server.profile('localhost');
      return profile && !profile.cookies.some(item => item.name === 'sid') && profile.cookies.some(item => item.name === 'pref');
    }, { message: 'vault dropped sid' });
    await waitFor(async () => {
      const cookies = await wb2.cookies(site.origin);
      return !cookies.includes('sid=') && cookies.includes('pref=dark');
    }, { message: 'WB2 removed sid' });
  });

  test('a cookie added in the dashboard is adopted by the primary and removed on sign-out', async () => {
    const profile = await server.profile('localhost');
    await server.admin(`/profiles/${profile.id}`, 'PUT', {
      name: profile.name,
      domain: profile.domain,
      enabled: true,
      cookies: [...profile.cookies.map(item => ({ ...item, value: '' })), { name: 'adm', value: 'from-dashboard', domain: 'localhost', path: '/', secure: false, httpOnly: false, sameSite: 'Lax' }]
    });
    await waitFor(async () => (await wb1.cookies(site.origin)).includes('adm=from-dashboard') && (await wb2.cookies(site.origin)).includes('adm=from-dashboard'), { message: 'dashboard cookie installed' });
    await waitFor(async () => (await server.profile('localhost')).cookies.some(item => item.name === 'adm' && item.sourceDeviceId === deviceId('WB1')), { message: 'adopted' });
    await wb1.navigate(`${site.origin}/clear-adm`);
    await waitFor(async () => !(await wb2.cookies(site.origin)).includes('adm='), { message: 'WB2 removed dashboard cookie' });
  });

  test('limiting a profile to the primary removes it from the other browser', async () => {
    const profile = await server.profile('localhost');
    await server.admin(`/profiles/${profile.id}`, 'PUT', {
      name: profile.name, domain: profile.domain, enabled: true, shareWithAllDevices: false, allowedDeviceIds: [deviceId('WB1')],
      cookies: profile.cookies.map(item => ({ ...item, value: '' }))
    });
    await waitFor(async () => !(await wb2.cookies(site.origin)).includes('pref='), { message: 'WB2 lost the profile' });
    assert.ok((await wb1.cookies(site.origin)).includes('pref=dark'));
    await server.admin(`/profiles/${profile.id}`, 'PUT', {
      name: profile.name, domain: profile.domain, enabled: true, shareWithAllDevices: true, allowedDeviceIds: [],
      cookies: (await server.profile('localhost')).cookies.map(item => ({ ...item, value: '' }))
    });
    await waitFor(async () => (await wb2.cookies(site.origin)).includes('pref=dark'), { message: 'WB2 regained the profile' });
  });

  test('shared bookmarks reach the browser', async () => {
    await server.admin('/bookmarks', 'PUT', [{ title: 'Local test', url: `${site.origin}/bookmarked` }]);
    await waitFor(async () => (await wb2.window.getAttribute('#bookmarks', 'title')) === 'Shared bookmarks (1)', { message: 'bookmark count' });
  });

  test('address bar: search terms, host names and localhost', async () => {
    await wb2.navigate('hello world');
    await waitFor(async () => (await wb2.address()).startsWith('https://duckduckgo.com/?q=hello%20world'), { message: 'search URL' });
    await wb2.navigate(`localhost:${site.port}/find`);
    await waitFor(async () => (await wb2.address()) === `http://localhost:${site.port}/find`, { message: 'localhost over http' });
  });

  test('find in page', async () => {
    await waitFor(async () => (await wb2.pageText()).some(text => text.includes('needle')), { message: 'page loaded' });
    await wb2.window.click('#address');
    await wb2.shortcut('F', ['control']);
    await waitFor(() => wb2.window.isVisible('#find-bar'), { message: 'find bar' });
    await wb2.window.fill('#find-text', 'needle');
    await waitFor(async () => (await wb2.window.textContent('#find-count')) === '1/3', { message: 'matches counted' });
    await wb2.window.press('#find-text', 'Enter');
    await waitFor(async () => (await wb2.window.textContent('#find-count')) === '2/3', { message: 'next match' });
    await wb2.window.press('#find-text', 'Escape');
    await waitFor(() => wb2.window.isHidden('#find-bar'), { message: 'find bar closed' });
  });

  test('a closed tab can be reopened', async () => {
    await wb2.window.click('.tab.active .tab-close');
    await waitFor(async () => (await wb2.address()) === '', { message: 'blank replacement tab' });
    await wb2.shortcut('T', ['control', 'shift']);
    await waitFor(async () => (await wb2.address()) === `http://localhost:${site.port}/find`, { message: 'reopened tab' });
  });

  test('tabs and the window size come back after a restart', async () => {
    await wb2.window.click('#new-tab');
    await wb2.navigate(`${site.origin}/second-tab`);
    await waitFor(async () => (await wb2.address()) === `${site.origin}/second-tab`, { message: 'second tab' });
    await wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setBounds({ x: 40, y: 30, width: 1100, height: 700 }));
    await sleep(300);
    await wb2.close();
    wb2 = await launchBrowser(home, 'WB2');
    // Blank tabs are not saved; the two pages are.
    const urls = () => wb2.app.evaluate(({ webContents }) => webContents.getAllWebContents().map(item => item.getURL()).filter(url => /^https?:/.test(url)).sort());
    await waitFor(async () => JSON.stringify(await urls()) === JSON.stringify([`${site.origin}/find`, `${site.origin}/second-tab`].sort()), { message: 'restored tabs' });
    assert.equal(await wb2.window.locator('.tab').count(), 2);
    await waitFor(async () => (await wb2.address()) === `${site.origin}/second-tab`, { message: 'active tab restored' });
    const bounds = await wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].getBounds());
    assert.equal(bounds.width, 1100);
    assert.equal(bounds.height, 700);
  });

  test('a revoked browser asks for settings once and keeps what the user types', async () => {
    await server.admin(`/devices/${deviceId('WB2')}/revoke`, 'POST', {});
    await waitFor(async () => /unauthorized/i.test(await wb2.status()), { message: 'unauthorized status', timeout: 40000 });
    await waitFor(() => wb2.window.evaluate(() => document.getElementById('settings-dialog').open), { message: 'settings dialog' });
    await wb2.window.fill('#device-name', 'typing-test');
    await sleep(6000);
    assert.equal(await wb2.window.inputValue('#device-name'), 'typing-test');
  });
});

describe('Electron browser in Managed proxy mode', () => {
  let server;
  let origin;
  let home;
  let browser;
  let haveOrigin;

  before(async () => {
    haveOrigin = await publicAddressAvailable();
    server = await startServer();
    if (haveOrigin) origin = await startOrigin();
    home = tempDir('home');
    await server.settings({}, { enabled: true, port: server.proxyPort, allowedPorts: ['80', '443', origin?.port].filter(Boolean).join(','), tls: true });
    await waitFor(async () => (await server.status()).proxy.listening, { message: 'proxy listening' });
    writeClientProfile(home, 'WB3', { serverUrl: server.url, deviceId: randomDeviceId(), credential: await server.code('WB3'), networkMode: 'managed' });
    browser = await launchBrowser(home, 'WB3');
    await waitFor(async () => (await server.status()).devices.some(item => item.name === 'WB3'), { message: 'WB3 enrolled' });
  });
  after(async () => {
    await browser?.close().catch(() => { });
    await origin?.close();
    await server?.stop();
  });

  test('browses through the TLS proxy, trusting only the pinned certificate', async t => {
    await waitFor(async () => (await browser.route('https://example.com/')) === `HTTPS 127.0.0.1:${server.proxyPort}`, { message: 'HTTPS proxy route' });
    if (!haveOrigin) return t.skip(`${PUBLIC_IP} is not bound locally`);
    await browser.navigate(`http://${PUBLIC_IP}:${origin.port}/through-proxy`);
    await waitFor(async () => (await browser.pageText()).some(text => text.includes('hello /through-proxy')), { message: 'page through proxy' });
    assert.ok(origin.requests.length > 0 && origin.requests.every(item => !item.proxyAuthorization));
  });

  test('switches to a changed proxy endpoint without a restart', async () => {
    await server.settings({}, { tls: false });
    await waitFor(async () => (await browser.route('https://example.com/')) === `PROXY 127.0.0.1:${server.proxyPort}`, { message: 'plain proxy route' });
    await server.settings({}, { tls: true });
    await waitFor(async () => (await browser.route('https://example.com/')) === `HTTPS 127.0.0.1:${server.proxyPort}`, { message: 'TLS route again' });
  });
});
