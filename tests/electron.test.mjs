import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  PUBLIC_IP, ROOT, launchBrowser, publicAddressAvailable, randomDeviceId, sleep, startOrigin, startServer, startSite,
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
    // These browsers run in Direct mode against a site on localhost, so they need the choice policy.
    await server.settings({ allowAdminTokenEnrollment: false, networkPolicy: 'choice' });
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

  test('a second account for the site: added on the primary, switched on each browser', async () => {
    await wb1.navigate(`${site.origin}/`);
    await waitFor(async () => /👤/.test(await wb1.window.textContent('#account')), { message: 'account button' });
    assert.ok(await wb1.window.isVisible('#account'));
    // The account menu is native; open the add-account dialog the way its menu item does.
    await wb1.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.send('browser:add-account', { domain: 'localhost' }));
    await wb1.window.waitForSelector('#account-dialog[open]');
    await wb1.window.fill('#account-name', 'second');
    await wb1.window.click('#account-form button.primary');
    await wb1.window.waitForSelector('#account-dialog[open]', { state: 'detached' });
    // The primary is signed out of the site and its next sign-in is saved as the new account.
    await waitFor(async () => !(await wb1.cookies(site.origin)).includes('pref='), { message: 'WB1 signed out' });
    await waitFor(async () => /second/.test(await wb1.window.textContent('#account')), { message: 'WB1 shows second account' });
    await wb1.navigate(`${site.origin}/other-login`);
    const accounts = async () => (await server.status()).profiles.filter(item => item.domain === 'localhost');
    await waitFor(async () => (await accounts()).find(item => item.name === 'second')?.cookies.some(item => item.name === 'other'), { message: 'second account saved' });
    let [first, second] = await accounts();
    assert.ok(first.cookies.some(item => item.name === 'pref') && !first.cookies.some(item => item.name === 'other'));
    // WB2 still uses the first account, then switches.
    assert.ok((await wb2.cookies(site.origin)).includes('pref=dark'));
    await wb2.navigate(`${site.origin}/`);
    await waitFor(async () => /\(2\)/.test(await wb2.window.textContent('#account')), { message: 'WB2 sees two accounts' });
    await wb2.window.evaluate(id => window.sharedBrowser.switchAccount(id), second.id);
    await waitFor(async () => {
      const cookies = await wb2.cookies(site.origin);
      return cookies.includes('other=1') && !cookies.includes('pref=');
    }, { message: 'WB2 on the second account' });
    await wb2.window.evaluate(id => window.sharedBrowser.switchAccount(id), first.id);
    await waitFor(async () => {
      const cookies = await wb2.cookies(site.origin);
      return cookies.includes('pref=dark') && !cookies.includes('other=');
    }, { message: 'WB2 back on the first account' });
    // Switching the primary back must not copy its cookies into the other account.
    // Switching reloads the site's tabs; leave the page that sets the second account's cookie first.
    await wb1.navigate(`${site.origin}/`);
    await wb1.window.evaluate(id => window.sharedBrowser.switchAccount(id), first.id);
    await waitFor(async () => {
      const cookies = await wb1.cookies(site.origin);
      return cookies.includes('pref=dark') && !cookies.includes('other=');
    }, { message: 'WB1 back on the first account' });
    await sleep(2500);
    [first, second] = await accounts();
    assert.deepEqual(first.cookies.map(item => item.name).sort(), ['pref']);
    assert.deepEqual(second.cookies.map(item => item.name), ['other']);
    await server.admin('/profiles/delete', 'POST', { ids: [second.id] });
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

  const tabViewTop = browser => browser.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].contentView.children.map(view => view.getBounds().y)[0]);

  test('announcements appear as a banner, plain text only, and can be dismissed', async () => {
    const baseline = await tabViewTop(wb2);
    const started = Date.now();
    const sent = await server.admin('/announcements', 'POST', {
      title: 'Maintenance tonight',
      message: 'Sessions refresh at 18:00 <img src=x onerror="document.title=\'pwned\'">',
      level: 'warning',
      url: `${site.origin}/status`
    });
    await waitFor(async () => (await wb2.window.textContent('#announcements')).includes('Maintenance tonight'), { message: 'banner on WB2', timeout: 8000, interval: 100 });
    assert.ok(Date.now() - started < 8000);
    // The message is rendered as text, never as markup.
    assert.equal(await wb2.window.locator('#announcements img').count(), 0);
    assert.ok((await wb2.window.textContent('#announcements')).includes('<img src=x'));
    // The page moves down so the banner does not cover it.
    await waitFor(async () => (await tabViewTop(wb2)) > baseline, { message: 'page below banner' });
    await wb2.window.click('.announcement button:has-text("Open link")');
    await waitFor(async () => (await wb2.address()) === `${site.origin}/status`, { message: 'link opened in a tab' });
    await wb2.window.click('.announcement .dismiss');
    await waitFor(async () => (await wb2.window.locator('.announcement').count()) === 0, { message: 'banner dismissed' });
    await waitFor(async () => (await tabViewTop(wb2)) === baseline, { message: 'page back in place' });
    await waitFor(async () => (await server.status()).announcements.find(item => item.id === sent.id).acknowledgedBy.some(entry => entry.name === 'WB2'), { message: 'dismissal recorded' });
    // WB1 still shows it until its own user dismisses it.
    assert.ok((await wb1.window.textContent('#announcements')).includes('Maintenance tonight'));
  });

  test('targeted announcements only reach the selected browser', async () => {
    await server.admin('/announcements', 'POST', { title: 'For WB1 only', level: 'info', shareWithAllDevices: false, allowedDeviceIds: [deviceId('WB1')] });
    await waitFor(async () => (await wb1.window.textContent('#announcements')).includes('For WB1 only'), { message: 'banner on WB1' });
    await sleep(1500);
    assert.ok(!(await wb2.window.textContent('#announcements')).includes('For WB1 only'));
  });

  test('tabs and the window size come back after a restart', async () => {
    await wb2.window.click('#new-tab');
    await wb2.navigate(`${site.origin}/second-tab`);
    await waitFor(async () => (await wb2.address()) === `${site.origin}/second-tab`, { message: 'second tab' });
    await wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setBounds({ x: 40, y: 30, width: 1100, height: 700 }));
    await sleep(300);
    // Blank tabs are not saved; every page is.
    const urls = () => wb2.app.evaluate(({ webContents }) => webContents.getAllWebContents().map(item => item.getURL()).filter(url => /^https?:/.test(url)).sort());
    const before = await urls();
    assert.ok(before.includes(`${site.origin}/find`) && before.includes(`${site.origin}/second-tab`));
    await wb2.close();
    wb2 = await launchBrowser(home, 'WB2');
    await waitFor(async () => JSON.stringify(await urls()) === JSON.stringify(before), { message: 'restored tabs' });
    assert.equal(await wb2.window.locator('.tab').count(), before.length);
    await waitFor(async () => (await wb2.address()) === `${site.origin}/second-tab`, { message: 'active tab restored' });
    const bounds = await wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].getBounds());
    assert.equal(bounds.width, 1100);
    assert.equal(bounds.height, 700);
    // A dismissed announcement stays dismissed after a restart.
    assert.equal(await wb2.window.locator('.announcement').count(), 0);
  });

  test('the unlock code locks running and restarted browsers until it is entered', async () => {
    const pages = browser => browser.app.evaluate(({ webContents }) => webContents.getAllWebContents().filter(item => /^https?:/.test(item.getURL())).length);
    const attached = browser => browser.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].contentView.children.length);
    const enter = async code => {
      await wb2.window.fill('#lock-code', code);
      await wb2.window.click('#lock-form button');
    };
    await server.admin('/client-lock', 'PUT', { enabled: true, code: 'letmein' });
    // A running browser locks as soon as the code is turned on, hides its pages and refuses browser actions.
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await waitFor(async () => (await attached(wb2)) === 0, { message: 'page view detached' });
    await assert.rejects(wb2.window.evaluate(() => window.sharedBrowser.newTab('about:blank')), /Unlock the browser first/);
    await enter('wrong code');
    await waitFor(async () => /Wrong unlock code/.test(await wb2.window.textContent('#lock-error')), { message: 'wrong code refused' });
    assert.ok(await wb2.window.isVisible('#lock-screen'));
    await enter('letmein');
    await wb2.window.waitForSelector('#lock-screen', { state: 'hidden' });
    assert.equal(await attached(wb2), 1);
    // After a restart no page loads until the code is entered; then the saved tabs come back.
    const open = await pages(wb2);
    await wb2.close();
    wb2 = await launchBrowser(home, 'WB2');
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await sleep(2000);
    assert.equal(await pages(wb2), 0);
    await enter('letmein');
    await waitFor(async () => (await pages(wb2)) === open, { message: 'tabs restored after unlock' });
    // Turning the code off releases a browser waiting on the lock screen.
    await wb2.close();
    wb2 = await launchBrowser(home, 'WB2');
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await server.admin('/client-lock', 'PUT', { enabled: false });
    await wb2.window.waitForSelector('#lock-screen', { state: 'hidden' });
    await waitFor(async () => (await pages(wb2)) === open, { message: 'tabs opened once the code was turned off' });
    const audit = (await server.status()).audit.map(item => item.action);
    assert.ok(audit.includes('browser.unlocked') && audit.includes('browser.unlock_failed'));
  });

  test('a browser below the minimum version shows the update screen until it updates', async () => {
    const attached = () => wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].contentView.children.length);
    await server.settings({ minimumClientVersion: '99.0.0' });
    await wb2.window.waitForSelector('#update-screen:not([hidden])');
    assert.match(await wb2.window.textContent('#update-required-text'), /requires Shared Browser 99\.0\.0 or newer/);
    await waitFor(async () => (await attached()) === 0, { message: 'pages hidden' });
    await assert.rejects(wb2.window.evaluate(() => window.sharedBrowser.newTab('about:blank')), /Update the browser first/);
    // A development build cannot download updates, so the screen reports that and offers to try again.
    await waitFor(async () => /could not be downloaded/.test(await wb2.window.textContent('#update-required-progress')), { message: 'update attempt reported' });
    assert.equal(await wb2.window.textContent('#update-required-action'), 'Try again');
    assert.match((await server.status()).devices.find(item => item.name === 'WB2').clientVersion, /^\d+\.\d+\.\d+$/);
    // Lowering the requirement releases the browser without a restart.
    await server.settings({ minimumClientVersion: '' });
    await wb2.window.waitForSelector('#update-screen', { state: 'hidden' });
    await waitFor(async () => (await attached()) === 1, { message: 'pages shown again' });
  });

  test('administrator actions reach the browser once: open, close tabs, clear cookies, lock', async () => {
    const urls = () => wb2.app.evaluate(({ webContents }) => webContents.getAllWebContents().map(item => item.getURL()).filter(url => /^https?:/.test(url)));
    const send = (type, argument = '') => server.admin(`/devices/${deviceId('WB2')}/commands`, 'POST', { type, argument });
    await send('open-url', `${site.origin}/opened-by-admin`);
    await waitFor(async () => (await urls()).includes(`${site.origin}/opened-by-admin`), { message: 'URL opened' });
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB2').pendingCommands.length === 0, { message: 'action acknowledged' });
    await send('close-tabs');
    await waitFor(async () => !(await urls()).includes(`${site.origin}/opened-by-admin`), { message: 'tabs closed' });
    assert.equal(await wb2.window.locator('.tab').count(), 1);
    // Clearing cookies for a site removes them from this browser only.
    await waitFor(async () => (await wb2.cookies(site.origin)).includes('pref=dark'), { message: 'WB2 has the shared cookie' });
    await send('clear-site', 'localhost');
    await waitFor(async () => !(await wb2.cookies(site.origin)).includes('pref='), { message: 'cookies cleared' });
    assert.ok((await wb1.cookies(site.origin)).includes('pref=dark'));
    // Lock needs an unlock code; with one, the browser locks at once. Idle time and the computer's lock do the same.
    await server.admin('/client-lock', 'PUT', { enabled: true, code: 'letmein', idleMinutes: 1, lockOnSystemLock: true });
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    const unlock = async () => {
      await wb2.window.fill('#lock-code', 'letmein');
      await wb2.window.click('#lock-form button');
      await wb2.window.waitForSelector('#lock-screen', { state: 'hidden' });
    };
    await unlock();
    await send('lock');
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await unlock();
    await wb2.app.evaluate(({ powerMonitor }) => powerMonitor.emit('lock-screen'));
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await unlock();
    await wb2.app.evaluate(({ powerMonitor }) => { powerMonitor.getSystemIdleTime = () => 120; });
    await wb2.window.waitForSelector('#lock-screen:not([hidden])', { timeout: 15000 });
    await wb2.app.evaluate(({ powerMonitor }) => { powerMonitor.getSystemIdleTime = () => 0; });
    await unlock();
    await server.admin('/client-lock', 'PUT', { enabled: false });
  });

  test('a pinned announcement cannot be dismissed, and the administrator can switch the browser to another account', async () => {
    const pinned = await server.admin('/announcements', 'POST', { title: 'Pinned for all', message: 'stays on screen', pinned: true });
    await waitFor(async () => /Pinned for all/.test(await wb2.window.textContent('#announcements')), { message: 'pinned banner' });
    assert.equal(await wb2.window.locator('.announcement.pinned .dismiss').count(), 0);
    await wb2.window.evaluate(id => window.sharedBrowser.dismissAnnouncement(id), pinned.id);
    await sleep(500);
    assert.match(await wb2.window.textContent('#announcements'), /Pinned for all/);
    await server.admin(`/announcements/${pinned.id}/pin`, 'PUT', { pinned: false });
    await waitFor(async () => (await wb2.window.locator('.announcement:has-text("Pinned for all") .dismiss').count()) === 1, { message: 'dismissable after unpin' });
    await server.admin(`/announcements/${pinned.id}`, 'DELETE');

    const second = await server.admin('/profiles', 'POST', { name: 'second', domain: 'localhost', enabled: true, cookies: [{ name: 'other', value: '2', domain: 'localhost', path: '/', secure: false, httpOnly: false, sameSite: 'Lax' }] });
    const first = (await server.status()).profiles.find(item => item.domain === 'localhost' && item.id !== second.id);
    const switchTo = id => server.admin(`/devices/${deviceId('WB2')}/commands`, 'POST', { type: 'switch-account', argument: id });
    await switchTo(second.id);
    await waitFor(async () => {
      const cookies = await wb2.cookies(site.origin);
      return cookies.includes('other=2') && !cookies.includes('pref=');
    }, { message: 'WB2 on the second account' });
    assert.ok((await server.status()).profiles.find(item => item.id === second.id).usedBy.includes('WB2'));
    await switchTo(first.id);
    await waitFor(async () => {
      const cookies = await wb2.cookies(site.origin);
      return cookies.includes('pref=dark') && !cookies.includes('other=');
    }, { message: 'WB2 back on the first account' });
    await server.admin('/profiles/delete', 'POST', { ids: [second.id] });
  });

  test('PRIMARY and EDITOR badges, session expiry on the account button, and the unlock code per browser', async () => {
    await waitFor(async () => await wb1.window.isVisible('#primary-badge'), { message: 'WB1 badge' });
    assert.ok(await wb2.window.isHidden('#primary-badge'));
    assert.ok(await wb2.window.isHidden('#editor-badge'));
    // A shared sign-in that expires in two days is flagged on the account button and in its tooltip.
    // A browser allowed to update the profile (here an API client) publishes a sign-in that expires in two days.
    const helper = await server.enroll(randomDeviceId(), 'api-editor');
    await server.admin('/profiles', 'POST', { name: '127.0.0.1', domain: '127.0.0.1', enabled: true, editorDeviceIds: [helper.id], cookies: [] });
    const soon = Math.floor(Date.now() / 1000) + 2 * 86400;
    await server.device(helper, '/sync', 'POST', { pageUrl: 'http://127.0.0.1/', complete: true, cookies: [{ name: 'token', value: 't', domain: '127.0.0.1', path: '/', secure: false, httpOnly: true, sameSite: 'Lax', expiresAt: soon }] });
    assert.ok(await wb1.window.isVisible('#primary-badge'));
    await wb2.navigate(`http://127.0.0.1:${site.port}/expiring`);
    await waitFor(async () => /👤 127\.0\.0\.1 ⏳ [12] d/.test(await wb2.window.textContent('#account')), { message: 'expiry on the account button' });
    assert.ok(await wb2.window.locator('#account').evaluate(element => element.classList.contains('expiring') && /Sign-in expires/.test(element.title)));
    await server.admin(`/devices/${helper.id}`, 'DELETE');
    await server.admin('/profiles/delete', 'POST', { ids: (await server.status()).profiles.filter(item => item.domain === '127.0.0.1').map(item => item.id) });
    // WB2 made an editor of the localhost profile: its own sign-in on that site reaches the vault.
    const local = await server.profile('localhost');
    await server.admin(`/profiles/${local.id}`, 'PUT', { name: local.name, domain: local.domain, enabled: true, editorDeviceIds: [deviceId('WB2')], cookies: local.cookies.map(item => ({ ...item, value: '' })) });
    await waitFor(async () => await wb2.window.isVisible('#editor-badge'), { message: 'EDITOR badge' });
    assert.match(await wb2.window.locator('#editor-badge').getAttribute('title'), /localhost/);
    await wb2.navigate(`${site.origin}/other-login`);
    await waitFor(async () => (await server.profile('localhost')).cookies.some(item => item.name === 'other'), { message: 'editor sign-in saved' });
    await waitFor(async () => (await wb1.cookies(site.origin)).includes('other=1'), { message: 'primary received it' });
    // While WB2 edits the profile, the primary's own sign-in there is not shared, and WB2's sign-out is not either.
    await wb1.navigate(`${site.origin}/login`);
    await waitFor(async () => (await wb1.cookies(site.origin)).includes('sid=secret-1'), { message: 'WB1 signed in locally' });
    await sleep(2500);
    assert.ok(!(await server.profile('localhost')).cookies.some(item => item.name === 'sid'));
    await wb2.navigate(`${site.origin}/login`);
    await waitFor(async () => (await server.profile('localhost')).cookies.some(item => item.name === 'sid'), { message: 'editor sign-in shared' });
    await wb2.navigate(`${site.origin}/logout`);
    await waitFor(async () => !(await wb2.cookies(site.origin)).includes('sid='), { message: 'WB2 signed out locally' });
    await sleep(2500);
    assert.ok((await server.profile('localhost')).cookies.some(item => item.name === 'sid'), 'the shared sign-in survives the editor signing out');
    const updated = await server.profile('localhost');
    await server.admin(`/profiles/${updated.id}`, 'PUT', { name: updated.name, domain: updated.domain, enabled: true, editorDeviceIds: [], cookies: updated.cookies.filter(item => item.name !== 'other' && item.name !== 'sid').map(item => ({ ...item, value: '' })) });
    await wb1.navigate(`${site.origin}/logout`);
    await waitFor(async () => await wb2.window.isHidden('#editor-badge'), { message: 'EDITOR badge gone' });
    // Unlock code: on for everyone but off for WB2, then on only for WB2.
    await server.admin('/client-lock', 'PUT', { enabled: false, code: 'letmein' });
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: false });
    await server.admin('/client-lock', 'PUT', { enabled: true });
    await sleep(2000);
    assert.ok(await wb2.window.isHidden('#lock-screen'));
    await server.admin('/client-lock', 'PUT', { enabled: false });
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: true });
    await wb2.window.waitForSelector('#lock-screen:not([hidden])');
    await wb2.window.fill('#lock-code', 'letmein');
    await wb2.window.click('#lock-form button');
    await wb2.window.waitForSelector('#lock-screen', { state: 'hidden' });
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: null });
  });

  test('site filter: blocked sites show a notice, allow lists keep everything else out', async () => {
    const text = async () => (await wb2.pageText()).join('\n');
    await server.settings({ siteFilter: { mode: 'block', domains: ['localhost'] } });
    await sleep(1500);
    await wb2.navigate(`${site.origin}/blocked-page`);
    await waitFor(async () => /localhost is blocked/.test(await wb2.app.evaluate(async ({ webContents }) => (await Promise.all(webContents.getAllWebContents().filter(item => item.getURL().startsWith('data:')).map(item => item.executeJavaScript('document.body.innerText')))).join(' '))), { message: 'blocked notice' });
    // A per-browser allow list replaces the shared filter for this browser only.
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: { mode: 'allow', domains: ['localhost'] }, scheduleExempt: false });
    await sleep(1500);
    await wb2.navigate(`${site.origin}/allowed-page`);
    await waitFor(async () => /needle/.test(await text()), { message: 'allowed page loads' });
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false });
    await server.settings({ siteFilter: { mode: 'off', domains: [] } });
  });

  test('allowed hours hide the pages outside them; an exempt browser is not affected', async () => {
    // Allowed only on a day that is not today in the chosen time zone.
    const today = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' })).getDay();
    await server.settings({ schedule: { enabled: true, days: [(today + 3) % 7], start: '09:00', end: '18:00', timeZone: 'Asia/Bangkok' } });
    await wb2.window.waitForSelector('#schedule-screen:not([hidden])');
    assert.match(await wb2.window.textContent('#schedule-text'), /09:00–18:00 \(Asia\/Bangkok\)/);
    assert.equal(await wb2.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].contentView.children.length), 0);
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: true });
    await wb2.window.waitForSelector('#schedule-screen', { state: 'hidden' });
    await server.admin(`/devices/${deviceId('WB2')}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false });
    await server.settings({ schedule: { enabled: false, days: [1], start: '09:00', end: '18:00', timeZone: 'Asia/Bangkok' } });
    await wb2.window.waitForSelector('#schedule-screen', { state: 'hidden' });
  });

  test('download manager, and data controls that block downloads, uploads and copying', async () => {
    await wb2.navigate(`${site.origin}/file`);
    await waitFor(async () => (await wb2.window.evaluate(() => window.sharedBrowser.downloads())).some(item => item.name === 'report.txt' && item.state === 'completed'), { message: 'download completed' });
    const [done] = await wb2.window.evaluate(() => window.sharedBrowser.downloads());
    assert.equal(fs.readFileSync(done.path, 'utf8'), 'quarterly numbers');
    await wb2.window.click('#downloads-button');
    await wb2.window.waitForSelector('#downloads-dialog[open]');
    assert.match(await wb2.window.textContent('#downloads-list'), /report\.txt[\s\S]*Done/);
    await wb2.window.click('#downloads-close');
    await server.settings({ dataControls: { blockDownloads: true, blockUploads: true, blockCopy: true, domains: ['localhost'] } });
    await sleep(1500);
    await wb2.navigate(`${site.origin}/protected`);
    await waitFor(async () => /needle/.test((await wb2.pageText()).join(' ')), { message: 'protected page' });
    await wb2.navigate(`${site.origin}/file`);
    await waitFor(async () => (await wb2.window.evaluate(() => window.sharedBrowser.downloads()))[0].state === 'blocked', { message: 'download blocked' });
    const guarded = await wb2.app.evaluate(async ({ webContents }) => {
      const page = webContents.getAllWebContents().find(item => item.getURL().endsWith('/protected'));
      return page.executeJavaScript(`(() => {
        const copy = new Event('copy', { cancelable: true, bubbles: true });
        document.body.dispatchEvent(copy);
        const input = document.createElement('input');
        input.type = 'file';
        document.body.append(input);
        const click = new MouseEvent('click', { cancelable: true, bubbles: true });
        input.dispatchEvent(click);
        return [copy.defaultPrevented, click.defaultPrevented];
      })()`);
    });
    assert.deepEqual(guarded, [true, true]);
    await server.settings({ dataControls: { blockDownloads: false, blockUploads: false, blockCopy: false, domains: [] } });
  });

  test('purging the vault removes shared cookies from the other browser but not from the primary', async () => {
    await waitFor(async () => (await wb2.cookies(site.origin)).includes('pref=dark'), { message: 'WB2 has the shared cookie' });
    await server.admin('/profiles/purge', 'POST', { confirm: true });
    await waitFor(async () => !(await wb2.cookies(site.origin)).includes('pref='), { message: 'WB2 removed the purged cookie' });
    assert.ok((await wb1.cookies(site.origin)).includes('pref=dark'));
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

  test('the default policy puts the browser in Strict privacy and locks the setting', async () => {
    const status = await server.status();
    assert.equal(status.settings.networkPolicy, 'strict');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB3')?.networkMode === 'strict', { message: 'WB3 reports strict' });
    const device = (await server.status()).devices.find(item => item.name === 'WB3');
    assert.equal(device.clientVersion, JSON.parse(fs.readFileSync(path.join(ROOT, 'electron-client/package.json'), 'utf8')).version);
    // Loopback goes through the proxy too, and pages refuse non-proxied WebRTC.
    assert.notEqual(await browser.route('http://127.0.0.1/'), 'DIRECT');
    const policies = await browser.app.evaluate(({ webContents }) => webContents.getAllWebContents().filter(item => /^https?:|about:blank/.test(item.getURL())).map(item => item.getWebRTCIPHandlingPolicy()));
    assert.ok(policies.length && policies.every(policy => policy === 'disable_non_proxied_udp'), JSON.stringify(policies));
    await browser.window.click('#settings');
    await waitFor(() => browser.window.evaluate(() => document.getElementById('settings-dialog').open), { message: 'settings open' });
    assert.ok(await browser.window.isDisabled('#network-mode'));
    assert.ok(await browser.window.isDisabled('#strict-privacy'));
    assert.match(await browser.window.textContent('#policy-note'), /Strict privacy/);
  });

  test('"What IP do websites see?" answers through the proxy', async t => {
    if (!haveOrigin) return t.skip(`${PUBLIC_IP} is not bound locally`);
    await server.settings({ ipCheckUrl: `http://${PUBLIC_IP}:${origin.port}/ip` });
    const dialogOpen = () => browser.window.evaluate(() => document.getElementById('settings-dialog').open);
    // The dialog reads the configuration when it opens, so reopen it until the new setting has synced.
    await waitFor(async () => {
      if (await dialogOpen()) await browser.window.click('#settings-close');
      await browser.window.click('#settings');
      await waitFor(dialogOpen, { message: 'settings open' });
      return !(await browser.window.isHidden('#ip-check'));
    }, { message: 'IP check button shown', interval: 500 });
    const before = origin.requests.length;
    await browser.window.click('#ip-check');
    await waitFor(async () => /Websites see/.test(await browser.window.textContent('#privacy-result')), { message: 'IP result' });
    const seen = origin.requests.slice(before).find(item => item.path === '/ip');
    assert.ok(seen && !seen.proxyAuthorization);
    assert.match(await browser.window.textContent('#privacy-result'), new RegExp(`Websites see ${seen.remote.replaceAll('.', '\\.')}\\. .*Strict privacy`));
    await browser.window.click('#settings-close');
  });

  test('switches to a changed proxy endpoint without a restart', async () => {
    await server.settings({}, { tls: false });
    await waitFor(async () => (await browser.route('https://example.com/')) === `PROXY 127.0.0.1:${server.proxyPort}`, { message: 'plain proxy route' });
    await server.settings({}, { tls: true });
    await waitFor(async () => (await browser.route('https://example.com/')) === `HTTPS 127.0.0.1:${server.proxyPort}`, { message: 'TLS route again' });
  });
});

describe('Electron browser switched by the connection policy', () => {
  let server;
  let home;
  let browser;

  before(async () => {
    server = await startServer();
    home = tempDir('home');
    await server.settings({ networkPolicy: 'choice' }, { enabled: true, port: server.proxyPort, tls: true });
    await waitFor(async () => (await server.status()).proxy.listening, { message: 'proxy listening' });
    writeClientProfile(home, 'WB4', { serverUrl: server.url, deviceId: randomDeviceId(), credential: await server.code('WB4'), networkMode: 'direct' });
    browser = await launchBrowser(home, 'WB4');
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB4')?.networkMode === 'direct', { message: 'WB4 reports direct' });
  });
  after(async () => {
    await browser?.close().catch(() => { });
    await server?.stop();
  });

  test('a running Direct-mode browser moves to the proxy with Strict privacy when the policy changes', async () => {
    assert.equal(await browser.route('https://example.com/'), 'DIRECT');
    await server.settings({ networkPolicy: 'strict' });
    await waitFor(async () => (await browser.route('https://example.com/')) === `HTTPS 127.0.0.1:${server.proxyPort}`, { message: 'proxy route', timeout: 10000 });
    await waitFor(async () => (await server.status()).devices.find(item => item.name === 'WB4')?.networkMode === 'strict', { message: 'WB4 reports strict' });
    const policies = await browser.app.evaluate(({ webContents }) => webContents.getAllWebContents().filter(item => /^https?:|about:blank/.test(item.getURL())).map(item => item.getWebRTCIPHandlingPolicy()));
    assert.ok(policies.every(policy => policy === 'disable_non_proxied_udp'), JSON.stringify(policies));
  });

  test('the managed policy still lets the user turn Strict privacy off', async () => {
    await server.settings({ networkPolicy: 'managed' });
    await browser.window.click('#settings');
    await waitFor(() => browser.window.evaluate(() => document.getElementById('settings-dialog').open), { message: 'settings open' });
    await waitFor(async () => /requires the managed proxy\./.test(await browser.window.textContent('#policy-note')), { message: 'managed note' });
    assert.ok(await browser.window.isDisabled('#network-mode'));
    assert.ok(!(await browser.window.isDisabled('#strict-privacy')));
    await browser.window.click('#settings-close');
  });
});

describe('A newly installed browser', () => {
  let browser;
  after(async () => { await browser?.close().catch(() => { }); });

  test('starts in Managed proxy mode with Strict privacy', async () => {
    browser = await launchBrowser(tempDir('home'), 'Fresh');
    const dialogOpen = () => browser.window.evaluate(() => document.getElementById('settings-dialog').open);
    await waitFor(dialogOpen, { message: 'first-run settings dialog' });
    assert.equal(await browser.window.inputValue('#network-mode'), 'managed');
    assert.ok(await browser.window.isChecked('#strict-privacy'));
    // Until it is enrolled and configured, nothing leaves the computer directly.
    assert.notEqual(await browser.route('https://example.com/'), 'DIRECT');
  });
});
