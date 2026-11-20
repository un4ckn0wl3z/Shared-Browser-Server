import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  ADMIN_TOKEN, PUBLIC_IP, SOURCE_IP, basic, connectProxy, publicAddressAvailable, randomDeviceId, readHead, sleep,
  startCapture, startEcho, startOrigin, startServer, waitFor
} from './lib/harness.mjs';

const cookie = (name, value, domain, extra = {}) => ({ name, value, domain, path: '/', secure: true, httpOnly: true, sameSite: 'Lax', ...extra });

describe('management API', () => {
  let server;
  before(async () => { server = await startServer(); });
  after(async () => { await server?.stop(); });

  test('one-time enrollment codes', async () => {
    const code = await server.code('laptop');
    assert.match(code, /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    // Codes are accepted in any case and with spaces instead of dashes.
    const device = await server.enroll(randomDeviceId(), 'WB1', code.toLowerCase().replaceAll('-', ' '));
    assert.ok(device.token);
    await assert.rejects(server.enroll(randomDeviceId(), 'WB2', code), { status: 401 });
    await assert.rejects(server.enroll(randomDeviceId(), 'WB2', 'not-a-code'), { status: 401 });
    const status = await server.status();
    const entry = status.enrollmentCodes.find(item => item.label === 'laptop');
    assert.equal(entry.active, false);
    assert.equal(entry.usedBy, 'WB1');
  });

  test('administrator-token enrollment can be disabled', async () => {
    await server.enroll(randomDeviceId(), 'with-token', ADMIN_TOKEN);
    await server.settings({ allowAdminTokenEnrollment: false });
    await assert.rejects(server.enroll(randomDeviceId(), 'with-token-2', ADMIN_TOKEN), { status: 403 });
    await server.enroll(randomDeviceId(), 'with-code');
    await server.settings({ allowAdminTokenEnrollment: true });
  });

  test('revoked enrollment codes stop working', async () => {
    const code = await server.code('revoke-me');
    const { id } = (await server.status()).enrollmentCodes.find(item => item.label === 'revoke-me');
    await server.admin(`/enrollment-codes/${id}`, 'DELETE');
    await assert.rejects(server.enroll(randomDeviceId(), 'nope', code), { status: 401 });
  });

  test('snapshot polling answers 204 when nothing changed', async () => {
    const device = await server.enroll(randomDeviceId(), 'poller');
    const first = await (await server.device(device, '/snapshot')).json();
    assert.equal((await server.device(device, `/snapshot?since=${first.revision}`)).status, 204);
    assert.equal((await server.device(device, `/snapshot?since=${first.revision - 1}`)).status, 200);
  });

  test('complete publishes remove signed-out cookies; small expiry shifts are ignored', async () => {
    const primary = await server.enroll(randomDeviceId(), 'primary');
    await server.settings({ primaryDeviceId: primary.id });
    const push = async (cookies, complete = true) => (await (await server.device(primary, '/sync', 'POST', { knownRevision: 0, pageUrl: 'https://sync.example/', cookies, complete })).json());
    const expires = Math.floor(Date.now() / 1000) + 86400 * 30;
    await push([cookie('a', '1', 'sync.example', { expiresAt: expires }), cookie('b', '2', 'sync.example')]);
    const revision = (await server.status()).revision;
    assert.equal((await push([cookie('a', '1', 'sync.example', { expiresAt: expires + 600 }), cookie('b', '2', 'sync.example')])).changedCookies, 0);
    assert.equal((await server.status()).revision, revision);
    await push([cookie('a', '1', 'sync.example', { expiresAt: expires })]);
    assert.deepEqual((await server.profile('sync.example')).cookies.map(item => item.name), ['a']);
    // A partial publish never removes anything.
    await push([], false);
    assert.equal((await server.profile('sync.example')).cookies.length, 1);
  });

  test('profile edits keep stored values; dashboard cookies are adopted by the primary', async () => {
    const primary = await server.enroll(randomDeviceId(), 'adopter');
    await server.settings({ primaryDeviceId: primary.id });
    const created = await server.admin('/profiles', 'POST', { name: 'Edit', domain: 'edit.example', enabled: true, cookies: [cookie('kept', 'secret', 'edit.example'), cookie('typed', 'by-admin', 'edit.example')] });
    await server.admin(`/profiles/${created.id}`, 'PUT', { name: 'Edit', domain: 'edit.example', enabled: true, cookies: [cookie('kept', '', 'edit.example'), cookie('typed', '', 'edit.example')] });
    const snapshot = await (await server.device(primary, '/snapshot')).json();
    const values = Object.fromEntries(snapshot.profiles.find(item => item.domain === 'edit.example').cookies.map(item => [item.name, item.value]));
    assert.deepEqual(values, { kept: 'secret', typed: 'by-admin' });
    await assert.rejects(server.admin(`/profiles/${created.id}`, 'PUT', { name: 'Edit', domain: 'edit.example', enabled: true, cookies: [cookie('new', '', 'edit.example')] }), /Enter a value/);
    // A complete publish that lacks the dashboard cookie does not remove it...
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://edit.example/', complete: true, cookies: [cookie('kept', 'secret', 'edit.example')] });
    assert.ok((await server.profile('edit.example')).cookies.some(item => item.name === 'typed'));
    // ...until the primary has confirmed it holds the same value; then a sign-out removes it.
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://edit.example/', complete: true, cookies: [cookie('kept', 'secret', 'edit.example'), cookie('typed', 'by-admin', 'edit.example')] });
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://edit.example/', complete: true, cookies: [cookie('kept', 'secret', 'edit.example')] });
    assert.deepEqual((await server.profile('edit.example')).cookies.map(item => item.name), ['kept']);
  });

  test('profiles can be limited to selected browsers', async () => {
    const one = await server.enroll(randomDeviceId(), 'allowed');
    const two = await server.enroll(randomDeviceId(), 'excluded');
    await server.admin('/profiles', 'POST', { name: 'Private', domain: 'private.example', enabled: true, shareWithAllDevices: false, allowedDeviceIds: [one.id], cookies: [cookie('p', '1', 'private.example')] });
    const sees = async device => (await (await server.device(device, '/snapshot')).json()).profiles.map(item => item.domain);
    assert.ok((await sees(one)).includes('private.example'));
    assert.ok(!(await sees(two)).includes('private.example'));
    // Deleting the only allowed browser must not widen the profile to everyone.
    await server.admin(`/devices/${one.id}`, 'DELETE');
    assert.ok(!(await sees(two)).includes('private.example'));
    await assert.rejects(server.admin('/profiles', 'POST', { name: 'Nobody', domain: 'nobody.example', enabled: true, shareWithAllDevices: false, allowedDeviceIds: [], cookies: [] }), /Select at least one/);
  });

  test('a site can have several accounts and each browser switches between them', async () => {
    const primary = await server.enroll(randomDeviceId(), 'accounts-primary');
    const other = await server.enroll(randomDeviceId(), 'accounts-other');
    await server.settings({ primaryDeviceId: primary.id });
    const snapshot = async device => (await server.device(device, '/snapshot')).json();
    const site = async device => {
      const data = await snapshot(device);
      return { profiles: data.profiles.filter(item => item.domain === 'git.example'), accounts: data.accounts.filter(item => item.domain === 'git.example'), revision: data.revision };
    };
    const alice = await server.admin('/profiles', 'POST', { name: 'alice', domain: 'git.example', enabled: true, cookies: [cookie('user', 'alice', 'git.example')] });
    // The same name twice is refused; a different name adds a second account.
    await assert.rejects(server.admin('/profiles', 'POST', { name: 'Alice', domain: 'git.example', enabled: true, cookies: [] }), /already has an account named/);
    const bob = await server.admin('/profiles', 'POST', { name: 'bob', domain: 'git.example', enabled: true, cookies: [cookie('user', 'bob', 'git.example')] });

    // Browsers start on the first account and only receive its cookies.
    let view = await site(other);
    assert.deepEqual(view.profiles.map(item => item.cookies[0].value), ['alice']);
    assert.deepEqual(view.accounts.map(item => [item.name, item.active, item.cookieCount]), [['alice', true, 1], ['bob', false, 1]]);
    assert.equal(view.accounts.some(item => 'cookies' in item), false);

    // Switching changes only that browser, and does not wake the others with a new revision.
    const before = view.revision;
    const switched = await server.device(other, `/accounts/${bob.id}/switch`, 'POST');
    assert.equal(switched.status, 200);
    assert.deepEqual((await switched.json()).profiles.filter(item => item.domain === 'git.example').map(item => item.cookies[0].value), ['bob']);
    view = await site(other);
    assert.equal(view.revision, before);
    assert.deepEqual(view.accounts.map(item => item.active), [false, true]);
    assert.deepEqual((await site(primary)).profiles.map(item => item.cookies[0].value), ['alice']);
    assert.equal((await server.device(other, `/snapshot?since=${before}`)).status, 204);
    let listed = (await server.status()).profiles.filter(item => item.domain === 'git.example');
    assert.deepEqual(listed.map(item => [item.name, item.accounts, item.usedBy.includes('accounts-other'), item.usedBy.includes('accounts-primary')]), [['alice', 2, false, true], ['bob', 2, true, false]]);

    // The primary browser's cookies go to the account it uses.
    await server.device(primary, `/accounts/${bob.id}/switch`, 'POST');
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://git.example/', complete: true, cookies: [cookie('user', 'bob-2', 'git.example')] });
    listed = (await server.status()).profiles.filter(item => item.domain === 'git.example');
    assert.deepEqual(listed.map(item => item.cookies.map(entry => entry.name)), [['user'], ['user']]);
    assert.deepEqual((await site(other)).profiles.map(item => item.cookies[0].value), ['bob-2']);
    assert.deepEqual((await site(primary)).profiles.map(item => item.cookies[0].value), ['bob-2']);

    // Only the primary browser adds accounts; the new one starts empty and becomes its account.
    const denied = await server.device(other, '/accounts', 'POST', { name: 'carol', pageUrl: 'https://www.git.example/login' });
    assert.equal(denied.status, 403);
    const created = await server.device(primary, '/accounts', 'POST', { name: 'carol', pageUrl: 'https://www.git.example/login' });
    assert.equal(created.status, 201);
    const carol = (await created.json()).accounts.find(item => item.name === 'carol');
    assert.deepEqual([carol.domain, carol.active, carol.cookieCount], ['git.example', true, 0]);
    assert.equal((await server.device(primary, '/accounts', 'POST', { name: 'CAROL', pageUrl: 'https://git.example/' })).status, 400);
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://git.example/', complete: true, cookies: [cookie('user', 'carol', 'git.example')] });
    listed = (await server.status()).profiles.filter(item => item.domain === 'git.example');
    assert.deepEqual(listed.map(item => [item.name, item.cookies.length]), [['alice', 1], ['bob', 1], ['carol', 1]]);
    assert.equal((await site(other)).accounts.length, 3);

    // An account the browser may not use cannot be selected; a disabled one falls back to the first.
    const hidden = await server.admin('/profiles', 'POST', { name: 'hidden', domain: 'git.example', enabled: true, shareWithAllDevices: false, allowedDeviceIds: [primary.id], cookies: [] });
    assert.equal((await server.device(other, `/accounts/${hidden.id}/switch`, 'POST')).status, 404);
    await server.admin(`/profiles/${bob.id}`, 'PUT', { name: 'bob', domain: 'git.example', enabled: false, cookies: [] });
    assert.deepEqual((await site(other)).profiles.map(item => item.name), ['alice']);
    assert.equal((await server.device(other, `/accounts/${bob.id}/switch`, 'POST')).status, 404);
    const audit = (await server.status()).audit.map(item => item.action);
    assert.ok(audit.includes('account.switched') && audit.includes('account.created'));
    await server.admin('/profiles/delete', 'POST', { ids: [alice.id, bob.id, carol.id, hidden.id] });
  });

  test('the browser unlock code is stored as a hash and survives other settings changes', async () => {
    const device = await server.enroll(randomDeviceId(), 'lock-device');
    const lockOf = async () => (await (await server.device(device, '/snapshot')).json()).settings.clientLock;
    assert.equal((await lockOf()).enabled, false);
    await assert.rejects(server.admin('/client-lock', 'PUT', { enabled: true }), /Enter an unlock code/);
    await assert.rejects(server.admin('/client-lock', 'PUT', { enabled: true, code: 'abc' }), /4 to 128/);
    await server.admin('/client-lock', 'PUT', { enabled: true, code: ' open-sesame ' });
    const lock = await lockOf();
    assert.equal(lock.enabled, true);
    assert.equal(JSON.stringify(lock).includes('open-sesame'), false);
    const { pbkdf2Sync } = await import('node:crypto');
    // Browsers check the code with the same PBKDF2-SHA256 parameters, trimming surrounding spaces.
    const derive = code => pbkdf2Sync(code, Buffer.from(lock.salt, 'base64'), lock.iterations, 32, 'sha256').toString('base64');
    assert.equal(derive('open-sesame'), lock.hash);
    assert.notEqual(derive('open-sesame!'), lock.hash);
    // Saving the other settings keeps the code; turning it off keeps the hash for later.
    await server.settings({ homePage: '' });
    assert.equal((await lockOf()).hash, lock.hash);
    await server.admin('/client-lock', 'PUT', { enabled: false });
    assert.deepEqual([(await lockOf()).enabled, (await lockOf()).hash], [false, lock.hash]);
    await server.admin('/client-lock', 'PUT', { enabled: true });
    await server.admin('/client-lock', 'PUT', { enabled: true, code: 'new-code' });
    assert.notEqual((await lockOf()).hash, lock.hash);
    assert.equal((await server.device(device, '/unlock-report', 'POST', { success: false })).status, 204);
    assert.equal((await server.device(device, '/unlock-report', 'POST', { success: true })).status, 204);
    const audit = (await server.status()).audit.map(item => item.action);
    for (const action of ['client_lock.updated', 'browser.unlocked', 'browser.unlock_failed']) assert.ok(audit.includes(action), action);
    await server.admin('/client-lock', 'PUT', { enabled: false });
  });

  test('a list of shared sites limits what the primary browser shares', async () => {
    const primary = await server.enroll(randomDeviceId(), 'list-primary');
    await server.settings({ primaryDeviceId: primary.id, autoShareCookies: true, autoShareScope: 'all', autoShareDomains: [] });
    const push = (host, value) => server.device(primary, '/sync', 'POST', { pageUrl: `https://${host}/`, complete: true, cookies: [cookie('s', value, host)] });
    await push('old.example', '1');
    assert.ok(await server.profile('old.example'));
    await assert.rejects(server.settings({ autoShareScope: 'listed', autoShareDomains: [] }), /at least one site/);
    await assert.rejects(server.settings({ autoShareScope: 'listed', autoShareDomains: ['not a site'] }), /not a valid site/);
    await server.settings({ autoShareScope: 'listed', autoShareDomains: ['https://Listed.example/login', '*.wild.example', 'listed.example'] });
    assert.deepEqual((await server.status()).settings.autoShareDomains, ['listed.example', 'wild.example']);
    // Listed sites, including subdomains, are shared under the listed domain; others are not.
    await push('www.listed.example', 'a');
    await push('other.example', 'b');
    assert.deepEqual((await server.profile('listed.example')).cookies.map(item => item.domain), ['www.listed.example']);
    assert.equal(await server.profile('www.listed.example'), undefined);
    assert.equal(await server.profile('other.example'), undefined);
    // A profile from before the list is kept but no longer updated, and the dashboard says so.
    await push('old.example', '2');
    const old = (await server.status()).profiles.find(item => item.domain === 'old.example');
    assert.equal(old.listed, false);
    assert.equal((await (await server.device(primary, '/snapshot')).json()).profiles.find(item => item.domain === 'old.example').cookies[0].value, '1');
    assert.equal((await server.status()).profiles.find(item => item.domain === 'listed.example').listed, true);
    // Accounts can only be added for listed sites.
    assert.equal((await server.device(primary, '/accounts', 'POST', { name: 'x', pageUrl: 'https://other.example/' })).status, 400);
    assert.equal((await server.device(primary, '/accounts', 'POST', { name: 'second', pageUrl: 'https://listed.example/' })).status, 201);
    await server.settings({ autoShareScope: 'all', autoShareDomains: [] });
    await server.admin('/profiles/delete', 'POST', { ids: (await server.status()).profiles.filter(item => /(old|listed)\.example$/.test(item.domain)).map(item => item.id) });
  });

  test('a minimum browser version stops outdated browsers until they update', async () => {
    const device = await server.enroll(randomDeviceId(), 'old-browser');
    await assert.rejects(server.settings({ minimumClientVersion: '1.x' }), /must look like/);
    await server.settings({ minimumClientVersion: 'v1.6.0' });
    assert.equal((await server.status()).settings.minimumClientVersion, '1.6.0');
    const sync = () => server.device(device, '/sync', 'POST', { pageUrl: 'https://version.example/', cookies: [] });
    const old = await server.device(device, '/snapshot?version=1.5.0');
    assert.equal(old.status, 426);
    const body = await old.json();
    assert.equal(body.minimumVersion, '1.6.0');
    assert.match(body.error, /1\.6\.0 or newer is required/);
    // Requests that do not carry a version use the one the browser last reported.
    assert.equal((await sync()).status, 426);
    assert.equal((await server.device(device, '/snapshot')).status, 426);
    assert.equal((await server.device(device, '/snapshot?version=1.6.0')).status, 200);
    assert.equal((await sync()).status, 200);
    // Versions compare numerically, and pre-release suffixes are ignored.
    assert.equal((await server.device(device, '/snapshot?version=1.10.0-beta.1')).status, 200);
    assert.equal((await server.device(device, '/snapshot?version=1.5.9')).status, 426);
    await server.settings({ minimumClientVersion: '' });
    assert.equal((await server.device(device, '/snapshot?version=1.0.0')).status, 200);
  });

  test('bookmarks and search URL validation', async () => {
    const saved = await server.admin('/bookmarks', 'PUT', [{ title: '', url: 'https://github.com' }, { title: 'Docs', url: 'https://example.com/docs' }]);
    assert.deepEqual(saved.map(item => item.title), ['github.com', 'Docs']);
    await assert.rejects(server.admin('/bookmarks', 'PUT', [{ title: 'x', url: 'javascript:alert(1)' }]), /invalid/i);
    await assert.rejects(server.settings({ searchUrl: 'https://search.example/' }), /%s/);
  });

  test('announcements reach their browsers and record dismissals', async () => {
    const everyone = await server.enroll(randomDeviceId(), 'reader-1');
    const other = await server.enroll(randomDeviceId(), 'reader-2');
    const visible = async device => (await (await server.device(device, '/snapshot')).json()).announcements;
    const all = await server.admin('/announcements', 'POST', { title: 'Maintenance', message: 'Line one\nLine two', level: 'warning', url: 'https://status.example/', expiresInMinutes: 60 });
    const targeted = await server.admin('/announcements', 'POST', { title: 'Only you', level: 'info', shareWithAllDevices: false, allowedDeviceIds: [everyone.id] });
    const first = await visible(everyone);
    assert.deepEqual(first.map(item => item.title).sort(), ['Maintenance', 'Only you']);
    const maintenance = first.find(item => item.id === all.id);
    assert.equal(maintenance.message, 'Line one\nLine two');
    assert.equal(maintenance.level, 'warning');
    assert.equal(maintenance.url, 'https://status.example/');
    assert.ok(maintenance.expiresAt);
    // Targeting and acknowledgements stay on the server.
    assert.equal(maintenance.allowedDeviceIds, undefined);
    assert.equal(maintenance.acknowledgements, undefined);
    assert.deepEqual((await visible(other)).map(item => item.title), ['Maintenance']);
    // A browser can only acknowledge announcements it was sent.
    assert.equal((await server.device(other, `/announcements/${targeted.id}/ack`, 'POST')).status, 404);
    assert.equal((await server.device(everyone, `/announcements/${all.id}/ack`, 'POST')).status, 204);
    assert.equal((await server.device(everyone, `/announcements/${all.id}/ack`, 'POST')).status, 204);
    const listed = (await server.status()).announcements.find(item => item.id === all.id);
    assert.deepEqual(listed.acknowledgedBy.map(entry => entry.name), ['reader-1']);
    assert.ok(listed.recipients.includes('reader-2'));
    await server.admin(`/announcements/${targeted.id}`, 'DELETE');
    assert.deepEqual((await visible(everyone)).map(item => item.title), ['Maintenance']);
    await server.admin(`/announcements/${all.id}`, 'DELETE');
    assert.deepEqual(await visible(everyone), []);
    const actions = (await server.status()).audit.map(item => item.action);
    assert.ok(actions.includes('announcement.sent') && actions.includes('announcement.deleted'));
  });

  test('announcement validation', async () => {
    await assert.rejects(server.admin('/announcements', 'POST', { title: '', message: '' }), /title or a message/);
    await assert.rejects(server.admin('/announcements', 'POST', { title: 'x', level: 'urgent' }), /Level/);
    await assert.rejects(server.admin('/announcements', 'POST', { title: 'x', url: 'javascript:alert(1)' }), /link/);
    await assert.rejects(server.admin('/announcements', 'POST', { title: 'x', expiresInMinutes: 0 }), /expire/);
    await assert.rejects(server.admin('/announcements', 'POST', { title: 'x'.repeat(121) }), /120/);
    await assert.rejects(server.admin('/announcements', 'POST', { title: 'x', shareWithAllDevices: false, allowedDeviceIds: [] }), /Select at least one/);
  });

  test('server-sent events announce new revisions', async () => {
    const device = await server.enroll(randomDeviceId(), 'listener');
    const controller = new AbortController();
    const response = await server.device(device, '/events');
    assert.equal(response.headers.get('content-type'), 'text/event-stream');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    const readUntil = async pattern => {
      const end = Date.now() + 5000;
      while (!pattern.test(text) && Date.now() < end) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value);
      }
      return pattern.test(text);
    };
    const start = (await server.status()).revision;
    assert.ok(await readUntil(new RegExp(`data: ${start}\\n`)));
    await server.admin('/bookmarks', 'PUT', [{ title: 'SSE', url: 'https://sse.example/' }]);
    assert.ok(await readUntil(new RegExp(`data: ${start + 1}\\n`)), text);
    await reader.cancel();
    controller.abort();
  });

  test('export, import and restore', async () => {
    const exported = await (await server.admin('/export', 'GET', undefined, true)).text();
    const before = await server.status();
    const removed = before.profiles.find(item => item.domain === 'sync.example');
    await server.admin(`/profiles/${removed.id}`, 'DELETE');
    const result = await server.admin('/import', 'POST', exported);
    assert.match(result.result, /before-import/);
    const after = await server.status();
    assert.ok(after.profiles.some(item => item.domain === 'sync.example'));
    assert.ok(after.revision > before.revision);
    // A vault written with a different data key is refused.
    const broken = JSON.parse(exported);
    broken.Profiles.find(item => item.Cookies.length).Cookies[0].Value = 'v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA==.AAAA';
    await assert.rejects(server.admin('/import', 'POST', JSON.stringify(broken)), /data key|decrypt/i);
    const backup = after.backups.find(item => item.name.includes('before-import'));
    await server.admin(`/backups/${backup.name}/restore`, 'POST', {});
    assert.ok(!(await server.status()).profiles.some(item => item.domain === 'sync.example'));
    await assert.rejects(server.admin('/backups/..%2Fstate.json/restore', 'POST', {}), { status: 400 });
  });

  test('backups can be deleted one by one', async () => {
    await server.admin('/profiles', 'POST', { name: 'Backup', domain: 'backup-delete.example', enabled: true, cookies: [] });
    await server.admin('/profiles/purge', 'POST', { confirm: true });
    const status = await server.status();
    assert.ok(status.backupPolicy.keep >= 1 && status.backupPolicy.intervalMinutes >= 1);
    const [first] = status.backups;
    assert.ok(first);
    const remove = name => server.admin(`/backups/${encodeURIComponent(name)}`, 'DELETE', undefined, true);
    assert.equal((await remove(first.name)).status, 204);
    assert.ok(!(await server.status()).backups.some(item => item.name === first.name));
    assert.equal((await remove(first.name)).status, 404);
    assert.equal((await remove('state.json')).status, 400);
    assert.ok((await server.status()).audit.some(item => item.action === 'backup.deleted' && item.target === first.name));
  });

  test('audit log records administration and failed sign-ins', async () => {
    assert.equal((await fetch(`${server.url}/api/admin/status`, { headers: { authorization: 'Bearer wrong' } })).status, 401);
    const actions = (await server.status()).audit.map(item => item.action);
    for (const action of ['enrollment_code.created', 'device.enrolled', 'settings.updated', 'profile.created', 'device.deleted', 'vault.imported', 'vault.restored', 'admin.sign_in_failed']) {
      assert.ok(actions.includes(action), `${action} missing from ${actions.join(', ')}`);
    }
  });

  test('security headers', async () => {
    const response = await fetch(`${server.url}/`);
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await fetch(`${server.url}/api/admin/status`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })).headers.get('cache-control'), 'no-store');
    // Dashboard files are revalidated on every load, so an upgrade never mixes an old script with a new page.
    for (const file of ['/', '/app.js', '/app.css']) assert.equal((await fetch(`${server.url}${file}`)).headers.get('cache-control'), 'no-cache', file);
  });
});

describe('bulk profile deletion', () => {
  let server;
  before(async () => { server = await startServer(); });
  after(async () => { await server?.stop(); });

  test('deletes selected profiles and purges the rest, backing up first', async () => {
    const reader = await server.enroll(randomDeviceId(), 'reader');
    const ids = [];
    for (const domain of ['one.example', 'two.example', 'three.example']) {
      ids.push((await server.admin('/profiles', 'POST', { name: domain, domain, enabled: true, cookies: [cookie('c', '1', domain)] })).id);
    }
    const domains = async () => (await (await server.device(reader, '/snapshot')).json()).profiles.map(item => item.domain).sort();
    assert.deepEqual(await domains(), ['one.example', 'three.example', 'two.example']);

    const revision = (await server.status()).revision;
    const deleted = await server.admin('/profiles/delete', 'POST', { ids: [ids[0], ids[1], 'missing-id'] });
    assert.equal(deleted.deleted, 2);
    assert.match(deleted.backup, /before-delete/);
    assert.deepEqual(await domains(), ['three.example']);
    // One bulk delete is one revision, so browsers apply it in a single step.
    assert.equal((await server.status()).revision, revision + 1);
    await assert.rejects(server.admin('/profiles/delete', 'POST', { ids: [] }), /Select at least one/);
    await assert.rejects(server.admin('/profiles/delete', 'POST', { ids: ['missing-id'] }), { status: 404 });

    await assert.rejects(server.admin('/profiles/purge', 'POST', { confirm: false }), /confirmed/);
    const purged = await server.admin('/profiles/purge', 'POST', { confirm: true });
    assert.equal(purged.deleted, 1);
    assert.match(purged.backup, /before-purge/);
    assert.deepEqual(await domains(), []);
    assert.equal((await server.admin('/profiles/purge', 'POST', { confirm: true })).deleted, 0);

    const status = await server.status();
    assert.ok(status.backups.some(item => item.name === purged.backup));
    const actions = status.audit.map(item => item.action);
    assert.ok(actions.includes('profiles.deleted') && actions.includes('profiles.purged'));
    // The purge can be undone from its backup.
    await server.admin(`/backups/${purged.backup}/restore`, 'POST', {});
    assert.deepEqual(await domains(), ['three.example']);
  });
});

describe('forward proxy', () => {
  let server;
  let device;
  let origin;
  let echo;
  let haveOrigin;
  before(async () => {
    server = await startServer();
    haveOrigin = await publicAddressAvailable();
    if (haveOrigin) {
      origin = await startOrigin();
      echo = await startEcho();
    }
    device = await server.enroll(randomDeviceId(), 'proxy-user');
    const ports = ['80', '443', origin?.port, echo?.port].filter(Boolean).join(',');
    await server.settings({}, { enabled: true, port: server.proxyPort, allowedPorts: ports, tls: false });
    await waitFor(async () => (await server.status()).proxy.listening, { message: 'proxy listening' });
  });
  after(async () => {
    await origin?.close();
    await echo?.close();
    await server?.stop();
  });

  const request = async (head, useTls = false) => {
    const { socket } = await connectProxy(server.proxyPort, useTls);
    socket.write(head);
    const response = await readHead(socket);
    socket.destroy();
    return response;
  };

  test('requires device credentials', async () => {
    assert.equal((await request('GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n')).status, 407);
    assert.equal((await request(`GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ${Buffer.from('a:b').toString('base64')}\r\n\r\n`)).status, 407);
  });

  test('blocks disallowed ports and private destinations', async () => {
    const auth = `Proxy-Authorization: ${basic(device)}\r\n`;
    assert.equal((await request(`GET http://example.com:8081/ HTTP/1.1\r\nHost: example.com:8081\r\n${auth}\r\n`)).status, 403);
    for (const host of ['127.0.0.1', '10.0.0.1', '100.100.100.100', '169.254.169.254', '[::1]', '[64:ff9b::a00:1]']) {
      assert.equal((await request(`GET http://${host}/ HTTP/1.1\r\nHost: ${host}\r\n${auth}\r\n`)).status, 403, host);
    }
  });

  test('an outdated browser can only reach the update servers through the proxy', async () => {
    const auth = `Proxy-Authorization: ${basic(device)}\r\n`;
    await server.settings({ minimumClientVersion: '1.6.0' });
    // This browser never reported a version, so it counts as outdated.
    const refused = await request(`CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n${auth}\r\n`);
    assert.equal(refused.status, 403);
    assert.match(refused.head, /or newer is required/);
    // GitHub passes the version check (and is then refused here only because port 8081 is not allowed).
    const github = await request(`CONNECT github.com:8081 HTTP/1.1\r\nHost: github.com:8081\r\n${auth}\r\n`);
    assert.equal(github.status, 403);
    assert.doesNotMatch(github.head, /or newer is required/);
    await server.settings({ minimumClientVersion: '' });
    assert.doesNotMatch((await request(`CONNECT example.com:8081 HTTP/1.1\r\nHost: example.com:8081\r\n${auth}\r\n`)).head, /or newer is required/);
  });

  test('plain HTTP responses close the connection so credentials never reach the origin', async t => {
    if (!haveOrigin) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const { socket } = await connectProxy(server.proxyPort, false);
    socket.write(`GET http://${PUBLIC_IP}:${origin.port}/first HTTP/1.1\r\nHost: ${PUBLIC_IP}:${origin.port}\r\nProxy-Authorization: ${basic(device)}\r\nProxy-Connection: keep-alive\r\n\r\n`);
    const response = await readHead(socket);
    assert.equal(response.status, 200);
    assert.match(response.head, /^Connection: close$/mi);
    assert.doesNotMatch(response.head, /keep-alive/i);
    // Even a client that ignores "Connection: close" cannot reach the origin with a second request.
    socket.write(`GET http://${PUBLIC_IP}:${origin.port}/second HTTP/1.1\r\nHost: ${PUBLIC_IP}:${origin.port}\r\nProxy-Authorization: ${basic(device)}\r\n\r\n`);
    await sleep(500);
    socket.destroy();
    assert.deepEqual(origin.requests.map(item => item.path), ['/first']);
    assert.ok(origin.requests.every(item => !item.proxyAuthorization));
  });

  test('TLS to the proxy with the advertised certificate', async t => {
    if (!haveOrigin) return t.skip(`${PUBLIC_IP} is not bound locally`);
    await server.settings({}, { tls: true });
    const advertised = (await server.status()).settings.proxy.certificateSha256;
    assert.match(advertised, /^[0-9a-f]{64}$/);
    const { socket, fingerprint } = await connectProxy(server.proxyPort, true);
    assert.equal(fingerprint, advertised);
    socket.write(`CONNECT ${PUBLIC_IP}:${echo.port} HTTP/1.1\r\nHost: ${PUBLIC_IP}:${echo.port}\r\nProxy-Authorization: ${basic(device)}\r\n\r\n`);
    assert.equal((await readHead(socket)).status, 200);
    socket.write('ping');
    const echoed = await new Promise(resolve => socket.once('data', data => resolve(String(data))));
    assert.equal(echoed, 'ping');
    socket.destroy();
    // A plain connection to the TLS proxy gets nowhere.
    const plain = await request(`GET http://${PUBLIC_IP}:${origin.port}/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: ${basic(device)}\r\n\r\n`).catch(() => ({ status: 0 }));
    assert.notEqual(plain.status, 200);
    await server.settings({}, { tls: false });
  });

  test('revoking a device closes its open tunnels', async t => {
    if (!haveOrigin) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const victim = await server.enroll(randomDeviceId(), 'victim');
    const { socket } = await connectProxy(server.proxyPort, false);
    socket.write(`CONNECT ${PUBLIC_IP}:${echo.port} HTTP/1.1\r\nHost: ${PUBLIC_IP}:${echo.port}\r\nProxy-Authorization: ${basic(victim)}\r\n\r\n`);
    assert.equal((await readHead(socket)).status, 200);
    const closed = new Promise(resolve => socket.once('close', resolve));
    const started = Date.now();
    await server.admin(`/devices/${victim.id}/revoke`, 'POST', {});
    await Promise.race([closed, sleep(12000).then(() => { throw new Error('tunnel stayed open'); })]);
    assert.ok(Date.now() - started < 12000);
  });
});

describe('connection policy, egress and per-browser proxy limits', () => {
  let server;
  let echo;
  let origin;
  let havePublic;
  let haveSource;

  // Opens a CONNECT tunnel to the echo server; resolves with the socket once the proxy answers 200.
  const tunnel = async device => {
    const { socket } = await connectProxy(server.proxyPort, false);
    socket.write(`CONNECT ${PUBLIC_IP}:${echo.port} HTTP/1.1\r\nHost: ${PUBLIC_IP}:${echo.port}\r\nProxy-Authorization: ${basic(device)}\r\n\r\n`);
    const response = await readHead(socket);
    return { socket, status: response.status, head: response.head };
  };
  // Sends bytes through a tunnel and waits until the echo has returned all of them.
  const roundTrip = (socket, size) => new Promise((resolve, reject) => {
    let received = 0;
    const onData = chunk => { received += chunk.length; if (received >= size) { socket.off('data', onData); resolve(); } };
    socket.on('data', onData).once('error', reject);
    socket.write(Buffer.alloc(size, 7));
  });
  const usageOf = async device => (await server.status()).devices.find(item => item.id === device.id).usage;

  before(async () => {
    server = await startServer();
    havePublic = await publicAddressAvailable();
    haveSource = havePublic && await publicAddressAvailable(SOURCE_IP);
    if (havePublic) {
      echo = await startEcho();
      origin = await startOrigin();
    }
    const ports = ['80', '443', echo?.port, origin?.port].filter(Boolean).join(',');
    await server.settings({}, { enabled: true, port: server.proxyPort, allowedPorts: ports, tls: false });
    await waitFor(async () => (await server.status()).proxy.listening, { message: 'proxy listening' });
  });
  after(async () => {
    await echo?.close();
    await origin?.close();
    await server?.stop();
  });

  test('strict is the default connection policy and browsers report their version and mode', async () => {
    const status = await server.status();
    assert.equal(status.settings.networkPolicy, 'strict');
    assert.equal(status.settings.ipCheckUrl, 'https://api64.ipify.org?format=json');
    await assert.rejects(server.settings({ networkPolicy: 'sometimes' }), /choice, managed or strict/);
    const device = await server.enroll(randomDeviceId(), 'reporter');
    assert.equal((await server.device(device, '/snapshot?version=1.3.0&mode=strict')).status, 200);
    const listed = (await server.status()).devices.find(item => item.id === device.id);
    assert.equal(listed.clientVersion, '1.3.0');
    assert.equal(listed.networkMode, 'strict');
    // Browsers receive the policy with their snapshot.
    assert.equal((await (await server.device(device, '/snapshot')).json()).settings.networkPolicy, 'strict');
  });

  test('limit validation', async () => {
    await assert.rejects(server.settings({}, { monthlyQuotaGb: -1 }), /between 0/);
    await assert.rejects(server.settings({}, { egressAddressFamily: 'ipx' }), /any, ipv4 or ipv6/);
    await assert.rejects(server.settings({}, { egressSourceAddress: 'not-an-ip' }), /IP address/);
    await assert.rejects(server.settings({}, { egressAddressFamily: 'ipv6', egressSourceAddress: '127.0.0.1' }), /does not match/);
    const device = await server.enroll(randomDeviceId(), 'limited');
    await assert.rejects(server.admin(`/devices/${device.id}/limits`, 'PUT', { maxConnections: -3 }), /between 0/);
    await server.admin(`/devices/${device.id}/limits`, 'PUT', { maxConnections: 2, monthlyQuotaGb: null, rateLimitMbps: 0 });
    const listed = (await server.status()).devices.find(item => item.id === device.id);
    assert.deepEqual(listed.limitOverrides, { maxConnections: 2, monthlyQuotaGb: null, rateLimitMbps: 0 });
    assert.ok((await server.status()).audit.some(entry => entry.action === 'device.limits_updated'));
  });

  test('usage is counted per browser with its top sites', async t => {
    if (!havePublic) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const device = await server.enroll(randomDeviceId(), 'counter');
    const { socket, status } = await tunnel(device);
    assert.equal(status, 200);
    await roundTrip(socket, 50_000);
    socket.destroy();
    await waitFor(async () => (await usageOf(device)).activeConnections === 0, { message: 'connection closed' });
    const usage = await usageOf(device);
    assert.ok(usage.bytesUp >= 50_000 && usage.bytesDown >= 50_000, JSON.stringify(usage));
    assert.equal(usage.connections, 1);
    assert.equal(usage.topHosts[0].host, PUBLIC_IP);
    assert.match(usage.month, /^\d{4}-\d{2}$/);
  });

  test('a browser cannot open more connections than its limit', async t => {
    if (!havePublic) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const device = await server.enroll(randomDeviceId(), 'one-at-a-time');
    await server.admin(`/devices/${device.id}/limits`, 'PUT', { maxConnections: 1 });
    const first = await tunnel(device);
    assert.equal(first.status, 200);
    const second = await tunnel(device);
    assert.equal(second.status, 429);
    second.socket.destroy();
    first.socket.destroy();
    await waitFor(async () => (await usageOf(device)).activeConnections === 0, { message: 'slot released' });
    const third = await tunnel(device);
    assert.equal(third.status, 200);
    third.socket.destroy();
  });

  test('the monthly quota stops new and open connections', async t => {
    if (!havePublic) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const device = await server.enroll(randomDeviceId(), 'quota');
    await server.admin(`/devices/${device.id}/limits`, 'PUT', { monthlyQuotaGb: 0.00002 }); // 20 kB
    const open = await tunnel(device);
    assert.equal(open.status, 200);
    const closed = new Promise(resolve => open.socket.once('close', resolve));
    await roundTrip(open.socket, 30_000);
    await Promise.race([closed, sleep(12000).then(() => { throw new Error('tunnel stayed open over quota'); })]);
    const refused = await tunnel(device);
    assert.equal(refused.status, 403);
    assert.match(refused.head, /quota/i);
    refused.socket.destroy();
    assert.ok((await server.status()).audit.some(entry => entry.action === 'proxy.quota_reached'));
  });

  test('the rate limit slows a browser down, and lifting it restores full speed', async t => {
    if (!havePublic) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const device = await server.enroll(randomDeviceId(), 'slow');
    await server.admin(`/devices/${device.id}/limits`, 'PUT', { rateLimitMbps: 2 }); // 250 kB/s for both directions together
    const slow = await tunnel(device);
    let started = Date.now();
    await roundTrip(slow.socket, 500_000);
    const limited = Date.now() - started;
    slow.socket.destroy();
    assert.ok(limited >= 2000, `took only ${limited} ms`);
    await server.admin(`/devices/${device.id}/limits`, 'PUT', { rateLimitMbps: null });
    const fast = await tunnel(device);
    started = Date.now();
    await roundTrip(fast.socket, 500_000);
    const unlimited = Date.now() - started;
    fast.socket.destroy();
    assert.ok(unlimited < limited / 2, `limited ${limited} ms, unlimited ${unlimited} ms`);
  });

  test('egress family and source address decide how the proxy reaches websites', async t => {
    if (!havePublic) return t.skip(`${PUBLIC_IP} is not bound locally`);
    const device = await server.enroll(randomDeviceId(), 'egress');
    await server.settings({}, { egressAddressFamily: 'ipv6' });
    const v6 = await tunnel(device);
    assert.equal(v6.status, 502);
    assert.match(v6.head, /IPv6/);
    v6.socket.destroy();
    await server.settings({}, { egressAddressFamily: 'ipv4' });
    const v4 = await tunnel(device);
    assert.equal(v4.status, 200);
    v4.socket.destroy();
    if (!haveSource) return t.skip(`${SOURCE_IP} is not bound locally`);
    await server.settings({ ipCheckUrl: `http://${PUBLIC_IP}:${origin.port}/ip` }, { egressSourceAddress: SOURCE_IP });
    const check = await server.admin('/egress-ip', 'POST', {});
    assert.equal(check.ip, SOURCE_IP);
    // Plain-HTTP requests through the proxy leave from the same source address.
    const { socket } = await connectProxy(server.proxyPort, false);
    socket.write(`GET http://${PUBLIC_IP}:${origin.port}/ip HTTP/1.1\r\nHost: ${PUBLIC_IP}:${origin.port}\r\nProxy-Authorization: ${basic(device)}\r\n\r\n`);
    const response = await readHead(socket);
    socket.destroy();
    assert.equal(response.status, 200);
    assert.equal(origin.requests.at(-1).remote, SOURCE_IP);
    await server.settings({}, { egressAddressFamily: 'any', egressSourceAddress: '' });
  });

  test('the egress check reports a bad IP check URL clearly', async () => {
    await server.settings({ ipCheckUrl: '' });
    await assert.rejects(server.admin('/egress-ip', 'POST', {}), /IP check URL/);
  });
});

describe('alerts, session health, remote actions and per-browser settings', () => {
  let server;
  let capture;
  let primary;
  let other;
  const now = () => Math.floor(Date.now() / 1000);
  before(async () => {
    capture = await startCapture();
    server = await startServer({ env: { SHARED_BROWSER_TELEGRAM_API: capture.url, SHARED_BROWSER_LINE_API: capture.url, SHARED_BROWSER_HEALTH_INTERVAL_SECONDS: '1' } });
    primary = await server.enroll(randomDeviceId(), 'alert-primary');
    other = await server.enroll(randomDeviceId(), 'alert-other');
    await server.settings({ primaryDeviceId: primary.id });
  });
  after(async () => {
    await server?.stop();
    await capture?.close();
  });
  // Each Discord alert is an embed; flatten its title and fields into text for the assertions.
  const discord = () => capture.requests.filter(item => item.url.startsWith('/api/webhooks/')).map(item => {
    const body = JSON.parse(item.text);
    const embed = body.embeds?.[0] || {};
    return { ...body, embed, content: [embed.title, ...(embed.fields || []).map(field => `${field.name}: ${field.value}`)].join('\n') };
  });

  test('notification settings are validated, kept secret and can be tested', async () => {
    await assert.rejects(server.admin('/notifications', 'PUT', { discordWebhookUrl: 'https://example.com/hook', events: [], offlineMinutes: 30, expiryWarningDays: 3 }), /discord\.com\/api\/webhooks/);
    await assert.rejects(server.admin('/notifications', 'PUT', { telegramBotToken: 'nope', events: [], offlineMinutes: 30, expiryWarningDays: 3 }), /Telegram bot token/);
    const hook = `${capture.url}/api/webhooks/1/secret-token`;
    const saved = await server.admin('/notifications', 'PUT', {
      discordWebhookUrl: hook, telegramBotToken: '123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ', telegramChatId: '-1001', lineChannelToken: 'line-token', lineTo: 'U123',
      events: ['session.lost', 'session.expiring', 'device.enrolled', 'browser.unlock_failed', 'backup.failed', 'bogus'], offlineMinutes: 30, expiryWarningDays: 3
    });
    assert.equal(saved.discordWebhookUrl, '••••••••');
    assert.ok(!saved.events.includes('bogus'));
    const status = JSON.stringify(await server.status());
    assert.ok(!status.includes('secret-token') && !status.includes('ABCDEFGHIJ') && !status.includes('line-token'));
    // Secrets are encrypted in the vault file and never reach browsers.
    const vault = fs.readFileSync(path.join(server.data, 'state.json'), 'utf8');
    assert.ok(!vault.includes('secret-token') && !vault.includes('line-token'));
    assert.ok(!JSON.stringify(await (await server.device(other, '/snapshot')).json()).includes('webhooks'));
    // Saving with the masked values keeps the stored secrets.
    await server.admin('/notifications', 'PUT', { ...saved, telegramChatId: '-1001', events: saved.events });
    const test = await server.admin('/notifications/test', 'POST', {});
    assert.deepEqual(test.results.map(item => [item.channel, item.ok]), [['Discord', true], ['Telegram', true], ['LINE', true]]);
    const [message] = discord();
    assert.match(message.content, /Test notification/);
    assert.deepEqual(message.allowed_mentions, { parse: [] });
    const telegram = capture.requests.find(item => item.url === '/bot123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ/sendMessage');
    assert.equal(JSON.parse(telegram.text).chat_id, '-1001');
    const line = capture.requests.find(item => item.url === '/v2/bot/message/push');
    assert.equal(line.headers.authorization, 'Bearer line-token');
    assert.equal(JSON.parse(line.text).to, 'U123');
  });

  test('enrollments and wrong unlock codes raise alerts', async () => {
    await server.enroll(randomDeviceId(), 'alert-new');
    await waitFor(() => discord().some(item => /New browser enrolled/.test(item.content) && /alert-new/.test(item.content)), { message: 'enrollment alert' });
    await server.device(other, '/unlock-report', 'POST', { success: false });
    await waitFor(() => discord().some(item => /Wrong unlock code/.test(item.content) && /alert-other/.test(item.content)), { message: 'unlock alert' });
  });

  test('session health, expiry warnings and sign-out alerts', async () => {
    const push = cookies => server.device(primary, '/sync', 'POST', { pageUrl: 'https://health.example/', complete: true, cookies });
    // An anti-bot cookie that lives 30 minutes is not the sign-in; the 2-day session cookie is, and expires within 3 days.
    await push([
      cookie('user_session', 's1', 'health.example', { expiresAt: now() + 2 * 86400 }),
      cookie('__cf_bm', 'x', 'health.example', { expiresAt: now() + 1800 }),
      cookie('theme', 'dark', 'health.example', { httpOnly: false, expiresAt: now() + 365 * 86400 })
    ]);
    let profile = await server.profile('health.example');
    assert.equal(profile.health.state, 'expiring');
    assert.ok(Math.abs(Date.parse(profile.health.expiresAt) / 1000 - (now() + 2 * 86400)) < 60);
    await waitFor(() => discord().some(item => /expires soon/.test(item.content) && /health\.example/.test(item.content)), { message: 'expiry alert' });
    // Naming the session cookie in the profile overrides the guess.
    await server.admin(`/profiles/${profile.id}`, 'PUT', { name: profile.name, domain: profile.domain, enabled: true, sessionCookie: 'theme', cookies: profile.cookies.map(item => ({ ...item, value: '' })) });
    profile = await server.profile('health.example');
    assert.deepEqual([profile.sessionCookie, profile.health.state], ['theme', 'ok']);
    await server.admin(`/profiles/${profile.id}`, 'PUT', { name: profile.name, domain: profile.domain, enabled: true, sessionCookie: '', cookies: profile.cookies.map(item => ({ ...item, value: '' })) });
    // Signing out on the primary browser removes the sign-in cookies: that is an alert.
    await push([cookie('theme', 'dark', 'health.example', { httpOnly: false, expiresAt: now() + 365 * 86400 })]);
    assert.equal((await server.profile('health.example')).health.state, 'signed-out');
    await waitFor(() => discord().some(item => /signed out/.test(item.content) && /health\.example/.test(item.content) && /alert-primary/.test(item.content)), { message: 'sign-out alert' });
    assert.ok((await server.status()).audit.some(item => item.action === 'session.lost'));
  });

  test('remote actions are delivered once and acknowledged', async () => {
    const send = body => server.admin(`/devices/${other.id}/commands`, 'POST', body);
    await assert.rejects(send({ type: 'format-disk' }), /Unknown action/);
    await assert.rejects(send({ type: 'open-url', argument: 'javascript:alert(1)' }), /HTTP or HTTPS/);
    const before = (await server.status()).revision;
    const lock = await send({ type: 'lock' });
    const open = await send({ type: 'open-url', argument: 'https://example.com/welcome' });
    const clear = await send({ type: 'clear-site', argument: 'https://www.GitHub.com/login' });
    assert.equal(clear.argument, 'www.github.com');
    assert.ok((await server.status()).revision > before);
    const commands = (await (await server.device(other, '/snapshot')).json()).commands;
    assert.deepEqual(commands.map(item => item.type), ['lock', 'open-url', 'clear-site']);
    assert.deepEqual((await (await server.device(primary, '/snapshot')).json()).commands, []);
    assert.equal((await server.device(other, `/commands/${lock.id}/ack`, 'POST')).status, 204);
    assert.equal((await server.admin(`/devices/${other.id}/commands/${open.id}`, 'DELETE', undefined, true)).status, 204);
    const device = (await server.status()).devices.find(item => item.id === other.id);
    assert.deepEqual(device.pendingCommands.map(item => item.type), ['clear-site']);
    const audit = (await server.status()).audit.map(item => item.action);
    for (const action of ['device.command_sent', 'device.command_done', 'device.command_cancelled']) assert.ok(audit.includes(action), action);
  });

  test('browsing controls: shared settings and per-browser overrides', async () => {
    await assert.rejects(server.settings({ siteFilter: { mode: 'allow', domains: [] } }), /at least one site/);
    await assert.rejects(server.settings({ schedule: { enabled: true, days: [1], start: '9am', end: '18:00', timeZone: 'Asia/Bangkok' } }), /HH:mm/);
    await assert.rejects(server.settings({ schedule: { enabled: true, days: [1], start: '09:00', end: '18:00', timeZone: 'Mars/Base' } }), /Unknown time zone/);
    await server.settings({
      homePage: 'https://home.example/',
      siteFilter: { mode: 'block', domains: ['https://Bad.example/x'] },
      schedule: { enabled: true, days: [1, 2, 3, 4, 5, 9], start: '08:30', end: '17:30', timeZone: 'Asia/Bangkok' },
      dataControls: { blockDownloads: true, blockUploads: false, blockCopy: true, domains: ['*.secret.example'] }
    });
    let settings = (await (await server.device(other, '/snapshot')).json()).settings;
    assert.deepEqual(settings.siteFilter, { mode: 'block', domains: ['bad.example'] });
    assert.deepEqual([settings.schedule.enabled, settings.schedule.days], [true, [1, 2, 3, 4, 5]]);
    assert.deepEqual(settings.dataControls, { blockDownloads: true, blockUploads: false, blockCopy: true, domains: ['secret.example'] });
    await assert.rejects(server.admin(`/devices/${other.id}/settings`, 'PUT', { homePage: 'ftp://x', scheduleExempt: false }), /HTTP or HTTPS/);
    await server.admin(`/devices/${other.id}/settings`, 'PUT', { homePage: 'https://desk.example/', siteFilter: { mode: 'allow', domains: ['work.example'] }, scheduleExempt: true });
    settings = (await (await server.device(other, '/snapshot')).json()).settings;
    assert.equal(settings.homePage, 'https://desk.example/');
    assert.deepEqual(settings.siteFilter, { mode: 'allow', domains: ['work.example'] });
    assert.equal(settings.schedule.enabled, false);
    // The other browser keeps the shared settings.
    const shared = (await (await server.device(primary, '/snapshot')).json()).settings;
    assert.deepEqual([shared.homePage, shared.siteFilter.mode, shared.schedule.enabled], ['https://home.example/', 'block', true]);
    await server.admin(`/devices/${other.id}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false });
    assert.equal((await (await server.device(other, '/snapshot')).json()).settings.homePage, 'https://home.example/');
    await server.settings({ homePage: '', siteFilter: { mode: 'off', domains: [] }, schedule: { enabled: false, days: [1], start: '09:00', end: '18:00', timeZone: 'Asia/Bangkok' }, dataControls: { blockDownloads: false, blockUploads: false, blockCopy: false, domains: [] } });
  });

  test('bookmarks keep their folders, and the idle lock is part of the unlock code', async () => {
    await server.admin('/bookmarks', 'PUT', [{ title: 'Repo', url: 'https://git.example/', folder: ' Work ' }, { title: 'News', url: 'https://news.example/' }]);
    assert.deepEqual((await (await server.device(other, '/snapshot')).json()).bookmarks.map(item => item.folder), ['Work', '']);
    await assert.rejects(server.admin('/client-lock', 'PUT', { enabled: true, code: 'abcd', idleMinutes: 5000 }), /1440/);
    await server.admin('/client-lock', 'PUT', { enabled: true, code: 'abcd', idleMinutes: 10, lockOnSystemLock: true });
    const lock = (await (await server.device(other, '/snapshot')).json()).settings.clientLock;
    assert.deepEqual([lock.idleMinutes, lock.lockOnSystemLock], [10, true]);
    await server.admin('/client-lock', 'PUT', { enabled: false });
  });

  test('backups are copied to S3-compatible storage with a valid signature', async () => {
    const storage = await startCapture(request => request.headers.authorization?.includes('Credential=BADKEY/') ? 403 : 200);
    try {
      await assert.rejects(server.admin('/offsite-backup', 'PUT', { enabled: true, endpoint: 'http://storage.example', region: 'sgp1', bucket: 'vault', prefix: 'sb', accessKeyId: 'AK', secretAccessKey: 'SK' }), /HTTPS address/);
      await assert.rejects(server.admin('/offsite-backup', 'PUT', { enabled: true, endpoint: storage.url, region: 'sgp1', bucket: 'vault', prefix: 'sb', accessKeyId: '', secretAccessKey: '' }), /Enter the endpoint/);
      const saved = await server.admin('/offsite-backup', 'PUT', { enabled: true, endpoint: storage.url, region: 'sgp1', bucket: 'vault', prefix: 'sb', accessKeyId: 'AKTEST', secretAccessKey: 'super-secret' });
      assert.deepEqual([saved.prefix, saved.secretAccessKey], ['sb/', '••••••••']);
      assert.ok(!fs.readFileSync(path.join(server.data, 'state.json'), 'utf8').includes('super-secret'));
      // A bulk delete takes a backup, which is uploaded on its own.
      await server.admin('/profiles', 'POST', { name: 'Offsite', domain: 'offsite.example', enabled: true, cookies: [] });
      await server.admin('/profiles/purge', 'POST', { confirm: true });
      await waitFor(() => storage.requests.some(item => /^\/vault\/sb\/state-.*-before-purge\.json$/.test(item.url)), { message: 'automatic upload' });
      const upload = storage.requests.find(item => /before-purge/.test(item.url));
      assert.equal(upload.method, 'PUT');
      assert.equal(upload.headers['x-amz-content-sha256'], crypto.createHash('sha256').update(upload.body).digest('hex'));
      // Recompute the AWS Signature Version 4 the way S3 does.
      const auth = /^AWS4-HMAC-SHA256 Credential=AKTEST\/(\d{8})\/sgp1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=([0-9a-f]{64})$/.exec(upload.headers.authorization);
      assert.ok(auth, upload.headers.authorization);
      const canonical = `PUT\n${upload.url}\n\nhost:${upload.headers.host}\nx-amz-content-sha256:${upload.headers['x-amz-content-sha256']}\nx-amz-date:${upload.headers['x-amz-date']}\n\nhost;x-amz-content-sha256;x-amz-date\n${upload.headers['x-amz-content-sha256']}`;
      const toSign = `AWS4-HMAC-SHA256\n${upload.headers['x-amz-date']}\n${auth[1]}/sgp1/s3/aws4_request\n${crypto.createHash('sha256').update(canonical).digest('hex')}`;
      const hmac = (key, value) => crypto.createHmac('sha256', key).update(value).digest();
      const signingKey = hmac(hmac(hmac(hmac('AWS4super-secret', auth[1]), 'sgp1'), 's3'), 'aws4_request');
      assert.equal(crypto.createHmac('sha256', signingKey).update(toSign).digest('hex'), auth[2]);
      assert.ok(Array.isArray(JSON.parse(upload.text).Profiles));
      await waitFor(async () => (await server.status()).offsiteBackup.lastUploadName.includes('before-purge'), { message: 'upload recorded' });
      // A rejected upload is reported in the dashboard and as an alert.
      await server.admin('/offsite-backup', 'PUT', { ...saved, accessKeyId: 'BADKEY' });
      const failed = await server.admin('/offsite-backup/upload', 'POST', {}, true);
      assert.equal(failed.status, 400);
      assert.match((await failed.json()).error, /403 \(AccessDenied\)/);
      assert.match((await server.status()).offsiteBackup.lastError, /AccessDenied/);
      await waitFor(() => discord().some(item => /Backup failed/.test(item.content)), { message: 'backup alert' });
      await server.admin('/offsite-backup', 'PUT', { ...saved, enabled: false, secretAccessKey: '' });
    } finally {
      await storage.close();
    }
  });
});

describe('detailed alerts, pinned announcements, account assignment and backup clean-up', () => {
  let server;
  let capture;
  before(async () => {
    capture = await startCapture();
    server = await startServer({ env: { SHARED_BROWSER_HEALTH_INTERVAL_SECONDS: '1' } });
  });
  after(async () => {
    await server?.stop();
    await capture?.close();
  });
  const embeds = () => capture.requests.map(item => JSON.parse(item.text).embeds?.[0]).filter(Boolean);
  const field = (embed, name) => embed.fields.find(item => item.name === name)?.value;

  test('alerts name the browser with its ID and version, the address and the time, for many more events', async () => {
    const saved = await server.admin('/notifications', 'PUT', { discordWebhookUrl: `${capture.url}/api/webhooks/9/x`, events: ['browser.unlock_failed', 'admin.sign_in_failed', 'device.revoked', 'account.switched'], offlineMinutes: 30, expiryWarningDays: 3 });
    assert.ok(saved.catalog.length > 20 && saved.catalog.every(item => item.key && item.title && item.group));
    assert.ok(saved.catalog.find(item => item.key === 'device.online'));
    // A fresh vault starts with the important events switched on.
    const device = await server.enroll(randomDeviceId(), 'front-desk');
    await server.device(device, '/snapshot?version=1.8.0');
    await server.device(device, '/unlock-report', 'POST', { success: false });
    await waitFor(() => embeds().some(item => /Wrong unlock code/.test(item.title)), { message: 'unlock alert' });
    const unlock = embeds().find(item => /Wrong unlock code/.test(item.title));
    assert.match(field(unlock, 'Browser'), new RegExp(`^front-desk \\(id ${device.id.slice(0, 8)}, v1\\.8\\.0\\)$`));
    assert.equal(field(unlock, 'IP address'), '127.0.0.1');
    assert.match(field(unlock, 'Time'), /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \(/);
    assert.ok(unlock.timestamp && unlock.color);
    // A failed administrator sign-in is a security alert.
    await fetch(`${server.url}/api/admin/status`, { headers: { authorization: 'Bearer wrong' } });
    await waitFor(() => embeds().some(item => /Failed administrator sign-in/.test(item.title)), { message: 'sign-in alert' });
    assert.equal(field(embeds().find(item => /Failed administrator sign-in/.test(item.title)), 'By'), 'Unknown (not signed in)');
    await server.admin(`/devices/${device.id}/revoke`, 'POST', {});
    await waitFor(() => embeds().some(item => /Browser revoked/.test(item.title) && field(item, 'By') === 'Administrator (dashboard)'), { message: 'revoke alert' });
  });

  test('pinned announcements reach browsers marked as pinned, first, and can be unpinned', async () => {
    const device = await server.enroll(randomDeviceId(), 'pin-reader');
    await server.admin('/announcements', 'POST', { title: 'Normal', message: 'one' });
    const pinned = await server.admin('/announcements', 'POST', { title: 'Always here', message: 'two', pinned: false });
    await server.admin(`/announcements/${pinned.id}/pin`, 'PUT', { pinned: true });
    let list = (await (await server.device(device, '/snapshot')).json()).announcements;
    assert.deepEqual(list.map(item => [item.title, item.pinned]), [['Always here', true], ['Normal', false]]);
    assert.equal((await server.status()).announcements[0].pinned, true);
    await server.admin(`/announcements/${pinned.id}/pin`, 'PUT', { pinned: false });
    list = (await (await server.device(device, '/snapshot')).json()).announcements;
    assert.equal(list.find(item => item.title === 'Always here').pinned, false);
    assert.equal((await server.admin('/announcements/nope/pin', 'PUT', { pinned: true }, true)).status, 404);
    const audit = (await server.status()).audit.map(item => item.action);
    assert.ok(audit.includes('announcement.pinned') && audit.includes('announcement.unpinned'));
  });

  test('the administrator can see and set the account a browser uses; same-named browsers are told apart', async () => {
    const one = await server.enroll(randomDeviceId(), 'default');
    const two = await server.enroll(randomDeviceId(), 'default');
    await server.admin('/profiles', 'POST', { name: 'Anuwat', domain: 'assign.example', enabled: true, cookies: [cookie('s', 'a', 'assign.example')] });
    const napon = await server.admin('/profiles', 'POST', { name: 'Napon', domain: 'assign.example', enabled: true, cookies: [cookie('s', 'n', 'assign.example')] });
    const usedBy = async name => (await server.status()).profiles.find(item => item.name === name).usedBy;
    assert.ok((await usedBy('Anuwat')).includes(`default (${one.id.slice(0, 6)})`));
    const accounts = (await server.status()).devices.find(item => item.id === one.id).accounts.find(item => item.domain === 'assign.example');
    assert.deepEqual(accounts.options.map(item => item.name), ['Anuwat', 'Napon']);
    await assert.rejects(server.admin(`/devices/${one.id}/commands`, 'POST', { type: 'switch-account', argument: 'missing' }), /not available/);
    const command = await server.admin(`/devices/${one.id}/commands`, 'POST', { type: 'switch-account', argument: napon.id });
    // The browser runs the switch itself; when it does, the dashboard follows.
    assert.deepEqual((await (await server.device(one, '/snapshot')).json()).commands.map(item => [item.type, item.argument]), [['switch-account', napon.id]]);
    await server.device(one, `/accounts/${napon.id}/switch`, 'POST');
    await server.device(one, `/commands/${command.id}/ack`, 'POST');
    assert.ok((await usedBy('Napon')).includes(`default (${one.id.slice(0, 6)})`));
    assert.ok((await usedBy('Anuwat')).includes(`default (${two.id.slice(0, 6)})`));
    assert.equal((await server.status()).devices.find(item => item.id === one.id).accounts[0].activeId, napon.id);
  });

  test('backups can be deleted in bulk or purged with confirmation', async () => {
    for (let index = 0; index < 3; index++) {
      await server.admin('/profiles', 'POST', { name: `B${index}`, domain: `b${index}.example`, enabled: true, cookies: [] });
      await server.admin('/profiles/purge', 'POST', { confirm: true });
      await sleep(1100);
    }
    let backups = (await server.status()).backups;
    assert.ok(backups.length >= 3);
    assert.equal((await server.admin('/backups/delete', 'POST', { names: [] }, true)).status, 400);
    assert.equal((await server.admin('/backups/delete', 'POST', { names: ['../state.json'] }, true)).status, 400);
    const result = await server.admin('/backups/delete', 'POST', { names: backups.slice(0, 2).map(item => item.name) });
    assert.equal(result.deleted, 2);
    backups = (await server.status()).backups;
    assert.equal((await server.admin('/backups/purge', 'POST', { confirm: false }, true)).status, 400);
    assert.equal((await server.admin('/backups/purge', 'POST', { confirm: true })).deleted, backups.length);
    assert.deepEqual((await server.status()).backups, []);
    assert.ok((await server.status()).audit.some(item => item.action === 'backups.purged'));
  });
});

describe('several primary browsers, per-browser unlock code and session expiry for browsers', () => {
  let server;
  before(async () => { server = await startServer(); });
  after(async () => { await server?.stop(); });
  const now = () => Math.floor(Date.now() / 1000);

  test('each primary browser publishes into the account it uses; an older dashboard can still set one', async () => {
    const a = await server.enroll(randomDeviceId(), 'primary-a');
    const b = await server.enroll(randomDeviceId(), 'primary-b');
    const reader = await server.enroll(randomDeviceId(), 'reader');
    await server.settings({ primaryDeviceIds: [a.id, b.id], primaryDeviceId: a.id });
    let settings = (await server.status()).settings;
    assert.deepEqual([settings.primaryDeviceIds, settings.primaryDeviceId], [[a.id, b.id], a.id]);
    assert.deepEqual((await server.status()).devices.filter(item => item.primary).map(item => item.name).sort(), ['primary-a', 'primary-b']);
    const one = await server.admin('/profiles', 'POST', { name: 'one', domain: 'multi.example', enabled: true, cookies: [] });
    const two = await server.admin('/profiles', 'POST', { name: 'two', domain: 'multi.example', enabled: true, cookies: [] });
    await server.device(b, `/accounts/${two.id}/switch`, 'POST');
    const push = (device, value) => server.device(device, '/sync', 'POST', { pageUrl: 'https://multi.example/', complete: true, cookies: [cookie('s', value, 'multi.example')] });
    await push(a, 'from-a');
    await push(b, 'from-b');
    await push(reader, 'from-reader');
    const profiles = (await server.status()).profiles.filter(item => item.domain === 'multi.example');
    assert.deepEqual(profiles.map(item => [item.name, item.cookies.length, item.primaries]), [['one', 1, ['primary-a']], ['two', 1, ['primary-b']]]);
    assert.equal((await (await server.device(reader, '/snapshot')).json()).profiles.find(item => item.domain === 'multi.example').cookies[0].value, 'from-a');
    // Both primaries on one account are flagged.
    await server.device(b, `/accounts/${one.id}/switch`, 'POST');
    assert.deepEqual((await server.status()).profiles.find(item => item.id === one.id).primaries.sort(), ['primary-a', 'primary-b']);
    // Any primary may add an account; the reader may not.
    assert.equal((await server.device(b, '/accounts', 'POST', { name: 'three', pageUrl: 'https://multi.example/' })).status, 201);
    assert.equal((await server.device(reader, '/accounts', 'POST', { name: 'four', pageUrl: 'https://multi.example/' })).status, 403);
    // A script that only knows primaryDeviceId replaces the list; clearing it clears the list.
    await server.settings({ primaryDeviceId: reader.id });
    settings = (await server.status()).settings;
    assert.deepEqual(settings.primaryDeviceIds, [reader.id]);
    await server.settings({ primaryDeviceIds: [a.id, b.id], primaryDeviceId: a.id });
    await server.admin(`/devices/${a.id}`, 'DELETE');
    settings = (await server.status()).settings;
    assert.deepEqual([settings.primaryDeviceIds, settings.primaryDeviceId], [[b.id], b.id]);
    const unknown = randomDeviceId();
    await assert.rejects(server.settings({ primaryDeviceIds: [b.id, unknown], primaryDeviceId: b.id }), /active enrolled/);
  });

  test('the unlock code can be switched on or off for one browser', async () => {
    const always = await server.enroll(randomDeviceId(), 'locked-one');
    const never = await server.enroll(randomDeviceId(), 'open-one');
    const lockOf = async device => (await (await server.device(device, '/snapshot')).json()).settings.clientLock.enabled;
    await assert.rejects(server.admin(`/devices/${always.id}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: true }), /Set an unlock code/);
    await server.admin('/client-lock', 'PUT', { enabled: false, code: 'secret-code' });
    await server.admin(`/devices/${always.id}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: true });
    await server.admin(`/devices/${never.id}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: false });
    assert.deepEqual([await lockOf(always), await lockOf(never)], [true, false]);
    await server.admin('/client-lock', 'PUT', { enabled: true });
    assert.deepEqual([await lockOf(always), await lockOf(never)], [true, false]);
    assert.equal((await server.status()).devices.find(item => item.id === never.id).unlockCode, false);
    await server.admin(`/devices/${never.id}/settings`, 'PUT', { homePage: '', siteFilter: null, scheduleExempt: false, unlockCode: null });
    assert.equal(await lockOf(never), true);
    await server.admin('/client-lock', 'PUT', { enabled: false });
  });

  test('browsers receive when each account sign-in expires', async () => {
    const primary = await server.enroll(randomDeviceId(), 'expiry-primary');
    await server.settings({ primaryDeviceIds: [primary.id], primaryDeviceId: primary.id });
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://soon.example/', complete: true, cookies: [cookie('user_session', 'x', 'soon.example', { expiresAt: now() + 2 * 86400 })] });
    await server.device(primary, '/sync', 'POST', { pageUrl: 'https://later.example/', complete: true, cookies: [cookie('user_session', 'y', 'later.example', { expiresAt: now() + 20 * 86400 })] });
    const accounts = (await (await server.device(primary, '/snapshot')).json()).accounts;
    const soon = accounts.find(item => item.domain === 'soon.example');
    const later = accounts.find(item => item.domain === 'later.example');
    assert.equal(soon.session, 'expiring');
    assert.ok(Math.abs(Date.parse(soon.expiresAt) / 1000 - (now() + 2 * 86400)) < 60);
    assert.equal(later.session, 'ok');
  });
});
