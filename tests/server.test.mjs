import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  ADMIN_TOKEN, PUBLIC_IP, basic, connectProxy, publicAddressAvailable, randomDeviceId, readHead, sleep,
  startEcho, startOrigin, startServer, waitFor
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

  test('bookmarks and search URL validation', async () => {
    const saved = await server.admin('/bookmarks', 'PUT', [{ title: '', url: 'https://github.com' }, { title: 'Docs', url: 'https://example.com/docs' }]);
    assert.deepEqual(saved.map(item => item.title), ['github.com', 'Docs']);
    await assert.rejects(server.admin('/bookmarks', 'PUT', [{ title: 'x', url: 'javascript:alert(1)' }]), /invalid/i);
    await assert.rejects(server.settings({ searchUrl: 'https://search.example/' }), /%s/);
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
