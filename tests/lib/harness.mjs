// Shared helpers for the integration tests: a real management server process, a small test website,
// origin servers on a "public" address for the forward proxy, and Electron browser profiles.
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const ADMIN_TOKEN = 'test-admin-token-0123456789abcdef0123456789abcdef';
export const DATA_KEY = 'test-data-key-0123456789abcdef0123456789abcdef01';
// The proxy refuses private and loopback destinations, so tunnel tests need an origin on an address it
// treats as public. CI adds this address to the loopback interface; locally the tests skip without it.
export const PUBLIC_IP = process.env.TEST_PUBLIC_IP || '8.8.4.4';
// A second local "public" address the proxy can be told to send from (egress source address tests).
export const SOURCE_IP = process.env.TEST_SOURCE_IP || '1.1.1.2';
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export function tempDir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `shared-browser-${name}-`));
}

export async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

export async function waitFor(check, { timeout = 20000, interval = 200, message = 'condition' } = {}) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      last = await check();
      if (last) return last;
    } catch (error) { last = error; }
    await sleep(interval);
  }
  throw new Error(`Timed out waiting for ${message} (last value: ${last instanceof Error ? last.message : JSON.stringify(last)})`);
}

/** Starts the built server (dotnet SharedBrowser.Server.dll). Build it first with `dotnet build -c Release`. */
export async function startServer({ env = {} } = {}) {
  const dll = process.env.SERVER_DLL || path.join(ROOT, 'server/bin/Release/net8.0/SharedBrowser.Server.dll');
  if (!fs.existsSync(dll)) throw new Error(`Server build not found at ${dll}. Run: dotnet build server -c Release`);
  const port = await freePort();
  const proxyPort = await freePort();
  const data = tempDir('data');
  const log = [];
  const child = spawn('dotnet', [dll], {
    // The dashboard is served from wwwroot relative to the content root.
    cwd: process.env.SERVER_CONTENT_ROOT || path.join(ROOT, 'server'),
    env: {
      ...process.env,
      SHARED_BROWSER_ADMIN_TOKEN: ADMIN_TOKEN,
      SHARED_BROWSER_DATA_KEY: DATA_KEY,
      SHARED_BROWSER_DATA: data,
      SHARED_BROWSER_PROXY_BIND: '127.0.0.1',
      ASPNETCORE_URLS: `http://127.0.0.1:${port}`,
      DOTNET_NOLOGO: '1',
      ...env
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', chunk => log.push(String(chunk)));
  child.stderr.on('data', chunk => log.push(String(chunk)));
  const url = `http://127.0.0.1:${port}`;
  await waitFor(async () => (await fetch(`${url}/healthz`)).ok, { timeout: 30000, message: `server on ${url}\n${log.join('')}` });
  const server = {
    url,
    port,
    proxyPort,
    data,
    log,
    async stop() {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        await new Promise(resolve => child.once('exit', resolve));
      }
    },
    async admin(pathname, method = 'GET', body, raw = false) {
      const response = await fetch(`${url}/api/admin${pathname}`, {
        method,
        headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body)
      });
      if (raw) return response;
      const text = await response.text();
      const data = text ? JSON.parse(text) : null;
      if (!response.ok) throw Object.assign(new Error(data?.error || `${method} ${pathname} → ${response.status}`), { status: response.status });
      return data;
    },
    async status() { return server.admin('/status'); },
    async settings(patch = {}, proxyPatch = {}) {
      const current = (await server.status()).settings;
      return server.admin('/settings', 'PUT', { ...current, ...patch, proxy: { ...current.proxy, ...proxyPatch } });
    },
    async code(label = '', ttlMinutes = 10) {
      return (await server.admin('/enrollment-codes', 'POST', { label, ttlMinutes })).code;
    },
    async enroll(deviceId, deviceName, credential) {
      const response = await fetch(`${url}/api/client/enroll`, {
        method: 'POST',
        headers: { authorization: `Bearer ${credential ?? await server.code(deviceName)}`, 'content-type': 'application/json' },
        body: JSON.stringify({ deviceId, deviceName })
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) throw Object.assign(new Error(data?.error || `enroll → ${response.status}`), { status: response.status });
      return { id: data.deviceId, token: data.deviceToken };
    },
    async device(device, pathname, method = 'GET', body) {
      return fetch(`${url}/api/client${pathname}`, {
        method,
        headers: { authorization: `Bearer ${device.token}`, 'x-device-id': device.id, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    },
    async profile(domain) {
      return (await server.status()).profiles.find(item => item.domain === domain);
    }
  };
  return server;
}

/** A website on localhost whose pages set, rotate and clear cookies. */
export async function startSite() {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const cookies = {
      '/login': ['sid=secret-1; Path=/; Max-Age=3600; HttpOnly', 'pref=dark; Path=/'],
      '/rotate': ['sid=secret-2; Path=/; Max-Age=3600; HttpOnly'],
      '/logout': ['sid=; Path=/; Max-Age=0; HttpOnly'],
      '/clear-adm': ['adm=; Path=/; Max-Age=0'],
      '/other-login': ['other=1; Path=/; Max-Age=3600']
    }[url.pathname];
    if (cookies) response.setHeader('Set-Cookie', cookies);
    response.setHeader('content-type', 'text/html; charset=utf-8');
    response.end(`<title>Test ${url.pathname}</title><p id="c">${request.headers.cookie || ''}</p><p>needle one needle two needle three</p>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { port, origin: `http://localhost:${port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

/** Returns true when the address (PUBLIC_IP by default) is bound locally, so servers can listen on it. */
export async function publicAddressAvailable(address = PUBLIC_IP) {
  return new Promise(resolve => {
    const probe = net.createServer().once('error', () => resolve(false)).listen(0, address, () => probe.close(() => resolve(true)));
  });
}

/** An HTTP origin on PUBLIC_IP that records whether each request carried proxy credentials. */
export async function startOrigin() {
  const requests = [];
  const server = http.createServer((request, response) => {
    const remote = String(request.socket.remoteAddress).replace(/^::ffff:/, '');
    requests.push({ path: request.url, proxyAuthorization: 'proxy-authorization' in request.headers, remote });
    // /ip answers like an IP echo service with the address the request came from.
    const body = request.url.startsWith('/ip') ? JSON.stringify({ ip: remote }) : `hello ${request.url}`;
    response.writeHead(200, { 'content-type': 'text/html', 'content-length': Buffer.byteLength(body), connection: 'keep-alive' });
    response.end(body);
  });
  server.keepAliveTimeout = 30000;
  await new Promise(resolve => server.listen(0, PUBLIC_IP, resolve));
  return { port: server.address().port, requests, close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

/** A TCP echo server on PUBLIC_IP, used as a CONNECT tunnel destination. */
export async function startEcho() {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => { });
    socket.pipe(socket);
  });
  await new Promise(resolve => server.listen(0, PUBLIC_IP, resolve));
  return { port: server.address().port, close: () => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(resolve); }) };
}

/** Opens a connection to the forward proxy, over TLS when requested. Resolves with the socket and certificate. */
export async function connectProxy(port, useTls) {
  if (!useTls) {
    const socket = net.connect(port, '127.0.0.1');
    await new Promise((resolve, reject) => socket.once('connect', resolve).once('error', reject));
    return { socket };
  }
  const socket = tls.connect({ port, host: '127.0.0.1', rejectUnauthorized: false });
  await new Promise((resolve, reject) => socket.once('secureConnect', resolve).once('error', reject));
  const certificate = socket.getPeerX509Certificate();
  return { socket, fingerprint: certificate.fingerprint256.replaceAll(':', '').toLowerCase() };
}

/** Reads from a socket until the HTTP header block (or the connection) ends. */
export async function readHead(socket) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end >= 0) finish(buffer.subarray(0, end).toString('latin1'), buffer.subarray(end + 4));
    };
    const finish = (head, rest) => {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', reject);
      resolve({ head, rest, status: Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1]) });
    };
    const onEnd = () => finish(buffer.toString('latin1'), Buffer.alloc(0));
    socket.on('data', onData).once('end', onEnd).once('error', reject);
  });
}

export function basic(device) {
  return `Basic ${Buffer.from(`${device.id}:${device.token}`).toString('base64')}`;
}

export function randomDeviceId() {
  return crypto.randomBytes(16).toString('hex');
}

// ---- Electron ----------------------------------------------------------------------------------

const electronRequire = createRequire(path.join(ROOT, 'electron-client/package.json'));

/** Writes a client profile that enrolls with `credential` on first start, like a user saving Settings. */
export function writeClientProfile(home, profile, { serverUrl, deviceId, credential, networkMode = 'direct', strictPrivacy = false }) {
  const directory = path.join(home, '.config', 'Shared Browser', profile);
  fs.mkdirSync(directory, { recursive: true });
  const secrets = { deviceToken: '', enrollmentToken: credential, cache: null };
  fs.writeFileSync(path.join(directory, 'client-config.json'), JSON.stringify({
    serverUrl,
    deviceId,
    deviceName: profile,
    networkMode,
    strictPrivacy,
    protected: `plain:${Buffer.from(JSON.stringify(secrets)).toString('base64')}`
  }));
}

export async function launchBrowser(home, profile) {
  const { _electron } = await import('playwright');
  const app = await _electron.launch({
    executablePath: electronRequire('electron'),
    args: [path.join(ROOT, 'electron-client'), `--profile=${profile}`, '--no-sandbox'],
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config') }
  });
  const window = await app.firstWindow();
  const browser = {
    app,
    window,
    async navigate(url) {
      await window.fill('#address', url);
      await window.press('#address', 'Enter');
    },
    async cookies(url) {
      return app.evaluate(async ({ session }, target) => (await session.fromPartition('persist:shared-browser').cookies.get({ url: target }))
        .map(cookie => `${cookie.name}=${cookie.value}${cookie.session ? '' : '(persistent)'}`).sort().join(' '), url);
    },
    async address() { return window.inputValue('#address'); },
    async status() { return window.textContent('#status'); },
    /** Sends a keyboard shortcut through Electron's real input path (Playwright's keyboard skips before-input-event). */
    async shortcut(keyCode, modifiers = []) {
      await app.evaluate(({ BrowserWindow }, input) => BrowserWindow.getAllWindows()[0].webContents.sendInputEvent({ type: 'keyDown', ...input }), { keyCode, modifiers });
    },
    async route(url) {
      return app.evaluate(({ session }, target) => session.fromPartition('persist:shared-browser').resolveProxy(target), url);
    },
    async pageText() {
      return app.evaluate(async ({ webContents }) => {
        const pages = webContents.getAllWebContents().filter(item => /^https?:/.test(item.getURL()));
        return Promise.all(pages.map(item => item.executeJavaScript('document.body ? document.body.innerText : ""')));
      });
    },
    async close() { await app.close(); }
  };
  return browser;
}
