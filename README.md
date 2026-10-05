# Shared Browser System

This system replaces the proxy design with a client/server browser architecture:

```text
Shared Browser WB1 ─┐
Shared Browser WB2 ─┼── Browser Management Server ── encrypted shared vault
Shared Browser WB3 ─┘
```

Each browser independently connects to the management server to synchronize authorized browser data. Website traffic can either connect directly or use the management server's authenticated forward proxy, selected per browser.

## Included

- `server/` — ASP.NET Core management server and web dashboard
- `client/` — native Windows Shared Browser using WebView2
- `electron-client/` — cross-platform Shared Browser for Windows, macOS, and Linux
- Encrypted server-side cookie/session vault
- Unique device identities and revocable device tokens
- Automatic per-domain cookie/session profiles
- A primary browser that publishes session changes while other browsers consume them
- Bidirectional cookie synchronization
- Shared home-page configuration
- Offline encrypted browser cache
- Browser/device status in the management dashboard
- Authenticated forward proxy built into the management server
- Per-browser choice between direct client-IP traffic and management-server-IP traffic

Session values are sensitive credentials. Use this only for domains and accounts you own or are explicitly authorized to administer.

## Docker deployment on Linux

Docker is the recommended server deployment. The image uses the .NET 8 non-root `app` user, stores the encrypted vault in a named volume, binds the dashboard to localhost by default, and includes an optional Caddy HTTPS profile.

On the Linux server:

```bash
git clone https://github.com/un4ckn0wl3z/Shared-Browser-Server.git
cd Shared-Browser-Server
cp .env.example .env
```

Generate two independent secrets and place them in `.env`:

```bash
openssl rand -hex 48
openssl rand -hex 48
chmod 600 .env
```

Do not change `SHARED_BROWSER_DATA_KEY` after the vault contains data. Without the original key, stored sessions cannot be decrypted.

Build and start the server:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f shared-browser
```

Verify it locally:

```bash
curl http://127.0.0.1:8787/healthz
```

The default bindings are intentionally local-only:

- Dashboard/API: `127.0.0.1:8787`
- Forward proxy: `127.0.0.1:8899`

For HTTPS, point the DNS record in `SHARED_BROWSER_DOMAIN` at the server and start the optional Caddy profile:

```bash
docker compose --profile https up -d
```

Caddy publishes ports 80 and 443 and forwards only the management dashboard/API to the server container. Browser clients should then use `https://browser.example.com` as their management-server URL.

To allow remote browsers to use Managed proxy mode, set `SHARED_BROWSER_PROXY_PUBLISH_IP` in `.env` to the Linux server's private or VPN interface address, recreate the container, and configure the same address as the advertised proxy host in the dashboard:

```bash
docker compose up -d
```

Keep port `8899` behind a private network, firewall allowlist, WireGuard, or Tailscale. Do not publish it openly to the internet: the destination HTTPS connection is tunneled, but the browser-to-proxy authentication exchange is not protected by TLS. If the dashboard proxy port is changed from `8899`, update the Compose port mapping at the same time.

Back up the `shared-browser-data` volume and securely retain the matching data key. Upgrade with:

```bash
git pull
docker compose up -d --build
```

## Start the server

PowerShell:

```powershell
$env:SHARED_BROWSER_ADMIN_TOKEN = 'choose-a-long-random-administrator-token'
$env:SHARED_BROWSER_DATA_KEY = 'choose-a-different-long-random-encryption-key'
$env:ASPNETCORE_URLS = 'http://127.0.0.1:8787'
$env:SHARED_BROWSER_PROXY_BIND = '127.0.0.1'
dotnet run --project server\SharedBrowser.Server.csproj -c Release
```

Open `http://127.0.0.1:8787` and enter the administrator token.

For browsers on other computers, bind the server to an appropriate private network interface and put HTTPS in front of it. Do not transmit device tokens or session cookies over untrusted plain HTTP.

`SHARED_BROWSER_PROXY_BIND` controls the interface used by the built-in forward proxy. Keep `127.0.0.1` for a local-only installation. For clients on a private network, set it to the server's private interface (or `0.0.0.0`) and protect the port with a firewall. The proxy always requires an active enrolled-device ID and device token; it is not an open unauthenticated proxy.

## Windows .NET client

```powershell
dotnet build client\SharedBrowser.csproj -c Release
```

Run each browser with a distinct local profile name:

```powershell
SharedBrowser.exe --profile=WB1
SharedBrowser.exe --profile=WB2
SharedBrowser.exe --profile=WB3
```

Each name creates an isolated WebView2 profile, device identity, encrypted token, and offline cache. All profiles connect to the same management server and shared vault.

On first launch:

1. Open **Server settings**.
2. Enter the management-server URL.
3. Enter a descriptive device name such as `WB1`.
4. Enter the server administrator token once as the enrollment token.
5. Save, close, and reopen Shared Browser.

The server issues a random per-device token. The administrator token is discarded from the browser after enrollment. The device token and offline cookie cache are protected with Windows DPAPI.

Repeat enrollment for WB2 and WB3. In the dashboard, choose the signed-in browser (normally WB1) as **Primary session browser**. Its stored cookies are scanned on startup, and every domain it visits is added to the shared vault automatically. WB2 and WB3 pull those changes approximately every 2.5 seconds.

## Cross-platform Electron client

The Electron client runs on Windows, macOS, and Linux while the original .NET/WebView2 client remains available. Both clients use the same server API and can share the same cookie/session vault.

Ready-to-use Windows and macOS installers are published on the [GitHub Releases page](https://github.com/un4ckn0wl3z/Shared-Browser-Server/releases). Release tags build a Windows x64 NSIS installer and a universal macOS DMG on native GitHub runners. These community builds are currently unsigned, so Windows SmartScreen or macOS Gatekeeper may display a warning; review the repository source before allowing an unsigned build.

Install and start it with Node.js 20 or newer:

```bash
cd electron-client
npm install
npm start -- --profile=WB1
```

Use a different profile name for every browser instance:

```bash
npm start -- --profile=WB2
npm start -- --profile=WB3
```

On first launch, the settings dialog opens automatically. Enter the management-server URL, a device name, the administrator token as the one-time enrollment token, and choose Direct or Managed proxy mode. Saving restarts and enrolls the client.

Electron stores each named profile in the operating system's application-data directory. Device credentials and the offline shared snapshot use Electron `safeStorage`; Chromium protects its persistent cookie store using the facilities available on the operating system. On Linux, install and unlock a supported secret store such as KWallet, GNOME Keyring, or Secret Service. The client warns when Electron falls back to unencrypted `basic_text` storage.

Create platform installers from the matching operating system:

```bash
npm run dist:win
npm run dist:mac
npm run dist:linux
```

macOS installers normally must be built and code-signed on macOS. Windows installers should be signed before public distribution.

## Direct IP or management-server IP

The dashboard's **Forward proxy management** section controls the built-in proxy endpoint, advertised host, port, allowed destination ports, and browser bypass list.

Each browser independently chooses its route in **Server settings**:

- **Direct connection — use client IP**: websites connect directly and see the browser computer's public IP.
- **Managed proxy — use server IP**: HTTP and HTTPS traffic goes through the authenticated management-server proxy, so websites see the management server's outbound IP.
- **Strict privacy**: requires Managed proxy mode, removes Chromium's implicit direct bypass routes, blocks browsing if the proxy configuration is unavailable, restricts WebRTC from using non-proxied UDP, and denies website permission prompts such as location, camera, microphone, and notifications.

Restart a browser after changing its connection mode or after changing the proxy endpoint. Both WebView2 and Electron establish proxy routing at startup. HTTPS uses standard `CONNECT` tunneling and remains end-to-end encrypted between the browser and destination; the management proxy does not install a certificate authority or decrypt page contents.

Strict privacy is leak reduction, not anonymity. Signed-in accounts, shared cookies, browser fingerprints, and account activity can still identify a user. Because WebRTC cannot use direct UDP in this mode, browser-based voice or video calls may fall back to TCP or fail.

The Electron settings dialog includes **Run privacy check**, which verifies that Chromium resolves both public and loopback destinations through the configured proxy and confirms that the non-proxied WebRTC policy was applied. Run it after saving and restarting the browser.

The default destination-port allowlist is `80,443`. Private, loopback, link-local, and multicast destinations are blocked to reduce server-side request-forgery risk.

## Synchronization rules

- Automatic sharing is enabled by default. The primary browser creates a profile for every domain whose cookies it publishes.
- Only the primary browser can publish cookie/session changes. This prevents a logged-out secondary browser from overwriting a logged-in session.
- Profiles can still be disabled or removed from the dashboard when a domain should not be shared.
- Server revisions provide a consistent order across browsers.
- Cookie conflicts use server-arrival last-write-wins behavior.
- Identical updates are deduplicated and do not create new revisions.
- A revoked browser can no longer pull or push shared data.
- In Direct mode, browser web traffic does not pass through the management server. In Managed mode, it passes through the authenticated forward proxy.

The first version deliberately uses the central server as the authority. Direct P2P transport can be added later without changing the browser data model.
