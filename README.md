# Shared Browser System

This system replaces the proxy design with a client/server browser architecture:

```text
Shared Browser WB1 ─┐
Shared Browser WB2 ─┼── Browser Management Server ── encrypted shared vault
Shared Browser WB3 ─┘
```

There are no proxy settings. Each browser connects normally to websites and independently connects to the management server to synchronize authorized browser data.

## Included

- `server/` — ASP.NET Core management server and web dashboard
- `client/` — native Windows Shared Browser using WebView2
- Encrypted server-side cookie/session vault
- Unique device identities and revocable device tokens
- Automatic per-domain cookie/session profiles
- A primary browser that publishes session changes while other browsers consume them
- Bidirectional cookie synchronization
- Shared home-page configuration
- Offline encrypted browser cache
- Browser/device status in the management dashboard

Session values are sensitive credentials. Use this only for domains and accounts you own or are explicitly authorized to administer.

## Start the server

PowerShell:

```powershell
$env:SHARED_BROWSER_ADMIN_TOKEN = 'choose-a-long-random-administrator-token'
$env:SHARED_BROWSER_DATA_KEY = 'choose-a-different-long-random-encryption-key'
$env:ASPNETCORE_URLS = 'http://127.0.0.1:8787'
dotnet run --project server\SharedBrowser.Server.csproj -c Release
```

Open `http://127.0.0.1:8787` and enter the administrator token.

For browsers on other computers, bind the server to an appropriate private network interface and put HTTPS in front of it. Do not transmit device tokens or session cookies over untrusted plain HTTP.

## Build and open a browser

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

## Synchronization rules

- Automatic sharing is enabled by default. The primary browser creates a profile for every domain whose cookies it publishes.
- Only the primary browser can publish cookie/session changes. This prevents a logged-out secondary browser from overwriting a logged-in session.
- Profiles can still be disabled or removed from the dashboard when a domain should not be shared.
- Server revisions provide a consistent order across browsers.
- Cookie conflicts use server-arrival last-write-wins behavior.
- Identical updates are deduplicated and do not create new revisions.
- A revoked browser can no longer pull or push shared data.
- Browser web traffic does not pass through the management server.

The first version deliberately uses the central server as the authority. Direct P2P transport can be added later without changing the browser data model.
