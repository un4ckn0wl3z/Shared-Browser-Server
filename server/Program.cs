using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<SharedStateStore>();
builder.Services.AddSingleton<ForwardProxyService>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<ForwardProxyService>());
var app = builder.Build();

var adminToken = Environment.GetEnvironmentVariable("SHARED_BROWSER_ADMIN_TOKEN");
var dataKey = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY");
if (string.IsNullOrWhiteSpace(adminToken)) throw new InvalidOperationException("SHARED_BROWSER_ADMIN_TOKEN is required");
if (string.IsNullOrWhiteSpace(dataKey)) throw new InvalidOperationException("SHARED_BROWSER_DATA_KEY is required");
if (adminToken.Length < 32) app.Logger.LogWarning("SHARED_BROWSER_ADMIN_TOKEN is shorter than 32 characters. Generate one with: openssl rand -hex 48");
if (dataKey.Length < 32) app.Logger.LogWarning("SHARED_BROWSER_DATA_KEY is shorter than 32 characters. Generate one with: openssl rand -hex 48");

app.Use(async (context, next) =>
{
    // The dashboard handles the administrator token, so it must never be framed or sniffed.
    var headers = context.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    if (context.Request.Path.StartsWithSegments("/api")) headers.CacheControl = "no-store";
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

bool AdminAuthorized(HttpRequest request) => Bearer(request) is { } token && FixedEquals(token, adminToken);
DeviceAuth? DeviceAuthorized(HttpRequest request, SharedStateStore store)
{
    var id = request.Headers["X-Device-Id"].ToString();
    var token = Bearer(request);
    return string.IsNullOrWhiteSpace(id) || token is null ? null : store.AuthorizeDevice(id, token);
}

app.MapGet("/healthz", (SharedStateStore store) => Results.Json(new { ok = true, revision = store.Revision }));

app.MapPost("/api/client/enroll", async (HttpContext context, EnrollRequest request, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { return Results.Json(await store.EnrollAsync(request), statusCode: StatusCodes.Status201Created); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

// Clients poll this every few seconds. Passing ?since=<revision> returns 204 when nothing changed, so
// an idle browser no longer downloads (and re-encrypts) the whole vault on every poll.
app.MapGet("/api/client/snapshot", async (HttpContext context, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    await store.TouchDeviceAsync(device.Id, context.Request.Query["deviceName"].ToString());
    var snapshot = store.Snapshot();
    if (long.TryParse(context.Request.Query["since"], out var since) && since == snapshot.Revision) return Results.NoContent();
    return Results.Json(snapshot);
});

app.MapPost("/api/client/sync", async (HttpContext context, SyncRequest request, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    try
    {
        var changed = await store.SyncCookiesAsync(device.Id, request);
        var snapshot = store.Snapshot();
        return Results.Json(new SyncResponse(snapshot.Revision, changed, snapshot));
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapGet("/api/admin/status", async (HttpContext context, SharedStateStore store, ForwardProxyService proxy) =>
    AdminAuthorized(context.Request)
        ? Results.Json(await store.AdminStatusAsync(proxy.PublicStatus()))
        : Results.Unauthorized());

app.MapPut("/api/admin/settings", async (HttpContext context, BrowserSettings settings, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { await store.UpdateSettingsAsync(settings); return Results.Json(store.Settings); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPut("/api/admin/bookmarks", async (HttpContext context, List<SharedBookmark> bookmarks, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { return Results.Json(await store.UpdateBookmarksAsync(bookmarks)); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPost("/api/admin/profiles", async (HttpContext context, SessionProfile profile, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { return Results.Json(await store.SaveProfileAsync(profile, null), statusCode: StatusCodes.Status201Created); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPut("/api/admin/profiles/{id}", async (HttpContext context, string id, SessionProfile profile, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { return Results.Json(await store.SaveProfileAsync(profile, id)); }
    catch (KeyNotFoundException) { return Results.NotFound(new { error = "Profile not found" }); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapDelete("/api/admin/profiles/{id}", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    return await store.DeleteProfileAsync(id) ? Results.NoContent() : Results.NotFound(new { error = "Profile not found" });
});

app.MapPost("/api/admin/devices/{id}/revoke", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    return await store.SetRevokedAsync(id, true) ? Results.Ok(new { ok = true }) : Results.NotFound(new { error = "Device not found" });
});

app.MapPost("/api/admin/devices/{id}/restore", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    return await store.SetRevokedAsync(id, false) ? Results.Ok(new { ok = true }) : Results.NotFound(new { error = "Device not found" });
});

app.MapDelete("/api/admin/devices/{id}", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    return await store.DeleteDeviceAsync(id) ? Results.NoContent() : Results.NotFound(new { error = "Device not found" });
});

app.Run();

static string? Bearer(HttpRequest request)
{
    var value = request.Headers.Authorization.ToString();
    return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : null;
}

static bool FixedEquals(string value, string expected)
{
    var a = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    var b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
    return CryptographicOperations.FixedTimeEquals(a, b);
}

/// <summary>
/// Owns the shared state. Every mutation runs under <see cref="_gate"/> and then publishes immutable
/// copies (<see cref="_snapshot"/> and <see cref="_deviceIndex"/>) that request handlers and the proxy
/// read without locking, so a slow request can never enumerate a list while another one changes it.
/// </summary>
public sealed class SharedStateStore
{
    public const string AdminSource = "admin";
    private const int MaxCookiesPerRequest = 200;
    private const int MaxBookmarks = 200;
    private static readonly TimeSpan LastSeenPersistInterval = TimeSpan.FromMinutes(5);
    // Many sites refresh a cookie's expiry on every response. Treat small expiry shifts as unchanged so
    // they do not create a new revision (and a client-wide cookie re-apply) on every page load.
    private const double ExpiryTolerance = 24 * 60 * 60;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;
    private readonly byte[] _key;
    private readonly ILogger<SharedStateStore> _logger;
    private readonly SharedState _state;
    private readonly Dictionary<string, DateTimeOffset> _lastSeenPersisted = [];
    private volatile SharedSnapshot _snapshot = null!;
    private volatile IReadOnlyDictionary<string, DeviceAuth> _deviceIndex = new Dictionary<string, DeviceAuth>();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public SharedStateStore(IWebHostEnvironment environment, ILogger<SharedStateStore> logger)
    {
        _logger = logger;
        var directory = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA") ?? Path.Combine(environment.ContentRootPath, "server-data");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "state.json");
        _key = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY")!));
        _state = Load();
        PublishLocked();
    }

    public long Revision => _snapshot.Revision;
    public BrowserSettings Settings => _snapshot.Settings;
    public SharedSnapshot Snapshot() => _snapshot;

    public DeviceAuth? AuthorizeDevice(string id, string token)
    {
        if (!_deviceIndex.TryGetValue(id.Trim().ToLowerInvariant(), out var device) || device.Revoked) return null;
        return SecureEquals(device.TokenHash, TokenHash(token)) ? device : null;
    }

    /// <summary>Used by the proxy to close tunnels that belong to a device revoked after they opened.</summary>
    public bool IsDeviceActive(string id) => _deviceIndex.TryGetValue(id, out var device) && !device.Revoked;

    public async Task<object> AdminStatusAsync(object proxyStatus)
    {
        await _gate.WaitAsync();
        try
        {
            return new
            {
                revision = _state.Revision,
                updatedAt = _state.UpdatedAt,
                profiles = _state.Profiles.Select(profile => new
                {
                    profile.Id,
                    profile.Name,
                    profile.Domain,
                    profile.Enabled,
                    cookieCount = profile.Cookies.Count,
                    cookies = profile.Cookies.Select(cookie => new { cookie.Name, cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.ExpiresAt, cookie.UpdatedAt, cookie.SourceDeviceId, hasValue = !string.IsNullOrEmpty(cookie.Value) }).ToList()
                }).ToList(),
                devices = _state.Devices.Select(device => new { device.Id, device.Name, device.EnrolledAt, device.LastSeenAt, device.Revoked, primary = device.Id == _state.Settings.PrimaryDeviceId }).ToList(),
                bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList(),
                settings = CloneSettings(_state.Settings),
                proxy = proxyStatus
            };
        }
        finally { _gate.Release(); }
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request)
    {
        var id = NormalizeId(request.DeviceId ?? "");
        var name = CleanName(request.DeviceName, "Unnamed browser");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await _gate.WaitAsync();
        try
        {
            var existing = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (existing is null)
            {
                existing = new DeviceRecord { Id = id, EnrolledAt = DateTimeOffset.UtcNow };
                _state.Devices.Add(existing);
            }
            existing.Name = name;
            existing.TokenHash = TokenHash(token);
            existing.Revoked = false;
            existing.LastSeenAt = DateTimeOffset.UtcNow;
            await SaveLockedAsync();
            return new EnrollResponse(id, token, _state.Revision);
        }
        finally { _gate.Release(); }
    }

    public async Task TouchDeviceAsync(string id, string name)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return;
            var now = DateTimeOffset.UtcNow;
            device.LastSeenAt = now;
            var renamed = false;
            if (!string.IsNullOrWhiteSpace(name))
            {
                var clean = CleanName(name, device.Name);
                renamed = clean != device.Name;
                device.Name = clean;
            }
            // Last-seen times are kept in memory and only persisted occasionally so that polling clients
            // do not rewrite the vault file every few seconds.
            var persist = renamed || !_lastSeenPersisted.TryGetValue(id, out var persisted) || now - persisted > LastSeenPersistInterval;
            if (persist)
            {
                _lastSeenPersisted[id] = now;
                await SaveLockedAsync(publish: false);
            }
        }
        finally { _gate.Release(); }
    }

    public async Task UpdateSettingsAsync(BrowserSettings settings)
    {
        var requestedHomePage = settings.HomePage?.Trim() ?? "";
        Uri? home = null;
        if (requestedHomePage.Length > 0 && (!Uri.TryCreate(requestedHomePage, UriKind.Absolute, out home) || home.Scheme is not ("http" or "https"))) throw new InvalidOperationException("Home page must be empty or a valid HTTP or HTTPS URL");
        var searchUrl = (settings.SearchUrl ?? "").Trim();
        if (searchUrl.Length > 0 && (!searchUrl.Contains("%s", StringComparison.Ordinal) || !Uri.TryCreate(searchUrl.Replace("%s", "test", StringComparison.Ordinal), UriKind.Absolute, out var search) || search.Scheme is not ("http" or "https") || searchUrl.Length > 500))
            throw new InvalidOperationException("Search URL must be empty or an HTTP or HTTPS URL containing %s");
        var primaryDeviceId = string.IsNullOrWhiteSpace(settings.PrimaryDeviceId) ? "" : NormalizeId(settings.PrimaryDeviceId);
        settings.Proxy ??= new ProxySettings();
        ValidateProxySettings(settings.Proxy);
        await _gate.WaitAsync();
        try
        {
            if (primaryDeviceId.Length > 0 && !_state.Devices.Any(item => item.Id == primaryDeviceId && !item.Revoked)) throw new InvalidOperationException("Primary browser must be an active enrolled device");
            _state.Settings.HomePage = home?.AbsoluteUri ?? "";
            _state.Settings.SearchUrl = searchUrl;
            _state.Settings.PrimaryDeviceId = primaryDeviceId;
            _state.Settings.AutoShareCookies = settings.AutoShareCookies;
            _state.Settings.Proxy = CloneProxySettings(settings.Proxy);
            BumpRevision();
            await SaveLockedAsync();
        }
        finally { _gate.Release(); }
    }

    public async Task<List<SharedBookmark>> UpdateBookmarksAsync(List<SharedBookmark>? input)
    {
        input ??= [];
        if (input.Count > MaxBookmarks) throw new InvalidOperationException($"At most {MaxBookmarks} bookmarks are supported");
        var clean = input.Select(item =>
        {
            var text = (item.Url ?? "").Trim();
            if (!Uri.TryCreate(text, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") || text.Length > 2000) throw new InvalidOperationException($"Bookmark URL is invalid: {text}");
            var title = string.IsNullOrWhiteSpace(item.Title) ? url.Host : item.Title.Trim();
            return new SharedBookmark { Title = title[..Math.Min(120, title.Length)], Url = url.AbsoluteUri };
        }).ToList();
        await _gate.WaitAsync();
        try
        {
            _state.Bookmarks = clean;
            BumpRevision();
            await SaveLockedAsync();
            return clean.Select(CloneBookmark).ToList();
        }
        finally { _gate.Release(); }
    }

    public async Task<SessionProfile> SaveProfileAsync(SessionProfile input, string? id)
    {
        var domain = NormalizeDomain(input.Domain ?? "");
        if (!ValidDomain(domain)) throw new InvalidOperationException("Invalid profile domain");
        await _gate.WaitAsync();
        try
        {
            var index = id is null ? -1 : _state.Profiles.FindIndex(item => item.Id == id);
            if (id is not null && index < 0) throw new KeyNotFoundException();
            var previous = index < 0 ? null : _state.Profiles[index];
            var cookies = new List<SharedCookie>();
            foreach (var incoming in input.Cookies ?? [])
            {
                // The dashboard never receives cookie values. An empty value means "keep the stored one",
                // so editing one cookie no longer requires re-entering every other secret in the profile.
                var keepExisting = string.IsNullOrEmpty(incoming.Value);
                var key = CookieKey(incoming.Name ?? "", NormalizeDomain(string.IsNullOrWhiteSpace(incoming.Domain) ? domain : incoming.Domain), string.IsNullOrWhiteSpace(incoming.Path) ? "/" : incoming.Path);
                var stored = previous?.Cookies.FirstOrDefault(item => CookieKey(item) == key);
                if (keepExisting && stored is null) throw new InvalidOperationException($"Enter a value for the new cookie '{incoming.Name}'");
                var candidate = keepExisting ? CloneCookie(incoming, stored!.Value) : incoming;
                var cookie = ValidateCookie(candidate, domain, AdminSource);
                cookie.ExpiresAt = stored?.ExpiresAt;
                if (stored is not null && CookieEqual(stored, cookie)) cookie = CloneCookie(stored);
                if (cookies.Any(item => CookieKey(item) == CookieKey(cookie))) throw new InvalidOperationException($"Cookie '{cookie.Name}' is listed twice for the same domain and path");
                cookies.Add(cookie);
            }
            var clean = new SessionProfile
            {
                Id = id ?? Guid.NewGuid().ToString("N"),
                Name = CleanName(input.Name, domain),
                Domain = domain,
                Enabled = input.Enabled,
                Cookies = cookies
            };
            if (index < 0 && _state.Profiles.Any(item => item.Domain == domain)) throw new InvalidOperationException("A profile for this domain already exists");
            if (index < 0) _state.Profiles.Add(clean); else _state.Profiles[index] = clean;
            BumpRevision();
            await SaveLockedAsync();
            return PublicProfile(clean);
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> DeleteProfileAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var removed = _state.Profiles.RemoveAll(item => item.Id == id) > 0;
            if (removed) { BumpRevision(); await SaveLockedAsync(); }
            return removed;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> SetRevokedAsync(string id, bool revoked)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return false;
            device.Revoked = revoked;
            await SaveLockedAsync();
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> DeleteDeviceAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            if (_state.Devices.RemoveAll(item => item.Id == id) == 0) return false;
            _lastSeenPersisted.Remove(id);
            if (_state.Settings.PrimaryDeviceId == id)
            {
                _state.Settings.PrimaryDeviceId = "";
                BumpRevision();
            }
            await SaveLockedAsync();
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<int> SyncCookiesAsync(string deviceId, SyncRequest request)
    {
        if (!Uri.TryCreate(request.PageUrl, UriKind.Absolute, out var page) || page.Scheme is not ("http" or "https")) throw new InvalidOperationException("Invalid page URL");
        var incomingCookies = request.Cookies ?? [];
        if (request.Complete && incomingCookies.Count > MaxCookiesPerRequest) throw new InvalidOperationException($"A complete cookie list may contain at most {MaxCookiesPerRequest} cookies");
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.First(item => item.Id == deviceId);
            device.LastSeenAt = DateTimeOffset.UtcNow;
            var settingsChanged = false;
            if (_state.Settings.AutoShareCookies && string.IsNullOrWhiteSpace(_state.Settings.PrimaryDeviceId))
            {
                _state.Settings.PrimaryDeviceId = deviceId;
                settingsChanged = true;
            }
            if (!string.Equals(_state.Settings.PrimaryDeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            {
                if (settingsChanged) { BumpRevision(); await SaveLockedAsync(); }
                return 0;
            }
            var host = NormalizeDomain(page.Host);
            var profile = _state.Profiles.Where(item => DomainMatches(host, item.Domain)).OrderByDescending(item => item.Domain.Length).FirstOrDefault();
            var profileCreated = false;
            // A disabled profile blocks sharing for its domain; it must not be shadowed by an automatic one.
            if (profile is { Enabled: false }) profile = null;
            else if (profile is null && _state.Settings.AutoShareCookies && incomingCookies.Count > 0)
            {
                if (!ValidDomain(host)) return 0;
                profile = new SessionProfile { Id = Guid.NewGuid().ToString("N"), Name = host, Domain = host, Enabled = true };
                _state.Profiles.Add(profile);
                profileCreated = true;
            }
            if (profile is null)
            {
                if (settingsChanged) { BumpRevision(); await SaveLockedAsync(); }
                return 0;
            }
            var changed = 0;
            var adopted = false;
            var seen = new HashSet<string>();
            foreach (var incoming in incomingCookies.Take(MaxCookiesPerRequest))
            {
                var cookie = ValidateCookie(incoming, profile.Domain, deviceId);
                if (!DomainMatches(host, cookie.Domain)) continue;
                seen.Add(CookieKey(cookie));
                if (cookie.ExpiresAt is { } expires && expires < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) continue;
                var index = profile.Cookies.FindIndex(item => CookieKey(item) == CookieKey(cookie));
                if (index >= 0 && CookieEqual(profile.Cookies[index], cookie))
                {
                    // The primary browser now holds the cookie an administrator typed in, so from here on it
                    // follows that browser: a later sign-out removes it like any other session cookie.
                    if (profile.Cookies[index].SourceDeviceId == AdminSource) { profile.Cookies[index].SourceDeviceId = deviceId; adopted = true; }
                    continue;
                }
                if (index < 0) profile.Cookies.Add(cookie); else profile.Cookies[index] = cookie;
                changed++;
            }
            // A complete list describes every cookie the primary browser holds for exactly this host, so
            // cookies it no longer has (sign-out, server-side deletion) are removed from the vault too.
            // Cookies typed in by an administrator are kept until the primary browser has confirmed it holds
            // them, so a publish that races ahead of installing a new cookie cannot delete it.
            if (request.Complete)
            {
                changed += profile.Cookies.RemoveAll(item => item.Domain == host && item.SourceDeviceId != AdminSource && !seen.Contains(CookieKey(item)));
            }
            if (changed > 0 || profileCreated || settingsChanged)
            {
                BumpRevision();
                await SaveLockedAsync();
            }
            else if (adopted) await SaveLockedAsync();
            return changed;
        }
        finally { _gate.Release(); }
    }

    private SharedState Load()
    {
        if (!File.Exists(_path)) return new SharedState();
        var disk = JsonSerializer.Deserialize<SharedState>(File.ReadAllText(_path), JsonOptions) ?? new SharedState();
        disk.Settings ??= new BrowserSettings();
        if (disk.Settings.HomePage is "https://example.com/" or "https://example.com") disk.Settings.HomePage = "";
        disk.Settings.SearchUrl ??= "";
        disk.Settings.Proxy ??= new ProxySettings();
        disk.Profiles ??= [];
        disk.Devices ??= [];
        disk.Bookmarks ??= [];
        foreach (var profile in disk.Profiles) profile.Cookies ??= [];
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Decrypt(cookie.Value);
        return disk;
    }

    private async Task SaveLockedAsync(bool publish = true)
    {
        var disk = new SharedState
        {
            Revision = _state.Revision,
            UpdatedAt = _state.UpdatedAt,
            Settings = CloneSettings(_state.Settings),
            Devices = _state.Devices.Select(device => new DeviceRecord { Id = device.Id, Name = device.Name, TokenHash = device.TokenHash, EnrolledAt = device.EnrolledAt, LastSeenAt = device.LastSeenAt, Revoked = device.Revoked }).ToList(),
            Profiles = _state.Profiles.Select(CloneProfile).ToList(),
            Bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList()
        };
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Encrypt(cookie.Value);
        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(disk, JsonOptions));
        File.Move(temp, _path, true);
        if (publish) PublishLocked();
    }

    /// <summary>Rebuilds the lock-free read models. Must be called while holding the gate (or from the constructor).</summary>
    private void PublishLocked()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _snapshot = new SharedSnapshot(
            _state.Revision,
            _state.UpdatedAt,
            CloneSettings(_state.Settings),
            _state.Profiles.Select(profile =>
            {
                var clone = CloneProfile(profile);
                clone.Cookies.RemoveAll(cookie => cookie.ExpiresAt is { } expires && expires < now);
                return clone;
            }).ToList(),
            _state.Bookmarks.Select(CloneBookmark).ToList());
        _deviceIndex = _state.Devices.ToDictionary(device => device.Id, device => new DeviceAuth(device.Id, device.TokenHash, device.Revoked));
    }

    private void BumpRevision()
    {
        _state.Revision++;
        _state.UpdatedAt = DateTimeOffset.UtcNow;
        var now = _state.UpdatedAt.ToUnixTimeSeconds();
        foreach (var profile in _state.Profiles) profile.Cookies.RemoveAll(cookie => cookie.ExpiresAt is { } expires && expires < now);
    }

    private string Encrypt(string value)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(value);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return $"v1.{Convert.ToBase64String(nonce)}.{Convert.ToBase64String(tag)}.{Convert.ToBase64String(ciphertext)}";
    }

    private string Decrypt(string value)
    {
        if (!value.StartsWith("v1.", StringComparison.Ordinal)) return value;
        var parts = value.Split('.');
        try
        {
            var nonce = Convert.FromBase64String(parts[1]);
            var tag = Convert.FromBase64String(parts[2]);
            var ciphertext = Convert.FromBase64String(parts[3]);
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception error) when (error is CryptographicException or FormatException or IndexOutOfRangeException)
        {
            throw new InvalidOperationException("The vault cannot be decrypted. SHARED_BROWSER_DATA_KEY does not match the key that wrote state.json.", error);
        }
    }

    private static string TokenHash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static bool SecureEquals(string value, string expected)
    {
        var a = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
    private static string NormalizeId(string value) => Guid.TryParse(value, out var id) ? id.ToString("N") : throw new InvalidOperationException("Device ID must be a GUID");
    private static string CleanName(string? value, string fallback)
    {
        var text = new string((value ?? "").Where(character => !char.IsControl(character)).ToArray()).Trim();
        return text.Length == 0 ? fallback : text[..Math.Min(80, text.Length)];
    }
    private static string NormalizeDomain(string value) => value.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant();
    private static bool ValidDomain(string value) => value.Length is > 0 and <= 253 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-');
    private static bool DomainMatches(string host, string domain) { host = NormalizeDomain(host); domain = NormalizeDomain(domain); return host == domain || host.EndsWith('.' + domain, StringComparison.Ordinal); }
    private static string CookieKey(SharedCookie cookie) => CookieKey(cookie.Name, cookie.Domain, cookie.Path);
    private static string CookieKey(string name, string domain, string path) => $"{name}\n{domain}\n{path}";

    private static SharedCookie ValidateCookie(SharedCookie input, string profileDomain, string source)
    {
        var name = input.Name ?? "";
        var value = input.Value ?? "";
        if (string.IsNullOrWhiteSpace(name) || name.Length > 256 || name.Any(character => char.IsWhiteSpace(character) || char.IsControl(character) || character is ';' or '=')) throw new InvalidOperationException("Invalid cookie name");
        if (value.Length > 8192 || value.Any(character => char.IsControl(character) || character == ';')) throw new InvalidOperationException("Invalid cookie value");
        var domain = NormalizeDomain(string.IsNullOrWhiteSpace(input.Domain) ? profileDomain : input.Domain);
        if (!ValidDomain(domain)) throw new InvalidOperationException("Invalid cookie domain");
        if (!(DomainMatches(domain, profileDomain) || DomainMatches(profileDomain, domain))) throw new InvalidOperationException("Cookie domain is outside its profile domain");
        var path = string.IsNullOrWhiteSpace(input.Path) ? "/" : input.Path;
        if (!path.StartsWith('/') || path.Length > 1024 || path.Any(char.IsControl)) throw new InvalidOperationException("Cookie path must start with /");
        double? expiresAt = input.ExpiresAt is { } expiry && double.IsFinite(expiry) && expiry > 0 ? Math.Floor(expiry) : null;
        return new SharedCookie
        {
            Name = name,
            Value = value,
            Domain = domain,
            Path = path,
            Secure = input.Secure,
            HttpOnly = input.HttpOnly,
            SameSite = input.SameSite is "Strict" or "None" ? input.SameSite : "Lax",
            ExpiresAt = expiresAt,
            UpdatedAt = DateTimeOffset.UtcNow,
            SourceDeviceId = source
        };
    }

    private static bool CookieEqual(SharedCookie a, SharedCookie b) =>
        a.Name == b.Name && a.Value == b.Value && a.Domain == b.Domain && a.Path == b.Path && a.Secure == b.Secure && a.HttpOnly == b.HttpOnly && a.SameSite == b.SameSite
        && (a.ExpiresAt is null) == (b.ExpiresAt is null) && Math.Abs((a.ExpiresAt ?? 0) - (b.ExpiresAt ?? 0)) < ExpiryTolerance;
    private static BrowserSettings CloneSettings(BrowserSettings settings) => new() { HomePage = settings.HomePage, SearchUrl = settings.SearchUrl, PrimaryDeviceId = settings.PrimaryDeviceId, AutoShareCookies = settings.AutoShareCookies, Proxy = CloneProxySettings(settings.Proxy) };
    private static ProxySettings CloneProxySettings(ProxySettings settings) => new() { Enabled = settings.Enabled, Host = settings.Host, Port = settings.Port, AllowedPorts = settings.AllowedPorts, BypassList = settings.BypassList };
    private static SharedBookmark CloneBookmark(SharedBookmark item) => new() { Title = item.Title, Url = item.Url };
    private static SharedCookie CloneCookie(SharedCookie cookie, string? value = null) => new() { Name = cookie.Name, Value = value ?? cookie.Value, Domain = cookie.Domain, Path = cookie.Path, Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, SameSite = cookie.SameSite, ExpiresAt = cookie.ExpiresAt, UpdatedAt = cookie.UpdatedAt, SourceDeviceId = cookie.SourceDeviceId };
    private static void ValidateProxySettings(ProxySettings proxy)
    {
        proxy.Host = (proxy.Host ?? "").Trim();
        proxy.AllowedPorts = string.Join(',', (proxy.AllowedPorts ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        proxy.BypassList = (proxy.BypassList ?? "").Trim();
        if (proxy.Port is < 1 or > 65535) throw new InvalidOperationException("Proxy port must be between 1 and 65535");
        if (proxy.Host.Length is < 1 or > 253 || proxy.Host.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or ':' or '[' or ']'))) throw new InvalidOperationException("Proxy host is invalid");
        if (proxy.AllowedPorts.Length == 0 || proxy.AllowedPorts.Split(',').Any(item => !int.TryParse(item, out var port) || port is < 1 or > 65535)) throw new InvalidOperationException("Allowed proxy ports must be comma-separated port numbers");
        if (proxy.BypassList.Length > 500 || proxy.BypassList.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '*' or ';' or ':' or '<' or '>' or '[' or ']'))) throw new InvalidOperationException("Proxy bypass list contains unsupported characters");
    }
    private static SessionProfile CloneProfile(SessionProfile profile) => new()
    {
        Id = profile.Id,
        Name = profile.Name,
        Domain = profile.Domain,
        Enabled = profile.Enabled,
        Cookies = profile.Cookies.Select(cookie => CloneCookie(cookie)).ToList()
    };
    private static SessionProfile PublicProfile(SessionProfile profile)
    {
        var clone = CloneProfile(profile);
        foreach (var cookie in clone.Cookies) cookie.Value = "";
        return clone;
    }
}

public sealed record DeviceAuth(string Id, string TokenHash, bool Revoked);

public sealed class SharedState
{
    public long Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public BrowserSettings Settings { get; set; } = new();
    public List<SessionProfile> Profiles { get; set; } = [];
    public List<DeviceRecord> Devices { get; set; } = [];
    public List<SharedBookmark> Bookmarks { get; set; } = [];
}

public sealed class BrowserSettings { public string HomePage { get; set; } = ""; public string SearchUrl { get; set; } = "https://duckduckgo.com/?q=%s"; public string PrimaryDeviceId { get; set; } = ""; public bool AutoShareCookies { get; set; } = true; public ProxySettings Proxy { get; set; } = new(); }
public sealed class ProxySettings { public bool Enabled { get; set; } public string Host { get; set; } = "127.0.0.1"; public int Port { get; set; } = 8899; public string AllowedPorts { get; set; } = "80,443"; public string BypassList { get; set; } = "localhost;127.0.0.1"; }
public sealed class SessionProfile { public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string Domain { get; set; } = ""; public bool Enabled { get; set; } = true; public List<SharedCookie> Cookies { get; set; } = []; }
/// <summary>ExpiresAt is the expiry in Unix seconds, or null for a browser-session cookie.</summary>
public sealed class SharedCookie { public string Name { get; set; } = ""; public string Value { get; set; } = ""; public string Domain { get; set; } = ""; public string Path { get; set; } = "/"; public bool Secure { get; set; } = true; public bool HttpOnly { get; set; } = true; public string SameSite { get; set; } = "Lax"; public double? ExpiresAt { get; set; } public DateTimeOffset UpdatedAt { get; set; } public string SourceDeviceId { get; set; } = ""; }
public sealed class SharedBookmark { public string Title { get; set; } = ""; public string Url { get; set; } = ""; }
public sealed class DeviceRecord { public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string TokenHash { get; set; } = ""; public DateTimeOffset EnrolledAt { get; set; } public DateTimeOffset LastSeenAt { get; set; } public bool Revoked { get; set; } }
public sealed record EnrollRequest(string DeviceId, string DeviceName);
public sealed record EnrollResponse(string DeviceId, string DeviceToken, long Revision);
/// <summary>
/// Complete=true means Cookies is every cookie the primary browser holds whose domain is exactly the
/// page host, so stored cookies missing from it were deleted. Without it the list is a partial update.
/// </summary>
public sealed record SyncRequest(long KnownRevision, string PageUrl, List<SharedCookie>? Cookies, bool Complete = false);
public sealed record SyncResponse(long Revision, int ChangedCookies, SharedSnapshot Snapshot);
public sealed record SharedSnapshot(long Revision, DateTimeOffset UpdatedAt, BrowserSettings Settings, List<SessionProfile> Profiles, List<SharedBookmark> Bookmarks);
