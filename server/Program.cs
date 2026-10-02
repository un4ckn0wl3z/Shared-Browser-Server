using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<SharedStateStore>();
var app = builder.Build();

var adminToken = Environment.GetEnvironmentVariable("SHARED_BROWSER_ADMIN_TOKEN");
var dataKey = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY");
if (string.IsNullOrWhiteSpace(adminToken)) throw new InvalidOperationException("SHARED_BROWSER_ADMIN_TOKEN is required");
if (string.IsNullOrWhiteSpace(dataKey)) throw new InvalidOperationException("SHARED_BROWSER_DATA_KEY is required");

app.UseDefaultFiles();
app.UseStaticFiles();

bool AdminAuthorized(HttpRequest request) => Bearer(request) is { } token && FixedEquals(token, adminToken);
DeviceRecord? DeviceAuthorized(HttpRequest request, SharedStateStore store)
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

app.MapGet("/api/client/snapshot", async (HttpContext context, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    await store.TouchDeviceAsync(device.Id, context.Request.Query["deviceName"].ToString());
    return Results.Json(store.Snapshot());
});

app.MapPost("/api/client/sync", async (HttpContext context, SyncRequest request, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    try
    {
        var changed = await store.SyncCookiesAsync(device.Id, request);
        return Results.Json(new SyncResponse(store.Revision, changed, store.Snapshot()));
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapGet("/api/admin/status", (HttpContext context, SharedStateStore store) =>
    AdminAuthorized(context.Request)
        ? Results.Json(new { revision = store.Revision, profiles = store.PublicProfiles(), devices = store.PublicDevices(), settings = store.Settings })
        : Results.Unauthorized());

app.MapPut("/api/admin/settings", async (HttpContext context, BrowserSettings settings, SharedStateStore store) =>
{
    if (!AdminAuthorized(context.Request)) return Results.Unauthorized();
    try { await store.UpdateSettingsAsync(settings); return Results.Json(store.Settings); }
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

app.Run();

static string? Bearer(HttpRequest request)
{
    var value = request.Headers.Authorization.ToString();
    return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..] : null;
}

static bool FixedEquals(string value, string expected)
{
    var a = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    var b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
    return CryptographicOperations.FixedTimeEquals(a, b);
}

public sealed class SharedStateStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;
    private readonly byte[] _key;
    private SharedState _state;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public SharedStateStore(IWebHostEnvironment environment)
    {
        var directory = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA") ?? Path.Combine(environment.ContentRootPath, "server-data");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "state.json");
        _key = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY")!));
        _state = Load();
    }

    public long Revision => _state.Revision;
    public BrowserSettings Settings => _state.Settings;

    public DeviceRecord? AuthorizeDevice(string id, string token)
    {
        var device = _state.Devices.FirstOrDefault(item => item.Id == id && !item.Revoked);
        return device is not null && SecureEquals(device.TokenHash, TokenHash(token)) ? device : null;
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request)
    {
        var id = NormalizeId(request.DeviceId);
        var name = string.IsNullOrWhiteSpace(request.DeviceName) ? "Unnamed browser" : request.DeviceName.Trim()[..Math.Min(80, request.DeviceName.Trim().Length)];
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
        }
        finally { _gate.Release(); }
        return new EnrollResponse(id, token, Revision);
    }

    public async Task TouchDeviceAsync(string id, string name)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return;
            device.LastSeenAt = DateTimeOffset.UtcNow;
            if (!string.IsNullOrWhiteSpace(name)) device.Name = name.Trim()[..Math.Min(80, name.Trim().Length)];
            await SaveLockedAsync(false);
        }
        finally { _gate.Release(); }
    }

    public SharedSnapshot Snapshot() => new(
        _state.Revision,
        _state.UpdatedAt,
        CloneSettings(_state.Settings),
        _state.Profiles.Select(CloneProfile).ToList(),
        _state.Bookmarks.Select(item => new SharedBookmark { Title = item.Title, Url = item.Url }).ToList());

    public object PublicProfiles() => _state.Profiles.Select(profile => new
    {
        profile.Id,
        profile.Name,
        profile.Domain,
        profile.Enabled,
        cookieCount = profile.Cookies.Count,
        cookies = profile.Cookies.Select(cookie => new { cookie.Name, cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.UpdatedAt, cookie.SourceDeviceId, hasValue = !string.IsNullOrEmpty(cookie.Value) })
    });

    public object PublicDevices() => _state.Devices.Select(device => new { device.Id, device.Name, device.EnrolledAt, device.LastSeenAt, device.Revoked });

    public async Task UpdateSettingsAsync(BrowserSettings settings)
    {
        if (!Uri.TryCreate(settings.HomePage, UriKind.Absolute, out var home) || home.Scheme is not ("http" or "https")) throw new InvalidOperationException("Home page must be a valid HTTP or HTTPS URL");
        var primaryDeviceId = string.IsNullOrWhiteSpace(settings.PrimaryDeviceId) ? "" : NormalizeId(settings.PrimaryDeviceId);
        await _gate.WaitAsync();
        try
        {
            if (primaryDeviceId.Length > 0 && !_state.Devices.Any(item => item.Id == primaryDeviceId && !item.Revoked)) throw new InvalidOperationException("Primary browser must be an active enrolled device");
            _state.Settings.HomePage = home.AbsoluteUri;
            _state.Settings.PrimaryDeviceId = primaryDeviceId;
            _state.Settings.AutoShareCookies = settings.AutoShareCookies;
            BumpRevision();
            await SaveLockedAsync();
        }
        finally { _gate.Release(); }
    }

    public async Task<SessionProfile> SaveProfileAsync(SessionProfile input, string? id)
    {
        var domain = NormalizeDomain(input.Domain);
        if (!ValidDomain(domain)) throw new InvalidOperationException("Invalid profile domain");
        var clean = new SessionProfile
        {
            Id = id ?? Guid.NewGuid().ToString("N"),
            Name = string.IsNullOrWhiteSpace(input.Name) ? domain : input.Name.Trim()[..Math.Min(80, input.Name.Trim().Length)],
            Domain = domain,
            Enabled = input.Enabled,
            Cookies = input.Cookies.Select(cookie => ValidateCookie(cookie, domain, "admin")).ToList()
        };
        await _gate.WaitAsync();
        try
        {
            var index = id is null ? -1 : _state.Profiles.FindIndex(item => item.Id == id);
            if (id is not null && index < 0) throw new KeyNotFoundException();
            if (index < 0) _state.Profiles.Add(clean); else _state.Profiles[index] = clean;
            BumpRevision();
            await SaveLockedAsync();
            return CloneProfile(clean);
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

    public async Task<int> SyncCookiesAsync(string deviceId, SyncRequest request)
    {
        if (!Uri.TryCreate(request.PageUrl, UriKind.Absolute, out var page) || page.Scheme is not ("http" or "https")) throw new InvalidOperationException("Invalid page URL");
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
            var profile = _state.Profiles.Where(item => item.Enabled && DomainMatches(page.Host, item.Domain)).OrderByDescending(item => item.Domain.Length).FirstOrDefault();
            var profileCreated = false;
            if (profile is null && _state.Settings.AutoShareCookies)
            {
                var domain = NormalizeDomain(page.Host);
                if (!ValidDomain(domain)) return 0;
                profile = new SessionProfile { Id = Guid.NewGuid().ToString("N"), Name = domain, Domain = domain, Enabled = true };
                _state.Profiles.Add(profile);
                profileCreated = true;
            }
            if (profile is null) return 0;
            var changed = 0;
            foreach (var incoming in request.Cookies.Take(200))
            {
                var cookie = ValidateCookie(incoming, profile.Domain, deviceId);
                if (!DomainMatches(page.Host, cookie.Domain)) continue;
                var existing = profile.Cookies.FirstOrDefault(item => item.Name == cookie.Name && item.Domain == cookie.Domain && item.Path == cookie.Path);
                if (existing is not null && CookieEqual(existing, cookie)) continue;
                if (existing is null) profile.Cookies.Add(cookie);
                else
                {
                    var index = profile.Cookies.IndexOf(existing);
                    profile.Cookies[index] = cookie;
                }
                changed++;
            }
            if (changed > 0 || profileCreated || settingsChanged) BumpRevision();
            await SaveLockedAsync(changed > 0 || profileCreated || settingsChanged);
            return changed;
        }
        finally { _gate.Release(); }
    }

    private SharedState Load()
    {
        if (!File.Exists(_path)) return new SharedState();
        var disk = JsonSerializer.Deserialize<SharedState>(File.ReadAllText(_path), JsonOptions) ?? new SharedState();
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Decrypt(cookie.Value);
        return disk;
    }

    private async Task SaveLockedAsync(bool write = true)
    {
        if (!write) return;
        var disk = new SharedState
        {
            Revision = _state.Revision,
            UpdatedAt = _state.UpdatedAt,
            Settings = CloneSettings(_state.Settings),
            Devices = _state.Devices.Select(device => new DeviceRecord { Id = device.Id, Name = device.Name, TokenHash = device.TokenHash, EnrolledAt = device.EnrolledAt, LastSeenAt = device.LastSeenAt, Revoked = device.Revoked }).ToList(),
            Profiles = _state.Profiles.Select(CloneProfile).ToList(),
            Bookmarks = _state.Bookmarks.Select(item => new SharedBookmark { Title = item.Title, Url = item.Url }).ToList()
        };
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Encrypt(cookie.Value);
        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(disk, JsonOptions));
        File.Move(temp, _path, true);
    }

    private void BumpRevision() { _state.Revision++; _state.UpdatedAt = DateTimeOffset.UtcNow; }

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
        var nonce = Convert.FromBase64String(parts[1]);
        var tag = Convert.FromBase64String(parts[2]);
        var ciphertext = Convert.FromBase64String(parts[3]);
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    private static string TokenHash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static bool SecureEquals(string value, string expected)
    {
        var a = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
    private static string NormalizeId(string value) => Guid.TryParse(value, out var id) ? id.ToString("N") : throw new InvalidOperationException("Device ID must be a GUID");
    private static string NormalizeDomain(string value) => value.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant();
    private static bool ValidDomain(string value) => value.Length is > 0 and <= 253 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-');
    private static bool DomainMatches(string host, string domain) { host = NormalizeDomain(host); domain = NormalizeDomain(domain); return host == domain || host.EndsWith('.' + domain, StringComparison.Ordinal); }

    private static SharedCookie ValidateCookie(SharedCookie input, string profileDomain, string source)
    {
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Any(character => char.IsWhiteSpace(character) || character is ';' or '=')) throw new InvalidOperationException("Invalid cookie name");
        if (input.Value.Contains('\r') || input.Value.Contains('\n') || input.Value.Contains(';')) throw new InvalidOperationException("Invalid cookie value");
        var domain = NormalizeDomain(string.IsNullOrWhiteSpace(input.Domain) ? profileDomain : input.Domain);
        if (!(DomainMatches(domain, profileDomain) || DomainMatches(profileDomain, domain))) throw new InvalidOperationException("Cookie domain is outside its profile domain");
        var path = string.IsNullOrWhiteSpace(input.Path) ? "/" : input.Path;
        if (!path.StartsWith('/')) throw new InvalidOperationException("Cookie path must start with /");
        return new SharedCookie
        {
            Name = input.Name,
            Value = input.Value,
            Domain = domain,
            Path = path,
            Secure = input.Secure,
            HttpOnly = input.HttpOnly,
            SameSite = input.SameSite is "Strict" or "None" ? input.SameSite : "Lax",
            UpdatedAt = DateTimeOffset.UtcNow,
            SourceDeviceId = source
        };
    }

    private static bool CookieEqual(SharedCookie a, SharedCookie b) => a.Name == b.Name && a.Value == b.Value && a.Domain == b.Domain && a.Path == b.Path && a.Secure == b.Secure && a.HttpOnly == b.HttpOnly && a.SameSite == b.SameSite;
    private static BrowserSettings CloneSettings(BrowserSettings settings) => new() { HomePage = settings.HomePage, PrimaryDeviceId = settings.PrimaryDeviceId, AutoShareCookies = settings.AutoShareCookies };
    private static SessionProfile CloneProfile(SessionProfile profile) => new()
    {
        Id = profile.Id,
        Name = profile.Name,
        Domain = profile.Domain,
        Enabled = profile.Enabled,
        Cookies = profile.Cookies.Select(cookie => new SharedCookie { Name = cookie.Name, Value = cookie.Value, Domain = cookie.Domain, Path = cookie.Path, Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, SameSite = cookie.SameSite, UpdatedAt = cookie.UpdatedAt, SourceDeviceId = cookie.SourceDeviceId }).ToList()
    };
}

public sealed class SharedState
{
    public long Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public BrowserSettings Settings { get; set; } = new();
    public List<SessionProfile> Profiles { get; set; } = [];
    public List<DeviceRecord> Devices { get; set; } = [];
    public List<SharedBookmark> Bookmarks { get; set; } = [];
}

public sealed class BrowserSettings { public string HomePage { get; set; } = "https://example.com/"; public string PrimaryDeviceId { get; set; } = ""; public bool AutoShareCookies { get; set; } = true; }
public sealed class SessionProfile { public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string Domain { get; set; } = ""; public bool Enabled { get; set; } = true; public List<SharedCookie> Cookies { get; set; } = []; }
public sealed class SharedCookie { public string Name { get; set; } = ""; public string Value { get; set; } = ""; public string Domain { get; set; } = ""; public string Path { get; set; } = "/"; public bool Secure { get; set; } = true; public bool HttpOnly { get; set; } = true; public string SameSite { get; set; } = "Lax"; public DateTimeOffset UpdatedAt { get; set; } public string SourceDeviceId { get; set; } = ""; }
public sealed class SharedBookmark { public string Title { get; set; } = ""; public string Url { get; set; } = ""; }
public sealed class DeviceRecord { public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string TokenHash { get; set; } = ""; public DateTimeOffset EnrolledAt { get; set; } public DateTimeOffset LastSeenAt { get; set; } public bool Revoked { get; set; } }
public sealed record EnrollRequest(string DeviceId, string DeviceName);
public sealed record EnrollResponse(string DeviceId, string DeviceToken, long Revision);
public sealed record SyncRequest(long KnownRevision, string PageUrl, List<SharedCookie> Cookies);
public sealed record SyncResponse(long Revision, int ChangedCookies, SharedSnapshot Snapshot);
public sealed record SharedSnapshot(long Revision, DateTimeOffset UpdatedAt, BrowserSettings Settings, List<SessionProfile> Profiles, List<SharedBookmark> Bookmarks);
