using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

/// <summary>
/// Owns the shared state. Every mutation runs under <see cref="_gate"/> and then publishes immutable
/// copies (<see cref="_snapshot"/> and <see cref="_deviceIndex"/>) that request handlers and the proxy
/// read without locking, so a slow request can never enumerate a list while another one changes it.
/// </summary>
public sealed partial class SharedStateStore
{
    public const string AdminSource = "admin";
    private const int MaxCookiesPerRequest = 200;
    private const int MaxBookmarks = 200;
    private const int MaxAnnouncements = 50;
    private const int MaxAccountsPerSite = 20;
    private const int MaxSharedSites = 500;
    public static readonly string[] AutoShareScopes = ["all", "listed"];
    private static readonly TimeSpan ExpiredAnnouncementRetention = TimeSpan.FromDays(7);
    private static readonly string[] AnnouncementLevels = ["info", "warning", "critical"];
    private const string CodeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
    private static readonly TimeSpan LastSeenPersistInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CodeRetention = TimeSpan.FromDays(7);
    // Many sites refresh a cookie's expiry on every response. Treat small expiry shifts as unchanged so
    // they do not create a new revision (and a client-wide cookie re-apply) on every page load.
    private const double ExpiryTolerance = 24 * 60 * 60;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;
    private readonly string _backupDirectory;
    private readonly TimeSpan _backupInterval;
    private readonly int _backupKeep;
    private readonly byte[] _key;
    private readonly ProxyCertificate _certificate;
    private readonly ILogger<SharedStateStore> _logger;
    private readonly Dictionary<string, DateTimeOffset> _lastSeenPersisted = [];
    private SharedState _state;
    private DateTimeOffset _lastBackup;
    private volatile SharedSnapshot _snapshot = null!;
    private volatile IReadOnlyDictionary<string, DeviceAuth> _deviceIndex = new Dictionary<string, DeviceAuth>();
    private volatile IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> _accountChoices = new Dictionary<string, IReadOnlyDictionary<string, string>>();
    private static readonly IReadOnlyDictionary<string, string> NoChoices = new Dictionary<string, string>();
    private TaskCompletionSource _revisionChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _publishedRevision = -1;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _liveConnections = new();

    public SharedStateStore(DataDirectory data, ProxyCertificate certificate, ILogger<SharedStateStore> logger)
    {
        _logger = logger;
        _certificate = certificate;
        _path = Path.Combine(data.Path, "state.json");
        _backupDirectory = Path.Combine(data.Path, "backups");
        Directory.CreateDirectory(_backupDirectory);
        _backupInterval = TimeSpan.FromMinutes(Math.Max(1, IntFromEnvironment("SHARED_BROWSER_BACKUP_INTERVAL_MINUTES", 60)));
        _backupKeep = Math.Max(1, IntFromEnvironment("SHARED_BROWSER_BACKUP_KEEP", 48));
        _key = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY")!));
        _state = File.Exists(_path) ? Parse(File.ReadAllText(_path)) : new SharedState();
        _lastBackup = ListBackups().Select(item => item.CreatedAt).DefaultIfEmpty(DateTimeOffset.MinValue).Max();
        PublishLocked();
    }

    public long Revision => _snapshot.Revision;
    public BrowserSettings Settings => _snapshot.Settings;
    public SharedSnapshot Snapshot() => _snapshot;

    /// <summary>
    /// The snapshot one device may see: profiles restricted to other devices are left out, and of a site
    /// with several accounts only the one this device uses carries cookies (the rest are listed in Accounts).
    /// </summary>
    public SharedSnapshot SnapshotFor(string deviceId)
    {
        var snapshot = _snapshot;
        var choices = _accountChoices.GetValueOrDefault(deviceId) ?? NoChoices;
        var profiles = new List<SessionProfile>();
        var accounts = new List<ClientAccount>();
        foreach (var site in snapshot.Profiles.Where(profile => Shares(profile, deviceId)).GroupBy(profile => profile.Domain))
        {
            var usable = site.Where(profile => profile.Enabled).ToList();
            // Disabled profiles still go out: they tell a browser that sharing for the site is switched off.
            if (usable.Count == 0) { profiles.AddRange(site); continue; }
            var active = PickAccount(usable, choices.GetValueOrDefault(site.Key));
            profiles.Add(active);
            accounts.AddRange(usable.Select(profile => new ClientAccount(profile.Id, profile.Name, profile.Domain, profile == active, profile.Cookies.Count)));
        }
        return snapshot with
        {
            Profiles = profiles,
            Announcements = snapshot.Announcements.Where(item => item.ShareWithAllDevices || item.AllowedDeviceIds.Contains(deviceId)).ToList(),
            Accounts = accounts
        };
    }

    private static bool Shares(SessionProfile profile, string deviceId) => profile.ShareWithAllDevices || profile.AllowedDeviceIds.Contains(deviceId);
    private static SessionProfile PickAccount(IReadOnlyList<SessionProfile> usable, string? choice) => usable.FirstOrDefault(profile => profile.Id == choice) ?? usable[0];

    /// <summary>The account a device uses for a site (profiles with the same domain), or null when none is enabled.</summary>
    private SessionProfile? ActiveAccountLocked(DeviceRecord? device, IEnumerable<SessionProfile> site, bool requireAccess)
    {
        var enabled = site.Where(profile => profile.Enabled).ToList();
        if (enabled.Count == 0) return null;
        var usable = device is null ? enabled : enabled.Where(profile => Shares(profile, device.Id)).ToList();
        if (usable.Count == 0) return requireAccess ? null : enabled[0];
        return PickAccount(usable, device?.ActiveProfiles.GetValueOrDefault(enabled[0].Domain));
    }

    private bool IsPrimaryLocked(string deviceId) => string.Equals(_state.Settings.PrimaryDeviceId, deviceId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Completes when the revision differs from <paramref name="known"/>, or after the timeout.</summary>
    public async Task WaitForRevisionChangeAsync(long known, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var signal = _revisionChanged.Task;
        if (Revision != known) return;
        await Task.WhenAny(signal, Task.Delay(timeout, cancellationToken));
    }

    public DeviceAuth? AuthorizeDevice(string id, string token)
    {
        if (!_deviceIndex.TryGetValue(id.Trim().ToLowerInvariant(), out var device) || device.Revoked) return null;
        return SecureEquals(device.TokenHash, TokenHash(token)) ? device : null;
    }

    /// <summary>Used by the proxy to close tunnels that belong to a device revoked after they opened.</summary>
    public bool IsDeviceActive(string id) => _deviceIndex.TryGetValue(id, out var device) && !device.Revoked;

    public string DeviceName(string id) => _deviceIndex.TryGetValue(id, out var device) ? device.Name : id;

    /// <summary>A browser's proxy limits: its own overrides, otherwise the defaults from the proxy settings.</summary>
    public ProxyLimits LimitsFor(string deviceId)
    {
        var proxy = _snapshot.Settings.Proxy;
        _deviceIndex.TryGetValue(deviceId, out var device);
        return new ProxyLimits(
            device?.MaxConnections ?? proxy.MaxConnectionsPerDevice,
            device?.MonthlyQuotaGb ?? proxy.MonthlyQuotaGb,
            device?.RateLimitMbps ?? proxy.RateLimitMbps);
    }

    public static readonly string[] NetworkPolicies = ["choice", "managed", "strict"];

    /// <summary>True when a minimum browser version is set and <paramref name="version"/> is older or unknown.</summary>
    public bool IsOutdated(string? version)
    {
        var minimum = ParseClientVersion(_snapshot.Settings.MinimumClientVersion);
        if (minimum is null) return false;
        var actual = ParseClientVersion(version);
        return actual is null || actual < minimum;
    }

    /// <summary>Uses the version the browser last reported (for requests that do not carry it).</summary>
    public bool IsDeviceOutdated(string deviceId) => IsOutdated(_deviceIndex.TryGetValue(deviceId, out var device) ? device.ClientVersion : "");

    public string UpdateRequiredMessage => $"Shared Browser {_snapshot.Settings.MinimumClientVersion} or newer is required. Install the update, or restart the browser if it has already downloaded it.";

    private static Version? ParseClientVersion(string? value)
    {
        var core = (value ?? "").Split('-', '+')[0].Trim();
        if (!Version.TryParse(core, out var parsed)) return null;
        return new Version(parsed.Major, parsed.Minor, Math.Max(0, parsed.Build));
    }
    private static readonly string[] NetworkModes = ["direct", "managed", "strict"];

    public async Task<string?> SetDeviceLimitsAsync(string id, DeviceLimitsRequest request)
    {
        ValidateLimit(request.MaxConnections, 100_000, "Connection limit");
        ValidateLimit(request.MonthlyQuotaGb, 1_000_000, "Monthly quota");
        ValidateLimit(request.RateLimitMbps, 100_000, "Rate limit");
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return null;
            (device.MaxConnections, device.MonthlyQuotaGb, device.RateLimitMbps) = (request.MaxConnections, request.MonthlyQuotaGb, request.RateLimitMbps);
            await SaveLockedAsync();
            return device.Name;
        }
        finally { _gate.Release(); }
    }

    private static void ValidateLimit(double? value, double max, string name)
    {
        if (value is { } number && (!double.IsFinite(number) || number < 0 || number > max)) throw new InvalidOperationException($"{name} must be between 0 (unlimited) and {max:N0}");
    }

    /// <summary>Counts a device's open event streams, shown as "live" in the dashboard. Dispose to release.</summary>
    public IDisposable TrackLiveConnection(string deviceId)
    {
        _liveConnections.AddOrUpdate(deviceId, 1, (_, count) => count + 1);
        return new Release(() => _liveConnections.AddOrUpdate(deviceId, 0, (_, count) => Math.Max(0, count - 1)));
    }

    private sealed class Release(Action action) : IDisposable { public void Dispose() => action(); }

    public async Task<object> AdminStatusAsync(object proxyStatus, IReadOnlyList<AuditEntry> audit, Func<string, object> usage)
    {
        await _gate.WaitAsync();
        try
        {
            var now = DateTimeOffset.UtcNow;
            return new
            {
                revision = _state.Revision,
                updatedAt = _state.UpdatedAt,
                profiles = _state.Profiles.Select(profile => new
                {
                    accounts = _state.Profiles.Count(item => item.Domain == profile.Domain),
                    // False when a sharing list is in use and does not cover the profile: the primary browser no longer updates it.
                    listed = ShareableSiteLocked(profile.Domain) is not null,
                    usedBy = _state.Devices.Where(device => !device.Revoked && ActiveAccountLocked(device, _state.Profiles.Where(item => item.Domain == profile.Domain), true) == profile).Select(device => device.Name).ToList(),
                    profile.Id,
                    profile.Name,
                    profile.Domain,
                    profile.Enabled,
                    profile.ShareWithAllDevices,
                    profile.AllowedDeviceIds,
                    cookieCount = profile.Cookies.Count,
                    cookies = profile.Cookies.Select(cookie => new { cookie.Name, cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.ExpiresAt, cookie.UpdatedAt, cookie.SourceDeviceId, hasValue = !string.IsNullOrEmpty(cookie.Value) }).ToList()
                }).ToList(),
                devices = _state.Devices.Select(device => new
                {
                    device.Id,
                    device.Name,
                    device.EnrolledAt,
                    device.LastSeenAt,
                    device.Revoked,
                    device.ClientVersion,
                    device.NetworkMode,
                    limitOverrides = new { device.MaxConnections, device.MonthlyQuotaGb, device.RateLimitMbps },
                    usage = usage(device.Id),
                    primary = device.Id == _state.Settings.PrimaryDeviceId,
                    live = _liveConnections.GetValueOrDefault(device.Id) > 0
                }).ToList(),
                bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList(),
                announcements = _state.Announcements.OrderByDescending(item => item.CreatedAt).Select(item =>
                {
                    var recipients = _state.Devices.Where(device => !device.Revoked && (item.ShareWithAllDevices || item.AllowedDeviceIds.Contains(device.Id))).ToList();
                    return new
                    {
                        item.Id,
                        item.Title,
                        item.Message,
                        item.Level,
                        item.Url,
                        item.CreatedAt,
                        item.ExpiresAt,
                        item.ShareWithAllDevices,
                        item.AllowedDeviceIds,
                        expired = item.ExpiresAt is { } expires && expires <= now,
                        recipients = recipients.Select(device => device.Name).ToList(),
                        acknowledgedBy = item.Acknowledgements.OrderBy(entry => entry.Value).Select(entry => new { deviceId = entry.Key, name = DeviceName(entry.Key), at = entry.Value }).ToList()
                    };
                }).ToList(),
                enrollmentCodes = _state.EnrollmentCodes.OrderByDescending(code => code.CreatedAt).Select(code => new
                {
                    code.Id,
                    code.Label,
                    code.CreatedAt,
                    code.ExpiresAt,
                    code.UsedAt,
                    usedBy = string.IsNullOrEmpty(code.UsedByDeviceId) ? "" : DeviceName(code.UsedByDeviceId),
                    code.Revoked,
                    active = code.UsedAt is null && !code.Revoked && code.ExpiresAt > now
                }).ToList(),
                settings = _snapshot.Settings,
                proxy = proxyStatus,
                backups = ListBackups(),
                audit
            };
        }
        finally { _gate.Release(); }
    }

    // ---- Enrollment -------------------------------------------------------------------------------

    public async Task<EnrollmentCodeResponse> CreateEnrollmentCodeAsync(EnrollmentCodeRequest request)
    {
        var minutes = request.TtlMinutes ?? 10;
        if (minutes is < 1 or > 7 * 24 * 60) throw new InvalidOperationException("An enrollment code must expire within 1 minute to 7 days");
        var raw = new string(RandomNumberGenerator.GetItems<char>(CodeAlphabet, 12));
        var code = new EnrollmentCode
        {
            Id = Guid.NewGuid().ToString("N"),
            CodeHash = TokenHash(raw),
            Label = CleanName(request.Label, ""),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(minutes)
        };
        await _gate.WaitAsync();
        try
        {
            PruneCodesLocked();
            if (_state.EnrollmentCodes.Count(item => item.UsedAt is null && !item.Revoked && item.ExpiresAt > DateTimeOffset.UtcNow) >= 100)
                throw new InvalidOperationException("Too many active enrollment codes. Revoke unused ones first");
            _state.EnrollmentCodes.Add(code);
            await SaveLockedAsync(publish: false);
        }
        finally { _gate.Release(); }
        return new EnrollmentCodeResponse(code.Id, $"{raw[..4]}-{raw[4..8]}-{raw[8..]}", code.Label, code.ExpiresAt);
    }

    public async Task<bool> RevokeEnrollmentCodeAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var code = _state.EnrollmentCodes.FirstOrDefault(item => item.Id == id);
            if (code is null) return false;
            code.Revoked = true;
            await SaveLockedAsync(publish: false);
            return true;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Normalizes user input such as "abcd efgh-jkmn" to the stored form, or null if it cannot be a code.</summary>
    public static string? NormalizeEnrollmentCode(string value)
    {
        var text = new string(value.Where(character => character is not ('-' or ' ')).ToArray()).ToUpperInvariant();
        return text.Length == 12 && text.All(CodeAlphabet.Contains) ? text : null;
    }

    /// <summary>
    /// Enrolls a device. With <paramref name="code"/> the code must be active and is consumed atomically
    /// with the enrollment; without it the caller has already checked the administrator token.
    /// Returns the response and a description of how the device was enrolled.
    /// </summary>
    public async Task<(EnrollResponse Response, string Via)> EnrollAsync(EnrollRequest request, string? code)
    {
        var id = NormalizeId(request.DeviceId ?? "");
        var name = CleanName(request.DeviceName, "Unnamed browser");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await _gate.WaitAsync();
        try
        {
            var via = "administrator token";
            if (code is not null)
            {
                var hash = TokenHash(code);
                var match = _state.EnrollmentCodes.FirstOrDefault(item => SecureEquals(item.CodeHash, hash));
                if (match is null || match.Revoked || match.UsedAt is not null || match.ExpiresAt <= DateTimeOffset.UtcNow)
                    throw new UnauthorizedAccessException("The enrollment code is invalid, expired, or already used");
                match.UsedAt = DateTimeOffset.UtcNow;
                match.UsedByDeviceId = id;
                via = string.IsNullOrEmpty(match.Label) ? "enrollment code" : $"enrollment code \"{match.Label}\"";
            }
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
            return (new EnrollResponse(id, token, _state.Revision), via);
        }
        finally { _gate.Release(); }
    }

    public async Task TouchDeviceAsync(string id, string name, string version = "", string mode = "")
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
            // Version and connection mode let the dashboard show whether each browser follows the policy.
            var cleanVersion = new string(version.Where(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '+').Take(32).ToArray());
            if (cleanVersion.Length > 0 && cleanVersion != device.ClientVersion) { device.ClientVersion = cleanVersion; renamed = true; }
            if (NetworkModes.Contains(mode) && mode != device.NetworkMode) { device.NetworkMode = mode; renamed = true; }
            // Last-seen times are kept in memory and only persisted occasionally so that polling clients
            // do not rewrite the vault file every few seconds.
            var persist = renamed || !_lastSeenPersisted.TryGetValue(id, out var persisted) || now - persisted > LastSeenPersistInterval;
            if (persist)
            {
                _lastSeenPersisted[id] = now;
                await SaveLockedAsync(publish: renamed);
            }
        }
        finally { _gate.Release(); }
    }

    // ---- Administration ---------------------------------------------------------------------------

    /// <summary>Applies new settings and returns a short description of what changed, for the audit log.</summary>
    public async Task<string> UpdateSettingsAsync(BrowserSettings settings)
    {
        var requestedHomePage = settings.HomePage?.Trim() ?? "";
        Uri? home = null;
        if (requestedHomePage.Length > 0 && (!Uri.TryCreate(requestedHomePage, UriKind.Absolute, out home) || home.Scheme is not ("http" or "https"))) throw new InvalidOperationException("Home page must be empty or a valid HTTP or HTTPS URL");
        var searchUrl = (settings.SearchUrl ?? "").Trim();
        if (searchUrl.Length > 0 && (!searchUrl.Contains("%s", StringComparison.Ordinal) || !Uri.TryCreate(searchUrl.Replace("%s", "test", StringComparison.Ordinal), UriKind.Absolute, out var search) || search.Scheme is not ("http" or "https") || searchUrl.Length > 500))
            throw new InvalidOperationException("Search URL must be empty or an HTTP or HTTPS URL containing %s");
        var primaryDeviceId = string.IsNullOrWhiteSpace(settings.PrimaryDeviceId) ? "" : NormalizeId(settings.PrimaryDeviceId);
        var policy = (settings.NetworkPolicy ?? "strict").Trim().ToLowerInvariant();
        if (!NetworkPolicies.Contains(policy)) throw new InvalidOperationException("Browser connection mode must be choice, managed or strict");
        var ipCheckUrl = (settings.IpCheckUrl ?? "").Trim();
        if (ipCheckUrl.Length > 0 && (ipCheckUrl.Length > 500 || !Uri.TryCreate(ipCheckUrl, UriKind.Absolute, out var check) || check.Scheme is not ("http" or "https"))) throw new InvalidOperationException("IP check URL must be empty or an HTTP or HTTPS URL");
        settings.Proxy ??= new ProxySettings();
        ValidateProxySettings(settings.Proxy);
        var minimumVersion = (settings.MinimumClientVersion ?? "").Trim().TrimStart('v', 'V');
        if (minimumVersion.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(minimumVersion, @"^\d{1,4}\.\d{1,4}\.\d{1,4}$")) throw new InvalidOperationException("Minimum browser version must look like 1.5.0, or be empty");
        var scope = (settings.AutoShareScope ?? "all").Trim().ToLowerInvariant();
        if (!AutoShareScopes.Contains(scope)) throw new InvalidOperationException("Automatic sharing must cover all sites or only the listed sites");
        var sharedSites = CleanSiteList(settings.AutoShareDomains);
        if (settings.AutoShareCookies && scope == "listed" && sharedSites.Count == 0) throw new InvalidOperationException("List at least one site to share, or choose another sharing option");
        await _gate.WaitAsync();
        try
        {
            if (primaryDeviceId.Length > 0 && !_state.Devices.Any(item => item.Id == primaryDeviceId && !item.Revoked)) throw new InvalidOperationException("Primary browser must be an active enrolled device");
            var before = _state.Settings;
            var changes = new List<string>();
            void Compare(string name, object? a, object? b) { if (!Equals(a, b)) changes.Add($"{name}: {a} → {b}"); }
            Compare("home page", before.HomePage, home?.AbsoluteUri ?? "");
            Compare("search URL", before.SearchUrl, searchUrl);
            Compare("primary browser", before.PrimaryDeviceId.Length == 0 ? "automatic" : DeviceName(before.PrimaryDeviceId), primaryDeviceId.Length == 0 ? "automatic" : DeviceName(primaryDeviceId));
            Compare("automatic sharing", SharingSummary(before.AutoShareCookies, before.AutoShareScope), SharingSummary(settings.AutoShareCookies, scope));
            Compare("shared sites", string.Join(", ", before.AutoShareDomains), string.Join(", ", sharedSites));
            Compare("admin-token enrollment", before.AllowAdminTokenEnrollment, settings.AllowAdminTokenEnrollment);
            Compare("proxy enabled", before.Proxy.Enabled, settings.Proxy.Enabled);
            Compare("proxy endpoint", $"{before.Proxy.Host}:{before.Proxy.Port}", $"{settings.Proxy.Host}:{settings.Proxy.Port}");
            Compare("proxy TLS", before.Proxy.Tls, settings.Proxy.Tls);
            Compare("allowed ports", before.Proxy.AllowedPorts, settings.Proxy.AllowedPorts);
            Compare("bypass list", before.Proxy.BypassList, settings.Proxy.BypassList);
            Compare("browser connection mode", before.NetworkPolicy, policy);
            Compare("IP check URL", before.IpCheckUrl, ipCheckUrl);
            Compare("minimum browser version", before.MinimumClientVersion.Length == 0 ? "any" : before.MinimumClientVersion, minimumVersion.Length == 0 ? "any" : minimumVersion);
            Compare("egress family", before.Proxy.EgressAddressFamily, settings.Proxy.EgressAddressFamily);
            Compare("egress source", before.Proxy.EgressSourceAddress, settings.Proxy.EgressSourceAddress);
            Compare("default connection limit", before.Proxy.MaxConnectionsPerDevice, settings.Proxy.MaxConnectionsPerDevice);
            Compare("default monthly quota (GB)", before.Proxy.MonthlyQuotaGb, settings.Proxy.MonthlyQuotaGb);
            Compare("default rate limit (Mbps)", before.Proxy.RateLimitMbps, settings.Proxy.RateLimitMbps);
            Compare("record destinations", before.Proxy.RecordDestinations, settings.Proxy.RecordDestinations);
            _state.Settings = new BrowserSettings
            {
                HomePage = home?.AbsoluteUri ?? "",
                SearchUrl = searchUrl,
                PrimaryDeviceId = primaryDeviceId,
                AutoShareCookies = settings.AutoShareCookies,
                AutoShareScope = scope,
                AutoShareDomains = sharedSites,
                AllowAdminTokenEnrollment = settings.AllowAdminTokenEnrollment,
                NetworkPolicy = policy,
                IpCheckUrl = ipCheckUrl,
                Proxy = CloneProxySettings(settings.Proxy),
                // The unlock code has its own endpoint; saving the other settings never changes it.
                ClientLock = CloneClientLock(before.ClientLock),
                MinimumClientVersion = minimumVersion
            };
            BumpRevision();
            await SaveLockedAsync();
            return changes.Count == 0 ? "no changes" : string.Join("; ", changes);
        }
        finally { _gate.Release(); }
    }

    private static string SharingSummary(bool enabled, string scope) => !enabled ? "off" : scope == "listed" ? "listed sites" : "every site";

    /// <summary>Accepts host names, URLs and "*.example.com"; returns lower-case domains without duplicates.</summary>
    private static List<string> CleanSiteList(IEnumerable<string>? input)
    {
        var result = new List<string>();
        foreach (var raw in input ?? [])
        {
            var text = (raw ?? "").Trim();
            if (text.Length == 0) continue;
            if (text.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(text, UriKind.Absolute, out var url)) text = url.Host;
            if (text.StartsWith("*.", StringComparison.Ordinal)) text = text[2..];
            var domain = NormalizeDomain(text);
            if (!ValidDomain(domain) || !domain.Contains('.') && domain != "localhost") throw new InvalidOperationException($"'{raw}' is not a valid site. Enter a domain such as github.com");
            if (!result.Contains(domain)) result.Add(domain);
        }
        if (result.Count > MaxSharedSites) throw new InvalidOperationException($"At most {MaxSharedSites} sites can be listed");
        return result;
    }

    /// <summary>
    /// The site under which the primary browser may share cookies for <paramref name="host"/>: the host itself,
    /// or with a sharing list the most specific listed domain that covers it. Null when the list leaves it out.
    /// </summary>
    private string? ShareableSiteLocked(string host)
    {
        var settings = _state.Settings;
        if (settings.AutoShareScope != "listed") return host;
        return settings.AutoShareDomains.Where(domain => DomainMatches(host, domain)).OrderByDescending(domain => domain.Length).FirstOrDefault();
    }

    public const int UnlockCodeIterations = 210_000;

    /// <summary>Turns the browser unlock code on or off, and sets a new code when one is given.</summary>
    public async Task<string> SetClientLockAsync(ClientLockRequest request)
    {
        var code = (request.Code ?? "").Trim().Normalize(NormalizationForm.FormC);
        if (code.Length > 0 && (code.Length is < 4 or > 128 || code.Any(char.IsControl))) throw new InvalidOperationException("The unlock code must be 4 to 128 characters");
        await _gate.WaitAsync();
        try
        {
            var current = _state.Settings.ClientLock;
            if (request.Enabled && code.Length == 0 && current.Hash.Length == 0) throw new InvalidOperationException("Enter an unlock code");
            var next = CloneClientLock(current);
            next.Enabled = request.Enabled;
            if (code.Length > 0)
            {
                var salt = RandomNumberGenerator.GetBytes(16);
                next.Salt = Convert.ToBase64String(salt);
                next.Hash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(code), salt, UnlockCodeIterations, HashAlgorithmName.SHA256, 32));
                next.Iterations = UnlockCodeIterations;
                next.ChangedAt = DateTimeOffset.UtcNow;
            }
            var changes = new List<string>();
            if (current.Enabled != next.Enabled) changes.Add(next.Enabled ? "enabled" : "disabled");
            if (code.Length > 0) changes.Add("code changed");
            if (changes.Count == 0) return "no changes";
            _state.Settings.ClientLock = next;
            BumpRevision();
            await SaveLockedAsync();
            return string.Join(", ", changes);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Republishes when the proxy certificate changed on disk, so browsers pin the new fingerprint.</summary>
    public async Task RefreshProxyFingerprintAsync()
    {
        if (!_snapshot.Settings.Proxy.Tls) return;
        var current = _certificate.CurrentFingerprint;
        if (current == _snapshot.Settings.Proxy.CertificateSha256) return;
        await _gate.WaitAsync();
        try
        {
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
                // so editing one cookie does not require re-entering every other secret in the profile.
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
            var allowed = (input.AllowedDeviceIds ?? []).Select(NormalizeId).Distinct().ToList();
            if (allowed.Any(device => !_state.Devices.Any(item => item.Id == device))) throw new InvalidOperationException("A selected browser is not enrolled");
            if (!input.ShareWithAllDevices && allowed.Count == 0) throw new InvalidOperationException("Select at least one browser, or share the profile with all browsers");
            var clean = new SessionProfile
            {
                Id = id ?? Guid.NewGuid().ToString("N"),
                Name = CleanName(input.Name, domain),
                Domain = domain,
                Enabled = input.Enabled,
                ShareWithAllDevices = input.ShareWithAllDevices,
                AllowedDeviceIds = input.ShareWithAllDevices ? [] : allowed,
                Cookies = cookies
            };
            var others = _state.Profiles.Where((_, position) => position != index).Where(item => item.Domain == domain).ToList();
            if (others.Any(item => string.Equals(item.Name, clean.Name, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException(others.Count == 1 && index < 0 && clean.Name == domain
                    ? $"{domain} already has a profile. Give this one a different name to add it as another account"
                    : $"{domain} already has an account named '{clean.Name}'");
            if (others.Count >= MaxAccountsPerSite) throw new InvalidOperationException($"A site can have at most {MaxAccountsPerSite} accounts");
            if (index < 0) _state.Profiles.Add(clean); else _state.Profiles[index] = clean;
            BumpRevision();
            await SaveLockedAsync();
            return PublicProfile(clean);
        }
        finally { _gate.Release(); }
    }

    public async Task<SessionProfile?> DeleteProfileAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var profile = _state.Profiles.FirstOrDefault(item => item.Id == id);
            if (profile is null) return null;
            _state.Profiles.Remove(profile);
            BumpRevision();
            await SaveLockedAsync();
            return PublicProfile(profile);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Deletes several profiles (or every profile when <paramref name="ids"/> is null) in one revision,
    /// after saving a backup so a mistaken purge can be restored from the dashboard.
    /// Returns the deleted profiles and the name of that backup.
    /// </summary>
    public async Task<(List<SessionProfile> Removed, string Backup)> DeleteProfilesAsync(IReadOnlyCollection<string>? ids)
    {
        await _gate.WaitAsync();
        try
        {
            var wanted = ids is null ? null : new HashSet<string>(ids);
            var removed = _state.Profiles.Where(item => wanted is null || wanted.Contains(item.Id)).ToList();
            if (removed.Count == 0) return ([], "");
            var backup = await BackupLockedAsync(ids is null ? "before-purge" : "before-delete");
            _state.Profiles.RemoveAll(removed.Contains);
            BumpRevision();
            await SaveLockedAsync();
            return (removed.Select(PublicProfile).ToList(), backup);
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> SetRevokedAsync(string id, bool revoked)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return null;
            device.Revoked = revoked;
            await SaveLockedAsync();
            return device.Name;
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> DeleteDeviceAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == id);
            if (device is null) return null;
            _state.Devices.Remove(device);
            _lastSeenPersisted.Remove(id);
            var bump = false;
            if (_state.Settings.PrimaryDeviceId == id)
            {
                _state.Settings.PrimaryDeviceId = "";
                bump = true;
            }
            // A profile limited to browsers that no longer exist stays limited (to nobody) rather than
            // silently widening to every browser.
            foreach (var profile in _state.Profiles.Where(item => item.AllowedDeviceIds.Remove(id))) bump = true;
            foreach (var announcement in _state.Announcements)
            {
                if (announcement.AllowedDeviceIds.Remove(id)) bump = true;
                announcement.Acknowledgements.Remove(id);
            }
            if (bump) BumpRevision();
            await SaveLockedAsync();
            return device.Name;
        }
        finally { _gate.Release(); }
    }

    // ---- Announcements ----------------------------------------------------------------------------

    public async Task<Announcement> CreateAnnouncementAsync(AnnouncementRequest request)
    {
        var title = (request.Title ?? "").Trim();
        var message = (request.Message ?? "").Replace("\r\n", "\n").Trim();
        if (title.Length == 0 && message.Length == 0) throw new InvalidOperationException("Enter a title or a message");
        if (title.Length > 120 || title.Any(char.IsControl)) throw new InvalidOperationException("The title must be one line of at most 120 characters");
        if (message.Length > 2000 || message.Any(character => char.IsControl(character) && character != '\n')) throw new InvalidOperationException("The message must be at most 2000 characters");
        var level = (request.Level ?? "info").Trim().ToLowerInvariant();
        if (!AnnouncementLevels.Contains(level)) throw new InvalidOperationException("Level must be info, warning or critical");
        var url = (request.Url ?? "").Trim();
        if (url.Length > 0 && (url.Length > 2000 || !Uri.TryCreate(url, UriKind.Absolute, out var link) || link.Scheme is not ("http" or "https"))) throw new InvalidOperationException("The link must be an HTTP or HTTPS URL");
        if (request.ExpiresInMinutes is < 1 or > 30 * 24 * 60) throw new InvalidOperationException("An announcement can expire after 1 minute to 30 days, or never");
        var allowed = (request.AllowedDeviceIds ?? []).Select(NormalizeId).Distinct().ToList();
        if (!request.ShareWithAllDevices && allowed.Count == 0) throw new InvalidOperationException("Select at least one browser, or send the announcement to all browsers");
        var now = DateTimeOffset.UtcNow;
        var announcement = new Announcement
        {
            Id = Guid.NewGuid().ToString("N"),
            Title = title,
            Message = message,
            Level = level,
            Url = url.Length > 0 ? new Uri(url).AbsoluteUri : "",
            CreatedAt = now,
            ExpiresAt = request.ExpiresInMinutes is { } minutes ? now.AddMinutes(minutes) : null,
            ShareWithAllDevices = request.ShareWithAllDevices,
            AllowedDeviceIds = request.ShareWithAllDevices ? [] : allowed
        };
        await _gate.WaitAsync();
        try
        {
            if (allowed.Any(device => !_state.Devices.Any(item => item.Id == device))) throw new InvalidOperationException("A selected browser is not enrolled");
            if (_state.Announcements.Count(item => item.ExpiresAt is null || item.ExpiresAt > now) >= MaxAnnouncements) throw new InvalidOperationException($"At most {MaxAnnouncements} announcements can be active. Delete old ones first");
            _state.Announcements.Add(announcement);
            BumpRevision();
            await SaveLockedAsync();
            return announcement;
        }
        finally { _gate.Release(); }
    }

    public async Task<Announcement?> DeleteAnnouncementAsync(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var announcement = _state.Announcements.FirstOrDefault(item => item.Id == id);
            if (announcement is null) return null;
            _state.Announcements.Remove(announcement);
            BumpRevision();
            await SaveLockedAsync();
            return announcement;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Records that a browser's user dismissed an announcement it was sent. Returns false if it cannot see it.</summary>
    public async Task<bool> AcknowledgeAnnouncementAsync(string deviceId, string id)
    {
        await _gate.WaitAsync();
        try
        {
            var announcement = _state.Announcements.FirstOrDefault(item => item.Id == id);
            if (announcement is null || !(announcement.ShareWithAllDevices || announcement.AllowedDeviceIds.Contains(deviceId))) return false;
            if (announcement.Acknowledgements.TryAdd(deviceId, DateTimeOffset.UtcNow)) await SaveLockedAsync(publish: false);
            return true;
        }
        finally { _gate.Release(); }
    }

    // ---- Accounts ---------------------------------------------------------------------------------

    /// <summary>
    /// Makes <paramref name="profileId"/> the account this device uses for its site. Only this device's
    /// snapshot changes, so the revision stays the same and other browsers are not woken up.
    /// </summary>
    public async Task<SessionProfile> SwitchAccountAsync(string deviceId, string profileId)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.First(item => item.Id == deviceId);
            var profile = _state.Profiles.FirstOrDefault(item => item.Id == profileId && item.Enabled && Shares(item, deviceId)) ?? throw new KeyNotFoundException();
            device.ActiveProfiles[profile.Domain] = profile.Id;
            // Forget choices for sites that no longer exist.
            foreach (var domain in device.ActiveProfiles.Keys.Where(domain => !_state.Profiles.Any(item => item.Domain == domain)).ToList()) device.ActiveProfiles.Remove(domain);
            await SaveLockedAsync(backup: false);
            return PublicProfile(profile);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Adds an empty account for the site of the page and switches this device to it, so the next sign-in
    /// on that site is saved as the new account. Only the primary browser saves cookies, so only it may.
    /// </summary>
    public async Task<SessionProfile> CreateAccountAsync(string deviceId, CreateAccountRequest request)
    {
        if (!Uri.TryCreate(request.PageUrl, UriKind.Absolute, out var page) || page.Scheme is not ("http" or "https")) throw new InvalidOperationException("Open the site you want to add an account for first");
        var host = NormalizeDomain(page.Host);
        var name = CleanName(request.Name, "");
        if (name.Length == 0) throw new InvalidOperationException("Enter a name for the account");
        await _gate.WaitAsync();
        try
        {
            if (_state.Settings.AutoShareCookies && string.IsNullOrWhiteSpace(_state.Settings.PrimaryDeviceId)) _state.Settings.PrimaryDeviceId = deviceId;
            if (!IsPrimaryLocked(deviceId)) throw new UnauthorizedAccessException("Only the primary browser can add accounts, because only its sign-ins are saved");
            var device = _state.Devices.First(item => item.Id == deviceId);
            var site = _state.Profiles.Where(item => DomainMatches(host, item.Domain)).GroupBy(item => item.Domain).OrderByDescending(group => group.Key.Length).FirstOrDefault()?.ToList() ?? [];
            var shareable = ShareableSiteLocked(host) ?? throw new InvalidOperationException($"{host} is not on the server's list of shared sites");
            var domain = site.Count > 0 ? site[0].Domain : shareable;
            if (!ValidDomain(domain)) throw new InvalidOperationException("Invalid site");
            if (site.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException($"{domain} already has an account named '{name}'");
            if (site.Count >= MaxAccountsPerSite) throw new InvalidOperationException($"A site can have at most {MaxAccountsPerSite} accounts");
            // The new account is shared like the one the browser is using now, and always with the browser adding it.
            var template = ActiveAccountLocked(device, site, false) ?? site.FirstOrDefault();
            var shareWithAll = template?.ShareWithAllDevices ?? true;
            var profile = new SessionProfile
            {
                Id = Guid.NewGuid().ToString("N"),
                Name = name,
                Domain = domain,
                Enabled = true,
                ShareWithAllDevices = shareWithAll,
                AllowedDeviceIds = shareWithAll ? [] : [.. template!.AllowedDeviceIds.Append(deviceId).Distinct()]
            };
            _state.Profiles.Add(profile);
            device.ActiveProfiles[domain] = profile.Id;
            BumpRevision();
            await SaveLockedAsync();
            return PublicProfile(profile);
        }
        finally { _gate.Release(); }
    }

    // ---- Cookie synchronization -------------------------------------------------------------------

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
            // With a sharing list, cookies of sites that are not on it are neither added nor updated.
            var shareable = ShareableSiteLocked(host);
            if (shareable is null)
            {
                if (settingsChanged) { BumpRevision(); await SaveLockedAsync(); }
                return 0;
            }
            var site = _state.Profiles.Where(item => DomainMatches(host, item.Domain)).GroupBy(item => item.Domain).OrderByDescending(group => group.Key.Length).FirstOrDefault();
            // Cookies go to the account this browser has switched to. A site whose profiles are all disabled
            // blocks sharing for its domain; it must not be shadowed by an automatic one.
            var profile = site is null ? null : ActiveAccountLocked(device, site, false);
            var profileCreated = false;
            if (site is null && _state.Settings.AutoShareCookies && incomingCookies.Count > 0)
            {
                if (!ValidDomain(shareable)) return 0;
                // A listed site keeps its subdomains in one profile (github.com also covers gist.github.com).
                profile = new SessionProfile { Id = Guid.NewGuid().ToString("N"), Name = shareable, Domain = shareable, Enabled = true };
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

    // ---- Backups, export and import ---------------------------------------------------------------

    public IReadOnlyList<BackupInfo> ListBackups() => Directory.EnumerateFiles(_backupDirectory, "state-*.json")
        .Select(path => new FileInfo(path))
        .Where(file => BackupName().IsMatch(file.Name))
        .Select(file => new BackupInfo(file.Name, file.Length, new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero)))
        .OrderByDescending(item => item.Name, StringComparer.Ordinal)
        .ToList();

    /// <summary>The vault file exactly as stored on disk: cookie values stay encrypted with the data key.</summary>
    public async Task<byte[]> ExportAsync()
    {
        await _gate.WaitAsync();
        try
        {
            await SaveLockedAsync(publish: false);
            return await File.ReadAllBytesAsync(_path);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Replaces the vault with an exported or backed-up one. The current vault is backed up first.</summary>
    public async Task<string> ImportAsync(string json, string reason)
    {
        SharedState incoming;
        try { incoming = Parse(json); }
        catch (Exception error) when (error is JsonException or InvalidOperationException or NotSupportedException)
        {
            throw new InvalidOperationException($"The file is not a usable Shared Browser vault: {error.Message}");
        }
        await _gate.WaitAsync();
        try
        {
            var safety = await BackupLockedAsync($"before-{reason}");
            // Move past both revisions so every browser notices the change and downloads the new vault.
            incoming.Revision = Math.Max(incoming.Revision, _state.Revision) + 1;
            incoming.UpdatedAt = DateTimeOffset.UtcNow;
            _state = incoming;
            _lastSeenPersisted.Clear();
            await SaveLockedAsync();
            return $"{incoming.Profiles.Count} profile(s), {incoming.Devices.Count} device(s); previous vault saved as {safety}";
        }
        finally { _gate.Release(); }
    }

    public async Task<string> RestoreBackupAsync(string name)
    {
        if (!BackupName().IsMatch(name)) throw new InvalidOperationException("Invalid backup name");
        var path = Path.Combine(_backupDirectory, name);
        if (!File.Exists(path)) throw new KeyNotFoundException();
        return await ImportAsync(await File.ReadAllTextAsync(path), "restore");
    }

    [GeneratedRegex(@"^state-\d{8}T\d{6}Z(-[a-z]+(-[a-z]+)*)?\.json$")]
    private static partial Regex BackupName();

    private async Task<string> BackupLockedAsync(string suffix = "")
    {
        await SaveLockedAsync(publish: false, backup: false);
        var name = $"state-{DateTimeOffset.UtcNow:yyyyMMdd'T'HHmmss'Z'}{(suffix.Length > 0 ? "-" + suffix : "")}.json";
        File.Copy(_path, Path.Combine(_backupDirectory, name), true);
        _lastBackup = DateTimeOffset.UtcNow;
        foreach (var old in ListBackups().Skip(_backupKeep))
        {
            try { File.Delete(Path.Combine(_backupDirectory, old.Name)); } catch (IOException) { }
        }
        return name;
    }

    // ---- Persistence ------------------------------------------------------------------------------

    /// <summary>Parses a vault file and decrypts its cookie values, which fails when the data key does not match.</summary>
    private SharedState Parse(string json)
    {
        var disk = JsonSerializer.Deserialize<SharedState>(json, JsonOptions) ?? throw new InvalidOperationException("The vault file is empty");
        disk.Settings ??= new BrowserSettings();
        if (disk.Settings.HomePage is "https://example.com/" or "https://example.com") disk.Settings.HomePage = "";
        disk.Settings.SearchUrl ??= "";
        disk.Settings.NetworkPolicy = NetworkPolicies.Contains(disk.Settings.NetworkPolicy) ? disk.Settings.NetworkPolicy : "strict";
        disk.Settings.IpCheckUrl ??= "";
        disk.Settings.Proxy ??= new ProxySettings();
        disk.Settings.ClientLock ??= new ClientLockSettings();
        disk.Settings.AutoShareScope = AutoShareScopes.Contains(disk.Settings.AutoShareScope) ? disk.Settings.AutoShareScope : "all";
        disk.Settings.AutoShareDomains ??= [];
        disk.Settings.MinimumClientVersion ??= "";
        disk.Settings.ClientLock.Salt ??= "";
        disk.Settings.ClientLock.Hash ??= "";
        disk.Profiles ??= [];
        disk.Devices ??= [];
        disk.Bookmarks ??= [];
        disk.EnrollmentCodes ??= [];
        disk.Announcements ??= [];
        foreach (var announcement in disk.Announcements)
        {
            announcement.AllowedDeviceIds ??= [];
            announcement.Acknowledgements ??= [];
        }
        foreach (var profile in disk.Profiles)
        {
            profile.Cookies ??= [];
            profile.AllowedDeviceIds ??= [];
        }
        foreach (var device in disk.Devices) device.ActiveProfiles ??= [];
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Decrypt(cookie.Value);
        return disk;
    }

    private async Task SaveLockedAsync(bool publish = true, bool backup = true)
    {
        var disk = new SharedState
        {
            Revision = _state.Revision,
            UpdatedAt = _state.UpdatedAt,
            Settings = CloneSettings(_state.Settings),
            Devices = _state.Devices.Select(device => new DeviceRecord { Id = device.Id, Name = device.Name, TokenHash = device.TokenHash, EnrolledAt = device.EnrolledAt, LastSeenAt = device.LastSeenAt, Revoked = device.Revoked, ClientVersion = device.ClientVersion, NetworkMode = device.NetworkMode, MaxConnections = device.MaxConnections, MonthlyQuotaGb = device.MonthlyQuotaGb, RateLimitMbps = device.RateLimitMbps, ActiveProfiles = new(device.ActiveProfiles) }).ToList(),
            Profiles = _state.Profiles.Select(CloneProfile).ToList(),
            Bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList(),
            EnrollmentCodes = _state.EnrollmentCodes.Select(code => new EnrollmentCode { Id = code.Id, CodeHash = code.CodeHash, Label = code.Label, CreatedAt = code.CreatedAt, ExpiresAt = code.ExpiresAt, UsedAt = code.UsedAt, UsedByDeviceId = code.UsedByDeviceId, Revoked = code.Revoked }).ToList(),
            Announcements = _state.Announcements.Select(item => new Announcement { Id = item.Id, Title = item.Title, Message = item.Message, Level = item.Level, Url = item.Url, CreatedAt = item.CreatedAt, ExpiresAt = item.ExpiresAt, ShareWithAllDevices = item.ShareWithAllDevices, AllowedDeviceIds = [.. item.AllowedDeviceIds], Acknowledgements = new(item.Acknowledgements) }).ToList()
        };
        disk.Settings.Proxy.CertificateSha256 = "";
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Encrypt(cookie.Value);
        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(disk, JsonOptions));
        File.Move(temp, _path, true);
        if (publish) PublishLocked();
        if (backup && DateTimeOffset.UtcNow - _lastBackup >= _backupInterval)
        {
            try { await BackupLockedAsync(); }
            catch (IOException error) { _logger.LogWarning(error, "Automatic vault backup failed"); }
        }
    }

    /// <summary>Rebuilds the lock-free read models. Must be called while holding the gate (or from the constructor).</summary>
    private void PublishLocked()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var settings = CloneSettings(_state.Settings);
        settings.Proxy.CertificateSha256 = settings.Proxy.Tls ? _certificate.CurrentFingerprint : "";
        _snapshot = new SharedSnapshot(
            _state.Revision,
            _state.UpdatedAt,
            settings,
            _state.Profiles.Select(profile =>
            {
                var clone = CloneProfile(profile);
                clone.Cookies.RemoveAll(cookie => cookie.ExpiresAt is { } expires && expires < now);
                return clone;
            }).ToList(),
            _state.Bookmarks.Select(CloneBookmark).ToList(),
            _state.Announcements
                .Where(item => item.ExpiresAt is null || item.ExpiresAt > DateTimeOffset.UtcNow)
                .OrderByDescending(item => item.CreatedAt)
                .Select(item => new ClientAnnouncement(item.Id, item.Title, item.Message, item.Level, item.Url, item.CreatedAt, item.ExpiresAt) { ShareWithAllDevices = item.ShareWithAllDevices, AllowedDeviceIds = [.. item.AllowedDeviceIds] })
                .ToList());
        _deviceIndex = _state.Devices.ToDictionary(device => device.Id, device => new DeviceAuth(device.Id, device.Name, device.TokenHash, device.Revoked, device.MaxConnections, device.MonthlyQuotaGb, device.RateLimitMbps, device.ClientVersion));
        _accountChoices = _state.Devices.Where(device => device.ActiveProfiles.Count > 0)
            .ToDictionary(device => device.Id, device => (IReadOnlyDictionary<string, string>)new Dictionary<string, string>(device.ActiveProfiles));
        if (_state.Revision != _publishedRevision)
        {
            _publishedRevision = _state.Revision;
            var signal = _revisionChanged;
            _revisionChanged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            signal.TrySetResult();
        }
    }

    private void BumpRevision()
    {
        _state.Revision++;
        _state.UpdatedAt = DateTimeOffset.UtcNow;
        var now = _state.UpdatedAt.ToUnixTimeSeconds();
        foreach (var profile in _state.Profiles) profile.Cookies.RemoveAll(cookie => cookie.ExpiresAt is { } expires && expires < now);
        // Expired announcements stay visible in the dashboard for a week, then go.
        _state.Announcements.RemoveAll(item => item.ExpiresAt is { } expires && expires < _state.UpdatedAt - ExpiredAnnouncementRetention);
    }

    private void PruneCodesLocked()
    {
        var cutoff = DateTimeOffset.UtcNow - CodeRetention;
        _state.EnrollmentCodes.RemoveAll(code => (code.UsedAt ?? (code.Revoked ? code.CreatedAt : code.ExpiresAt)) < cutoff);
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
            throw new InvalidOperationException("The vault cannot be decrypted. SHARED_BROWSER_DATA_KEY does not match the key that wrote it.", error);
        }
    }

    // ---- Helpers ----------------------------------------------------------------------------------

    private static int IntFromEnvironment(string name, int fallback) => int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;
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
    private static BrowserSettings CloneSettings(BrowserSettings settings) => new() { HomePage = settings.HomePage, SearchUrl = settings.SearchUrl, PrimaryDeviceId = settings.PrimaryDeviceId, AutoShareCookies = settings.AutoShareCookies, AutoShareScope = settings.AutoShareScope, AutoShareDomains = [.. settings.AutoShareDomains], AllowAdminTokenEnrollment = settings.AllowAdminTokenEnrollment, NetworkPolicy = settings.NetworkPolicy, IpCheckUrl = settings.IpCheckUrl, Proxy = CloneProxySettings(settings.Proxy), ClientLock = CloneClientLock(settings.ClientLock), MinimumClientVersion = settings.MinimumClientVersion };
    private static ClientLockSettings CloneClientLock(ClientLockSettings? value) => value is null ? new() : new() { Enabled = value.Enabled, Salt = value.Salt, Hash = value.Hash, Iterations = value.Iterations, ChangedAt = value.ChangedAt };
    private static ProxySettings CloneProxySettings(ProxySettings settings) => new()
    {
        Enabled = settings.Enabled, Host = settings.Host, Port = settings.Port, AllowedPorts = settings.AllowedPorts, BypassList = settings.BypassList, Tls = settings.Tls, CertificateSha256 = settings.CertificateSha256,
        EgressAddressFamily = settings.EgressAddressFamily, EgressSourceAddress = settings.EgressSourceAddress,
        MaxConnectionsPerDevice = settings.MaxConnectionsPerDevice, MonthlyQuotaGb = settings.MonthlyQuotaGb, RateLimitMbps = settings.RateLimitMbps, RecordDestinations = settings.RecordDestinations
    };
    private static SharedBookmark CloneBookmark(SharedBookmark item) => new() { Title = item.Title, Url = item.Url };
    private static SharedCookie CloneCookie(SharedCookie cookie, string? value = null) => new() { Name = cookie.Name, Value = value ?? cookie.Value, Domain = cookie.Domain, Path = cookie.Path, Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, SameSite = cookie.SameSite, ExpiresAt = cookie.ExpiresAt, UpdatedAt = cookie.UpdatedAt, SourceDeviceId = cookie.SourceDeviceId };
    private static void ValidateProxySettings(ProxySettings proxy)
    {
        proxy.Host = (proxy.Host ?? "").Trim();
        proxy.AllowedPorts = string.Join(',', (proxy.AllowedPorts ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        proxy.BypassList = (proxy.BypassList ?? "").Trim();
        proxy.CertificateSha256 = "";
        if (proxy.Port is < 1 or > 65535) throw new InvalidOperationException("Proxy port must be between 1 and 65535");
        if (proxy.Host.Length is < 1 or > 253 || proxy.Host.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or ':' or '[' or ']'))) throw new InvalidOperationException("Proxy host is invalid");
        if (proxy.AllowedPorts.Length == 0 || proxy.AllowedPorts.Split(',').Any(item => !int.TryParse(item, out var port) || port is < 1 or > 65535)) throw new InvalidOperationException("Allowed proxy ports must be comma-separated port numbers");
        if (proxy.BypassList.Length > 500 || proxy.BypassList.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '*' or ';' or ':' or '<' or '>' or '[' or ']'))) throw new InvalidOperationException("Proxy bypass list contains unsupported characters");
        Egress.Validate(proxy);
        ValidateLimit(proxy.MaxConnectionsPerDevice, 100_000, "Connection limit");
        ValidateLimit(proxy.MonthlyQuotaGb, 1_000_000, "Monthly quota");
        ValidateLimit(proxy.RateLimitMbps, 100_000, "Rate limit");
    }
    private static SessionProfile CloneProfile(SessionProfile profile) => new()
    {
        Id = profile.Id,
        Name = profile.Name,
        Domain = profile.Domain,
        Enabled = profile.Enabled,
        ShareWithAllDevices = profile.ShareWithAllDevices,
        AllowedDeviceIds = [.. profile.AllowedDeviceIds],
        Cookies = profile.Cookies.Select(cookie => CloneCookie(cookie)).ToList()
    };
    private static SessionProfile PublicProfile(SessionProfile profile)
    {
        var clone = CloneProfile(profile);
        foreach (var cookie in clone.Cookies) cookie.Value = "";
        return clone;
    }
}
