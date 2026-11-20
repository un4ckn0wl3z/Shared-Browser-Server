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
    private volatile IReadOnlyDictionary<string, DeviceView> _deviceViews = new Dictionary<string, DeviceView>();
    private volatile NotificationSettings _notifications = new();
    private volatile OffsiteBackupSettings _offsite = new();
    private static readonly IReadOnlyDictionary<string, string> NoChoices = new Dictionary<string, string>();

    /// <summary>What one browser's snapshot needs beyond the shared state (published with the snapshot).</summary>
    private sealed record DeviceView(IReadOnlyDictionary<string, string> Choices, string HomePage, SiteFilterSettings? SiteFilter, bool ScheduleExempt, List<ClientCommand> Commands, bool? UnlockCode);

    /// <summary>Raised (on the thread pool, never under the gate) for events the audit log and alerts should know about.</summary>
    public event Action<string, string, string>? Activity;
    /// <summary>Raised with the file name after every backup is written.</summary>
    public event Action<string>? BackupCreated;
    public string BackupDirectory => _backupDirectory;
    private void RaiseActivity(string action, string target, string details) => Task.Run(() => Activity?.Invoke(action, target, details));

    public NotificationSettings NotificationSettings() => _notifications;
    public OffsiteBackupSettings OffsiteSettings() => _offsite;
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
        var view = _deviceViews.GetValueOrDefault(deviceId);
        var choices = view?.Choices ?? NoChoices;
        var profiles = new List<SessionProfile>();
        var accounts = new List<ClientAccount>();
        foreach (var site in snapshot.Profiles.Where(profile => Shares(profile, deviceId)).GroupBy(profile => profile.Domain))
        {
            var usable = site.Where(profile => profile.Enabled).ToList();
            // Disabled profiles still go out: they tell a browser that sharing for the site is switched off.
            if (usable.Count == 0) { profiles.AddRange(site); continue; }
            var active = PickAccount(usable, choices.GetValueOrDefault(site.Key));
            profiles.Add(active);
            var warningDays = _notifications.ExpiryWarningDays;
            accounts.AddRange(usable.Select(profile =>
            {
                var (session, expiresAt) = SessionState(profile, warningDays);
                return new ClientAccount(profile.Id, profile.Name, profile.Domain, profile == active, profile.Cookies.Count) { Session = session, ExpiresAt = expiresAt };
            }));
        }
        var settings = snapshot.Settings;
        if (view is not null && (view.HomePage.Length > 0 || view.SiteFilter is not null || view.ScheduleExempt || view.UnlockCode is not null))
        {
            settings = CloneSettings(settings);
            settings.Proxy.CertificateSha256 = snapshot.Settings.Proxy.CertificateSha256;
            if (view.HomePage.Length > 0) settings.HomePage = view.HomePage;
            if (view.SiteFilter is not null) settings.SiteFilter = CloneSiteFilter(view.SiteFilter);
            if (view.ScheduleExempt) settings.Schedule.Enabled = false;
            // This browser's own unlock code setting; it needs a code to have been set.
            if (view.UnlockCode is { } unlock) settings.ClientLock.Enabled = unlock && settings.ClientLock.Hash.Length > 0;
        }
        var editable = profiles.Where(profile => profile.Enabled && profile.EditorDeviceIds.Contains(deviceId)).Select(profile => profile.Domain).Distinct().ToList();
        var readOnly = string.Equals(settings.PrimaryDeviceId, deviceId, StringComparison.OrdinalIgnoreCase)
            ? profiles.Where(profile => profile.Enabled && profile.EditorDeviceIds.Count > 0 && !profile.EditorDeviceIds.Contains(deviceId)).Select(profile => profile.Domain).Distinct().ToList()
            : [];
        return snapshot with
        {
            EditableDomains = editable,
            ReadOnlyDomains = readOnly,
            Settings = settings,
            Profiles = profiles,
            Announcements = snapshot.Announcements.Where(item => item.ShareWithAllDevices || item.AllowedDeviceIds.Contains(deviceId)).ToList(),
            Accounts = accounts,
            Commands = view?.Commands ?? []
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

    /// <summary>With automatic sharing and no primary browser yet, the first browser that shares becomes it.</summary>
    private bool ClaimPrimaryLocked(string deviceId)
    {
        if (!_state.Settings.AutoShareCookies || _state.Settings.PrimaryDeviceId.Length > 0) return false;
        _state.Settings.PrimaryDeviceId = deviceId;
        _state.Settings.PrimaryDeviceIds = [deviceId];
        return true;
    }

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
                    profile.SessionCookie,
                    health = SessionHealth(profile, _state.Notifications.ExpiryWarningDays),
                    // False when a sharing list is in use and does not cover the profile: the primary browser no longer updates it.
                    listed = ShareableSiteLocked(profile.Domain) is not null,
                    usedBy = _state.Devices.Where(device => !device.Revoked && ActiveAccountLocked(device, _state.Profiles.Where(item => item.Domain == profile.Domain), true) == profile).Select(DisplayName).ToList(),
                    profile.EditorDeviceIds,
                    editors = _state.Devices.Where(device => profile.EditorDeviceIds.Contains(device.Id)).Select(DisplayName).ToList(),
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
                    device.HomePage,
                    device.SiteFilter,
                    device.ScheduleExempt,
                    // For sites with several accounts: which one this browser uses (null when it can use none).
                    accounts = _state.Profiles.GroupBy(item => item.Domain).Where(site => site.Count(item => item.Enabled) > 1)
                        .Select(site => new
                        {
                            domain = site.Key,
                            activeId = ActiveAccountLocked(device, site, true)?.Id,
                            options = site.Where(item => item.Enabled && Shares(item, device.Id)).Select(item => new { item.Id, item.Name }).ToList()
                        }).Where(site => site.options.Count > 0).ToList(),
                    pendingCommands = device.Commands.Where(command => command.CreatedAt > now - CommandLifetime).Select(CloneCommand).ToList(),
                    usage = usage(device.Id),
                    primary = IsPrimaryLocked(device.Id),
                    editorOf = _state.Profiles.Where(profile => profile.EditorDeviceIds.Contains(device.Id)).Select(ProfileLabel).ToList(),
                    device.UnlockCode,
                    live = _liveConnections.GetValueOrDefault(device.Id) > 0
                }).ToList(),
                bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList(),
                announcements = _state.Announcements.OrderByDescending(item => item.Pinned).ThenByDescending(item => item.CreatedAt).Select(item =>
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
                        item.Pinned,
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
                backupPolicy = new { keep = _backupKeep, intervalMinutes = (int)_backupInterval.TotalMinutes },
                notifications = Notifier.Public(_state.Notifications),
                offsiteBackup = OffsiteUploader.Public(_state.OffsiteBackup),
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
        var siteFilter = CleanSiteFilter(settings.SiteFilter);
        var schedule = CleanSchedule(settings.Schedule);
        var dataControls = settings.DataControls ?? new DataControls();
        dataControls = new DataControls { BlockDownloads = dataControls.BlockDownloads, BlockUploads = dataControls.BlockUploads, BlockCopy = dataControls.BlockCopy, Domains = CleanSiteList(dataControls.Domains) };
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
            Compare("site filter", $"{before.SiteFilter.Mode} {string.Join(", ", before.SiteFilter.Domains)}".Trim(), $"{siteFilter.Mode} {string.Join(", ", siteFilter.Domains)}".Trim());
            Compare("allowed hours", ScheduleSummary(before.Schedule), ScheduleSummary(schedule));
            Compare("data controls", DataControlsSummary(before.DataControls), DataControlsSummary(dataControls));
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
                PrimaryDeviceIds = primaryDeviceId.Length > 0 ? [primaryDeviceId] : [],
                AutoShareCookies = settings.AutoShareCookies,
                AutoShareScope = scope,
                AutoShareDomains = sharedSites,
                AllowAdminTokenEnrollment = settings.AllowAdminTokenEnrollment,
                NetworkPolicy = policy,
                IpCheckUrl = ipCheckUrl,
                Proxy = CloneProxySettings(settings.Proxy),
                // The unlock code has its own endpoint; saving the other settings never changes it.
                ClientLock = CloneClientLock(before.ClientLock),
                MinimumClientVersion = minimumVersion,
                SiteFilter = siteFilter,
                Schedule = schedule,
                DataControls = dataControls
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
        if (request.IdleMinutes is < 0 or > 24 * 60) throw new InvalidOperationException("Lock after idle must be between 0 (never) and 1440 minutes");
        await _gate.WaitAsync();
        try
        {
            var current = _state.Settings.ClientLock;
            if (request.Enabled && code.Length == 0 && current.Hash.Length == 0) throw new InvalidOperationException("Enter an unlock code");
            var next = CloneClientLock(current);
            next.Enabled = request.Enabled;
            next.IdleMinutes = request.IdleMinutes;
            next.LockOnSystemLock = request.LockOnSystemLock;
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
            if (current.IdleMinutes != next.IdleMinutes) changes.Add(next.IdleMinutes > 0 ? $"locks after {next.IdleMinutes} idle minutes" : "no idle lock");
            if (current.LockOnSystemLock != next.LockOnSystemLock) changes.Add(next.LockOnSystemLock ? "locks with the computer" : "does not lock with the computer");
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
            var folder = CleanName(item.Folder, "");
            return new SharedBookmark { Title = title[..Math.Min(120, title.Length)], Url = url.AbsoluteUri, Folder = folder[..Math.Min(60, folder.Length)] };
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
            var editors = (input.EditorDeviceIds ?? []).Select(NormalizeId).Distinct().ToList();
            if (editors.Any(device => !_state.Devices.Any(item => item.Id == device))) throw new InvalidOperationException("A browser chosen to update cookies is not enrolled");
            // An editor must receive the profile to be able to sign in to it.
            if (!input.ShareWithAllDevices && editors.Any(device => !allowed.Contains(device))) throw new InvalidOperationException("Browsers that update the cookies must also be among the browsers the profile is shared with");
            var clean = new SessionProfile
            {
                Id = id ?? Guid.NewGuid().ToString("N"),
                Name = CleanName(input.Name, domain),
                SessionCookie = CleanName(input.SessionCookie, "").Replace(" ", ""),
                EditorDeviceIds = editors,
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
                _state.Settings.PrimaryDeviceIds = [];
                bump = true;
            }
            foreach (var profile in _state.Profiles.Where(item => item.EditorDeviceIds.Remove(id))) bump = true;
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
            AllowedDeviceIds = request.ShareWithAllDevices ? [] : allowed,
            Pinned = request.Pinned
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

    public async Task<Announcement?> SetAnnouncementPinnedAsync(string id, bool pinned)
    {
        await _gate.WaitAsync();
        try
        {
            var announcement = _state.Announcements.FirstOrDefault(item => item.Id == id);
            if (announcement is null) return null;
            if (announcement.Pinned != pinned)
            {
                announcement.Pinned = pinned;
                BumpRevision();
                await SaveLockedAsync();
            }
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

    // ---- Notifications and offsite backups ---------------------------------------------------------

    public async Task<string> SetNotificationsAsync(NotificationSettings input)
    {
        await _gate.WaitAsync();
        try
        {
            _state.Notifications = Notifier.Clean(input, _state.Notifications);
            await SaveLockedAsync(backup: false);
            var channels = new[] { _state.Notifications.DiscordWebhookUrl.Length > 0 ? "Discord" : "", _state.Notifications.TelegramBotToken.Length > 0 ? "Telegram" : "", _state.Notifications.LineChannelToken.Length > 0 ? "LINE" : "" }.Where(item => item.Length > 0).ToList();
            return $"channels: {(channels.Count == 0 ? "none" : string.Join(", ", channels))}; events: {string.Join(", ", _state.Notifications.Events)}";
        }
        finally { _gate.Release(); }
    }

    public async Task<string> SetOffsiteBackupAsync(OffsiteBackupSettings input)
    {
        await _gate.WaitAsync();
        try
        {
            var current = _state.OffsiteBackup;
            var clean = OffsiteUploader.Clean(input, current);
            clean.LastUploadAt = current.LastUploadAt;
            clean.LastUploadName = current.LastUploadName;
            clean.LastError = current.LastError;
            _state.OffsiteBackup = clean;
            await SaveLockedAsync(backup: false);
            return clean.Enabled ? $"to {clean.Endpoint}/{clean.Bucket}/{clean.Prefix}" : "disabled";
        }
        finally { _gate.Release(); }
    }

    public async Task RecordOffsiteResultAsync(string name, string error)
    {
        await _gate.WaitAsync();
        try
        {
            if (error.Length == 0) { _state.OffsiteBackup.LastUploadAt = DateTimeOffset.UtcNow; _state.OffsiteBackup.LastUploadName = name; }
            _state.OffsiteBackup.LastError = error;
            await SaveLockedAsync(backup: false);
        }
        finally { _gate.Release(); }
    }

    // ---- Session health ---------------------------------------------------------------------------

    /// <summary>
    /// The cookies that hold a profile's sign-in: the one named in the profile, or else HttpOnly cookies that
    /// are not short-lived (anti-bot and CSRF cookies that last less than a day are left out).
    /// </summary>
    private static List<SharedCookie> SignInCookies(SessionProfile profile)
    {
        if (profile.SessionCookie.Length > 0) return profile.Cookies.Where(cookie => cookie.Name == profile.SessionCookie).ToList();
        return profile.Cookies.Where(cookie => cookie.HttpOnly && (cookie.ExpiresAt is not { } expires || expires - cookie.UpdatedAt.ToUnixTimeSeconds() >= 24 * 60 * 60)).ToList();
    }

    /// <summary>A device name, with the start of its ID when another browser has the same name.</summary>
    private string DisplayName(DeviceRecord device) =>
        _state.Devices.Count(item => item.Name == device.Name) > 1 ? $"{device.Name} ({device.Id[..Math.Min(6, device.Id.Length)]})" : device.Name;

    private static string ProfileLabel(SessionProfile profile) => profile.Name == profile.Domain ? profile.Domain : $"{profile.Domain} ({profile.Name})";

    private static (string State, DateTimeOffset? ExpiresAt) SessionState(SessionProfile profile, int warningDays)
    {
        if (profile.Cookies.Count == 0) return ("empty", null);
        var signIn = SignInCookies(profile);
        if (signIn.Count == 0) return ("signed-out", null);
        var expiry = signIn.Where(cookie => cookie.ExpiresAt is not null).Select(cookie => cookie.ExpiresAt!.Value).DefaultIfEmpty(0).Min();
        if (expiry == 0) return ("ok", null);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds((long)expiry);
        return (expiresAt - DateTimeOffset.UtcNow < TimeSpan.FromDays(warningDays) ? "expiring" : "ok", expiresAt);
    }

    private static object SessionHealth(SessionProfile profile, int warningDays)
    {
        var lastUpdate = profile.Cookies.Select(cookie => (DateTimeOffset?)cookie.UpdatedAt).Max();
        if (profile.Cookies.Count == 0) return new { state = "empty", expiresAt = (DateTimeOffset?)null, lastUpdate };
        var signIn = SignInCookies(profile);
        if (signIn.Count == 0) return new { state = "signed-out", expiresAt = (DateTimeOffset?)null, lastUpdate };
        var expiry = signIn.Where(cookie => cookie.ExpiresAt is not null).Select(cookie => cookie.ExpiresAt!.Value).DefaultIfEmpty(0).Min();
        if (expiry == 0) return new { state = "ok", expiresAt = (DateTimeOffset?)null, lastUpdate };
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds((long)expiry);
        return new { state = expiresAt - DateTimeOffset.UtcNow < TimeSpan.FromDays(warningDays) ? "expiring" : "ok", expiresAt = (DateTimeOffset?)expiresAt, lastUpdate };
    }

    /// <summary>Enabled profiles whose sign-in expires within the warning period: (label, expiry).</summary>
    public async Task<List<(string Label, DateTimeOffset ExpiresAt)>> ExpiringSessionsAsync()
    {
        await _gate.WaitAsync();
        try
        {
            var limit = DateTimeOffset.UtcNow.AddDays(_state.Notifications.ExpiryWarningDays).ToUnixTimeSeconds();
            return _state.Profiles.Where(profile => profile.Enabled)
                .Select(profile => (profile, expiry: SignInCookies(profile).Where(cookie => cookie.ExpiresAt is not null).Select(cookie => cookie.ExpiresAt!.Value).DefaultIfEmpty(0).Min()))
                .Where(item => item.expiry > 0 && item.expiry < limit)
                .Select(item => (ProfileLabel(item.profile), DateTimeOffset.FromUnixTimeSeconds((long)item.expiry)))
                .ToList();
        }
        finally { _gate.Release(); }
    }

    public async Task<List<(string Id, string Name, DateTimeOffset LastSeenAt, bool Revoked, string ClientVersion)>> DeviceStatusesAsync()
    {
        await _gate.WaitAsync();
        try { return _state.Devices.Select(device => (device.Id, device.Name, device.LastSeenAt, device.Revoked, device.ClientVersion)).ToList(); }
        finally { _gate.Release(); }
    }

    // ---- Per-browser settings and commands --------------------------------------------------------

    public static readonly string[] CommandTypes = ["lock", "close-tabs", "clear-site", "restart", "open-url", "switch-account"];
    private static readonly TimeSpan CommandLifetime = TimeSpan.FromDays(1);

    public async Task<DeviceCommand?> AddCommandAsync(string deviceId, DeviceCommandRequest request)
    {
        var type = (request.Type ?? "").Trim().ToLowerInvariant();
        if (!CommandTypes.Contains(type)) throw new InvalidOperationException("Unknown action");
        var argument = (request.Argument ?? "").Trim();
        if (type == "open-url")
        {
            if (!Uri.TryCreate(argument, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") || argument.Length > 2000) throw new InvalidOperationException("Enter an HTTP or HTTPS address to open");
            argument = url.AbsoluteUri;
        }
        else if (type == "clear-site")
        {
            var sites = CleanSiteList([argument]);
            if (sites.Count != 1) throw new InvalidOperationException("Enter the site whose cookies should be cleared, for example github.com");
            argument = sites[0];
        }
        else if (type != "switch-account") argument = "";
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == deviceId);
            if (device is null) return null;
            // The browser switches itself, so its own cookies are replaced safely (the primary browser would
            // otherwise publish the old account's cookies into the new one).
            if (type == "switch-account")
            {
                var profile = _state.Profiles.FirstOrDefault(item => item.Id == argument && item.Enabled && Shares(item, deviceId)) ?? throw new InvalidOperationException("That account is not available to this browser");
                device.Commands.RemoveAll(command => command.Type == "switch-account" && _state.Profiles.Any(item => item.Id == command.Argument && item.Domain == profile.Domain));
            }
            device.Commands.RemoveAll(command => command.CreatedAt < DateTimeOffset.UtcNow - CommandLifetime);
            if (device.Commands.Count >= 20) throw new InvalidOperationException("This browser already has 20 actions waiting. It runs them the next time it connects");
            var command = new DeviceCommand { Id = Guid.NewGuid().ToString("N"), Type = type, Argument = argument, CreatedAt = DateTimeOffset.UtcNow };
            device.Commands.Add(command);
            BumpRevision();
            await SaveLockedAsync(backup: false);
            return CloneCommand(command);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Removes a pending command: the browser ran it (acknowledged) or the administrator cancelled it.</summary>
    public async Task<DeviceCommand?> RemoveCommandAsync(string deviceId, string commandId)
    {
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == deviceId);
            var command = device?.Commands.FirstOrDefault(item => item.Id == commandId);
            if (command is null) return null;
            device!.Commands.Remove(command);
            await SaveLockedAsync(backup: false);
            return command;
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> SetDeviceSettingsAsync(string deviceId, DeviceSettingsRequest request)
    {
        var homePage = (request.HomePage ?? "").Trim();
        if (homePage.Length > 0)
        {
            if (!Uri.TryCreate(homePage, UriKind.Absolute, out var home) || home.Scheme is not ("http" or "https") || homePage.Length > 2000) throw new InvalidOperationException("Home page must be empty or an HTTP or HTTPS address");
            homePage = home.AbsoluteUri;
        }
        var filter = request.SiteFilter is null ? null : CleanSiteFilter(request.SiteFilter);
        await _gate.WaitAsync();
        try
        {
            var device = _state.Devices.FirstOrDefault(item => item.Id == deviceId);
            if (device is null) return null;
            if (request.UnlockCode == true && _state.Settings.ClientLock.Hash.Length == 0) throw new InvalidOperationException("Set an unlock code under Unlock code first");
            (device.HomePage, device.SiteFilter, device.ScheduleExempt, device.UnlockCode) = (homePage, filter, request.ScheduleExempt, request.UnlockCode);
            BumpRevision();
            await SaveLockedAsync();
            return $"{device.Name}: home page {(homePage.Length == 0 ? "shared" : homePage)}; site filter {(filter is null ? "shared" : $"{filter.Mode} {string.Join(", ", filter.Domains)}".Trim())}; {(request.ScheduleExempt ? "any time" : "allowed hours apply")}; unlock code {(request.UnlockCode is null ? "shared" : request.UnlockCode.Value ? "always" : "never")}";
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
            ClaimPrimaryLocked(deviceId);
            if (!IsPrimaryLocked(deviceId)) throw new UnauthorizedAccessException("Only the primary browser can add accounts, because new sign-ins are onboarded there");
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
            if (ClaimPrimaryLocked(deviceId)) settingsChanged = true;
            // The primary browser onboards and updates sessions. Any other browser may only update the account it
            // uses on a site, and only when that profile lists it as an editor.
            var primary = IsPrimaryLocked(deviceId);
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
            var profile = site is null ? null : ActiveAccountLocked(device, site, !primary);
            // A profile with editors has one kind of writer: its editors. The primary browser leaves it alone.
            var editor = profile is not null && profile.EditorDeviceIds.Contains(deviceId);
            if (profile is not null && (primary ? profile.EditorDeviceIds.Count > 0 && !editor : !editor)) profile = null;
            var profileCreated = false;
            if (primary && site is null && _state.Settings.AutoShareCookies && incomingCookies.Count > 0)
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
            var signedIn = SignInCookies(profile).Count > 0;
            foreach (var incoming in incomingCookies.Take(MaxCookiesPerRequest))
            {
                var cookie = ValidateCookie(incoming, profile.Domain, deviceId);
                if (!DomainMatches(host, cookie.Domain)) continue;
                // An editor cannot empty a cookie, which is how many sites clear a sign-in.
                if (editor && cookie.Value.Length == 0) continue;
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
            // Editors never remove cookies, so an editor that signs out or loses its cookies cannot sign everyone out.
            if (request.Complete && !editor)
            {
                changed += profile.Cookies.RemoveAll(item => item.Domain == host && item.SourceDeviceId != AdminSource && !seen.Contains(CookieKey(item)));
                // The primary browser no longer holds the sign-in: everyone sharing this profile is now signed out.
                if (signedIn && SignInCookies(profile).Count == 0) RaiseActivity(NotificationEvents.SessionLost, ProfileLabel(profile), $"signed out on {_state.Devices.First(item => item.Id == deviceId).Name}");
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

    /// <summary>Deletes the named backups, or every backup when <paramref name="names"/> is null. Returns the deleted names.</summary>
    public async Task<List<string>> DeleteBackupsAsync(IReadOnlyCollection<string>? names)
    {
        if (names is not null && names.Any(name => !BackupName().IsMatch(name))) throw new InvalidOperationException("Invalid backup name");
        await _gate.WaitAsync();
        try
        {
            var deleted = new List<string>();
            foreach (var backup in ListBackups().Where(item => names is null || names.Contains(item.Name)))
            {
                try { File.Delete(Path.Combine(_backupDirectory, backup.Name)); deleted.Add(backup.Name); }
                catch (IOException error) { _logger.LogWarning(error, "Could not delete backup {Name}", backup.Name); }
            }
            return deleted;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Deletes one backup file. Returns false when it does not exist.</summary>
    public async Task<bool> DeleteBackupAsync(string name)
    {
        if (!BackupName().IsMatch(name)) throw new InvalidOperationException("Invalid backup name");
        await _gate.WaitAsync();
        try
        {
            var path = Path.Combine(_backupDirectory, name);
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        finally { _gate.Release(); }
    }

    [GeneratedRegex(@"^state-\d{8}T\d{6}Z(-[a-z]+(-[a-z]+)*)?\.json$")]
    private static partial Regex BackupName();

    private async Task<string> BackupLockedAsync(string suffix = "")
    {
        var name = await WriteBackupLockedAsync(suffix);
        var created = BackupCreated;
        if (created is not null) _ = Task.Run(() => created(name));
        return name;
    }

    private async Task<string> WriteBackupLockedAsync(string suffix)
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
        disk.Settings.PrimaryDeviceId ??= "";
        disk.Settings.PrimaryDeviceIds ??= [];
        // There is one primary browser. Vaults saved by 1.9, which allowed several, keep the first.
        if (disk.Settings.PrimaryDeviceId.Length == 0) disk.Settings.PrimaryDeviceId = disk.Settings.PrimaryDeviceIds.FirstOrDefault() ?? "";
        disk.Settings.PrimaryDeviceIds = disk.Settings.PrimaryDeviceId.Length > 0 ? [disk.Settings.PrimaryDeviceId] : [];
        foreach (var profile in disk.Profiles) profile.EditorDeviceIds ??= [];
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
        foreach (var device in disk.Devices)
        {
            device.ActiveProfiles ??= [];
            device.HomePage ??= "";
            device.Commands ??= [];
        }
        disk.Settings.SiteFilter ??= new SiteFilterSettings();
        disk.Settings.SiteFilter.Domains ??= [];
        disk.Settings.Schedule ??= new UsageSchedule();
        disk.Settings.Schedule.Days ??= [];
        disk.Settings.DataControls ??= new DataControls();
        disk.Settings.DataControls.Domains ??= [];
        foreach (var bookmark in disk.Bookmarks) bookmark.Folder ??= "";
        foreach (var profile in disk.Profiles) profile.SessionCookie ??= "";
        disk.Notifications ??= new NotificationSettings();
        disk.Notifications.Events ??= [];
        disk.Notifications.DiscordWebhookUrl = Decrypt(disk.Notifications.DiscordWebhookUrl ?? "");
        disk.Notifications.TelegramBotToken = Decrypt(disk.Notifications.TelegramBotToken ?? "");
        disk.Notifications.TelegramChatId ??= "";
        disk.Notifications.LineChannelToken = Decrypt(disk.Notifications.LineChannelToken ?? "");
        disk.Notifications.LineTo ??= "";
        disk.OffsiteBackup ??= new OffsiteBackupSettings();
        disk.OffsiteBackup.SecretAccessKey = Decrypt(disk.OffsiteBackup.SecretAccessKey ?? "");
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
            Devices = _state.Devices.Select(device => new DeviceRecord { Id = device.Id, Name = device.Name, TokenHash = device.TokenHash, EnrolledAt = device.EnrolledAt, LastSeenAt = device.LastSeenAt, Revoked = device.Revoked, ClientVersion = device.ClientVersion, NetworkMode = device.NetworkMode, MaxConnections = device.MaxConnections, MonthlyQuotaGb = device.MonthlyQuotaGb, RateLimitMbps = device.RateLimitMbps, ActiveProfiles = new(device.ActiveProfiles), HomePage = device.HomePage, SiteFilter = device.SiteFilter is null ? null : CloneSiteFilter(device.SiteFilter), ScheduleExempt = device.ScheduleExempt, UnlockCode = device.UnlockCode, Commands = device.Commands.Select(CloneCommand).ToList() }).ToList(),
            Profiles = _state.Profiles.Select(CloneProfile).ToList(),
            Bookmarks = _state.Bookmarks.Select(CloneBookmark).ToList(),
            EnrollmentCodes = _state.EnrollmentCodes.Select(code => new EnrollmentCode { Id = code.Id, CodeHash = code.CodeHash, Label = code.Label, CreatedAt = code.CreatedAt, ExpiresAt = code.ExpiresAt, UsedAt = code.UsedAt, UsedByDeviceId = code.UsedByDeviceId, Revoked = code.Revoked }).ToList(),
            Announcements = _state.Announcements.Select(item => new Announcement { Id = item.Id, Title = item.Title, Message = item.Message, Level = item.Level, Url = item.Url, CreatedAt = item.CreatedAt, ExpiresAt = item.ExpiresAt, ShareWithAllDevices = item.ShareWithAllDevices, AllowedDeviceIds = [.. item.AllowedDeviceIds], Acknowledgements = new(item.Acknowledgements), Pinned = item.Pinned }).ToList()
        };
        disk.Settings.Proxy.CertificateSha256 = "";
        foreach (var cookie in disk.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Encrypt(cookie.Value);
        // Webhook URLs, bot tokens and storage keys are as sensitive as cookies.
        disk.Notifications = CloneNotifications(_state.Notifications);
        disk.Notifications.DiscordWebhookUrl = EncryptSecret(disk.Notifications.DiscordWebhookUrl);
        disk.Notifications.TelegramBotToken = EncryptSecret(disk.Notifications.TelegramBotToken);
        disk.Notifications.LineChannelToken = EncryptSecret(disk.Notifications.LineChannelToken);
        disk.OffsiteBackup = CloneOffsite(_state.OffsiteBackup);
        disk.OffsiteBackup.SecretAccessKey = EncryptSecret(disk.OffsiteBackup.SecretAccessKey);
        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(disk, JsonOptions));
        File.Move(temp, _path, true);
        if (publish) PublishLocked();
        if (backup && DateTimeOffset.UtcNow - _lastBackup >= _backupInterval)
        {
            try { await BackupLockedAsync(); }
            catch (IOException error)
            {
                _logger.LogWarning(error, "Automatic vault backup failed");
                RaiseActivity(NotificationEvents.BackupFailed, "local backup", error.Message);
            }
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
                .OrderByDescending(item => item.Pinned).ThenByDescending(item => item.CreatedAt)
                .Select(item => new ClientAnnouncement(item.Id, item.Title, item.Message, item.Level, item.Url, item.CreatedAt, item.ExpiresAt) { Pinned = item.Pinned, ShareWithAllDevices = item.ShareWithAllDevices, AllowedDeviceIds = [.. item.AllowedDeviceIds] })
                .ToList());
        _deviceIndex = _state.Devices.ToDictionary(device => device.Id, device => new DeviceAuth(device.Id, device.Name, device.TokenHash, device.Revoked, device.MaxConnections, device.MonthlyQuotaGb, device.RateLimitMbps, device.ClientVersion));
        _deviceViews = _state.Devices.ToDictionary(device => device.Id, device => new DeviceView(
            new Dictionary<string, string>(device.ActiveProfiles), device.HomePage, device.SiteFilter is null ? null : CloneSiteFilter(device.SiteFilter), device.ScheduleExempt,
            device.Commands.Select(command => new ClientCommand(command.Id, command.Type, command.Argument, command.CreatedAt)).ToList(), device.UnlockCode));
        _notifications = CloneNotifications(_state.Notifications);
        _offsite = CloneOffsite(_state.OffsiteBackup);
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

    private string EncryptSecret(string value) => value.Length == 0 ? "" : Encrypt(value);

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
    private static BrowserSettings CloneSettings(BrowserSettings settings) => new() { HomePage = settings.HomePage, SearchUrl = settings.SearchUrl, PrimaryDeviceId = settings.PrimaryDeviceId, PrimaryDeviceIds = [.. settings.PrimaryDeviceIds], AutoShareCookies = settings.AutoShareCookies, AutoShareScope = settings.AutoShareScope, AutoShareDomains = [.. settings.AutoShareDomains], AllowAdminTokenEnrollment = settings.AllowAdminTokenEnrollment, NetworkPolicy = settings.NetworkPolicy, IpCheckUrl = settings.IpCheckUrl, Proxy = CloneProxySettings(settings.Proxy), ClientLock = CloneClientLock(settings.ClientLock), MinimumClientVersion = settings.MinimumClientVersion, SiteFilter = CloneSiteFilter(settings.SiteFilter), Schedule = CloneSchedule(settings.Schedule), DataControls = CloneDataControls(settings.DataControls) };
    private static ClientLockSettings CloneClientLock(ClientLockSettings? value) => value is null ? new() : new() { Enabled = value.Enabled, Salt = value.Salt, Hash = value.Hash, Iterations = value.Iterations, ChangedAt = value.ChangedAt, IdleMinutes = value.IdleMinutes, LockOnSystemLock = value.LockOnSystemLock };
    private static SiteFilterSettings CloneSiteFilter(SiteFilterSettings? value) => value is null ? new() : new() { Mode = value.Mode, Domains = [.. value.Domains] };
    private static UsageSchedule CloneSchedule(UsageSchedule? value) => value is null ? new() : new() { Enabled = value.Enabled, Days = [.. value.Days], Start = value.Start, End = value.End, TimeZone = value.TimeZone };
    private static DataControls CloneDataControls(DataControls? value) => value is null ? new() : new() { BlockDownloads = value.BlockDownloads, BlockUploads = value.BlockUploads, BlockCopy = value.BlockCopy, Domains = [.. value.Domains] };
    private static NotificationSettings CloneNotifications(NotificationSettings value) => new()
    {
        DiscordWebhookUrl = value.DiscordWebhookUrl, TelegramBotToken = value.TelegramBotToken, TelegramChatId = value.TelegramChatId, LineChannelToken = value.LineChannelToken,
        LineTo = value.LineTo, Events = [.. value.Events], OfflineMinutes = value.OfflineMinutes, ExpiryWarningDays = value.ExpiryWarningDays
    };
    private static OffsiteBackupSettings CloneOffsite(OffsiteBackupSettings value) => new()
    {
        Enabled = value.Enabled, Endpoint = value.Endpoint, Region = value.Region, Bucket = value.Bucket, Prefix = value.Prefix, AccessKeyId = value.AccessKeyId,
        SecretAccessKey = value.SecretAccessKey, LastUploadAt = value.LastUploadAt, LastUploadName = value.LastUploadName, LastError = value.LastError
    };
    private static DeviceCommand CloneCommand(DeviceCommand value) => new() { Id = value.Id, Type = value.Type, Argument = value.Argument, CreatedAt = value.CreatedAt };

    public static readonly string[] SiteFilterModes = ["off", "allow", "block"];

    private static SiteFilterSettings CleanSiteFilter(SiteFilterSettings? input)
    {
        var mode = (input?.Mode ?? "off").Trim().ToLowerInvariant();
        if (!SiteFilterModes.Contains(mode)) throw new InvalidOperationException("Site filter must be off, allow or block");
        var domains = CleanSiteList(input?.Domains);
        if (mode == "allow" && domains.Count == 0) throw new InvalidOperationException("List at least one site that browsers may open");
        return new SiteFilterSettings { Mode = mode, Domains = domains };
    }

    private static UsageSchedule CleanSchedule(UsageSchedule? input)
    {
        input ??= new UsageSchedule();
        static bool Time(string? value) => TimeOnly.TryParseExact(value ?? "", "HH:mm", out _);
        if (!Time(input.Start) || !Time(input.End)) throw new InvalidOperationException("Allowed hours must be written as HH:mm, for example 09:00");
        var days = (input.Days ?? []).Where(day => day is >= 0 and <= 6).Distinct().Order().ToList();
        if (input.Enabled && days.Count == 0) throw new InvalidOperationException("Choose at least one day on which browsers can be used");
        var zone = (input.TimeZone ?? "").Trim();
        try { TimeZoneInfo.FindSystemTimeZoneById(zone); }
        catch (Exception error) when (error is TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException) { throw new InvalidOperationException($"Unknown time zone '{zone}'. Use a name such as Asia/Bangkok"); }
        return new UsageSchedule { Enabled = input.Enabled, Days = days, Start = input.Start, End = input.End, TimeZone = zone };
    }

    private static string ScheduleSummary(UsageSchedule schedule) => schedule.Enabled ? $"{string.Join(",", schedule.Days)} {schedule.Start}-{schedule.End} {schedule.TimeZone}" : "any time";
    private static string DataControlsSummary(DataControls controls)
    {
        var blocked = new[] { controls.BlockDownloads ? "downloads" : "", controls.BlockUploads ? "uploads" : "", controls.BlockCopy ? "copying" : "" }.Where(item => item.Length > 0).ToList();
        return blocked.Count == 0 ? "none" : $"block {string.Join(", ", blocked)} on {(controls.Domains.Count == 0 ? "all sites" : string.Join(", ", controls.Domains))}";
    }
    private static ProxySettings CloneProxySettings(ProxySettings settings) => new()
    {
        Enabled = settings.Enabled, Host = settings.Host, Port = settings.Port, AllowedPorts = settings.AllowedPorts, BypassList = settings.BypassList, Tls = settings.Tls, CertificateSha256 = settings.CertificateSha256,
        EgressAddressFamily = settings.EgressAddressFamily, EgressSourceAddress = settings.EgressSourceAddress,
        MaxConnectionsPerDevice = settings.MaxConnectionsPerDevice, MonthlyQuotaGb = settings.MonthlyQuotaGb, RateLimitMbps = settings.RateLimitMbps, RecordDestinations = settings.RecordDestinations
    };
    private static SharedBookmark CloneBookmark(SharedBookmark item) => new() { Title = item.Title, Url = item.Url, Folder = item.Folder };
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
        SessionCookie = profile.SessionCookie,
        EditorDeviceIds = [.. profile.EditorDeviceIds],
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
