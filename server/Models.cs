using System.Text.Json.Serialization;

public sealed class SharedState
{
    public long Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public BrowserSettings Settings { get; set; } = new();
    public List<SessionProfile> Profiles { get; set; } = [];
    public List<DeviceRecord> Devices { get; set; } = [];
    public List<SharedBookmark> Bookmarks { get; set; } = [];
    public List<EnrollmentCode> EnrollmentCodes { get; set; } = [];
    public List<Announcement> Announcements { get; set; } = [];
    /// <summary>Server-side only (never sent to browsers); secrets are encrypted on disk.</summary>
    public NotificationSettings Notifications { get; set; } = new();
    public OffsiteBackupSettings OffsiteBackup { get; set; } = new();
}

/// <summary>Where the server sends alerts, and which events it sends.</summary>
public sealed class NotificationSettings
{
    public string DiscordWebhookUrl { get; set; } = "";
    public string TelegramBotToken { get; set; } = "";
    public string TelegramChatId { get; set; } = "";
    public string LineChannelToken { get; set; } = "";
    public string LineTo { get; set; } = "";
    public List<string> Events { get; set; } = [.. NotificationEvents.Defaults];
    /// <summary>A browser counts as offline after this many minutes without contact.</summary>
    public int OfflineMinutes { get; set; } = 30;
    /// <summary>Warn this many days before a shared session expires.</summary>
    public int ExpiryWarningDays { get; set; } = 3;
}

public static class NotificationEvents
{
    public const string SessionLost = "session.lost";
    public const string SessionExpiring = "session.expiring";
    public const string DeviceOffline = "device.offline";
    public const string DeviceOnline = "device.online";
    public const string DeviceEnrolled = "device.enrolled";
    public const string QuotaReached = "proxy.quota_reached";
    public const string UnlockFailed = "browser.unlock_failed";
    public const string BackupFailed = "backup.failed";

    /// <summary>An audit action that can raise an alert, its title, group in the dashboard, and whether it is on by default.</summary>
    public sealed record Kind(string Key, string Title, string Group, bool Default, string Severity);

    public static readonly Kind[] Catalog =
    [
        new("admin.sign_in_failed", "Failed administrator sign-in", "Security", true, "danger"),
        new("device.enroll_failed", "Failed browser enrollment", "Security", true, "danger"),
        new(UnlockFailed, "Wrong unlock code entered", "Security", true, "danger"),
        new("browser.unlocked", "Browser unlocked", "Security", false, "info"),
        new(SessionLost, "Shared session signed out", "Sessions", true, "warning"),
        new(SessionExpiring, "Shared session expires soon", "Sessions", true, "warning"),
        new("account.switched", "Browser switched account", "Sessions", false, "info"),
        new("account.created", "Account added", "Sessions", true, "info"),
        new("profile.created", "Profile created", "Sessions", false, "info"),
        new("profile.updated", "Profile changed", "Sessions", false, "info"),
        new("profile.deleted", "Profile deleted", "Sessions", true, "warning"),
        new("profiles.deleted", "Profiles deleted", "Sessions", true, "warning"),
        new("profiles.purged", "Vault purged", "Sessions", true, "danger"),
        new(DeviceEnrolled, "New browser enrolled", "Browsers", true, "info"),
        new(DeviceOffline, "Browser offline", "Browsers", true, "warning"),
        new(DeviceOnline, "Browser back online", "Browsers", false, "info"),
        new("device.revoked", "Browser revoked", "Browsers", true, "warning"),
        new("device.restored", "Browser restored", "Browsers", false, "info"),
        new("device.deleted", "Browser deleted", "Browsers", true, "warning"),
        new("device.command_sent", "Action sent to a browser", "Browsers", false, "info"),
        new("device.command_done", "Browser ran an action", "Browsers", false, "info"),
        new("device.settings_updated", "Browser settings changed", "Browsers", false, "info"),
        new("device.limits_updated", "Browser limits changed", "Browsers", false, "info"),
        new(QuotaReached, "Proxy quota reached", "Browsers", true, "warning"),
        new("settings.updated", "Shared settings changed", "Administration", false, "info"),
        new("client_lock.updated", "Unlock code changed", "Administration", true, "warning"),
        new("notifications.updated", "Notification settings changed", "Administration", false, "info"),
        new("announcement.sent", "Announcement sent", "Administration", false, "info"),
        new("bookmarks.updated", "Bookmarks changed", "Administration", false, "info"),
        new("enrollment_code.created", "Enrollment code created", "Administration", false, "info"),
        new("vault.exported", "Vault exported", "Administration", true, "warning"),
        new("vault.imported", "Vault imported", "Administration", true, "warning"),
        new("vault.restored", "Vault restored from a backup", "Administration", true, "warning"),
        new(BackupFailed, "Backup failed", "Backups", true, "danger"),
        new("backup.uploaded", "Backup copied offsite", "Backups", false, "info"),
        new("backup.deleted", "Backup deleted", "Backups", false, "info"),
        new("backups.purged", "All backups deleted", "Backups", true, "danger")
    ];

    public static readonly string[] All = Catalog.Select(kind => kind.Key).ToArray();
    public static readonly string[] Defaults = Catalog.Where(kind => kind.Default).Select(kind => kind.Key).ToArray();
    public static Kind? Find(string key) => Catalog.FirstOrDefault(kind => kind.Key == key);
}

/// <summary>Copies every vault backup to S3-compatible storage (AWS S3, DigitalOcean Spaces, MinIO, ...).</summary>
public sealed class OffsiteBackupSettings
{
    public bool Enabled { get; set; }
    /// <summary>For example https://sgp1.digitaloceanspaces.com or https://s3.eu-central-1.amazonaws.com.</summary>
    public string Endpoint { get; set; } = "";
    public string Region { get; set; } = "us-east-1";
    public string Bucket { get; set; } = "";
    public string Prefix { get; set; } = "shared-browser/";
    public string AccessKeyId { get; set; } = "";
    public string SecretAccessKey { get; set; } = "";
    public DateTimeOffset? LastUploadAt { get; set; }
    public string LastUploadName { get; set; } = "";
    public string LastError { get; set; } = "";
}

/// <summary>Which sites browsers may open: "off", "allow" (only the listed sites) or "block" (all but the listed sites).</summary>
public sealed class SiteFilterSettings
{
    public string Mode { get; set; } = "off";
    public List<string> Domains { get; set; } = [];
}

/// <summary>Hours in which browsers can be used, in the given IANA time zone.</summary>
public sealed class UsageSchedule
{
    public bool Enabled { get; set; }
    /// <summary>0 = Sunday ... 6 = Saturday.</summary>
    public List<int> Days { get; set; } = [1, 2, 3, 4, 5];
    public string Start { get; set; } = "09:00";
    public string End { get; set; } = "18:00";
    public string TimeZone { get; set; } = "Asia/Bangkok";
}

/// <summary>Stops downloads, file uploads or copying text on the listed sites (all sites when the list is empty).</summary>
public sealed class DataControls
{
    public bool BlockDownloads { get; set; }
    public bool BlockUploads { get; set; }
    public bool BlockCopy { get; set; }
    public List<string> Domains { get; set; } = [];
}

/// <summary>An action the administrator asked one browser to perform once.</summary>
public sealed class DeviceCommand
{
    public string Id { get; set; } = "";
    /// <summary>lock, close-tabs, clear-site, restart or open-url.</summary>
    public string Type { get; set; } = "";
    public string Argument { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A message from the administrator that browsers show in a banner until the user dismisses it.</summary>
public sealed class Announcement
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    /// <summary>info, warning or critical. Warning and critical also raise a desktop notification.</summary>
    public string Level { get; set; } = "info";
    /// <summary>Optional http(s) link the banner offers to open.</summary>
    public string Url { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public bool ShareWithAllDevices { get; set; } = true;
    public List<string> AllowedDeviceIds { get; set; } = [];
    /// <summary>Device ID → when that browser's user dismissed the announcement.</summary>
    public Dictionary<string, DateTimeOffset> Acknowledgements { get; set; } = [];
    /// <summary>Shown all the time, without a way to dismiss it, until it is unpinned, deleted or expires.</summary>
    public bool Pinned { get; set; }
}

public sealed class BrowserSettings
{
    public string HomePage { get; set; } = "";
    public string SearchUrl { get; set; } = "https://duckduckgo.com/?q=%s";
    /// <summary>
    /// The one browser that onboards sessions: its sign-ins create profiles and accounts and it updates the
    /// accounts it uses. Other browsers update a profile only when the profile lists them as editors.
    /// </summary>
    public string PrimaryDeviceId { get; set; } = "";
    /// <summary>Always the primary browser alone (or empty); kept because browsers 1.9 read this list.</summary>
    public List<string> PrimaryDeviceIds { get; set; } = [];
    public bool AutoShareCookies { get; set; } = true;
    /// <summary>
    /// With automatic sharing on: "all" shares every site the primary browser has cookies for, "listed"
    /// only the sites in <see cref="AutoShareDomains"/> (and their subdomains).
    /// </summary>
    public string AutoShareScope { get; set; } = "all";
    public List<string> AutoShareDomains { get; set; } = [];
    /// <summary>When false, browsers can only enroll with a one-time enrollment code from the dashboard.</summary>
    public bool AllowAdminTokenEnrollment { get; set; } = true;
    /// <summary>
    /// How browsers connect to websites: "choice" lets each browser pick Direct or Managed in its settings,
    /// "managed" requires the managed proxy, and "strict" requires the managed proxy with Strict privacy.
    /// </summary>
    public string NetworkPolicy { get; set; } = "strict";
    /// <summary>Service that answers with the caller's public IP, used by "Check egress IP" (empty disables it).</summary>
    public string IpCheckUrl { get; set; } = "https://api64.ipify.org?format=json";
    public ProxySettings Proxy { get; set; } = new();
    public ClientLockSettings ClientLock { get; set; } = new();
    public SiteFilterSettings SiteFilter { get; set; } = new();
    public UsageSchedule Schedule { get; set; } = new();
    public DataControls DataControls { get; set; } = new();
    /// <summary>
    /// Browsers older than this (for example "1.5.0") cannot synchronize, and the proxy only lets them reach
    /// GitHub to download the update. Empty allows every version.
    /// </summary>
    public string MinimumClientVersion { get; set; } = "";
}

/// <summary>
/// An unlock code browsers ask for every time they start, before any page opens. Only a salted
/// PBKDF2-SHA256 hash is stored and sent to browsers, which check the code locally so it also works offline.
/// </summary>
public sealed class ClientLockSettings
{
    public bool Enabled { get; set; }
    public string Salt { get; set; } = "";
    public string Hash { get; set; } = "";
    public int Iterations { get; set; }
    public DateTimeOffset? ChangedAt { get; set; }
    /// <summary>Lock again after this many minutes without keyboard or mouse use (0 = never).</summary>
    public int IdleMinutes { get; set; }
    /// <summary>Lock when the computer's screen locks or it goes to sleep.</summary>
    public bool LockOnSystemLock { get; set; }
}

public sealed class ProxySettings
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 8899;
    public string AllowedPorts { get; set; } = "80,443";
    public string BypassList { get; set; } = "localhost;127.0.0.1";
    /// <summary>Encrypts the browser-to-proxy connection, which carries the device credentials.</summary>
    public bool Tls { get; set; }
    /// <summary>SHA-256 of the proxy's TLS certificate (hex). Set by the server; browsers pin it.</summary>
    public string CertificateSha256 { get; set; } = "";
    /// <summary>any, ipv4 or ipv6: which address family the proxy uses to reach websites.</summary>
    public string EgressAddressFamily { get; set; } = "any";
    /// <summary>Optional local IP the proxy's outgoing connections are bound to, on servers with several addresses.</summary>
    public string EgressSourceAddress { get; set; } = "";
    /// <summary>Default per-browser limits; 0 means unlimited. Each browser can override them.</summary>
    public int MaxConnectionsPerDevice { get; set; }
    public double MonthlyQuotaGb { get; set; }
    public double RateLimitMbps { get; set; }
    /// <summary>Keep per-browser counts of the sites reached through the proxy (host names only).</summary>
    public bool RecordDestinations { get; set; } = true;
}

public sealed class SessionProfile
{
    /// <summary>Optional name of the cookie that holds the sign-in, used for session health and alerts.</summary>
    public string SessionCookie { get; set; } = "";
    /// <summary>
    /// Browsers that update this profile's cookies while they use it. When there are any, they are its only
    /// writers: the primary browser stops updating it (it still onboards new sites and accounts). Editors add
    /// and change cookies but never remove them.
    /// </summary>
    public List<string> EditorDeviceIds { get; set; } = [];
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Domain { get; set; } = "";
    public bool Enabled { get; set; } = true;
    /// <summary>True: every enrolled browser receives the profile. False: only <see cref="AllowedDeviceIds"/>.</summary>
    public bool ShareWithAllDevices { get; set; } = true;
    public List<string> AllowedDeviceIds { get; set; } = [];
    public List<SharedCookie> Cookies { get; set; } = [];
}

/// <summary>ExpiresAt is the expiry in Unix seconds, or null for a browser-session cookie.</summary>
public sealed class SharedCookie
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Path { get; set; } = "/";
    public bool Secure { get; set; } = true;
    public bool HttpOnly { get; set; } = true;
    public string SameSite { get; set; } = "Lax";
    public double? ExpiresAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string SourceDeviceId { get; set; } = "";
}

public sealed class SharedBookmark { public string Title { get; set; } = ""; public string Url { get; set; } = ""; public string Folder { get; set; } = ""; }

public sealed class DeviceRecord
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public DateTimeOffset EnrolledAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public bool Revoked { get; set; }
    /// <summary>Reported by the browser: its version and how it reaches websites (direct, managed or strict).</summary>
    public string ClientVersion { get; set; } = "";
    public string NetworkMode { get; set; } = "";
    /// <summary>Per-browser proxy limits; null uses the default from the proxy settings, 0 is unlimited.</summary>
    public int? MaxConnections { get; set; }
    public double? MonthlyQuotaGb { get; set; }
    public double? RateLimitMbps { get; set; }
    /// <summary>
    /// Which account this browser uses for a site that has several (profile domain → profile ID).
    /// A site without an entry, or whose entry no longer exists, uses its first enabled account.
    /// </summary>
    public Dictionary<string, string> ActiveProfiles { get; set; } = [];
    /// <summary>Overrides the shared home page for this browser (empty uses the shared one).</summary>
    public string HomePage { get; set; } = "";
    /// <summary>Null uses the shared site filter; otherwise this browser's own.</summary>
    public SiteFilterSettings? SiteFilter { get; set; }
    /// <summary>True: this browser can be used outside the allowed hours.</summary>
    public bool ScheduleExempt { get; set; }
    /// <summary>Null follows the shared unlock code setting; true always asks for the code, false never does.</summary>
    public bool? UnlockCode { get; set; }
    public List<DeviceCommand> Commands { get; set; } = [];
}

/// <summary>A single-use code an administrator hands to one browser instead of the administrator token.</summary>
public sealed class EnrollmentCode
{
    public string Id { get; set; } = "";
    public string CodeHash { get; set; } = "";
    public string Label { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public string UsedByDeviceId { get; set; } = "";
    public bool Revoked { get; set; }
}

public sealed record DeviceAuth(string Id, string Name, string TokenHash, bool Revoked, int? MaxConnections, double? MonthlyQuotaGb, double? RateLimitMbps, string ClientVersion = "");
public sealed record DeviceLimitsRequest(int? MaxConnections, double? MonthlyQuotaGb, double? RateLimitMbps);
/// <summary>Effective proxy limits for one browser; 0 means unlimited.</summary>
public sealed record ProxyLimits(int MaxConnections, double MonthlyQuotaGb, double RateLimitMbps)
{
    public long QuotaBytes => MonthlyQuotaGb > 0 ? (long)(MonthlyQuotaGb * 1_000_000_000) : 0;
    public double BytesPerSecond => RateLimitMbps * 125_000;
}
public sealed record EnrollRequest(string DeviceId, string DeviceName);
public sealed record EnrollResponse(string DeviceId, string DeviceToken, long Revision);
public sealed record EnrollmentCodeRequest(string? Label, int? TtlMinutes);
public sealed record EnrollmentCodeResponse(string Id, string Code, string Label, DateTimeOffset ExpiresAt);
/// <summary>
/// Complete=true means Cookies is every cookie the primary browser holds whose domain is exactly the
/// page host, so stored cookies missing from it were deleted. Without it the list is a partial update.
/// </summary>
public sealed record SyncRequest(long KnownRevision, string PageUrl, List<SharedCookie>? Cookies, bool Complete = false);
public sealed record SyncResponse(long Revision, int ChangedCookies, SharedSnapshot Snapshot);
/// <summary>
/// Profiles holds, per site, only the account the receiving browser uses, so clients that predate account
/// switching keep working. Accounts lists every account the browser may switch to (without cookies).
/// </summary>
public sealed record SharedSnapshot(long Revision, DateTimeOffset UpdatedAt, BrowserSettings Settings, List<SessionProfile> Profiles, List<SharedBookmark> Bookmarks, List<ClientAnnouncement> Announcements)
{
    public List<ClientAccount> Accounts { get; init; } = [];
    /// <summary>Sites whose cookies this browser may update: the sites of the accounts it uses and edits.</summary>
    public List<string> EditableDomains { get; init; } = [];
    /// <summary>For the primary browser: sites whose account it uses is updated by editors, so it only receives them.</summary>
    public List<string> ReadOnlyDomains { get; init; } = [];
    /// <summary>Actions waiting for this browser; it acknowledges each one after running it.</summary>
    public List<ClientCommand> Commands { get; init; } = [];
}
public sealed record ClientCommand(string Id, string Type, string Argument, DateTimeOffset CreatedAt);
public sealed record DeviceCommandRequest(string? Type, string? Argument);
public sealed record DeviceSettingsRequest(string? HomePage, SiteFilterSettings? SiteFilter, bool ScheduleExempt, bool? UnlockCode = null);
/// <summary>One account (session profile) of a site that a browser can switch to.</summary>
public sealed record ClientAccount(string Id, string Name, string Domain, bool Active, int CookieCount)
{
    /// <summary>ok, expiring (within the warning period), signed-out or empty; and when the sign-in expires.</summary>
    public string Session { get; init; } = "ok";
    public DateTimeOffset? ExpiresAt { get; init; }
}
/// <summary>Adds an empty account for the site of PageUrl, which the primary browser then signs in to.</summary>
public sealed record CreateAccountRequest(string? Name, string? PageUrl);
/// <summary>Code null or empty keeps the current code.</summary>
public sealed record ClientLockRequest(bool Enabled, string? Code, int IdleMinutes = 0, bool LockOnSystemLock = false);
public sealed record UnlockReport(bool Success);
public sealed record AnnouncementRequest(string? Title, string? Message, string? Level, string? Url, int? ExpiresInMinutes, bool ShareWithAllDevices = true, List<string>? AllowedDeviceIds = null, bool Pinned = false);
public sealed record PinRequest(bool Pinned);
public sealed record DeleteBackupsRequest(List<string>? Names);
/// <summary>What a browser receives. Targeting stays on the server.</summary>
public sealed record ClientAnnouncement(string Id, string Title, string Message, string Level, string Url, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)
{
    /// <summary>Pinned announcements stay on screen and cannot be dismissed (browsers 1.8 and newer).</summary>
    public bool Pinned { get; init; }
    [JsonIgnore] public bool ShareWithAllDevices { get; init; } = true;
    [JsonIgnore] public IReadOnlyList<string> AllowedDeviceIds { get; init; } = [];
}
public sealed record BackupInfo(string Name, long Size, DateTimeOffset CreatedAt);
public sealed record DeleteProfilesRequest(List<string>? Ids);
/// <summary>Purging every profile must be confirmed explicitly, so a stray request cannot do it.</summary>
public sealed record PurgeProfilesRequest(bool Confirm);
