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
}

public sealed class BrowserSettings
{
    public string HomePage { get; set; } = "";
    public string SearchUrl { get; set; } = "https://duckduckgo.com/?q=%s";
    public string PrimaryDeviceId { get; set; } = "";
    public bool AutoShareCookies { get; set; } = true;
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

public sealed class SharedBookmark { public string Title { get; set; } = ""; public string Url { get; set; } = ""; }

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

public sealed record DeviceAuth(string Id, string Name, string TokenHash, bool Revoked, int? MaxConnections, double? MonthlyQuotaGb, double? RateLimitMbps);
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
public sealed record SharedSnapshot(long Revision, DateTimeOffset UpdatedAt, BrowserSettings Settings, List<SessionProfile> Profiles, List<SharedBookmark> Bookmarks, List<ClientAnnouncement> Announcements);
public sealed record AnnouncementRequest(string? Title, string? Message, string? Level, string? Url, int? ExpiresInMinutes, bool ShareWithAllDevices = true, List<string>? AllowedDeviceIds = null);
/// <summary>What a browser receives. Targeting stays on the server.</summary>
public sealed record ClientAnnouncement(string Id, string Title, string Message, string Level, string Url, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt)
{
    [JsonIgnore] public bool ShareWithAllDevices { get; init; } = true;
    [JsonIgnore] public IReadOnlyList<string> AllowedDeviceIds { get; init; } = [];
}
public sealed record BackupInfo(string Name, long Size, DateTimeOffset CreatedAt);
public sealed record DeleteProfilesRequest(List<string>? Ids);
/// <summary>Purging every profile must be confirmed explicitly, so a stray request cannot do it.</summary>
public sealed record PurgeProfilesRequest(bool Confirm);
