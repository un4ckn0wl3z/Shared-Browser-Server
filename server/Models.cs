public sealed class SharedState
{
    public long Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public BrowserSettings Settings { get; set; } = new();
    public List<SessionProfile> Profiles { get; set; } = [];
    public List<DeviceRecord> Devices { get; set; } = [];
    public List<SharedBookmark> Bookmarks { get; set; } = [];
    public List<EnrollmentCode> EnrollmentCodes { get; set; } = [];
}

public sealed class BrowserSettings
{
    public string HomePage { get; set; } = "";
    public string SearchUrl { get; set; } = "https://duckduckgo.com/?q=%s";
    public string PrimaryDeviceId { get; set; } = "";
    public bool AutoShareCookies { get; set; } = true;
    /// <summary>When false, browsers can only enroll with a one-time enrollment code from the dashboard.</summary>
    public bool AllowAdminTokenEnrollment { get; set; } = true;
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

public sealed record DeviceAuth(string Id, string Name, string TokenHash, bool Revoked);
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
public sealed record SharedSnapshot(long Revision, DateTimeOffset UpdatedAt, BrowserSettings Settings, List<SessionProfile> Profiles, List<SharedBookmark> Bookmarks);
public sealed record BackupInfo(string Name, long Size, DateTimeOffset CreatedAt);
