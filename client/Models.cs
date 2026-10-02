namespace SharedBrowser;

public sealed class ClientConfig
{
    public string ServerUrl { get; set; } = "http://127.0.0.1:8787";
    public string DeviceId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeviceName { get; set; } = $"{Environment.MachineName} browser";
    public string DeviceToken { get; set; } = "";
    public string EnrollmentToken { get; set; } = "";
    public string NetworkMode { get; set; } = "direct";
    public SharedSnapshot Cache { get; set; } = new();
}

public sealed class SharedSnapshot
{
    public long Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public BrowserSettings Settings { get; set; } = new();
    public List<SessionProfile> Profiles { get; set; } = [];
    public List<SharedBookmark> Bookmarks { get; set; } = [];
}

public sealed class BrowserSettings { public string HomePage { get; set; } = "https://example.com/"; public string PrimaryDeviceId { get; set; } = ""; public bool AutoShareCookies { get; set; } = true; public ProxySettings Proxy { get; set; } = new(); }
public sealed class ProxySettings { public bool Enabled { get; set; } public string Host { get; set; } = "127.0.0.1"; public int Port { get; set; } = 8899; public string AllowedPorts { get; set; } = "80,443"; public string BypassList { get; set; } = "localhost;127.0.0.1"; }
public sealed class SessionProfile { public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string Domain { get; set; } = ""; public bool Enabled { get; set; } = true; public List<SharedCookie> Cookies { get; set; } = []; }
public sealed class SharedCookie { public string Name { get; set; } = ""; public string Value { get; set; } = ""; public string Domain { get; set; } = ""; public string Path { get; set; } = "/"; public bool Secure { get; set; } = true; public bool HttpOnly { get; set; } = true; public string SameSite { get; set; } = "Lax"; public DateTimeOffset UpdatedAt { get; set; } public string SourceDeviceId { get; set; } = ""; }
public sealed class SharedBookmark { public string Title { get; set; } = ""; public string Url { get; set; } = ""; }
public sealed record EnrollRequest(string DeviceId, string DeviceName);
public sealed record EnrollResponse(string DeviceId, string DeviceToken, long Revision);
public sealed record SyncRequest(long KnownRevision, string PageUrl, List<SharedCookie> Cookies);
public sealed record SyncResponse(long Revision, int ChangedCookies, SharedSnapshot Snapshot);
