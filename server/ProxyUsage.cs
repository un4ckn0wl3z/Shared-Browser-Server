using System.Collections.Concurrent;
using System.Text.Json;

/// <summary>
/// Per-browser proxy usage for the current calendar month (UTC): bytes in each direction, connections,
/// open connections and, optionally, the sites reached. It enforces the per-browser limits and is saved
/// to proxy-usage.json in the data directory about once a minute.
/// </summary>
public sealed class ProxyUsageTracker
{
    private const int MaxHostsPerDevice = 500;
    private const string OtherHosts = "(other sites)";
    private static readonly TimeSpan SaveInterval = TimeSpan.FromMinutes(1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly ConcurrentDictionary<string, DeviceUsage> _devices = new();
    private readonly string _path;
    private readonly ILogger<ProxyUsageTracker> _logger;
    private readonly object _saveLock = new();
    private DateTimeOffset _lastSave = DateTimeOffset.UtcNow;
    private int _dirty;

    public ProxyUsageTracker(DataDirectory data, ILogger<ProxyUsageTracker> logger)
    {
        _logger = logger;
        _path = Path.Combine(data.Path, "proxy-usage.json");
        if (!File.Exists(_path)) return;
        try
        {
            var stored = JsonSerializer.Deserialize<Dictionary<string, StoredUsage>>(File.ReadAllText(_path), JsonOptions) ?? [];
            foreach (var (id, usage) in stored) _devices[id] = DeviceUsage.From(usage);
        }
        catch (Exception error) when (error is JsonException or IOException) { _logger.LogWarning(error, "Could not read proxy usage; starting from zero"); }
    }

    public static string CurrentMonth => DateTimeOffset.UtcNow.ToString("yyyy-MM");

    /// <summary>Opens a connection for a browser, or explains why its limits refuse one (status and message).</summary>
    public IDisposable? TryOpen(string deviceId, ProxyLimits limits, out int status, out string refusal)
    {
        var usage = Get(deviceId);
        lock (usage)
        {
            if (limits.QuotaBytes > 0 && usage.Up + usage.Down >= limits.QuotaBytes)
            {
                (status, refusal) = (403, "Monthly proxy data quota reached for this browser");
                return null;
            }
            if (limits.MaxConnections > 0 && usage.Active >= limits.MaxConnections)
            {
                (status, refusal) = (429, "Too many open proxy connections for this browser");
                return null;
            }
            usage.Active++;
            usage.Connections++;
        }
        MarkDirty();
        (status, refusal) = (0, "");
        return new Lease(() => { lock (usage) usage.Active--; });
    }

    public void RecordHost(string deviceId, string host, bool enabled)
    {
        if (!enabled) return;
        var usage = Get(deviceId);
        var key = host.ToLowerInvariant();
        if (!usage.Hosts.ContainsKey(key) && usage.Hosts.Count >= MaxHostsPerDevice) key = OtherHosts;
        usage.Hosts.GetOrAdd(key, _ => new HostUsage()).AddConnection();
    }

    public void AddBytes(string deviceId, string host, long bytes, bool upload, bool recordHost)
    {
        var usage = Get(deviceId);
        lock (usage)
        {
            if (upload) usage.Up += bytes; else usage.Down += bytes;
        }
        if (recordHost && usage.Hosts.TryGetValue(host.ToLowerInvariant(), out var entry)) entry.AddBytes(bytes);
        MarkDirty();
    }

    public bool OverQuota(string deviceId, ProxyLimits limits)
    {
        if (limits.QuotaBytes <= 0) return false;
        var usage = Get(deviceId);
        lock (usage) return usage.Up + usage.Down >= limits.QuotaBytes;
    }

    /// <summary>
    /// Shares one token bucket among all of a browser's connections, so its rate limit applies to the browser
    /// as a whole. Bytes are spent first and the caller waits off any debt, which keeps transfers smooth.
    /// </summary>
    public async ValueTask ThrottleAsync(string deviceId, int bytes, ProxyLimits limits, CancellationToken cancellationToken)
    {
        var rate = limits.BytesPerSecond;
        if (rate <= 0) return;
        var usage = Get(deviceId);
        TimeSpan wait;
        lock (usage.BucketLock)
        {
            var now = Environment.TickCount64;
            var capacity = Math.Max(rate, 64 * 1024);
            if (usage.LastRefill == 0) usage.Tokens = capacity;
            else usage.Tokens = Math.Min(capacity, usage.Tokens + (now - usage.LastRefill) / 1000.0 * rate);
            usage.LastRefill = now;
            usage.Tokens -= bytes;
            wait = usage.Tokens < 0 ? TimeSpan.FromSeconds(-usage.Tokens / rate) : TimeSpan.Zero;
        }
        if (wait > TimeSpan.Zero) await Task.Delay(wait, cancellationToken);
    }

    /// <summary>Returns true once per browser and month when it first runs out of quota, for the audit log.</summary>
    public bool ShouldReportQuota(string deviceId)
    {
        var usage = Get(deviceId);
        lock (usage)
        {
            if (usage.QuotaReported) return false;
            usage.QuotaReported = true;
            return true;
        }
    }

    public object Report(string deviceId, ProxyLimits limits)
    {
        var usage = Get(deviceId);
        lock (usage)
        {
            return new
            {
                month = usage.Month,
                bytesUp = usage.Up,
                bytesDown = usage.Down,
                connections = usage.Connections,
                activeConnections = usage.Active,
                quotaBytes = limits.QuotaBytes,
                limits,
                topHosts = usage.Hosts.Select(entry => new { host = entry.Key, connections = entry.Value.Connections, bytes = entry.Value.Bytes })
                    .OrderByDescending(entry => entry.bytes).ThenByDescending(entry => entry.connections).Take(10).ToList(),
                previous = usage.PreviousMonth is null ? null : new { month = usage.PreviousMonth, bytesUp = usage.PreviousUp, bytesDown = usage.PreviousDown, connections = usage.PreviousConnections }
            };
        }
    }

    public void Forget(string deviceId)
    {
        if (_devices.TryRemove(deviceId, out _)) MarkDirty();
    }

    public void SaveIfDue(bool force = false)
    {
        if (Volatile.Read(ref _dirty) == 0 || (!force && DateTimeOffset.UtcNow - _lastSave < SaveInterval)) return;
        lock (_saveLock)
        {
            Interlocked.Exchange(ref _dirty, 0);
            _lastSave = DateTimeOffset.UtcNow;
            var stored = _devices.ToDictionary(entry => entry.Key, entry => entry.Value.ToStored());
            try
            {
                File.WriteAllText(_path + ".tmp", JsonSerializer.Serialize(stored, JsonOptions));
                File.Move(_path + ".tmp", _path, true);
            }
            catch (IOException error) { _logger.LogWarning(error, "Could not save proxy usage"); }
        }
    }

    private DeviceUsage Get(string deviceId)
    {
        var usage = _devices.GetOrAdd(deviceId, _ => new DeviceUsage { Month = CurrentMonth });
        var month = CurrentMonth;
        if (usage.Month != month)
        {
            lock (usage)
            {
                if (usage.Month != month)
                {
                    // A new month starts from zero; the previous month's totals stay visible in the dashboard.
                    (usage.PreviousMonth, usage.PreviousUp, usage.PreviousDown, usage.PreviousConnections) = (usage.Month, usage.Up, usage.Down, usage.Connections);
                    (usage.Month, usage.Up, usage.Down, usage.Connections, usage.QuotaReported) = (month, 0, 0, 0, false);
                    usage.Hosts.Clear();
                    MarkDirty();
                }
            }
        }
        return usage;
    }

    private void MarkDirty() => Interlocked.Exchange(ref _dirty, 1);

    private sealed class Lease(Action release) : IDisposable
    {
        private int _released;
        public void Dispose() { if (Interlocked.Exchange(ref _released, 1) == 0) release(); }
    }

    private sealed class HostUsage
    {
        public long Connections;
        public long Bytes;
        public void AddConnection() => Interlocked.Increment(ref Connections);
        public void AddBytes(long bytes) => Interlocked.Add(ref Bytes, bytes);
    }

    private sealed class DeviceUsage
    {
        public string Month = "";
        public long Up, Down, Connections;
        public int Active;
        public bool QuotaReported;
        public string? PreviousMonth;
        public long PreviousUp, PreviousDown, PreviousConnections;
        public readonly ConcurrentDictionary<string, HostUsage> Hosts = new();
        public readonly object BucketLock = new();
        public double Tokens;
        public long LastRefill;

        public StoredUsage ToStored()
        {
            lock (this)
            {
                return new StoredUsage(Month, Up, Down, Connections, QuotaReported,
                    Hosts.ToDictionary(entry => entry.Key, entry => new StoredHost(entry.Value.Connections, entry.Value.Bytes)),
                    PreviousMonth, PreviousUp, PreviousDown, PreviousConnections);
            }
        }

        public static DeviceUsage From(StoredUsage stored)
        {
            var usage = new DeviceUsage
            {
                Month = stored.Month ?? CurrentMonth,
                Up = stored.Up,
                Down = stored.Down,
                Connections = stored.Connections,
                QuotaReported = stored.QuotaReported,
                PreviousMonth = stored.PreviousMonth,
                PreviousUp = stored.PreviousUp,
                PreviousDown = stored.PreviousDown,
                PreviousConnections = stored.PreviousConnections
            };
            foreach (var (host, value) in stored.Hosts ?? []) usage.Hosts[host] = new HostUsage { Connections = value.Connections, Bytes = value.Bytes };
            return usage;
        }
    }

    private sealed record StoredHost(long Connections, long Bytes);
    private sealed record StoredUsage(string? Month, long Up, long Down, long Connections, bool QuotaReported, Dictionary<string, StoredHost>? Hosts, string? PreviousMonth, long PreviousUp, long PreviousDown, long PreviousConnections);
}
