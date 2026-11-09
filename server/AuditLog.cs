using System.Collections.Concurrent;
using System.Text.Json;

public sealed record AuditEntry(DateTimeOffset At, string Actor, string Action, string Target, string Details, string Ip);

/// <summary>
/// Append-only record of administrative and enrollment activity, kept in audit.jsonl next to the vault.
/// The newest entries stay in memory for the dashboard; the file is trimmed once it grows large.
/// </summary>
public sealed class AuditLog
{
    private const int MemoryEntries = 500;
    private const int MaxFileEntries = 10_000;
    private static readonly TimeSpan FailureThrottle = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _path;
    private readonly object _lock = new();
    private readonly LinkedList<AuditEntry> _recent = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastFailure = new();
    private readonly ILogger<AuditLog> _logger;
    private int _fileEntries;

    public AuditLog(DataDirectory data, ILogger<AuditLog> logger)
    {
        _logger = logger;
        _path = Path.Combine(data.Path, "audit.jsonl");
        if (!File.Exists(_path)) return;
        foreach (var line in File.ReadLines(_path))
        {
            _fileEntries++;
            try
            {
                if (JsonSerializer.Deserialize<AuditEntry>(line, JsonOptions) is { } entry) Remember(entry);
            }
            catch (JsonException) { }
        }
    }

    public IReadOnlyList<AuditEntry> Recent(int count)
    {
        lock (_lock) return _recent.Take(count).ToList();
    }

    public void Record(string actor, string action, string target = "", string details = "", string ip = "")
    {
        var entry = new AuditEntry(DateTimeOffset.UtcNow, actor, action, Clip(target, 200), Clip(details, 500), ip);
        lock (_lock)
        {
            Remember(entry);
            try
            {
                File.AppendAllText(_path, JsonSerializer.Serialize(entry, JsonOptions) + "\n");
                if (++_fileEntries > MaxFileEntries) Trim();
            }
            catch (IOException error) { _logger.LogWarning(error, "Could not write the audit log"); }
        }
        _logger.LogInformation("Audit {Action} by {Actor} on {Target} {Details}", action, actor, target, details);
    }

    /// <summary>Records a failed sign-in at most once per address and action every few minutes.</summary>
    public void RecordFailure(string action, string ip, string details = "")
    {
        var key = $"{action}\n{ip}";
        var now = DateTimeOffset.UtcNow;
        if (_lastFailure.TryGetValue(key, out var last) && now - last < FailureThrottle) return;
        _lastFailure[key] = now;
        Record("anonymous", action, "", details, ip);
    }

    private void Remember(AuditEntry entry)
    {
        _recent.AddFirst(entry);
        while (_recent.Count > MemoryEntries) _recent.RemoveLast();
    }

    private void Trim()
    {
        var keep = File.ReadLines(_path).TakeLast(MaxFileEntries / 2).ToList();
        File.WriteAllLines(_path + ".tmp", keep);
        File.Move(_path + ".tmp", _path, true);
        _fileEntries = keep.Count;
    }

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..length] + "…";
}

public sealed class DataDirectory
{
    public DataDirectory(IWebHostEnvironment environment)
    {
        Path = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA") ?? System.IO.Path.Combine(environment.ContentRootPath, "server-data");
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }
}
