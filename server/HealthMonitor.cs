/// <summary>
/// Checks once a minute for browsers that went offline and shared sessions that expire soon, and records
/// each condition once in the audit log, which turns it into an alert.
/// </summary>
public sealed class HealthMonitor(SharedStateStore store, AuditLog audit) : BackgroundService
{
    // Tests shorten the interval with SHARED_BROWSER_HEALTH_INTERVAL_SECONDS.
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(int.TryParse(Environment.GetEnvironmentVariable("SHARED_BROWSER_HEALTH_INTERVAL_SECONDS"), out var seconds) && seconds > 0 ? seconds : 60);
    /// <summary>Browsers reported offline, with when they were last seen.</summary>
    private readonly Dictionary<string, DateTimeOffset> _offline = [];
    private readonly HashSet<string> _expiring = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Browsers already offline when the server starts are not reported (the server itself was down).
        var first = true;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await CheckAsync(first); }
            catch (Exception error) when (error is not OperationCanceledException) { }
            first = false;
            try { await Task.Delay(Interval, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }

    private static string Duration(TimeSpan span) => span.TotalDays >= 1 ? $"{(int)span.TotalDays} d {span.Hours} h" : span.TotalHours >= 1 ? $"{(int)span.TotalHours} h {span.Minutes} min" : $"{Math.Max(1, (int)span.TotalMinutes)} min";

    private async Task CheckAsync(bool startup)
    {
        var settings = store.NotificationSettings();
        var now = DateTimeOffset.UtcNow;
        var threshold = TimeSpan.FromMinutes(settings.OfflineMinutes);
        foreach (var device in await store.DeviceStatusesAsync())
        {
            var away = now - device.LastSeenAt;
            var label = $"{device.Name} (id {device.Id[..Math.Min(8, device.Id.Length)]}{(device.ClientVersion.Length > 0 ? $", v{device.ClientVersion}" : "")})";
            if (device.Revoked || away < threshold || away > TimeSpan.FromDays(7))
            {
                // A browser reported offline that connects again is reported back online, with how long it was away.
                if (_offline.Remove(device.Id, out var since) && !device.Revoked && away < threshold)
                    audit.Record("server", NotificationEvents.DeviceOnline, label, $"back after {Duration(now - since)}");
                continue;
            }
            if (_offline.ContainsKey(device.Id)) continue;
            _offline[device.Id] = device.LastSeenAt;
            if (!startup) audit.Record("server", NotificationEvents.DeviceOffline, label, $"no contact for {Duration(away)}; last seen {device.LastSeenAt:yyyy-MM-dd HH:mm} UTC");
        }
        foreach (var (label, expiresAt) in await store.ExpiringSessionsAsync())
        {
            if (!_expiring.Add($"{label}|{expiresAt.ToUnixTimeSeconds()}")) continue;
            var left = expiresAt - now;
            audit.Record("server", NotificationEvents.SessionExpiring, label, left <= TimeSpan.Zero ? "expired" : $"expires in {(left.TotalDays >= 1 ? $"{left.TotalDays:0.#} days" : $"{left.TotalHours:0} hours")} ({expiresAt:yyyy-MM-dd HH:mm} UTC)");
        }
    }
}
