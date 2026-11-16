/// <summary>
/// Checks once a minute for browsers that went offline and shared sessions that expire soon, and records
/// each condition once in the audit log, which turns it into an alert.
/// </summary>
public sealed class HealthMonitor(SharedStateStore store, AuditLog audit) : BackgroundService
{
    // Tests shorten the interval with SHARED_BROWSER_HEALTH_INTERVAL_SECONDS.
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(int.TryParse(Environment.GetEnvironmentVariable("SHARED_BROWSER_HEALTH_INTERVAL_SECONDS"), out var seconds) && seconds > 0 ? seconds : 60);
    private readonly HashSet<string> _offline = [];
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

    private async Task CheckAsync(bool startup)
    {
        var settings = store.NotificationSettings();
        var now = DateTimeOffset.UtcNow;
        var threshold = TimeSpan.FromMinutes(settings.OfflineMinutes);
        foreach (var device in await store.DeviceStatusesAsync())
        {
            var away = now - device.LastSeenAt;
            // Only browsers that were in use this week; long-retired ones are not news.
            if (device.Revoked || away < threshold || away > TimeSpan.FromDays(7)) { _offline.Remove(device.Id); continue; }
            if (!_offline.Add(device.Id) || startup) continue;
            audit.Record("server", NotificationEvents.DeviceOffline, device.Name, $"last seen {device.LastSeenAt:yyyy-MM-dd HH:mm} UTC");
        }
        foreach (var (label, expiresAt) in await store.ExpiringSessionsAsync())
        {
            if (!_expiring.Add($"{label}|{expiresAt.ToUnixTimeSeconds()}")) continue;
            var left = expiresAt - now;
            audit.Record("server", NotificationEvents.SessionExpiring, label, left <= TimeSpan.Zero ? "expired" : $"expires in {(left.TotalDays >= 1 ? $"{left.TotalDays:0.#} days" : $"{left.TotalHours:0} hours")} ({expiresAt:yyyy-MM-dd HH:mm} UTC)");
        }
    }
}
