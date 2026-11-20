using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Threading.Channels;

/// <summary>
/// Sends alerts to Discord, Telegram and LINE. Audit entries and health checks raise them; each alert is
/// throttled per event and target so a flapping condition cannot flood the channels.
/// </summary>
public sealed class Notifier : BackgroundService
{
    private static readonly TimeSpan Throttle = TimeSpan.FromMinutes(10);
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly SharedStateStore _store;
    private readonly ILogger<Notifier> _logger;
    private readonly Channel<Alert> _queue = Channel.CreateBounded<Alert>(new BoundedChannelOptions(200) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSent = new();
    // Base addresses can be pointed at a test server.
    private readonly string _telegramApi = Environment.GetEnvironmentVariable("SHARED_BROWSER_TELEGRAM_API") ?? "https://api.telegram.org";
    private readonly string _lineApi = Environment.GetEnvironmentVariable("SHARED_BROWSER_LINE_API") ?? "https://api.line.me";

    public Notifier(SharedStateStore store, AuditLog audit, ILogger<Notifier> logger)
    {
        _store = store;
        _logger = logger;
        audit.Recorded += OnAudit;
    }

    public sealed record Alert(string Event, string Title, string Severity, List<(string Name, string Value)> Fields, DateTimeOffset At, string Key);
    public sealed record ChannelResult(string Channel, bool Ok, string Error);

    /// <summary>Turns an audit entry into labelled fields: who, which browser or site, details, address and time.</summary>
    private void OnAudit(AuditEntry entry)
    {
        var kind = NotificationEvents.Find(entry.Action);
        if (kind is null) return;
        var fields = new List<(string, string)>();
        var deviceActor = entry.Actor.StartsWith("device:", StringComparison.Ordinal) ? entry.Actor[7..] : "";
        var aboutBrowser = entry.Action.StartsWith("device.", StringComparison.Ordinal) || entry.Action.StartsWith("browser.", StringComparison.Ordinal);
        var targetUsed = false;
        if (aboutBrowser && entry.Target.Length > 0) { fields.Add(("Browser", entry.Target)); targetUsed = true; }
        else if (deviceActor.Length > 0) fields.Add(("Browser", deviceActor));
        if (entry.Actor == "admin") fields.Add(("By", "Administrator (dashboard)"));
        else if (entry.Actor == "anonymous") fields.Add(("By", "Unknown (not signed in)"));
        if (!targetUsed && entry.Target.Length > 0)
        {
            var label = entry.Action.Split('.')[0] switch
            {
                "session" or "account" or "profile" or "profiles" => "Site",
                "backup" or "vault" => "Backup",
                "announcement" => "Announcement",
                _ => "Target"
            };
            fields.Add((label, entry.Target));
        }
        if (entry.Details.Length > 0) fields.Add(("Details", entry.Details));
        if (entry.Ip.Length > 0) fields.Add(("IP address", entry.Ip));
        Enqueue(new Alert(entry.Action, kind.Title, kind.Severity, fields, entry.At, $"{entry.Action}|{entry.Actor}|{entry.Target}|{entry.Ip}"));
    }

    public void Enqueue(Alert alert)
    {
        var settings = _store.NotificationSettings();
        if (!settings.Events.Contains(alert.Event) || !HasChannel(settings)) return;
        var now = DateTimeOffset.UtcNow;
        if (_lastSent.TryGetValue(alert.Key, out var last) && now - last < Throttle) return;
        _lastSent[alert.Key] = now;
        _queue.Writer.TryWrite(alert);
    }

    private static bool HasChannel(NotificationSettings settings) =>
        settings.DiscordWebhookUrl.Length > 0 || (settings.TelegramBotToken.Length > 0 && settings.TelegramChatId.Length > 0) || (settings.LineChannelToken.Length > 0 && settings.LineTo.Length > 0);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var alert in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            foreach (var result in await SendAsync(_store.NotificationSettings(), alert, stoppingToken))
            {
                if (!result.Ok) _logger.LogWarning("Notification to {Channel} failed: {Error}", result.Channel, result.Error);
            }
        }
    }

    /// <summary>A test message, sent straight away to every configured channel ("Send test").</summary>
    public Task<List<ChannelResult>> SendTestAsync(NotificationSettings settings, CancellationToken cancellationToken) =>
        SendAsync(settings, new Alert("test", "Test notification", "info", [("Details", "Alerts from Shared Browser reach this channel.")], DateTimeOffset.UtcNow, "test"), cancellationToken);

    private static readonly Dictionary<string, (int Color, string Icon)> Severities = new()
    {
        ["danger"] = (0xE5484D, "🚨"),
        ["warning"] = (0xF5A524, "⚠️"),
        ["info"] = (0x3B82F6, "ℹ️")
    };

    /// <summary>Times in alerts use the time zone of the allowed hours (Asia/Bangkok unless changed).</summary>
    private string LocalTime(DateTimeOffset at)
    {
        var zoneId = _store.Settings.Schedule?.TimeZone;
        try
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(string.IsNullOrWhiteSpace(zoneId) ? "UTC" : zoneId);
            return $"{TimeZoneInfo.ConvertTime(at, zone):yyyy-MM-dd HH:mm:ss} ({zone.Id})";
        }
        catch (Exception error) when (error is TimeZoneNotFoundException or InvalidTimeZoneException) { return $"{at:yyyy-MM-dd HH:mm:ss} UTC"; }
    }

    private async Task<List<ChannelResult>> SendAsync(NotificationSettings settings, Alert alert, CancellationToken cancellationToken)
    {
        var (color, icon) = Severities.GetValueOrDefault(alert.Severity, Severities["info"]);
        var fields = alert.Fields.Append(("Time", LocalTime(alert.At))).ToList();
        var text = $"{icon} {alert.Title}\n{string.Join("\n", fields.Select(field => $"{field.Item1}: {field.Item2}"))}";
        var results = new List<ChannelResult>();
        if (settings.DiscordWebhookUrl.Length > 0)
        {
            // An embed lays the fields out as a card; Discord shows the timestamp in each reader's own time zone.
            // allowed_mentions: none, so a device or site name can never ping @everyone.
            var embed = new
            {
                title = $"{icon} {Clip(alert.Title, 240)}",
                color,
                fields = fields.Take(20).Select(field => new { name = field.Item1, value = Clip(Escape(field.Item2), 1000), inline = field.Item1 is "Browser" or "Site" or "IP address" or "By" }).ToArray(),
                timestamp = alert.At.UtcDateTime.ToString("o"),
                footer = new { text = "Shared Browser" }
            };
            results.Add(await PostAsync("Discord", settings.DiscordWebhookUrl, new { username = "Shared Browser", embeds = new[] { embed }, allowed_mentions = new { parse = Array.Empty<string>() } }, null, cancellationToken));
        }
        if (settings.TelegramBotToken.Length > 0 && settings.TelegramChatId.Length > 0)
        {
            results.Add(await PostAsync("Telegram", $"{_telegramApi.TrimEnd('/')}/bot{settings.TelegramBotToken}/sendMessage", new { chat_id = settings.TelegramChatId, text, disable_web_page_preview = true }, null, cancellationToken));
        }
        if (settings.LineChannelToken.Length > 0 && settings.LineTo.Length > 0)
        {
            results.Add(await PostAsync("LINE", $"{_lineApi.TrimEnd('/')}/v2/bot/message/push", new { to = settings.LineTo, messages = new[] { new { type = "text", text } } }, settings.LineChannelToken, cancellationToken));
        }
        return results;
    }

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..(length - 1)] + "…";
    private static string Escape(string value) => value.Replace("@", "@​").Replace("*", "\\*").Replace("_", "\\_");

    private static async Task<ChannelResult> PostAsync(string channel, string url, object body, string? bearer, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
            if (bearer is not null) request.Headers.Authorization = new("Bearer", bearer);
            using var response = await Http.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode) return new(channel, true, "");
            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            return new(channel, false, $"{(int)response.StatusCode} {text[..Math.Min(200, text.Length)]}".Trim());
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException)
        {
            return new(channel, false, error.Message);
        }
    }

    /// <summary>Validates and cleans settings from the dashboard. Empty secret fields keep the stored value.</summary>
    public static NotificationSettings Clean(NotificationSettings input, NotificationSettings current)
    {
        string Keep(string? value, string stored) => value is null || value == Masked ? stored : value.Trim();
        var discord = Keep(input.DiscordWebhookUrl, current.DiscordWebhookUrl);
        if (discord.Length > 0 && !AllowedUrl(discord, ["discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"], "/api/webhooks/"))
            throw new InvalidOperationException("The Discord webhook URL must look like https://discord.com/api/webhooks/...");
        var telegramToken = Keep(input.TelegramBotToken, current.TelegramBotToken);
        if (telegramToken.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(telegramToken, @"^\d+:[A-Za-z0-9_-]{20,}$")) throw new InvalidOperationException("The Telegram bot token must look like 123456:ABC...");
        var telegramChat = (input.TelegramChatId ?? "").Trim();
        if (telegramChat.Length > 64) throw new InvalidOperationException("The Telegram chat ID is too long");
        var lineToken = Keep(input.LineChannelToken, current.LineChannelToken);
        if (lineToken.Length > 500 || lineToken.Any(char.IsWhiteSpace)) throw new InvalidOperationException("The LINE channel access token is invalid");
        var lineTo = (input.LineTo ?? "").Trim();
        if (lineTo.Length > 64) throw new InvalidOperationException("The LINE user or group ID is too long");
        if (input.OfflineMinutes is < 5 or > 7 * 24 * 60) throw new InvalidOperationException("Offline alerts need between 5 minutes and 7 days");
        if (input.ExpiryWarningDays is < 1 or > 60) throw new InvalidOperationException("Expiry warnings need between 1 and 60 days");
        return new NotificationSettings
        {
            DiscordWebhookUrl = discord,
            TelegramBotToken = telegramToken,
            TelegramChatId = telegramChat,
            LineChannelToken = lineToken,
            LineTo = lineTo,
            Events = (input.Events ?? []).Where(NotificationEvents.All.Contains).Distinct().ToList(),
            OfflineMinutes = input.OfflineMinutes,
            ExpiryWarningDays = input.ExpiryWarningDays
        };
    }

    public const string Masked = "••••••••";

    /// <summary>What the dashboard sees: secrets are only reported as set.</summary>
    public static object Public(NotificationSettings settings) => new
    {
        discordWebhookUrl = settings.DiscordWebhookUrl.Length > 0 ? Masked : "",
        telegramBotToken = settings.TelegramBotToken.Length > 0 ? Masked : "",
        settings.TelegramChatId,
        lineChannelToken = settings.LineChannelToken.Length > 0 ? Masked : "",
        settings.LineTo,
        settings.Events,
        settings.OfflineMinutes,
        settings.ExpiryWarningDays,
        catalog = NotificationEvents.Catalog.Select(kind => new { kind.Key, kind.Title, kind.Group, kind.Default })
    };

    /// <summary>HTTPS to one of the given hosts, or plain HTTP to this machine (used by tests).</summary>
    public static bool AllowedUrl(string value, string[] hosts, string pathPrefix)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var url) || value.Length > 500) return false;
        var loopback = url.IsLoopback && url.Scheme is "http" or "https";
        return (loopback || (url.Scheme == "https" && hosts.Contains(url.Host.ToLowerInvariant()))) && url.AbsolutePath.StartsWith(pathPrefix, StringComparison.Ordinal);
    }
}
