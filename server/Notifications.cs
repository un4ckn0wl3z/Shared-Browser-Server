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

    public sealed record Alert(string Event, string Title, string Message, string Key);
    public sealed record ChannelResult(string Channel, bool Ok, string Error);

    private static readonly Dictionary<string, string> Titles = new()
    {
        [NotificationEvents.SessionLost] = "Shared session signed out",
        [NotificationEvents.SessionExpiring] = "Shared session expires soon",
        [NotificationEvents.DeviceOffline] = "Browser offline",
        [NotificationEvents.DeviceEnrolled] = "New browser enrolled",
        [NotificationEvents.QuotaReached] = "Proxy quota reached",
        [NotificationEvents.UnlockFailed] = "Wrong unlock code entered",
        [NotificationEvents.BackupFailed] = "Backup failed"
    };

    private void OnAudit(AuditEntry entry)
    {
        if (!Titles.TryGetValue(entry.Action, out var title)) return;
        var subject = entry.Actor.StartsWith("device:", StringComparison.Ordinal) ? entry.Actor[7..] : entry.Target;
        var details = string.Join(" — ", new[] { entry.Target == subject ? "" : entry.Target, entry.Details }.Where(item => !string.IsNullOrWhiteSpace(item)));
        Enqueue(new Alert(entry.Action, title, string.IsNullOrEmpty(details) ? subject : $"{subject}: {details}", $"{entry.Action}|{subject}|{entry.Target}"));
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
            foreach (var result in await SendAsync(_store.NotificationSettings(), alert.Title, alert.Message, stoppingToken))
            {
                if (!result.Ok) _logger.LogWarning("Notification to {Channel} failed: {Error}", result.Channel, result.Error);
            }
        }
    }

    /// <summary>Sends straight away to every configured channel and reports each outcome (used by "Send test").</summary>
    public async Task<List<ChannelResult>> SendAsync(NotificationSettings settings, string title, string message, CancellationToken cancellationToken)
    {
        var text = $"{title}\n{message}";
        var results = new List<ChannelResult>();
        if (settings.DiscordWebhookUrl.Length > 0)
        {
            // allowed_mentions: none, so a device or site name can never ping @everyone.
            results.Add(await PostAsync("Discord", settings.DiscordWebhookUrl, new { username = "Shared Browser", content = $"**{Escape(title)}**\n{Escape(message)}", allowed_mentions = new { parse = Array.Empty<string>() } }, null, cancellationToken));
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
        allEvents = NotificationEvents.All
    };

    /// <summary>HTTPS to one of the given hosts, or plain HTTP to this machine (used by tests).</summary>
    public static bool AllowedUrl(string value, string[] hosts, string pathPrefix)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var url) || value.Length > 500) return false;
        var loopback = url.IsLoopback && url.Scheme is "http" or "https";
        return (loopback || (url.Scheme == "https" && hosts.Contains(url.Host.ToLowerInvariant()))) && url.AbsolutePath.StartsWith(pathPrefix, StringComparison.Ordinal);
    }
}
