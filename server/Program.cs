using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<DataDirectory>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton<ProxyCertificate>();
builder.Services.AddSingleton<ProxyUsageTracker>();
builder.Services.AddSingleton<SharedStateStore>();
builder.Services.AddSingleton<ForwardProxyService>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<ForwardProxyService>());
var app = builder.Build();

var adminToken = Environment.GetEnvironmentVariable("SHARED_BROWSER_ADMIN_TOKEN");
var dataKey = Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY");
if (string.IsNullOrWhiteSpace(adminToken)) throw new InvalidOperationException("SHARED_BROWSER_ADMIN_TOKEN is required");
if (string.IsNullOrWhiteSpace(dataKey)) throw new InvalidOperationException("SHARED_BROWSER_DATA_KEY is required");
if (adminToken.Length < 32) app.Logger.LogWarning("SHARED_BROWSER_ADMIN_TOKEN is shorter than 32 characters. Generate one with: openssl rand -hex 48");
if (dataKey.Length < 32) app.Logger.LogWarning("SHARED_BROWSER_DATA_KEY is shorter than 32 characters. Generate one with: openssl rand -hex 48");

// Behind a reverse proxy such as the bundled Caddy profile, client addresses in the audit log come from
// X-Forwarded-For. Only enable this when the server is reachable through that proxy alone.
if (string.Equals(Environment.GetEnvironmentVariable("SHARED_BROWSER_TRUST_FORWARDED_HEADERS"), "true", StringComparison.OrdinalIgnoreCase))
{
    var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto };
    forwarded.KnownNetworks.Clear();
    forwarded.KnownProxies.Clear();
    app.UseForwardedHeaders(forwarded);
}

app.Use(async (context, next) =>
{
    // The dashboard handles the administrator token, so it must never be framed or sniffed.
    var headers = context.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    if (context.Request.Path.StartsWithSegments("/api")) headers.CacheControl = "no-store";
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

var audit = app.Services.GetRequiredService<AuditLog>();

string Ip(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "";

bool IsAdminToken(string? token) => token is not null && FixedEquals(token, adminToken);

bool Admin(HttpContext context)
{
    if (IsAdminToken(Bearer(context.Request))) return true;
    audit.RecordFailure("admin.sign_in_failed", Ip(context));
    return false;
}

DeviceAuth? DeviceAuthorized(HttpRequest request, SharedStateStore store)
{
    var id = request.Headers["X-Device-Id"].ToString();
    var token = Bearer(request);
    return string.IsNullOrWhiteSpace(id) || token is null ? null : store.AuthorizeDevice(id, token);
}

void Record(HttpContext context, string action, string target = "", string details = "") => audit.Record("admin", action, target, details, Ip(context));

app.MapGet("/healthz", (SharedStateStore store) => Results.Json(new { ok = true, revision = store.Revision }));

// ---- Browser clients ------------------------------------------------------------------------------

// Accepts a one-time enrollment code from the dashboard or, unless disabled, the administrator token.
app.MapPost("/api/client/enroll", async (HttpContext context, EnrollRequest request, SharedStateStore store) =>
{
    var credential = Bearer(context.Request) ?? "";
    string? code = null;
    if (IsAdminToken(credential))
    {
        if (!store.Settings.AllowAdminTokenEnrollment)
            return Results.Json(new { error = "Enrollment with the administrator token is disabled. Create an enrollment code in the dashboard." }, statusCode: StatusCodes.Status403Forbidden);
    }
    else
    {
        code = SharedStateStore.NormalizeEnrollmentCode(credential);
        if (code is null)
        {
            audit.RecordFailure("device.enroll_failed", Ip(context), "unknown credential");
            return Results.Unauthorized();
        }
    }
    try
    {
        var (response, via) = await store.EnrollAsync(request, code);
        audit.Record($"device:{store.DeviceName(response.DeviceId)}", "device.enrolled", response.DeviceId, $"via {via}", Ip(context));
        return Results.Json(response, statusCode: StatusCodes.Status201Created);
    }
    catch (UnauthorizedAccessException error)
    {
        audit.RecordFailure("device.enroll_failed", Ip(context), error.Message);
        return Results.Json(new { error = error.Message }, statusCode: StatusCodes.Status401Unauthorized);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

// Clients poll this, or pull right after an event from /api/client/events. Passing ?since=<revision>
// returns 204 when nothing changed, so an idle browser does not download the vault again.
app.MapGet("/api/client/snapshot", async (HttpContext context, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    await store.TouchDeviceAsync(device.Id, context.Request.Query["deviceName"].ToString(), context.Request.Query["version"].ToString(), context.Request.Query["mode"].ToString());
    var snapshot = store.SnapshotFor(device.Id);
    if (long.TryParse(context.Request.Query["since"], out var since) && since == snapshot.Revision) return Results.NoContent();
    return Results.Json(snapshot);
});

// Server-Sent Events: one "revision" event whenever the shared state changes, and a comment every
// 25 seconds so proxies keep the connection open and clients notice when it silently dies.
app.MapGet("/api/client/events", async (HttpContext context, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }
    var aborted = context.RequestAborted;
    context.Response.Headers.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers["X-Accel-Buffering"] = "no";
    long sent = -1;
    using var live = store.TrackLiveConnection(device.Id);
    try
    {
        while (!aborted.IsCancellationRequested && store.IsDeviceActive(device.Id))
        {
            var revision = store.Revision;
            if (revision != sent)
            {
                await context.Response.WriteAsync($"event: revision\ndata: {revision}\n\n", aborted);
                sent = revision;
            }
            else await context.Response.WriteAsync(": keep-alive\n\n", aborted);
            await context.Response.Body.FlushAsync(aborted);
            await store.TouchDeviceAsync(device.Id, "", context.Request.Query["version"].ToString(), context.Request.Query["mode"].ToString());
            await store.WaitForRevisionChangeAsync(sent, TimeSpan.FromSeconds(25), aborted);
        }
    }
    catch (OperationCanceledException) { }
});

app.MapPost("/api/client/announcements/{id}/ack", async (HttpContext context, string id, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    return await store.AcknowledgeAnnouncementAsync(device.Id, id) ? Results.NoContent() : Results.NotFound(new { error = "Announcement not found" });
});

app.MapPost("/api/client/sync", async (HttpContext context, SyncRequest request, SharedStateStore store) =>
{
    var device = DeviceAuthorized(context.Request, store);
    if (device is null) return Results.Unauthorized();
    try
    {
        var changed = await store.SyncCookiesAsync(device.Id, request);
        var snapshot = store.SnapshotFor(device.Id);
        return Results.Json(new SyncResponse(snapshot.Revision, changed, snapshot));
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

// ---- Administration -------------------------------------------------------------------------------

app.MapGet("/api/admin/status", async (HttpContext context, SharedStateStore store, ForwardProxyService proxy) =>
    Admin(context)
        ? Results.Json(await store.AdminStatusAsync(proxy.PublicStatus(), audit.Recent(200), proxy.UsageReport))
        : Results.Unauthorized());

app.MapPut("/api/admin/settings", async (HttpContext context, BrowserSettings settings, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var changes = await store.UpdateSettingsAsync(settings);
        Record(context, "settings.updated", "", changes);
        return Results.Json(store.Settings);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPost("/api/admin/enrollment-codes", async (HttpContext context, EnrollmentCodeRequest request, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var code = await store.CreateEnrollmentCodeAsync(request);
        Record(context, "enrollment_code.created", code.Label, $"expires {code.ExpiresAt:u}");
        return Results.Json(code, statusCode: StatusCodes.Status201Created);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapDelete("/api/admin/enrollment-codes/{id}", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    if (!await store.RevokeEnrollmentCodeAsync(id)) return Results.NotFound(new { error = "Enrollment code not found" });
    Record(context, "enrollment_code.revoked", id);
    return Results.NoContent();
});

app.MapPost("/api/admin/announcements", async (HttpContext context, AnnouncementRequest request, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var announcement = await store.CreateAnnouncementAsync(request);
        var audience = announcement.ShareWithAllDevices ? "all browsers" : string.Join(", ", announcement.AllowedDeviceIds.Select(store.DeviceName));
        Record(context, "announcement.sent", announcement.Title.Length > 0 ? announcement.Title : announcement.Message, $"{announcement.Level}, to {audience}{(announcement.ExpiresAt is { } expires ? $", expires {expires:u}" : "")}");
        return Results.Json(announcement, statusCode: StatusCodes.Status201Created);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapDelete("/api/admin/announcements/{id}", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var removed = await store.DeleteAnnouncementAsync(id);
    if (removed is null) return Results.NotFound(new { error = "Announcement not found" });
    Record(context, "announcement.deleted", removed.Title.Length > 0 ? removed.Title : removed.Message, $"dismissed by {removed.Acknowledgements.Count} browser(s)");
    return Results.NoContent();
});

app.MapPut("/api/admin/bookmarks", async (HttpContext context, List<SharedBookmark> bookmarks, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var saved = await store.UpdateBookmarksAsync(bookmarks);
        Record(context, "bookmarks.updated", "", $"{saved.Count} bookmark(s)");
        return Results.Json(saved);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPost("/api/admin/profiles", async (HttpContext context, SessionProfile profile, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var saved = await store.SaveProfileAsync(profile, null);
        Record(context, "profile.created", saved.Domain, ProfileSummary(saved, store));
        return Results.Json(saved, statusCode: StatusCodes.Status201Created);
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPut("/api/admin/profiles/{id}", async (HttpContext context, string id, SessionProfile profile, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var saved = await store.SaveProfileAsync(profile, id);
        Record(context, "profile.updated", saved.Domain, ProfileSummary(saved, store));
        return Results.Json(saved);
    }
    catch (KeyNotFoundException) { return Results.NotFound(new { error = "Profile not found" }); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapDelete("/api/admin/profiles/{id}", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var removed = await store.DeleteProfileAsync(id);
    if (removed is null) return Results.NotFound(new { error = "Profile not found" });
    Record(context, "profile.deleted", removed.Domain, $"{removed.Cookies.Count} cookie(s)");
    return Results.NoContent();
});

app.MapPost("/api/admin/profiles/delete", async (HttpContext context, DeleteProfilesRequest request, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var ids = (request.Ids ?? []).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct().ToList();
    if (ids.Count == 0) return Results.BadRequest(new { error = "Select at least one profile" });
    var (removed, backup) = await store.DeleteProfilesAsync(ids);
    if (removed.Count == 0) return Results.NotFound(new { error = "None of the selected profiles exist" });
    Record(context, "profiles.deleted", $"{removed.Count} profile(s)", $"{DomainList(removed)}; backup {backup}");
    return Results.Ok(new { deleted = removed.Count, backup });
});

app.MapPost("/api/admin/profiles/purge", async (HttpContext context, PurgeProfilesRequest request, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    if (!request.Confirm) return Results.BadRequest(new { error = "Purging every profile must be confirmed" });
    var (removed, backup) = await store.DeleteProfilesAsync(null);
    Record(context, "profiles.purged", $"{removed.Count} profile(s)", removed.Count == 0 ? "vault was already empty" : $"{DomainList(removed)}; backup {backup}");
    return Results.Ok(new { deleted = removed.Count, backup });
});

app.MapPost("/api/admin/devices/{id}/revoke", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var name = await store.SetRevokedAsync(id, true);
    if (name is null) return Results.NotFound(new { error = "Device not found" });
    Record(context, "device.revoked", name);
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/admin/devices/{id}/restore", async (HttpContext context, string id, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var name = await store.SetRevokedAsync(id, false);
    if (name is null) return Results.NotFound(new { error = "Device not found" });
    Record(context, "device.restored", name);
    return Results.Ok(new { ok = true });
});

app.MapPut("/api/admin/devices/{id}/limits", async (HttpContext context, string id, DeviceLimitsRequest request, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var name = await store.SetDeviceLimitsAsync(id, request);
        if (name is null) return Results.NotFound(new { error = "Device not found" });
        static string Text(double? value) => value is null ? "default" : value == 0 ? "unlimited" : value.Value.ToString("0.###");
        Record(context, "device.limits_updated", name, $"connections {Text(request.MaxConnections)}, quota {Text(request.MonthlyQuotaGb)} GB, rate {Text(request.RateLimitMbps)} Mbps");
        return Results.Ok(new { ok = true });
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.MapPost("/api/admin/egress-ip", async (HttpContext context, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var settings = store.Settings;
    try
    {
        var ip = await Egress.CheckAsync(settings.IpCheckUrl, settings.Proxy, context.RequestAborted);
        return Results.Ok(new { ip, family = settings.Proxy.EgressAddressFamily, source = settings.Proxy.EgressSourceAddress, checkedAt = DateTimeOffset.UtcNow });
    }
    catch (Exception error) when (error is InvalidOperationException or HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
    {
        return Results.BadRequest(new { error = $"Egress check failed: {error.Message}" });
    }
});

app.MapDelete("/api/admin/devices/{id}", async (HttpContext context, string id, SharedStateStore store, ProxyUsageTracker usage) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var name = await store.DeleteDeviceAsync(id);
    if (name is null) return Results.NotFound(new { error = "Device not found" });
    usage.Forget(id);
    Record(context, "device.deleted", name);
    return Results.NoContent();
});

app.MapGet("/api/admin/export", async (HttpContext context, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    var bytes = await store.ExportAsync();
    Record(context, "vault.exported", "", $"{bytes.Length} bytes");
    return Results.File(bytes, "application/json", $"shared-browser-vault-{DateTimeOffset.UtcNow:yyyyMMdd'T'HHmmss'Z'}.json");
});

app.MapPost("/api/admin/import", async (HttpContext context, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
    var json = await reader.ReadToEndAsync();
    try
    {
        var result = await store.ImportAsync(json, "import");
        Record(context, "vault.imported", "", result);
        return Results.Ok(new { ok = true, result });
    }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
}).WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(256L * 1024 * 1024));

app.MapPost("/api/admin/backups/{name}/restore", async (HttpContext context, string name, SharedStateStore store) =>
{
    if (!Admin(context)) return Results.Unauthorized();
    try
    {
        var result = await store.RestoreBackupAsync(name);
        Record(context, "vault.restored", name, result);
        return Results.Ok(new { ok = true, result });
    }
    catch (KeyNotFoundException) { return Results.NotFound(new { error = "Backup not found" }); }
    catch (InvalidOperationException error) { return Results.BadRequest(new { error = error.Message }); }
});

app.Run();

static string DomainList(IReadOnlyList<SessionProfile> profiles)
{
    var names = profiles.Select(item => item.Domain).Take(10).ToList();
    return string.Join(", ", names) + (profiles.Count > names.Count ? $" and {profiles.Count - names.Count} more" : "");
}

static string ProfileSummary(SessionProfile profile, SharedStateStore store)
{
    var sharing = profile.ShareWithAllDevices ? "all browsers" : string.Join(", ", profile.AllowedDeviceIds.Select(store.DeviceName));
    return $"{profile.Cookies.Count} cookie(s), {(profile.Enabled ? "enabled" : "disabled")}, shared with {(sharing.Length == 0 ? "no browsers" : sharing)}";
}

static string? Bearer(HttpRequest request)
{
    var value = request.Headers.Authorization.ToString();
    return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : null;
}

static bool FixedEquals(string value, string expected)
{
    var a = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    var b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
    return CryptographicOperations.FixedTimeEquals(a, b);
}
