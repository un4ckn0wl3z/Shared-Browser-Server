using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;

/// <summary>
/// Copies each vault backup to S3-compatible object storage with an AWS Signature Version 4 PUT, so the
/// vault survives the loss of the server. Old copies are left to the bucket's lifecycle rules.
/// </summary>
public sealed partial class OffsiteUploader : BackgroundService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(5) };
    private readonly SharedStateStore _store;
    private readonly AuditLog _audit;
    private readonly Channel<string> _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(20) { FullMode = BoundedChannelFullMode.DropOldest });

    public OffsiteUploader(SharedStateStore store, AuditLog audit)
    {
        _store = store;
        _audit = audit;
        store.BackupCreated += name => { if (_store.OffsiteSettings().Enabled) _queue.Writer.TryWrite(name); };
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var name in _queue.Reader.ReadAllAsync(stoppingToken)) await UploadAsync(name, stoppingToken);
    }

    /// <summary>Uploads the newest backup now ("Upload latest backup" in the dashboard). Returns an error or "".</summary>
    public async Task<(string Name, string Error)> UploadLatestAsync(CancellationToken cancellationToken)
    {
        var latest = _store.ListBackups().FirstOrDefault();
        if (latest is null) return ("", "There is no backup yet");
        return (latest.Name, await UploadAsync(latest.Name, cancellationToken));
    }

    private async Task<string> UploadAsync(string name, CancellationToken cancellationToken)
    {
        var settings = _store.OffsiteSettings();
        string error;
        try
        {
            if (settings.Endpoint.Length == 0 || settings.Bucket.Length == 0 || settings.AccessKeyId.Length == 0 || settings.SecretAccessKey.Length == 0) throw new InvalidOperationException("Offsite backup is not configured");
            var body = await File.ReadAllBytesAsync(Path.Combine(_store.BackupDirectory, name), cancellationToken);
            await PutAsync(settings, settings.Prefix + name, body, cancellationToken);
            error = "";
        }
        catch (Exception failure) when (failure is IOException or HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            error = failure.Message.Length > 300 ? failure.Message[..300] : failure.Message;
        }
        await _store.RecordOffsiteResultAsync(name, error);
        if (error.Length > 0) _audit.Record("server", NotificationEvents.BackupFailed, "offsite backup", $"{name}: {error}");
        else _audit.Record("server", "backup.uploaded", name, $"{settings.Endpoint}/{settings.Bucket}/{settings.Prefix}");
        return error;
    }

    private static async Task PutAsync(OffsiteBackupSettings settings, string key, byte[] body, CancellationToken cancellationToken)
    {
        // Path-style addressing (endpoint/bucket/key) works with AWS S3, DigitalOcean Spaces, MinIO and others.
        // Bucket, prefix and backup names are restricted to characters that need no URI encoding.
        var endpoint = new Uri(settings.Endpoint.TrimEnd('/'));
        var path = $"/{settings.Bucket}/{key}";
        var url = new Uri(endpoint, path);
        var now = DateTime.UtcNow;
        var amzDate = now.ToString("yyyyMMdd'T'HHmmss'Z'");
        var date = now.ToString("yyyyMMdd");
        var payloadHash = Hex(SHA256.HashData(body));
        var host = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}";
        const string signedHeaders = "host;x-amz-content-sha256;x-amz-date";
        var canonicalRequest = $"PUT\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payloadHash}\nx-amz-date:{amzDate}\n\n{signedHeaders}\n{payloadHash}";
        var scope = $"{date}/{settings.Region}/s3/aws4_request";
        var stringToSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{scope}\n{Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)))}";
        var key1 = HMACSHA256.HashData(Encoding.UTF8.GetBytes("AWS4" + settings.SecretAccessKey), Encoding.UTF8.GetBytes(date));
        var key2 = HMACSHA256.HashData(key1, Encoding.UTF8.GetBytes(settings.Region));
        var key3 = HMACSHA256.HashData(key2, "s3"u8.ToArray());
        var signingKey = HMACSHA256.HashData(key3, "aws4_request"u8.ToArray());
        var signature = Hex(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(stringToSign)));

        using var request = new HttpRequestMessage(HttpMethod.Put, url) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new("application/json");
        request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
        request.Headers.TryAddWithoutValidation("x-amz-content-sha256", payloadHash);
        request.Headers.TryAddWithoutValidation("Authorization", $"AWS4-HMAC-SHA256 Credential={settings.AccessKeyId}/{scope}, SignedHeaders={signedHeaders}, Signature={signature}");
        using var response = await Http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            var code = ErrorCode().Match(text);
            throw new HttpRequestException($"Storage returned {(int)response.StatusCode}{(code.Success ? $" ({code.Groups[1].Value})" : "")}");
        }
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [GeneratedRegex("<Code>([^<]{1,80})</Code>")]
    private static partial Regex ErrorCode();

    /// <summary>Validates settings from the dashboard; an empty or masked secret keeps the stored one.</summary>
    public static OffsiteBackupSettings Clean(OffsiteBackupSettings input, OffsiteBackupSettings current)
    {
        var endpoint = (input.Endpoint ?? "").Trim().TrimEnd('/');
        var region = (input.Region ?? "").Trim();
        var bucket = (input.Bucket ?? "").Trim();
        var prefix = (input.Prefix ?? "").Trim().TrimStart('/');
        var accessKey = (input.AccessKeyId ?? "").Trim();
        var secret = input.SecretAccessKey is null || input.SecretAccessKey == Notifier.Masked || input.SecretAccessKey.Length == 0 ? current.SecretAccessKey : input.SecretAccessKey.Trim();
        if (endpoint.Length > 0 && !(Uri.TryCreate(endpoint, UriKind.Absolute, out var url) && (url.Scheme == "https" || (url.Scheme == "http" && url.IsLoopback)) && url.AbsolutePath == "/"))
            throw new InvalidOperationException("The storage endpoint must be an HTTPS address such as https://sgp1.digitaloceanspaces.com");
        if (region.Length == 0) region = "us-east-1";
        if (!Regex.IsMatch(region, "^[a-z0-9-]{2,32}$")) throw new InvalidOperationException("The region must look like us-east-1 or sgp1");
        if (bucket.Length > 0 && !Regex.IsMatch(bucket, "^[a-z0-9][a-z0-9.-]{1,62}$")) throw new InvalidOperationException("The bucket name may contain lower-case letters, digits, dots and hyphens");
        if (!Regex.IsMatch(prefix, "^[A-Za-z0-9/_.-]{0,200}$")) throw new InvalidOperationException("The folder may contain letters, digits, / _ . and -");
        if (prefix.Length > 0 && !prefix.EndsWith('/')) prefix += "/";
        if (accessKey.Length > 128 || accessKey.Any(char.IsWhiteSpace) || secret.Length > 256) throw new InvalidOperationException("The access key is invalid");
        if (input.Enabled && (endpoint.Length == 0 || bucket.Length == 0 || accessKey.Length == 0 || secret.Length == 0)) throw new InvalidOperationException("Enter the endpoint, bucket, access key and secret key");
        return new OffsiteBackupSettings { Enabled = input.Enabled, Endpoint = endpoint, Region = region, Bucket = bucket, Prefix = prefix, AccessKeyId = accessKey, SecretAccessKey = secret };
    }

    public static object Public(OffsiteBackupSettings settings) => new
    {
        settings.Enabled,
        settings.Endpoint,
        settings.Region,
        settings.Bucket,
        settings.Prefix,
        settings.AccessKeyId,
        secretAccessKey = settings.SecretAccessKey.Length > 0 ? Notifier.Masked : "",
        settings.LastUploadAt,
        settings.LastUploadName,
        settings.LastError
    };
}
