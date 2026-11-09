using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

public sealed class ForwardProxyService : BackgroundService
{
    private const int MaxHeaderBytes = 64 * 1024;
    private const int MaxActiveConnections = 2048;
    private static readonly TimeSpan HeaderTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);
    // Tunnels stay open while data flows (downloads, WebSockets, streaming) and close after this much silence.
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RevocationCheckInterval = TimeSpan.FromSeconds(5);
    private readonly SharedStateStore _store;
    private readonly ProxyCertificate _certificate;
    private readonly ProxyUsageTracker _usage;
    private readonly AuditLog _audit;
    private readonly ILogger<ForwardProxyService> _logger;
    private DateTimeOffset _lastFingerprintCheck;
    private long _totalConnections;
    private long _activeConnections;
    private long _bytesFromClients;
    private long _bytesToClients;
    private volatile bool _listening;
    private volatile int _listeningPort;
    private string _lastError = "";

    public ForwardProxyService(SharedStateStore store, ProxyCertificate certificate, ProxyUsageTracker usage, AuditLog audit, ILogger<ForwardProxyService> logger)
    {
        _store = store;
        _certificate = certificate;
        _usage = usage;
        _audit = audit;
        _logger = logger;
    }

    public object PublicStatus() => new
    {
        listening = _listening,
        bindAddress = Environment.GetEnvironmentVariable("SHARED_BROWSER_PROXY_BIND") ?? "127.0.0.1",
        port = _listeningPort,
        tls = _store.Settings.Proxy.Tls,
        certificateSha256 = _store.Settings.Proxy.CertificateSha256,
        certificateSource = _certificate.OperatorSupplied ? "operator" : "generated",
        egressAddressFamily = _store.Settings.Proxy.EgressAddressFamily,
        egressSourceAddress = _store.Settings.Proxy.EgressSourceAddress,
        activeConnections = Interlocked.Read(ref _activeConnections),
        totalConnections = Interlocked.Read(ref _totalConnections),
        bytesFromClients = Interlocked.Read(ref _bytesFromClients),
        bytesToClients = Interlocked.Read(ref _bytesToClients),
        lastError = _lastError
    };

    public object UsageReport(string deviceId) => _usage.Report(deviceId, _store.LimitsFor(deviceId));

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        _usage.SaveIfDue(force: true);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _usage.SaveIfDue();
            var proxy = _store.Settings.Proxy;
            if (!proxy.Enabled)
            {
                _listening = false;
                _listeningPort = 0;
                await Task.Delay(750, stoppingToken);
                continue;
            }

            TcpListener? listener = null;
            try
            {
                var bindText = Environment.GetEnvironmentVariable("SHARED_BROWSER_PROXY_BIND") ?? "127.0.0.1";
                if (!IPAddress.TryParse(bindText, out var bindAddress)) throw new InvalidOperationException("SHARED_BROWSER_PROXY_BIND must be an IP address");
                listener = new TcpListener(bindAddress, proxy.Port);
                listener.Start(256);
                _listening = true;
                _listeningPort = proxy.Port;
                _lastError = "";
                _logger.LogInformation("Authenticated forward proxy listening on {Address}:{Port}", bindAddress, proxy.Port);

                while (!stoppingToken.IsCancellationRequested)
                {
                    await RefreshFingerprintAsync();
                    _usage.SaveIfDue();
                    var current = _store.Settings.Proxy;
                    if (!current.Enabled || current.Port != proxy.Port) break;
                    using var acceptCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    var accept = listener.AcceptTcpClientAsync(acceptCts.Token).AsTask();
                    var check = Task.Delay(750, stoppingToken);
                    if (await Task.WhenAny(accept, check) != accept)
                    {
                        acceptCts.Cancel();
                        try { await accept; } catch (OperationCanceledException) { }
                        continue;
                    }
                    var client = await accept;
                    if (Interlocked.Read(ref _activeConnections) >= MaxActiveConnections)
                    {
                        _logger.LogWarning("Forward proxy rejected a connection because {Limit} connections are already open", MaxActiveConnections);
                        client.Dispose();
                        continue;
                    }
                    _ = HandleClientAsync(client, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception error)
            {
                _lastError = error.Message;
                _logger.LogError(error, "Forward proxy listener failed");
                try { await Task.Delay(1500, stoppingToken); } catch (OperationCanceledException) { }
            }
            finally
            {
                _listening = false;
                _listeningPort = 0;
                listener?.Stop();
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverToken)
    {
        Interlocked.Increment(ref _totalConnections);
        Interlocked.Increment(ref _activeConnections);
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                timeout.CancelAfter(HeaderTimeout);
                Stream clientStream = client.GetStream();
                if (_store.Settings.Proxy.Tls)
                {
                    // The browser sends its device credentials to the proxy, so they travel inside TLS.
                    var tls = new SslStream(clientStream, leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate.Current, ClientCertificateRequired = false }, timeout.Token);
                    clientStream = tls;
                }
                await using var clientStreamScope = clientStream;
                var request = await ReadRequestAsync(clientStream, timeout.Token);
                if (request is null) return;
                Interlocked.Add(ref _bytesFromClients, request.Header.Length + request.Remainder.Length);

                var deviceId = AuthorizedDevice(request.Headers);
                if (deviceId is null)
                {
                    await WriteAsciiAsync(clientStream, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Shared Browser Proxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", timeout.Token);
                    return;
                }

                if (!TryGetDestination(request, out var host, out var port, out var originTarget))
                {
                    await WriteErrorAsync(clientStream, 400, "Bad proxy request", timeout.Token);
                    return;
                }
                var settings = _store.Settings.Proxy;
                if (!ParseAllowedPorts(settings.AllowedPorts).Contains(port))
                {
                    await WriteErrorAsync(clientStream, 403, "Destination port is not allowed", timeout.Token);
                    return;
                }

                var limits = _store.LimitsFor(deviceId);
                using var lease = _usage.TryOpen(deviceId, limits, out var refusalStatus, out var refusal);
                if (lease is null)
                {
                    if (refusalStatus == 403 && _usage.ShouldReportQuota(deviceId))
                        _audit.Record($"device:{_store.DeviceName(deviceId)}", "proxy.quota_reached", deviceId, $"{limits.MonthlyQuotaGb} GB this month");
                    await WriteErrorAsync(clientStream, refusalStatus, refusal, timeout.Token);
                    return;
                }

                var (address, resolveError) = await ResolveDestinationAsync(host, settings, timeout.Token);
                if (address is null)
                {
                    await WriteErrorAsync(clientStream, resolveError.Status, resolveError.Message, timeout.Token);
                    return;
                }

                timeout.CancelAfter(ConnectTimeout);
                Socket socket;
                try { socket = await Egress.ConnectAsync(address, port, settings, timeout.Token); }
                catch (Exception error) when (error is SocketException || (error is OperationCanceledException && !serverToken.IsCancellationRequested))
                {
                    await WriteErrorAsync(clientStream, 502, "Destination is unreachable", CancellationToken.None);
                    return;
                }
                timeout.CancelAfter(IdleTimeout);
                await using var remoteStream = new NetworkStream(socket, ownsSocket: true);
                var record = settings.RecordDestinations;
                _usage.RecordHost(deviceId, host, record);
                var flow = new Flow(deviceId, host, limits, record);
                _usage.AddBytes(deviceId, host, request.Header.Length + request.Remainder.Length, upload: true, record);

                if (request.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteAsciiAsync(clientStream, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: SharedBrowser\r\n\r\n", timeout.Token);
                }
                else
                {
                    var rewritten = RewriteHttpRequest(request, originTarget);
                    await remoteStream.WriteAsync(rewritten, timeout.Token);
                    if (request.Remainder.Length > 0) await remoteStream.WriteAsync(request.Remainder, timeout.Token);
                }

                var upload = PumpAsync(clientStream, remoteStream, true, timeout, flow);
                var download = request.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase)
                    ? PumpAsync(remoteStream, clientStream, false, timeout, flow)
                    : ForwardResponseAsync(remoteStream, clientStream, timeout, flow);
                var revocation = WatchRevocationAsync(deviceId, limits, timeout.Token);
                await Task.WhenAny(upload, download, revocation);
                timeout.Cancel();
                try { await Task.WhenAll(upload, download, revocation); } catch (Exception error) when (error is OperationCanceledException or IOException or SocketException) { }
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { _logger.LogDebug(error, "Proxy connection ended with an error"); }
            finally { Interlocked.Decrement(ref _activeConnections); }
        }
    }

    private string? AuthorizedDevice(Dictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Proxy-Authorization", out var value) || !value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(value[6..].Trim()));
            var separator = decoded.IndexOf(':');
            if (separator < 1) return null;
            return _store.AuthorizeDevice(decoded[..separator], decoded[(separator + 1)..])?.Id;
        }
        catch { return null; }
    }

    // Revoking a device in the dashboard also ends the tunnels it already has open, instead of letting
    // them run until they go idle.
    // An exhausted monthly quota ends open tunnels the same way.
    private async Task WatchRevocationAsync(string deviceId, ProxyLimits limits, CancellationToken cancellationToken)
    {
        while (_store.IsDeviceActive(deviceId) && _store.Settings.Proxy.Enabled && !_usage.OverQuota(deviceId, _store.LimitsFor(deviceId)))
            await Task.Delay(RevocationCheckInterval, cancellationToken);
        if (_usage.OverQuota(deviceId, _store.LimitsFor(deviceId)) && _usage.ShouldReportQuota(deviceId))
            _audit.Record($"device:{_store.DeviceName(deviceId)}", "proxy.quota_reached", deviceId, $"{limits.MonthlyQuotaGb} GB this month");
    }

    private async Task RefreshFingerprintAsync()
    {
        if (DateTimeOffset.UtcNow - _lastFingerprintCheck < TimeSpan.FromSeconds(30)) return;
        _lastFingerprintCheck = DateTimeOffset.UtcNow;
        try { await _store.RefreshProxyFingerprintAsync(); }
        catch (Exception error) { _logger.LogWarning(error, "Could not refresh the proxy certificate fingerprint"); }
    }

    /// <summary>
    /// Forwards a plain-HTTP origin response with "Connection: close" added. Without it the browser would
    /// reuse this connection, and its next request (carrying Proxy-Authorization, possibly for another
    /// site) would be pumped unparsed to the first origin. Interim 1xx responses pass through unchanged.
    /// </summary>
    private async Task ForwardResponseAsync(Stream remote, Stream client, CancellationTokenSource idle, Flow flow)
    {
        var pending = Array.Empty<byte>();
        while (true)
        {
            var block = await ReadHeaderBlockAsync(remote, pending, idle.Token);
            if (block is null)
            {
                if (pending.Length > 0) await client.WriteAsync(pending, idle.Token);
                return;
            }
            var (header, rest) = block.Value;
            var text = Encoding.ASCII.GetString(header);
            var statusLine = text[..text.IndexOf("\r\n", StringComparison.Ordinal)];
            var parts = statusLine.Split(' ', 3);
            var interim = parts.Length > 1 && parts[1].Length == 3 && parts[1][0] == '1' && parts[1] != "101";
            if (interim)
            {
                await client.WriteAsync(header, idle.Token);
                Interlocked.Add(ref _bytesToClients, header.Length);
                _usage.AddBytes(flow.DeviceId, flow.Host, header.Length, upload: false, flow.RecordHost);
                pending = rest;
                continue;
            }
            var builder = new StringBuilder(statusLine).Append("\r\n");
            foreach (var line in text.Split("\r\n").Skip(1))
            {
                if (line.Length == 0) continue;
                var name = line.Split(':', 2)[0].Trim();
                if (name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)) continue;
                builder.Append(line).Append("\r\n");
            }
            builder.Append("Connection: close\r\nProxy-Connection: close\r\n\r\n");
            var rewritten = Encoding.ASCII.GetBytes(builder.ToString());
            await client.WriteAsync(rewritten, idle.Token);
            if (rest.Length > 0) await client.WriteAsync(rest, idle.Token);
            Interlocked.Add(ref _bytesToClients, rewritten.Length + rest.Length);
            _usage.AddBytes(flow.DeviceId, flow.Host, rewritten.Length + rest.Length, upload: false, flow.RecordHost);
            await PumpAsync(remote, client, false, idle, flow);
            return;
        }
    }

    /// <summary>Reads one header block (through the blank line), starting with bytes already received.</summary>
    private static async Task<(byte[] Header, byte[] Remainder)?> ReadHeaderBlockAsync(Stream stream, byte[] initial, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        buffer.Write(initial);
        var chunk = new byte[8192];
        var end = FindHeaderEnd(buffer.GetBuffer(), (int)buffer.Length);
        while (end < 0)
        {
            if (buffer.Length >= MaxHeaderBytes) throw new InvalidOperationException("Origin response headers are too large");
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) return null;
            buffer.Write(chunk, 0, read);
            end = FindHeaderEnd(buffer.GetBuffer(), (int)buffer.Length);
        }
        var bytes = buffer.ToArray();
        return (bytes[..end], bytes[end..]);
    }

    private static async Task<ProxyRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        var headerEnd = -1;
        while (buffer.Length < MaxHeaderBytes && headerEnd < 0)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) return null;
            buffer.Write(chunk, 0, read);
            headerEnd = FindHeaderEnd(buffer.GetBuffer(), (int)buffer.Length);
        }
        if (headerEnd < 0) throw new InvalidOperationException("Proxy request headers are too large");
        var bytes = buffer.ToArray();
        var header = bytes[..headerEnd];
        var remainder = bytes[headerEnd..];
        var text = Encoding.ASCII.GetString(header);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        var first = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (first.Length != 3) throw new InvalidOperationException("Invalid proxy request line");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator > 0) headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }
        return new ProxyRequest(first[0], first[1], first[2], headers, header, remainder);
    }

    private static int FindHeaderEnd(byte[] bytes, int length)
    {
        for (var index = 3; index < length; index++)
            if (bytes[index - 3] == 13 && bytes[index - 2] == 10 && bytes[index - 1] == 13 && bytes[index] == 10) return index + 1;
        return -1;
    }

    private static bool TryGetDestination(ProxyRequest request, out string host, out int port, out string originTarget)
    {
        host = ""; port = 0; originTarget = request.Target;
        if (request.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate("http://" + request.Target, UriKind.Absolute, out var authority)) return false;
            host = authority.Host; port = authority.IsDefaultPort ? 443 : authority.Port; originTarget = request.Target; return host.Length > 0;
        }
        if (Uri.TryCreate(request.Target, UriKind.Absolute, out var absolute) && absolute.Scheme is "http" or "https")
        {
            host = absolute.Host; port = absolute.IsDefaultPort ? (absolute.Scheme == "https" ? 443 : 80) : absolute.Port;
            originTarget = string.IsNullOrEmpty(absolute.PathAndQuery) ? "/" : absolute.PathAndQuery;
            return true;
        }
        if (!request.Headers.TryGetValue("Host", out var hostHeader) || !Uri.TryCreate("http://" + hostHeader, UriKind.Absolute, out var fromHost)) return false;
        host = fromHost.Host; port = fromHost.IsDefaultPort ? 80 : fromHost.Port; return host.Length > 0;
    }

    private static byte[] RewriteHttpRequest(ProxyRequest request, string originTarget)
    {
        var builder = new StringBuilder().Append(request.Method).Append(' ').Append(originTarget).Append(' ').Append(request.Version).Append("\r\n");
        foreach (var header in request.Headers)
        {
            if (header.Key.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }
        builder.Append("Connection: close\r\n\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static HashSet<int> ParseAllowedPorts(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(item => int.TryParse(item, out var port) ? port : 0).Where(port => port is > 0 and <= 65535).ToHashSet();

    /// <summary>Picks a public address for the destination that the configured egress family can reach.</summary>
    private static async Task<(IPAddress? Address, (int Status, string Message) Error)> ResolveDestinationAsync(string host, ProxySettings settings, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try { addresses = await Dns.GetHostAddressesAsync(host, cancellationToken); }
        catch { return (null, (403, "Private or unresolved destinations are blocked")); }
        var publicAddresses = addresses.Where(IsPublicAddress).ToList();
        if (publicAddresses.Count == 0) return (null, (403, "Private or unresolved destinations are blocked"));
        var usable = Egress.Usable(publicAddresses, settings).FirstOrDefault();
        return usable is null
            ? (null, (502, $"The destination has no {(Egress.RequiredFamily(settings) == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address for the configured egress"))
            : (usable, (0, ""));
    }

    internal static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6None) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal) return false;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !(bytes[0] is 0 or 10 or 127
                || bytes[0] == 100 && bytes[1] is >= 64 and <= 127          // 100.64.0.0/10 carrier-grade NAT (also Tailscale)
                || bytes[0] == 169 && bytes[1] == 254                       // link-local, including cloud metadata endpoints
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2   // IETF protocol assignments, TEST-NET-1
                || bytes[0] == 192 && bytes[1] == 168
                || bytes[0] == 198 && bytes[1] is 18 or 19                  // benchmarking
                || bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100     // TEST-NET-2
                || bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113      // TEST-NET-3
                || bytes[0] >= 224);                                        // multicast, reserved, broadcast
        }
        // NAT64 (64:ff9b::/96) embeds an IPv4 address, which must pass the IPv4 rules as well.
        if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xFF && bytes[3] == 0x9B && bytes[4..12].All(value => value == 0))
            return IsPublicAddress(new IPAddress(bytes[12..16]));
        // ::/96 (deprecated IPv4-compatible), 2001:db8::/32 documentation, 6to4 relays to private space.
        if (bytes[..12].All(value => value == 0)) return false;
        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8) return false;
        if (bytes[0] == 0x20 && bytes[1] == 0x02) return IsPublicAddress(new IPAddress(bytes[2..6]));
        return true;
    }

    private async Task PumpAsync(Stream source, Stream destination, bool fromClient, CancellationTokenSource idle, Flow flow)
    {
        // Smaller reads keep a rate-limited browser's traffic smooth instead of bursting 32 KB at a time.
        var buffer = new byte[flow.Limits.RateLimitMbps > 0 ? 8 * 1024 : 32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, idle.Token);
            if (read == 0) break;
            await _usage.ThrottleAsync(flow.DeviceId, read, flow.Limits, idle.Token);
            await destination.WriteAsync(buffer.AsMemory(0, read), idle.Token);
            // Any traffic in either direction pushes the idle deadline back.
            try { idle.CancelAfter(IdleTimeout); } catch (ObjectDisposedException) { break; }
            if (fromClient) Interlocked.Add(ref _bytesFromClients, read); else Interlocked.Add(ref _bytesToClients, read);
            _usage.AddBytes(flow.DeviceId, flow.Host, read, fromClient, flow.RecordHost);
        }
    }

    private sealed record Flow(string DeviceId, string Host, ProxyLimits Limits, bool RecordHost);

    private static Task WriteAsciiAsync(Stream stream, string value, CancellationToken cancellationToken) => stream.WriteAsync(Encoding.ASCII.GetBytes(value), cancellationToken).AsTask();
    private static Task WriteErrorAsync(Stream stream, int status, string message, CancellationToken cancellationToken)
    {
        var body = Encoding.UTF8.GetBytes(message);
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} {message}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {body.Length}\r\n\r\n");
        return WritePartsAsync(stream, header, body, cancellationToken);
    }
    private static async Task WritePartsAsync(Stream stream, byte[] header, byte[] body, CancellationToken cancellationToken) { await stream.WriteAsync(header, cancellationToken); await stream.WriteAsync(body, cancellationToken); }

    private sealed record ProxyRequest(string Method, string Target, string Version, Dictionary<string, string> Headers, byte[] Header, byte[] Remainder);
}
