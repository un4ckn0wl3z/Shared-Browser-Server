using System.Net;
using System.Net.Sockets;
using System.Text;

public sealed class ForwardProxyService : BackgroundService
{
    private const int MaxHeaderBytes = 64 * 1024;
    private readonly SharedStateStore _store;
    private readonly ILogger<ForwardProxyService> _logger;
    private long _totalConnections;
    private long _activeConnections;
    private long _bytesFromClients;
    private long _bytesToClients;
    private volatile bool _listening;
    private volatile int _listeningPort;
    private string _lastError = "";

    public ForwardProxyService(SharedStateStore store, ILogger<ForwardProxyService> logger)
    {
        _store = store;
        _logger = logger;
    }

    public object PublicStatus() => new
    {
        listening = _listening,
        bindAddress = Environment.GetEnvironmentVariable("SHARED_BROWSER_PROXY_BIND") ?? "127.0.0.1",
        port = _listeningPort,
        activeConnections = Interlocked.Read(ref _activeConnections),
        totalConnections = Interlocked.Read(ref _totalConnections),
        bytesFromClients = Interlocked.Read(ref _bytesFromClients),
        bytesToClients = Interlocked.Read(ref _bytesToClients),
        lastError = _lastError
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
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
                    _ = HandleClientAsync(client, proxy.AllowedPorts, stoppingToken);
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

    private async Task HandleClientAsync(TcpClient client, string allowedPorts, CancellationToken serverToken)
    {
        Interlocked.Increment(ref _totalConnections);
        Interlocked.Increment(ref _activeConnections);
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                timeout.CancelAfter(TimeSpan.FromMinutes(5));
                var clientStream = client.GetStream();
                var request = await ReadRequestAsync(clientStream, timeout.Token);
                if (request is null) return;
                Interlocked.Add(ref _bytesFromClients, request.Header.Length + request.Remainder.Length);

                if (!Authorized(request.Headers))
                {
                    await WriteAsciiAsync(clientStream, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Shared Browser Proxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", timeout.Token);
                    return;
                }

                if (!TryGetDestination(request, out var host, out var port, out var originTarget))
                {
                    await WriteErrorAsync(clientStream, 400, "Bad proxy request", timeout.Token);
                    return;
                }
                if (!ParseAllowedPorts(allowedPorts).Contains(port))
                {
                    await WriteErrorAsync(clientStream, 403, "Destination port is not allowed", timeout.Token);
                    return;
                }

                var address = await ResolvePublicAddressAsync(host, timeout.Token);
                if (address is null)
                {
                    await WriteErrorAsync(clientStream, 403, "Private or unresolved destinations are blocked", timeout.Token);
                    return;
                }

                using var remote = new TcpClient(address.AddressFamily) { NoDelay = true };
                await remote.ConnectAsync(address, port, timeout.Token);
                var remoteStream = remote.GetStream();

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

                var upload = PumpAsync(clientStream, remoteStream, true, timeout.Token);
                var download = PumpAsync(remoteStream, clientStream, false, timeout.Token);
                await Task.WhenAny(upload, download);
                timeout.Cancel();
                try { await Task.WhenAll(upload, download); } catch (OperationCanceledException) { }
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { _logger.LogDebug(error, "Proxy connection ended with an error"); }
            finally { Interlocked.Decrement(ref _activeConnections); }
        }
    }

    private bool Authorized(Dictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Proxy-Authorization", out var value) || !value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(value[6..].Trim()));
            var separator = decoded.IndexOf(':');
            if (separator < 1) return false;
            return _store.AuthorizeDevice(decoded[..separator], decoded[(separator + 1)..]) is not null;
        }
        catch { return false; }
    }

    private static async Task<ProxyRequest?> ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
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

    private static async Task<IPAddress?> ResolvePublicAddressAsync(string host, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try { addresses = await Dns.GetHostAddressesAsync(host, cancellationToken); }
        catch { return null; }
        return addresses.FirstOrDefault(IsPublicAddress);
    }

    private static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) return false;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !(bytes[0] is 0 or 10 or 127 || bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168 || bytes[0] >= 224);
        }
        return !(bytes[0] is 0xFC or 0xFD);
    }

    private async Task PumpAsync(Stream source, Stream destination, bool fromClient, CancellationToken cancellationToken)
    {
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            if (fromClient) Interlocked.Add(ref _bytesFromClients, read); else Interlocked.Add(ref _bytesToClients, read);
        }
    }

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
