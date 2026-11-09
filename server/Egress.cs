using System.Net;
using System.Net.Sockets;
using System.Text.Json;

/// <summary>
/// How the proxy reaches websites: optionally only over IPv4 or IPv6, and optionally from one chosen local
/// address. Keeping the egress address fixed matters because sites that see a session move between an
/// IPv4 and an IPv6 address (or between several server IPs) often treat it as suspicious.
/// </summary>
public static class Egress
{
    public static readonly string[] Families = ["any", "ipv4", "ipv6"];

    public static IPAddress? SourceAddress(ProxySettings settings) =>
        IPAddress.TryParse(settings.EgressSourceAddress, out var address) ? address : null;

    /// <summary>The address family outgoing connections must use, or null when either will do.</summary>
    public static AddressFamily? RequiredFamily(ProxySettings settings)
    {
        if (SourceAddress(settings) is { } source) return source.AddressFamily;
        return settings.EgressAddressFamily switch
        {
            "ipv4" => AddressFamily.InterNetwork,
            "ipv6" => AddressFamily.InterNetworkV6,
            _ => null
        };
    }

    public static IEnumerable<IPAddress> Usable(IEnumerable<IPAddress> addresses, ProxySettings settings)
    {
        var family = RequiredFamily(settings);
        return addresses.Select(address => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
            .Where(address => family is null || address.AddressFamily == family);
    }

    /// <summary>Connects to one destination address using the configured source address, if any.</summary>
    public static async Task<Socket> ConnectAsync(IPAddress address, int port, ProxySettings settings, CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (SourceAddress(settings) is { } source) socket.Bind(new IPEndPoint(source, 0));
            await socket.ConnectAsync(address, port, cancellationToken);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static void Validate(ProxySettings proxy)
    {
        proxy.EgressAddressFamily = string.IsNullOrWhiteSpace(proxy.EgressAddressFamily) ? "any" : proxy.EgressAddressFamily.Trim().ToLowerInvariant();
        if (!Families.Contains(proxy.EgressAddressFamily)) throw new InvalidOperationException("Egress address family must be any, ipv4 or ipv6");
        proxy.EgressSourceAddress = (proxy.EgressSourceAddress ?? "").Trim();
        if (proxy.EgressSourceAddress.Length == 0) return;
        if (!IPAddress.TryParse(proxy.EgressSourceAddress, out var source)) throw new InvalidOperationException("Egress source address must be an IP address of this server");
        if (proxy.EgressAddressFamily == "ipv4" && source.AddressFamily != AddressFamily.InterNetwork
            || proxy.EgressAddressFamily == "ipv6" && source.AddressFamily != AddressFamily.InterNetworkV6)
            throw new InvalidOperationException("The egress source address does not match the selected address family");
        proxy.EgressSourceAddress = source.ToString();
    }

    /// <summary>
    /// Asks an IP echo service which address the server's proxy traffic comes from, using the same family
    /// and source address as the proxy. The service may answer with JSON ({"ip": "..."}) or plain text.
    /// </summary>
    public static async Task<string> CheckAsync(string url, ProxySettings settings, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var target) || target.Scheme is not ("http" or "https")) throw new InvalidOperationException("Set an IP check URL in the browser settings first");
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (context, token) =>
            {
                var addresses = Usable(await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, token), settings).ToList();
                if (addresses.Count == 0) throw new HttpRequestException($"{context.DnsEndPoint.Host} has no address of the selected egress family");
                Exception? last = null;
                foreach (var address in addresses)
                {
                    try { return new NetworkStream(await ConnectAsync(address, context.DnsEndPoint.Port, settings, token), ownsSocket: true); }
                    catch (Exception error) when (error is SocketException or OperationCanceledException && !token.IsCancellationRequested) { last = error; }
                }
                throw new HttpRequestException($"Could not reach {context.DnsEndPoint.Host}", last);
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        var text = (await client.GetStringAsync(target, cancellationToken)).Trim();
        var ip = text;
        if (text.StartsWith('{'))
        {
            using var document = JsonDocument.Parse(text);
            ip = document.RootElement.TryGetProperty("ip", out var value) ? value.GetString() ?? "" : "";
        }
        if (!IPAddress.TryParse(ip, out var parsed)) throw new InvalidOperationException("The IP check service did not answer with an IP address");
        return parsed.ToString();
    }
}
