using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// The TLS certificate the forward proxy presents to browsers. An operator can supply a PEM certificate
/// and key (SHARED_BROWSER_PROXY_TLS_CERT / SHARED_BROWSER_PROXY_TLS_KEY); otherwise a self-signed
/// certificate is generated once and kept in the data directory. Browsers do not rely on a public CA:
/// they pin the SHA-256 fingerprint the management server advertises over its authenticated API.
/// </summary>
public sealed class ProxyCertificate
{
    private static readonly TimeSpan ReloadCheckInterval = TimeSpan.FromSeconds(30);
    private readonly string? _certPath = Environment.GetEnvironmentVariable("SHARED_BROWSER_PROXY_TLS_CERT");
    private readonly string? _keyPath = Environment.GetEnvironmentVariable("SHARED_BROWSER_PROXY_TLS_KEY");
    private readonly string _generatedPath;
    private readonly string _password;
    private readonly ILogger<ProxyCertificate> _logger;
    private readonly object _lock = new();
    private X509Certificate2? _certificate;
    private DateTime _loadedWriteTime;
    private DateTimeOffset _lastCheck;

    public ProxyCertificate(DataDirectory data, ILogger<ProxyCertificate> logger)
    {
        _logger = logger;
        _generatedPath = Path.Combine(data.Path, "proxy-tls.pfx");
        // The generated private key is protected with a password derived from the vault key.
        _password = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("shared-browser-proxy-tls:" + Environment.GetEnvironmentVariable("SHARED_BROWSER_DATA_KEY"))));
        if (string.IsNullOrWhiteSpace(_certPath) != string.IsNullOrWhiteSpace(_keyPath))
            throw new InvalidOperationException("Set both SHARED_BROWSER_PROXY_TLS_CERT and SHARED_BROWSER_PROXY_TLS_KEY, or neither");
    }

    public bool OperatorSupplied => !string.IsNullOrWhiteSpace(_certPath);

    /// <summary>Returns the current certificate, reloading an operator certificate after it is renewed on disk.</summary>
    public X509Certificate2 Current
    {
        get
        {
            lock (_lock)
            {
                var now = DateTimeOffset.UtcNow;
                if (_certificate is not null && now - _lastCheck < ReloadCheckInterval) return _certificate;
                _lastCheck = now;
                var source = OperatorSupplied ? _certPath! : _generatedPath;
                var writeTime = File.Exists(source) ? File.GetLastWriteTimeUtc(source) : DateTime.MinValue;
                if (_certificate is not null && writeTime == _loadedWriteTime) return _certificate;
                _certificate = OperatorSupplied ? LoadOperatorCertificate() : LoadOrCreateGenerated();
                _loadedWriteTime = File.Exists(source) ? File.GetLastWriteTimeUtc(source) : DateTime.MinValue;
                _logger.LogInformation("Proxy TLS certificate {Subject} loaded, SHA-256 {Fingerprint}", _certificate.Subject, Fingerprint(_certificate));
                return _certificate;
            }
        }
    }

    public string CurrentFingerprint => Fingerprint(Current);

    public static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();

    private X509Certificate2 LoadOperatorCertificate()
    {
        using var pem = X509Certificate2.CreateFromPemFile(_certPath!, _keyPath!);
        // Re-import so the private key is usable by SslStream on every platform.
        return new X509Certificate2(pem.Export(X509ContentType.Pkcs12));
    }

    private X509Certificate2 LoadOrCreateGenerated()
    {
        if (File.Exists(_generatedPath))
        {
            try
            {
                var existing = new X509Certificate2(File.ReadAllBytes(_generatedPath), _password, X509KeyStorageFlags.Exportable);
                if (existing.NotAfter > DateTime.UtcNow.AddDays(30)) return existing;
                _logger.LogInformation("The generated proxy certificate expires soon and will be replaced");
            }
            catch (CryptographicException error) { _logger.LogWarning(error, "The generated proxy certificate could not be read and will be replaced"); }
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Shared Browser Proxy", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        var pfx = created.Export(X509ContentType.Pkcs12, _password);
        File.WriteAllBytes(_generatedPath + ".tmp", pfx);
        File.Move(_generatedPath + ".tmp", _generatedPath, true);
        return new X509Certificate2(pfx, _password, X509KeyStorageFlags.Exportable);
    }
}
