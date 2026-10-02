using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SharedBrowser;

public static class ConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    public static readonly string DataDirectory = Path.Combine(AppContext.BaseDirectory, "browser-data", Environment.GetEnvironmentVariable("SHARED_BROWSER_PROFILE") ?? "default");
    public static readonly string ProfileDirectory = Path.Combine(DataDirectory, "webview-profile");
    public static readonly string ConfigPath = Path.Combine(DataDirectory, "client-config.json");

    public static ClientConfig Load()
    {
        Directory.CreateDirectory(ProfileDirectory);
        if (!File.Exists(ConfigPath)) { var fresh = new ClientConfig(); Save(fresh); return fresh; }
        var config = JsonSerializer.Deserialize<ClientConfig>(File.ReadAllText(ConfigPath), JsonOptions) ?? new ClientConfig();
        config.NetworkMode = config.NetworkMode?.Equals("managed", StringComparison.OrdinalIgnoreCase) == true ? "managed" : "direct";
        config.Cache ??= new SharedSnapshot();
        config.Cache.Settings ??= new BrowserSettings();
        config.Cache.Settings.Proxy ??= new ProxySettings();
        config.DeviceToken = Unprotect(config.DeviceToken);
        config.EnrollmentToken = Unprotect(config.EnrollmentToken);
        foreach (var cookie in config.Cache.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Unprotect(cookie.Value);
        return config;
    }

    public static void Save(ClientConfig config)
    {
        Directory.CreateDirectory(DataDirectory);
        var disk = Clone(config);
        disk.DeviceToken = Protect(disk.DeviceToken);
        disk.EnrollmentToken = Protect(disk.EnrollmentToken);
        foreach (var cookie in disk.Cache.Profiles.SelectMany(profile => profile.Cookies)) cookie.Value = Protect(cookie.Value);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(disk, JsonOptions));
    }

    public static ClientConfig Clone(ClientConfig input) => new()
    {
        ServerUrl = input.ServerUrl,
        DeviceId = input.DeviceId,
        DeviceName = input.DeviceName,
        DeviceToken = input.DeviceToken,
        EnrollmentToken = input.EnrollmentToken,
        NetworkMode = input.NetworkMode,
        Cache = new SharedSnapshot
        {
            Revision = input.Cache.Revision,
            UpdatedAt = input.Cache.UpdatedAt,
            Settings = new BrowserSettings
            {
                HomePage = input.Cache.Settings.HomePage,
                PrimaryDeviceId = input.Cache.Settings.PrimaryDeviceId,
                AutoShareCookies = input.Cache.Settings.AutoShareCookies,
                Proxy = new ProxySettings { Enabled = input.Cache.Settings.Proxy.Enabled, Host = input.Cache.Settings.Proxy.Host, Port = input.Cache.Settings.Proxy.Port, AllowedPorts = input.Cache.Settings.Proxy.AllowedPorts, BypassList = input.Cache.Settings.Proxy.BypassList }
            },
            Profiles = input.Cache.Profiles.Select(profile => new SessionProfile
            {
                Id = profile.Id, Name = profile.Name, Domain = profile.Domain, Enabled = profile.Enabled,
                Cookies = profile.Cookies.Select(cookie => new SharedCookie { Name = cookie.Name, Value = cookie.Value, Domain = cookie.Domain, Path = cookie.Path, Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, SameSite = cookie.SameSite, UpdatedAt = cookie.UpdatedAt, SourceDeviceId = cookie.SourceDeviceId }).ToList()
            }).ToList(),
            Bookmarks = input.Cache.Bookmarks.Select(item => new SharedBookmark { Title = item.Title, Url = item.Url }).ToList()
        }
    };

    private static string Protect(string value) => string.IsNullOrEmpty(value) || value.StartsWith("dpapi:", StringComparison.Ordinal) ? value : "dpapi:" + Convert.ToBase64String(Dpapi.Protect(Encoding.UTF8.GetBytes(value)));
    private static string Unprotect(string value)
    {
        if (!value.StartsWith("dpapi:", StringComparison.Ordinal)) return value;
        try { return Encoding.UTF8.GetString(Dpapi.Unprotect(Convert.FromBase64String(value[6..]))); } catch { return ""; }
    }
}

internal static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    public static byte[] Protect(byte[] input) => Transform(input, true);
    public static byte[] Unprotect(byte[] input) => Transform(input, false);
    private static byte[] Transform(byte[] input, bool protect)
    {
        var pointer = Marshal.AllocHGlobal(input.Length);
        try
        {
            Marshal.Copy(input, 0, pointer, input.Length);
            var source = new DataBlob { Length = input.Length, Data = pointer }; var result = new DataBlob();
            var ok = protect ? CryptProtectData(ref source, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, ref result) : CryptUnprotectData(ref source, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, ref result);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try { var output = new byte[result.Length]; Marshal.Copy(result.Data, output, 0, result.Length); return output; }
            finally { LocalFree(result.Data); }
        }
        finally { Marshal.Copy(new byte[input.Length], 0, pointer, input.Length); Marshal.FreeHGlobal(pointer); }
    }
}
