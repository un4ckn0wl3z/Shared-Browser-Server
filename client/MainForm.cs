using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace SharedBrowser;

public sealed class MainForm : Form
{
    private ClientConfig _config = ConfigStore.Load();
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly SemaphoreSlim _syncGate = new(1, 1);
    private CoreWebView2Environment? _environment;
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly TextBox _address = new() { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 10) };
    private readonly ToolStripButton _back = new("←"), _forward = new("→"), _reload = new("↻"), _newTab = new("+"), _syncNow = new("Sync now"), _serverSettings = new("Server settings");
    private readonly ToolStripLabel _syncStatus = new("Offline cache");
    private readonly HashSet<string> _prepared = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 2500 };

    public MainForm()
    {
        Text = "Shared Browser"; Width = 1280; Height = 820; MinimumSize = new Size(850, 560); StartPosition = FormStartPosition.CenterScreen;
        var toolbar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(6), RenderMode = ToolStripRenderMode.System };
        toolbar.Items.AddRange([_back, _forward, _reload, _newTab, new ToolStripSeparator()]);
        toolbar.Items.Add(new ToolStripControlHost(_address) { AutoSize = false, Width = 620, Margin = new Padding(4, 0, 4, 0) });
        var go = new ToolStripButton("Go"); toolbar.Items.AddRange([go, new ToolStripSeparator(), _syncNow, _serverSettings, new ToolStripSeparator(), _syncStatus]);
        Controls.Add(_tabs); Controls.Add(toolbar); toolbar.Dock = DockStyle.Top;

        _back.Click += (_, _) => Current()?.GoBack(); _forward.Click += (_, _) => Current()?.GoForward(); _reload.Click += (_, _) => Current()?.Reload();
        _newTab.Click += async (_, _) => await NewTabAsync(_config.Cache.Settings.HomePage); go.Click += async (_, _) => await NavigateCurrentAsync(_address.Text);
        _address.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await NavigateCurrentAsync(_address.Text); } };
        _tabs.SelectedIndexChanged += (_, _) => UpdateToolbar(); _syncNow.Click += async (_, _) => await PullSnapshotAsync(true); _serverSettings.Click += (_, _) => OpenServerSettings();
        _timer.Tick += async (_, _) => await PullSnapshotAsync(false); FormClosing += (_, _) => ConfigStore.Save(_config);
        Shown += async (_, _) => await InitializeAsync();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        BeginInvoke(() => { ShowInTaskbar = true; WindowState = FormWindowState.Normal; Show(); BringToFront(); Activate(); });
    }

    private async Task InitializeAsync()
    {
        try
        {
            await EnsureEnrolledAsync();
            await PullSnapshotAsync(false);
        }
        catch (Exception error) { SetStatus("Offline cache", true); MessageBox.Show(this, error.Message + "\n\nThe browser will open using its last synchronized cache.", "Server unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning); }

        try
        {
            var options = new CoreWebView2EnvironmentOptions();
            if (_config.NetworkMode.Equals("managed", StringComparison.OrdinalIgnoreCase))
            {
                var proxy = _config.Cache.Settings.Proxy;
                if (!proxy.Enabled) throw new InvalidOperationException("Managed proxy mode is selected, but the proxy is disabled on the management server. Choose Direct mode or enable the proxy in the dashboard.");
                options.AdditionalBrowserArguments = $"--proxy-server=http://{proxy.Host}:{proxy.Port} --proxy-bypass-list=\"{proxy.BypassList}\"";
            }
            _environment = await CoreWebView2Environment.CreateAsync(null, ConfigStore.ProfileDirectory, options);
            await NewTabAsync(_config.Cache.Settings.HomePage);
            await PushAllStoredCookiesAsync(Current());
            _timer.Start();
        }
        catch (Exception error) { MessageBox.Show(this, error.ToString(), "Browser startup failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private async Task EnsureEnrolledAsync()
    {
        if (!string.IsNullOrEmpty(_config.DeviceToken)) return;
        if (string.IsNullOrWhiteSpace(_config.EnrollmentToken)) throw new InvalidOperationException("This browser is not enrolled. Open Server settings and enter the management server administrator token.");
        using var request = new HttpRequestMessage(HttpMethod.Post, Url("/api/client/enroll"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config.EnrollmentToken);
        request.Content = JsonContent.Create(new EnrollRequest(_config.DeviceId, _config.DeviceName));
        using var response = await _http.SendAsync(request);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Enrollment failed ({(int)response.StatusCode})");
        var enrolled = await response.Content.ReadFromJsonAsync<EnrollResponse>() ?? throw new InvalidOperationException("Enrollment returned no device token");
        _config.DeviceId = enrolled.DeviceId; _config.DeviceToken = enrolled.DeviceToken; _config.EnrollmentToken = ""; ConfigStore.Save(_config);
    }

    private async Task PullSnapshotAsync(bool notify)
    {
        if (string.IsNullOrEmpty(_config.DeviceToken) || !await _syncGate.WaitAsync(0)) return;
        WebView2? reload = null;
        try
        {
            using var request = DeviceRequest(HttpMethod.Get, $"/api/client/snapshot?deviceName={Uri.EscapeDataString(_config.DeviceName)}");
            using var response = await _http.SendAsync(request);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException(response.StatusCode == System.Net.HttpStatusCode.Unauthorized ? "This browser is not authorized or was revoked" : $"Server returned {(int)response.StatusCode}");
            var snapshot = await response.Content.ReadFromJsonAsync<SharedSnapshot>() ?? throw new InvalidOperationException("Invalid server snapshot");
            if (snapshot.Revision != _config.Cache.Revision)
            {
                _config.Cache = snapshot; ConfigStore.Save(_config); _prepared.Clear();
                var web = Current();
                if (web?.CoreWebView2 is not null)
                {
                    await ApplyAllCookiesAsync(web);
                    if (!IsPrimaryBrowser() && web.Source is not null && FindProfile(web.Source.Host)?.Cookies.Count > 0) reload = web;
                }
            }
            SetStatus($"Synced r{snapshot.Revision}", false); if (notify) ShowTransient("Synchronization complete");
        }
        catch (Exception error) { SetStatus("Offline cache", true); if (notify) MessageBox.Show(this, error.Message, "Sync failed", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        finally { _syncGate.Release(); }
        reload?.Reload();
    }

    private async Task NewTabAsync(string? url)
    {
        if (_environment is null) return;
        var page = new TabPage("New tab"); var web = new WebView2 { Dock = DockStyle.Fill }; page.Controls.Add(web); _tabs.TabPages.Add(page); _tabs.SelectedTab = page;
        await web.EnsureCoreWebView2Async(_environment);
        web.CoreWebView2.Settings.IsStatusBarEnabled = false;
        web.CoreWebView2.BasicAuthenticationRequested += (_, args) =>
        {
            if (!_config.NetworkMode.Equals("managed", StringComparison.OrdinalIgnoreCase) || !args.Challenge.Contains("Shared Browser Proxy", StringComparison.OrdinalIgnoreCase)) return;
            args.Response.UserName = _config.DeviceId;
            args.Response.Password = _config.DeviceToken;
        };
        web.CoreWebView2.NavigationStarting += async (_, args) => await PrepareNavigationAsync(web, args);
        web.CoreWebView2.NavigationCompleted += async (_, _) => { UpdateToolbar(); await PushCurrentDomainAsync(web); };
        web.CoreWebView2.SourceChanged += (_, _) => { if (Current() == web) _address.Text = DisplayAddress(web.Source); };
        web.CoreWebView2.DocumentTitleChanged += (_, _) => page.Text = ShortTitle(web.CoreWebView2.DocumentTitle);
        await ApplyAllCookiesAsync(web);
        await NavigateAsync(web, url ?? "");
    }

    private async Task PrepareNavigationAsync(WebView2 web, CoreWebView2NavigationStartingEventArgs args)
    {
        if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return;
        var profile = FindProfile(uri.Host); if (profile is null) return;
        var key = $"{_config.Cache.Revision}:{profile.Id}"; if (_prepared.Contains(key)) return;
        args.Cancel = true; await ApplyProfileAsync(web, profile); _prepared.Add(key); web.CoreWebView2.Navigate(args.Uri);
    }

    private async Task ApplyAllCookiesAsync(WebView2 web)
    {
        foreach (var profile in _config.Cache.Profiles.Where(item => item.Enabled)) await ApplyProfileAsync(web, profile);
    }

    private static async Task ApplyProfileAsync(WebView2 web, SessionProfile profile)
    {
        foreach (var item in profile.Cookies)
        {
            var cookie = web.CoreWebView2.CookieManager.CreateCookie(item.Name, item.Value, item.Domain, item.Path);
            cookie.IsHttpOnly = item.HttpOnly; cookie.IsSecure = item.Secure;
            cookie.SameSite = item.SameSite switch { "Strict" => CoreWebView2CookieSameSiteKind.Strict, "None" => CoreWebView2CookieSameSiteKind.None, _ => CoreWebView2CookieSameSiteKind.Lax };
            web.CoreWebView2.CookieManager.AddOrUpdateCookie(cookie);
        }
        await Task.CompletedTask;
    }

    private async Task PushCurrentDomainAsync(WebView2 web)
    {
        if (!IsPrimaryBrowser() || string.IsNullOrEmpty(_config.DeviceToken) || web.Source is null || web.Source.Scheme is not ("http" or "https")) return;
        var profile = FindProfile(web.Source.Host);
        if (profile is null && !_config.Cache.Settings.AutoShareCookies) return;
        if (!await _syncGate.WaitAsync(0)) return;
        try
        {
            var found = await web.CoreWebView2.CookieManager.GetCookiesAsync(web.Source.AbsoluteUri);
            var cookies = found.Where(cookie => DomainMatches(web.Source.Host, cookie.Domain)).Take(200).Select(cookie => new SharedCookie
            {
                Name = cookie.Name, Value = cookie.Value, Domain = cookie.Domain.TrimStart('.'), Path = cookie.Path, Secure = cookie.IsSecure, HttpOnly = cookie.IsHttpOnly, SameSite = cookie.SameSite.ToString()
            }).ToList();
            await PushCookiesLockedAsync(web.Source.AbsoluteUri, cookies);
            SetStatus($"Synced r{_config.Cache.Revision}", false);
        }
        catch (Exception error) { LogSyncError(error); SetStatus("Offline cache", true); }
        finally { _syncGate.Release(); }
    }

    private async Task PushAllStoredCookiesAsync(WebView2? web)
    {
        if (web?.CoreWebView2 is null || !IsPrimaryBrowser() || string.IsNullOrEmpty(_config.DeviceToken) || !await _syncGate.WaitAsync(0)) return;
        try
        {
            var all = await web.CoreWebView2.CookieManager.GetCookiesAsync(string.Empty);
            foreach (var group in all.Where(cookie => !string.IsNullOrWhiteSpace(cookie.Domain)).GroupBy(cookie => cookie.Domain.Trim().TrimStart('.').ToLowerInvariant()).Take(500))
            {
                if (group.Key.Length == 0) continue;
                var cookies = group.Take(200).Select(cookie => new SharedCookie
                {
                    Name = cookie.Name, Value = cookie.Value, Domain = cookie.Domain.TrimStart('.'), Path = cookie.Path, Secure = cookie.IsSecure, HttpOnly = cookie.IsHttpOnly, SameSite = cookie.SameSite.ToString()
                }).ToList();
                await PushCookiesLockedAsync($"https://{group.Key}/", cookies);
            }
            SetStatus($"Synced r{_config.Cache.Revision}", false);
        }
        catch (Exception error) { LogSyncError(error); SetStatus("Offline cache", true); }
        finally { _syncGate.Release(); }
    }

    private async Task PushCookiesLockedAsync(string pageUrl, List<SharedCookie> cookies)
    {
        using var request = DeviceRequest(HttpMethod.Post, "/api/client/sync");
        request.Content = JsonContent.Create(new SyncRequest(_config.Cache.Revision, pageUrl, cookies));
        using var response = await _http.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            var detail = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Sync push failed ({(int)response.StatusCode}): {detail}");
        }
        var result = await response.Content.ReadFromJsonAsync<SyncResponse>();
        if (result is not null && result.Revision != _config.Cache.Revision)
        {
            _config.Cache = result.Snapshot;
            ConfigStore.Save(_config);
            _prepared.Clear();
        }
    }

    private HttpRequestMessage DeviceRequest(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, Url(path)); request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config.DeviceToken); request.Headers.Add("X-Device-Id", _config.DeviceId); return request;
    }

    private string Url(string path) => _config.ServerUrl.TrimEnd('/') + path;
    private bool IsPrimaryBrowser() =>
        (_config.Cache.Settings.AutoShareCookies && string.IsNullOrWhiteSpace(_config.Cache.Settings.PrimaryDeviceId)) ||
        string.Equals(_config.Cache.Settings.PrimaryDeviceId, _config.DeviceId, StringComparison.OrdinalIgnoreCase);
    private SessionProfile? FindProfile(string host) => _config.Cache.Profiles.Where(profile => profile.Enabled && DomainMatches(host, profile.Domain)).OrderByDescending(profile => profile.Domain.Length).FirstOrDefault();
    private static bool DomainMatches(string host, string domain) { host = host.Trim('.').ToLowerInvariant(); domain = domain.Trim('.').ToLowerInvariant(); return host == domain || host.EndsWith('.' + domain, StringComparison.Ordinal); }

    private void OpenServerSettings()
    {
        using var form = new ServerSettingsForm(_config); if (form.ShowDialog(this) != DialogResult.OK) return;
        _config = form.Result; ConfigStore.Save(_config); _timer.Stop();
        MessageBox.Show(this, "Server settings saved. Restart Shared Browser to reconnect with the new identity or server.", "Restart required", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private async Task NavigateCurrentAsync(string value) { var web = Current(); if (web is not null) await NavigateAsync(web, value); }
    private static async Task NavigateAsync(WebView2 web, string value)
    {
        var url = value.Trim();
        if (string.IsNullOrWhiteSpace(url) || url.Equals("about:blank", StringComparison.OrdinalIgnoreCase)) { web.CoreWebView2.Navigate("about:blank"); return; }
        if (!url.Contains("://", StringComparison.Ordinal)) url = "https://" + url;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) { MessageBox.Show("Enter a valid HTTP or HTTPS address."); return; }
        web.CoreWebView2.Navigate(uri.AbsoluteUri); await Task.CompletedTask;
    }
    private WebView2? Current() => _tabs.SelectedTab?.Controls.OfType<WebView2>().FirstOrDefault();
    private void UpdateToolbar() { var web = Current(); _back.Enabled = web?.CanGoBack == true; _forward.Enabled = web?.CanGoForward == true; _address.Text = DisplayAddress(web?.Source); }
    private static string DisplayAddress(Uri? source) => source?.AbsoluteUri == "about:blank" ? "" : source?.ToString() ?? "";
    private void SetStatus(string text, bool error) { _syncStatus.Text = $"{text} • {(_config.NetworkMode.Equals("managed", StringComparison.OrdinalIgnoreCase) ? "Server IP" : "Client IP")}"; _syncStatus.ForeColor = error ? Color.Firebrick : Color.SeaGreen; }
    private static void LogSyncError(Exception error)
    {
        try { File.AppendAllText(Path.Combine(ConfigStore.DataDirectory, "sync-errors.log"), $"{DateTimeOffset.Now:O} {error.Message}{Environment.NewLine}"); } catch { }
    }
    private void ShowTransient(string text) { var old = Text; Text = $"Shared Browser — {text}"; var timer = new System.Windows.Forms.Timer { Interval = 1800 }; timer.Tick += (_, _) => { Text = old; timer.Stop(); timer.Dispose(); }; timer.Start(); }
    private static string ShortTitle(string title) => string.IsNullOrWhiteSpace(title) ? "New tab" : title.Length > 24 ? title[..24] + "…" : title;
}
