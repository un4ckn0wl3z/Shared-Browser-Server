namespace SharedBrowser;

public sealed class ServerSettingsForm : Form
{
    private readonly TextBox _server = new();
    private readonly TextBox _name = new();
    private readonly TextBox _enrollment = new() { UseSystemPasswordChar = true };
    private readonly ComboBox _networkMode = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly CheckBox _strictPrivacy = new() { Text = "Strict privacy — require proxy, block direct WebRTC and deny website permissions", AutoSize = true };
    private readonly Label _device = new() { AutoSize = true };
    public ClientConfig Result { get; private set; }

    public ServerSettingsForm(ClientConfig config)
    {
        Result = ConfigStore.Clone(config);
        Text = "Browser management server";
        Width = 610; Height = 500; StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        _server.Text = Result.ServerUrl;
        _name.Text = Result.DeviceName;
        _networkMode.Items.AddRange(["Direct connection — use client IP", "Managed proxy — use server IP"]);
        _networkMode.SelectedIndex = Result.NetworkMode.Equals("managed", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        _strictPrivacy.Checked = Result.StrictPrivacy;
        _strictPrivacy.CheckedChanged += (_, _) => { if (_strictPrivacy.Checked) _networkMode.SelectedIndex = 1; };
        _device.Text = string.IsNullOrEmpty(Result.DeviceToken) ? "Not enrolled" : $"Enrolled device: {Result.DeviceId[..12]}…";

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 2, RowCount = 8 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Add(layout, 0, "Server URL", _server);
        Add(layout, 1, "Device name", _name);
        Add(layout, 2, "Enrollment token", _enrollment);
        Add(layout, 3, "Website connection", _networkMode);
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54)); layout.Controls.Add(_strictPrivacy, 0, 4); layout.SetColumnSpan(_strictPrivacy, 2);
        layout.Controls.Add(new Label { Text = "Strict privacy reduces IP leaks but does not hide signed-in accounts, shared cookies, or browser fingerprints.", AutoSize = true, ForeColor = Color.DarkOrange, MaximumSize = new Size(540, 0) }, 0, 5); layout.SetColumnSpan(layout.GetControlFromPosition(0, 5), 2);
        layout.Controls.Add(_device, 0, 6); layout.SetColumnSpan(_device, 2);
        var proxy = Result.Cache.Settings.Proxy;
        var proxyText = proxy.Enabled ? $"Managed proxy available at {proxy.Host}:{proxy.Port}. Proxy mode requires a browser restart." : "Managed proxy is disabled on the server. Direct mode uses this computer's IP.";
        layout.Controls.Add(new Label { Text = proxyText, AutoSize = true, ForeColor = proxy.Enabled ? Color.SeaGreen : Color.DarkOrange, MaximumSize = new Size(540, 0) }, 0, 7); layout.SetColumnSpan(layout.GetControlFromPosition(0, 7), 2);

        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 55, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(10) };
        var save = new Button { Text = "Save and reconnect", Width = 135 }; var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        save.Click += (_, _) => Save(); footer.Controls.AddRange([save, cancel]);
        Controls.Add(layout); Controls.Add(footer); AcceptButton = save; CancelButton = cancel;
    }

    private static void Add(TableLayoutPanel layout, int row, string text, Control control)
    {
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        layout.Controls.Add(new Label { Text = text, Anchor = AnchorStyles.Left, AutoSize = true }, 0, row);
        control.Dock = DockStyle.Fill; layout.Controls.Add(control, 1, row);
    }

    private void Save()
    {
        if (!Uri.TryCreate(_server.Text.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) { MessageBox.Show(this, "Enter a valid HTTP or HTTPS server URL."); return; }
        if (string.IsNullOrWhiteSpace(_name.Text)) { MessageBox.Show(this, "Enter a device name."); return; }
        if (_strictPrivacy.Checked && _networkMode.SelectedIndex != 1) { MessageBox.Show(this, "Strict privacy requires Managed proxy mode."); return; }
        if (_strictPrivacy.Checked && !Result.Cache.Settings.Proxy.Enabled) { MessageBox.Show(this, "Enable the managed proxy in the server dashboard before turning on Strict privacy."); return; }
        var serverChanged = !string.Equals(Result.ServerUrl.TrimEnd('/'), uri.AbsoluteUri.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
        Result.ServerUrl = uri.AbsoluteUri.TrimEnd('/'); Result.DeviceName = _name.Text.Trim(); Result.NetworkMode = _networkMode.SelectedIndex == 1 ? "managed" : "direct"; Result.StrictPrivacy = _strictPrivacy.Checked;
        if (!string.IsNullOrWhiteSpace(_enrollment.Text) || serverChanged)
        {
            Result.DeviceToken = "";
            Result.EnrollmentToken = _enrollment.Text;
            Result.Cache = new SharedSnapshot();
        }
        DialogResult = DialogResult.OK; Close();
    }
}
