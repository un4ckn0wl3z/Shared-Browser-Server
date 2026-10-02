namespace SharedBrowser;

public sealed class ServerSettingsForm : Form
{
    private readonly TextBox _server = new();
    private readonly TextBox _name = new();
    private readonly TextBox _enrollment = new() { UseSystemPasswordChar = true };
    private readonly Label _device = new() { AutoSize = true };
    public ClientConfig Result { get; private set; }

    public ServerSettingsForm(ClientConfig config)
    {
        Result = ConfigStore.Clone(config);
        Text = "Browser management server";
        Width = 540; Height = 365; StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        _server.Text = Result.ServerUrl;
        _name.Text = Result.DeviceName;
        _device.Text = string.IsNullOrEmpty(Result.DeviceToken) ? "Not enrolled" : $"Enrolled device: {Result.DeviceId[..12]}…";

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 2, RowCount = 6 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Add(layout, 0, "Server URL", _server);
        Add(layout, 1, "Device name", _name);
        Add(layout, 2, "Enrollment token", _enrollment);
        layout.Controls.Add(new Label { Text = "Enter the server administrator token once when enrolling or re-enrolling this browser.", AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(450, 0) }, 0, 3); layout.SetColumnSpan(layout.GetControlFromPosition(0, 3), 2);
        layout.Controls.Add(_device, 0, 4); layout.SetColumnSpan(_device, 2);
        layout.Controls.Add(new Label { Text = "No proxy is configured. All synchronization uses the server API; web traffic connects normally.", AutoSize = true, ForeColor = Color.SeaGreen, MaximumSize = new Size(450, 0) }, 0, 5); layout.SetColumnSpan(layout.GetControlFromPosition(0, 5), 2);

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
        var serverChanged = !string.Equals(Result.ServerUrl.TrimEnd('/'), uri.AbsoluteUri.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
        Result.ServerUrl = uri.AbsoluteUri.TrimEnd('/'); Result.DeviceName = _name.Text.Trim();
        if (!string.IsNullOrWhiteSpace(_enrollment.Text) || serverChanged)
        {
            Result.DeviceToken = "";
            Result.EnrollmentToken = _enrollment.Text;
            Result.Cache = new SharedSnapshot();
        }
        DialogResult = DialogResult.OK; Close();
    }
}
