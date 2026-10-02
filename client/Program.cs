namespace SharedBrowser;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        var requestedProfile = args.FirstOrDefault(value => value.StartsWith("--profile=", StringComparison.OrdinalIgnoreCase))?[10..] ?? "default";
        var profile = new string(requestedProfile.Where(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_').Take(40).ToArray());
        if (string.IsNullOrWhiteSpace(profile)) profile = "default";
        Environment.SetEnvironmentVariable("SHARED_BROWSER_PROFILE", profile);
        var data = Path.Combine(AppContext.BaseDirectory, "browser-data", profile);
        Directory.CreateDirectory(data);
        var log = Path.Combine(data, "startup.log");
        void Write(string message) => File.AppendAllText(log, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
        try
        {
            ApplicationConfiguration.Initialize();
            Application.ThreadException += (_, args) => Write("UI exception: " + args.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, args) => Write("Unhandled exception: " + args.ExceptionObject);
            using var form = new MainForm();
            form.Shown += (_, _) => Write($"window shown: handle={form.Handle}, visible={form.Visible}");
            Application.Run(form);
        }
        catch (Exception error)
        {
            Write("Fatal startup exception: " + error);
            MessageBox.Show(error.ToString(), "Shared Browser startup failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
