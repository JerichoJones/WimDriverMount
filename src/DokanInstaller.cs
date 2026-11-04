using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class DokanInstaller
{
    // Installer success alone does not prove that this run owns the product.
    internal readonly record struct CheckResult(bool Ready, bool InstallerReportedSuccess);
    // The newest official release; its signature, publisher and version are
    // checked (DokanPackage) before it is run.
    internal static string DefaultInstallerUrl => DokanPackage.LatestUrl;
    // A bundled MSI enables the same setup on an isolated computer, with the same checks.
    internal static string DefaultInstallerSource => DokanSourceSelection.Default(AppContext.BaseDirectory, DefaultInstallerUrl, File.Exists);
    private const long MaxInstallerBytes = 32 * 1024 * 1024;

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetGetConnectionW(string localName, StringBuilder remoteName, ref int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    // Source validation lives in DokanSource, so the option parser can use it
    // without pulling in downloading, elevation and the MSI checks.
    internal static string ValidateUrl(string value) => DokanSource.ValidateUrl(value);

    private static FileStream OpenInstallerFile(string path)
    {
        FileStream file = new(path, FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
        if (GetFileType(file.SafeFileHandle) != 1)
        {
            file.Dispose();
            throw new IOException("Dokan source is not a disk file.");
        }
        return file;
    }

    // Also used for --wim paths: elevated processes often lack the caller's mapped drives.
    internal static string ResolveMappedSource(string path)
    {
        if (path.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return path;
        string root = Path.GetPathRoot(path) ?? throw new ArgumentException("Dokan file path has no root.");
        // Elevated processes often lack the caller's mapped drive letters.
        // Convert a mapped drive to its UNC share before requesting elevation.
        if (root.Length == 3 && root[1] == ':' && new DriveInfo(root).DriveType == DriveType.Network)
        {
            int length = 32768;
            var remote = new StringBuilder(length);
            int error = WNetGetConnectionW(root[..2], remote, ref length);
            if (error != 0) throw new IOException($"Cannot resolve the mapped drive {root[..2]} to a network path (error {error}).");
            path = Path.GetFullPath(remote.ToString().TrimEnd('\\') + path[2..]);
            DokanSource.ValidateFileComponents(path, Path.GetPathRoot(path) ?? throw new ArgumentException("Mapped path has no root."));
        }
        return path;
    }

    internal static bool ProbeDownload(string installerUrl)
    {
        installerUrl = ResolveMappedSource(ValidateUrl(installerUrl));
        if (!installerUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var file = OpenInstallerFile(installerUrl);
                Console.WriteLine($"WHATIF: Dokan MSI opened using the current process identity: {SafeText.Path(installerUrl)}. Its signature, and access with administrator rights, were not checked.");
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"WHATIF: Dokan MSI cannot be opened: {SafeText.Message(ex.Message)}");
                return false;
            }
        }
        Console.WriteLine($"WHATIF: Checking installer access using the current process identity (HEAD): {SafeText.Path(installerUrl)}");
        try
        {
            using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Head, ValidateUrl(installerUrl));
            using var response = client.Send(request);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"WHATIF: Installer access failed: HTTP {(int)response.StatusCode} {SafeText.Quote(response.ReasonPhrase)}.");
                return false;
            }
            Console.WriteLine($"WHATIF: Installer request returned HTTP {(int)response.StatusCode}; this does not verify the installer download or elevated-process network access. No installer was downloaded or checked.");
            return true;
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or TaskCanceledException or IOException)
        {
            Console.Error.WriteLine($"WHATIF: Could not verify installer access: {SafeText.Message(ex.Message)}");
            return false;
        }
    }

    // Whether Windows still has Dokan's driver service, stopping and never finishing: what an
    // uninstall leaves until the restart. False when Windows cannot say, so setup goes ahead as before.
    private static bool RemovedPendingRestart()
    {
        IntPtr manager = OpenSCManagerW(null, null, 0x0001 /* SC_MANAGER_CONNECT */);
        if (manager == IntPtr.Zero) return false;
        try
        {
            IntPtr service = OpenServiceW(manager, "dokan2", 0x0004 /* SERVICE_QUERY_STATUS */);
            if (service == IntPtr.Zero) return false;
            try { return QueryServiceStatus(service, out ServiceStatus status) && status.CurrentState == 3 /* SERVICE_STOP_PENDING */; }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    internal static CheckResult EnsureInstalled(bool whatIf = false, bool noInstall = false, string? installerUrl = null,
        Action<DokanSetupRestart>? reportRestart = null)
    {
        installerUrl ??= DefaultInstallerUrl;
        installerUrl = ValidateUrl(installerUrl);
        string system = Environment.SystemDirectory;
        string driver = Path.Combine(system, "drivers", "dokan2.sys");
        string library = Path.Combine(system, "dokan2.dll");
        if (File.Exists(driver) || File.Exists(library))
        {
            if (!File.Exists(driver) || !File.Exists(library))
                throw new InvalidOperationException("Dokan is only partly installed (its driver or its library is missing). Uninstall Dokan in Settings > Apps, then run this again.");
            var driverVersion = FileVersionInfo.GetVersionInfo(driver);
            var libraryVersion = FileVersionInfo.GetVersionInfo(library);
            if (driverVersion.FileMajorPart != 2 || driverVersion.FileMinorPart < 3 ||
                libraryVersion.FileMajorPart != 2 || libraryVersion.FileMinorPart < 3)
                throw new InvalidOperationException($"Dokan {driverVersion.FileMajorPart}.{driverVersion.FileMinorPart} is installed, but this needs Dokan 2.3 or later. Uninstall Dokan in Settings > Apps, then run this again.");
            if (whatIf) Console.WriteLine("WHATIF: Dokan 2.3 or later files are present; no installation planned. Runtime compatibility is not verified.");
            return new CheckResult(true, false);
        }
        // After Dokan has mounted a drive, an uninstall deletes its files but its driver stays
        // loaded, stuck stopping, until Windows restarts, and installing it again meanwhile fails
        // (Windows Installer error 1603; measured with Dokan 2.3.0). Say what is wrong instead.
        // After --no-install-dokan: that refusal holds whatever a restart does.
        const string RemovedNeedsRestart = "Dokan was removed earlier and its driver is still loaded, usually until Windows restarts, so it cannot be installed again yet. Restart Windows, then run this again.";

        if (whatIf)
        {
            if (noInstall) throw new InvalidOperationException("WHATIF: Dokan is not installed, and --no-install-dokan says not to install it, so the mount could not go ahead.");
            if (RemovedPendingRestart()) throw new InvalidOperationException("WHATIF: " + RemovedNeedsRestart);
            Console.WriteLine($"WHATIF: Would obtain {SafeText.Path(installerUrl)}, check that it is a Dokan release signed by LEOSAC" +
                (string.Equals(installerUrl, DokanPackage.TestedUrl, StringComparison.OrdinalIgnoreCase) ? " with the tested release's exact SHA-256" : "") +
                ", and install Dokan. Administrator approval may be required.");
            return new CheckResult(ProbeDownload(installerUrl), false);
        }
        if (noInstall) throw new InvalidOperationException("Dokan is not installed, and --no-install-dokan says not to install it. Install Dokan 2.3 or later, or leave out --no-install-dokan.");
        if (RemovedPendingRestart()) throw new InvalidOperationException(RemovedNeedsRestart);
        installerUrl = ResolveMappedSource(installerUrl);
        bool direct = Program.IsAdministrator();
        int exitCode = direct ? InstallElevated(installerUrl, reportRestart) : StartElevatedSetup(installerUrl);
        DokanSetupRestartException.Check(exitCode, direct ? null : reportRestart);
        if (exitCode != 0)
            throw new InvalidOperationException($"Dokan could not be installed (Windows Installer error {exitCode}). Install Dokan 2.3 or later yourself, then run this again.");
        if (!File.Exists(driver) || !File.Exists(library))
            throw new InvalidOperationException("Dokan's installer reported success, but Dokan's driver or library is missing. Restart Windows and run this again; if it repeats, reinstall Dokan.");
        return new CheckResult(true, true);
    }

    private static int StartElevatedSetup(string installerUrl)
    {
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the application executable.");
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Run the WIM Driver Mount executable to enable automatic Dokan setup.");
        Console.WriteLine("Dokan setup requires administrator rights. Requesting elevation...");
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        start.ArgumentList.Add("--internal-dokan-setup");
        start.ArgumentList.Add("--get-dokan");
        start.ArgumentList.Add(installerUrl);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start elevated Dokan setup.");
        process.WaitForExit();
        return process.ExitCode;
    }

    // A new folder under System32 that only Administrators and SYSTEM can open, made with
    // those permissions in one step and checked to be a real folder, not a link. An
    // elevated process may create and delete files in it by path: nobody else can put a
    // link there. `what` names it in messages, such as "The folder used to ...".
    internal static string CreateStagingFolder(string prefix, string what)
    {
        string directory = Path.Combine(Environment.SystemDirectory, prefix + Guid.NewGuid().ToString("N"));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        var staging = new DirectoryInfo(directory);
        if (staging.Exists) throw new IOException($"{what} already exists: {SafeText.Path(directory)}. Delete it, then run this again.");
        staging.Create(security);
        try
        {
            // Exists can cache the pre-creation state on this DirectoryInfo instance.
            staging.Refresh();
            if (!staging.Exists) throw new IOException("It was not there after it was created.");
            if ((staging.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("It is a link (a symbolic link or junction).");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Do not recursively delete a path whose identity has not been verified.
            // One message, not wrapped: the reason is short and the inner one would only repeat it.
            string reason = ex is UnauthorizedAccessException ? "Access to it was denied." : SafeText.Message(ex.Message);
            throw new IOException($"{what} could not be checked, so it was not used: {SafeText.Path(directory)}. {reason} Delete the folder, then run this again.");
        }
        return directory;
    }

    internal static int InstallElevated(string? installerUrl = null, Action<DokanSetupRestart>? reportRestart = null)
    {
        installerUrl ??= DefaultInstallerUrl;
        if (!Program.IsAdministrator()) throw new InvalidOperationException("Dokan setup requires administrator rights.");
        installerUrl = ResolveMappedSource(ValidateUrl(installerUrl));
        string directory = CreateStagingFolder("WimDrive-", "The folder used to prepare Dokan's installer");
        string installer = Path.Combine(directory, DokanPackage.MsiName);
        try
        {
            Console.WriteLine($"Dokan is missing. Reading the installer from {SafeText.Path(installerUrl)}...");
            using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            using var response = installerUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? client.GetAsync(installerUrl, System.Net.Http.HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult() : null;
            response?.EnsureSuccessStatusCode();
            if (response?.Content.Headers.ContentLength is long length && length > MaxInstallerBytes)
                throw new InvalidOperationException("The Dokan installer is unexpectedly large.");
            using (var input = response is null
                ? OpenInstallerFile(installerUrl)
                : response.Content.ReadAsStream())
            using (var output = new FileStream(installer, FileMode.CreateNew, System.IO.FileAccess.Write, FileShare.None))
            {
                byte[] buffer = new byte[65536];
                long total = 0;
                int count;
                while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                {
                    total += count;
                    if (total > MaxInstallerBytes) throw new InvalidOperationException("The Dokan download is unexpectedly large.");
                    output.Write(buffer, 0, count);
                }
                output.Flush(true);
            }
            // Allow MSI to open the verified file for reading, while denying writes and deletion.
            using var file = new FileStream(installer, FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
            DokanPackage.RequirePinned(installerUrl, file);
            // Windows must accept the signature, the signer must be Dokan's publisher by
            // exact identity, and the package must declare Dokan's upgrade code and a
            // usable version. No human step: anything else is refused.
            DokanPackage.RequireTrusted(installer);
            var identity = DokanPackage.ReadIdentity(installer);
            string product = identity.Name.Contains($"{identity.Version}", StringComparison.Ordinal) ? identity.Name : $"{identity.Name} {identity.Version}";
            Console.WriteLine($"Installer checked: {SafeText.Path(product)}, signed by {DokanPackage.SignerOrganisation} ({DokanPackage.SignerRegistration}).");
            Console.WriteLine("Installing Dokan; Windows may request administrator approval...");
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe")) { UseShellExecute = false };
            start.ArgumentList.Add("/i");
            start.ArgumentList.Add(installer);
            start.ArgumentList.Add("/qn");
            start.ArgumentList.Add("/norestart");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows Installer.");
            process.WaitForExit();
            int exitCode = process.ExitCode;
            // Preserve the result before process, staging and source cleanup.
            DokanSetupRestartException.Observe(exitCode, reportRestart);
            return exitCode;
        }
        finally
        {
            try { Directory.Delete(directory, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
