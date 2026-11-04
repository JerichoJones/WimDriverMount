using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

// Reports fixed summaries only: no paths, URLs, device IDs or exception text.
// A successful Windows call does not prove durable delivery or rendering.
internal static class WimDriveEventLog
{
    internal const string Source = "WIM Driver Mount";
    // Event IDs: 1000 + n when an operation succeeds, 2000 + n when it fails, so all
    // failures are one filter (2000-2999) and each operation can be picked out.
    // .NET's EventLogMessages.dll renders every ID as its text; MessageFile checks.
    private const uint DiagnosticId = 2900;
    internal static uint EventId(string operation, bool failed) => (failed ? 2000u : 1000u) + operation switch
    {
        "mount" => 0u, "background-start" => 1u, "worker" => 2u, "unmount" => 3u, "configuration" => 4u, "driver" => 5u,
        _ => throw new ArgumentException("Invalid event operation."),
    };
    private const int KeyAccess = 0x0002 | 0x0001;
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegCreateKeyExW(SafeRegistryHandle parent, string subkey, int reserved, string? cls, int options,
        int access, IntPtr security, out SafeRegistryHandle result, out int disposition);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr RegisterEventSourceW(string? server, string source);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ReportEventW(IntPtr handle, ushort type, ushort category,
        uint id, IntPtr sid, ushort count, uint dataSize, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] strings, IntPtr data);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeregisterEventSource(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr LoadLibraryExW(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint FormatMessageW(uint flags, IntPtr source, uint messageId, uint language, StringBuilder buffer, uint size, IntPtr arguments);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FreeLibrary(IntPtr module);

    private static string MessageFile(uint messageId)
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string path = Path.Combine(windows, "Microsoft.NET", "Framework64", "v4.0.30319", "EventLogMessages.dll");
        if (string.IsNullOrWhiteSpace(windows) || !Path.IsPathFullyQualified(path) || !File.Exists(path))
            throw new IOException("Windows Event Log message resource is unavailable.");
        IntPtr module = LoadLibraryExW(path, IntPtr.Zero, 0x00000002 | 0x00000020);
        if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect Event Log message resource.");
        try
        {
            var buffer = new StringBuilder(2048);
            if (FormatMessageW(0x00000800 | 0x00000200, module, messageId, 0, buffer, (uint)buffer.Capacity, IntPtr.Zero) == 0 ||
                !buffer.ToString().Contains("%1", StringComparison.Ordinal))
                throw new InvalidDataException("Event Log message resource cannot render the required insertion.");
        }
        finally { if (!FreeLibrary(module)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot release Event Log message resource."); }
        return path;
    }

    // Only creates our source; never changes an existing or foreign source.
    private static void EnsureSource(string messageFile)
    {
        using RegistryKey logs = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog", writable: false)
            ?? throw new IOException("Windows Event Log registration is unavailable.");
        foreach (string name in logs.GetSubKeyNames())
        {
            if (name.Equals("Application", StringComparison.OrdinalIgnoreCase)) continue;
            using RegistryKey? log = logs.OpenSubKey(name);
            using RegistryKey? conflict = log?.OpenSubKey(Source);
            if (conflict is not null) throw new IOException("The requested event source is registered in a different log.");
        }
        using RegistryKey application = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog\Application", writable: true)
            ?? throw new IOException("Application Event Log registration is unavailable.");
        int error = RegCreateKeyExW(application.Handle, Source, 0, null, 0, KeyAccess, IntPtr.Zero, out SafeRegistryHandle handle, out int disposition);
        if (error != 0) throw new Win32Exception(error, "Cannot open Event Log source registration.");
        using (handle)
        using (RegistryKey key = RegistryKey.FromHandle(handle))
        {
            if (disposition == 1)
            {
                // If this write fails, retain the partial source for review.
                key.SetValue("EventMessageFile", messageFile, RegistryValueKind.String);
                key.SetValue("TypesSupported", 7, RegistryValueKind.DWord);
                key.Flush();
            }
            else if (!string.Equals(key.GetValue("EventMessageFile", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                         messageFile, StringComparison.OrdinalIgnoreCase))
                throw new IOException("An existing Event Log source has a different message resource.");
        }
    }

    internal static void Write(DriverOperationRunner.EventRecord record)
    {
        if (!OperatingSystem.IsWindows() || !Program.IsAdministrator()) throw new InvalidOperationException("Event Log reporting requires Windows administrator rights.");
        if (record.Operation is not ("mount" or "configuration" or "unmount" or "driver" or "background-start" or "worker")) throw new ArgumentException("Invalid event operation.");
        // A --run program's own exit code is its result, not a failed mount.
        bool failed = record.ExitCode is not (0 or 3010) && record.ProgramExitCode != record.ExitCode;
        uint id = EventId(record.Operation, failed);
        EnsureSource(MessageFile(id));
        Report(id, failed, Describe(record));
    }

    // A title line, then one plain line per fact that applies to this operation.
    internal static string Describe(DriverOperationRunner.EventRecord record)
    {
        string what = record.Operation switch
        {
            "mount" => "Mount", "configuration" => "Settings-file run", "unmount" => "Unmount",
            "driver" => "Driver installation", "background-start" => "Background mount start", _ => "Background mount",
        };
        var lines = new List<string>
        {
            record.ProgramExitCode is { } program && program == record.ExitCode
                ? $"{what} succeeded. The program from the WIM exited with code {program}."
                : record.ExitCode switch
            {
                0 => $"{what} succeeded.",
                3010 => $"{what} succeeded. A restart is required.",
                _ => $"{what} FAILED (exit code {record.ExitCode}).",
            },
        };
        if (record.Operation == "driver" || record.CallsReturned != 0)
            lines.Add(record.CallsReturned == 0 ? "Windows was not asked to install any driver."
                : $"Drivers: {record.SuccessfulCalls} of {record.CallsReturned} call(s) to Windows made a change.");
        if (record.RestartReported) lines.Add("Windows reported that a restart is required for a driver.");
        if (record.DriverOutcomeUnknown) lines.Add("The driver outcome is UNKNOWN: check Device Manager before running again.");
        if (record.SetupRestart != DokanSetupRestart.None)
            lines.Add(record.SetupRestart == DokanSetupRestart.Required ? "Dokan's installer said Windows must restart." : "Dokan's installer started a restart of Windows.");
        if (record.Closure is { } closure)
        {
            if (closure.SourceFailed) lines.Add("The WIM source failed or changed before the mount closed.");
            string? dokan = closure.Dokan switch
            {
                WorkerCompletionReceipt.DokanStatus.Kept => "Dokan was kept installed.",
                WorkerCompletionReceipt.DokanStatus.Removed => "Dokan was removed.",
                WorkerCompletionReceipt.DokanStatus.RestartRequired => "Dokan was removed; a restart is required before mounting again.",
                WorkerCompletionReceipt.DokanStatus.Deferred => "Dokan removal was deferred: another mount is still using it.",
                WorkerCompletionReceipt.DokanStatus.Failed => "Dokan removal FAILED or its result is unknown.",
                WorkerCompletionReceipt.DokanStatus.FailedRestart => "Dokan removal is uncertain, and a restart was reported.",
                WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated => "Dokan removal is uncertain; Windows Installer started a restart.",
                _ => null,
            };
            if (dokan is not null) lines.Add(dokan);
        }
        return string.Join(Environment.NewLine, lines);
    }

    // A failure from an elevated step with no console (see WorkerDiagnostics).
    // Does nothing without administrator rights: there is then no safe place to
    // write, and the caller already treats diagnostics as best effort.
    internal static void WriteDiagnostic(string detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        if (!OperatingSystem.IsWindows() || !Program.IsAdministrator()) return;
        EnsureSource(MessageFile(DiagnosticId));
        Report(DiagnosticId, true, "A WIM Driver Mount step failed (a background mount, a request to one, or checking or removing Dokan). The details below are for support." +
            Environment.NewLine + detail);
    }

    // The caller has already validated the message resource and registered the source.
    private static void Report(uint id, bool failed, string message)
    {
        IntPtr handle = RegisterEventSourceW(null, Source);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open Event Log source.");
        try
        {
            if (!ReportEventW(handle, failed ? (ushort)1 : (ushort)4, 0, id, IntPtr.Zero, 1, 0, new[] { message }, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot write Event Log entry.");
        }
        finally
        {
            if (!DeregisterEventSource(handle)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Event Log handle close failed; delivery is unknown.");
        }
    }
}
