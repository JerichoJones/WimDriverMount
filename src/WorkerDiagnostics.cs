// Records why an elevated step failed when nobody is watching a console: the
// background worker, and Dokan setup inside it.
//
// It writes to the Windows Event Log through the program's own audited source
// (WimDriveEventLog), where there is no file to redirect. The worker runs
// elevated, and a log file in a folder such as %LOCALAPPDATA%\WimDrive\Logs is
// writable by the user's own non-elevated processes: with nothing refusing a
// reparse point there, turning the folder into a junction would steer an
// elevated process into creating and appending a file in any privileged location.
//
// The exception's type name alone would leave a background failure impossible
// to diagnose afterwards. So it records each exception's type and HRESULT down
// the inner chain, and Dokan's own status when Dokan raised it -- and still
// nothing that may carry secrets or paths: no pipe frames, capabilities, source
// paths or exception messages.
internal static class WorkerDiagnostics
{
    // Wired to the Event Log by Program at startup. Left null in unit tests,
    // which therefore write nothing anywhere.
    internal static Action<string>? Sink;
    // Wired to the --log file when there is one. Unlike the event log, it gets the
    // exception's message too: the file is the user's own, and a background mount
    // that failed should say why somewhere a person can read.
    internal static Action<string, Exception>? FileSink;

    private const int MaxChain = 8;

    internal static string Describe(string stage, Exception error)
    {
        ArgumentNullException.ThrowIfNull(stage);
        ArgumentNullException.ThrowIfNull(error);
        var parts = new List<string>();
        for (Exception? current = error; current is not null && parts.Count < MaxChain; current = current.InnerException)
        {
            Type type = current.GetType();
            string part = $"{type.Name} 0x{current.HResult:X8}";
            // DokanNet names the actual cause here (a driver version mismatch, a
            // mount point in use) as an enum, with no path or message. Read by
            // name so this file needs no DokanNet reference in the tests that
            // compile it on its own.
            if (type.Name == "DokanException" && type.GetProperty("ErrorStatus")?.GetValue(current) is { } status)
                part += $" status {status}";
            parts.Add(part);
        }
        return $"{stage}: {string.Join(" <- ", parts)}";
    }

    internal static void Log(string stage, Exception error)
    {
        try { Sink?.Invoke(Describe(stage, error)); }
        catch (Exception) { }
        try { FileSink?.Invoke(stage, error); }
        catch (Exception) { }
    }
}
