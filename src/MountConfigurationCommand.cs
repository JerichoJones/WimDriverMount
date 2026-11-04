// Each [mount] section runs in file order, keeping that worker's existing
// independent recovery record. A failed mount does not close the ones that
// already succeeded. A foreground mount, such as one that installs drivers,
// finishes before the next section starts.
internal static class MountConfigurationCommand
{
    internal static int Run(IReadOnlyList<MountConfiguration.Entry> entries,
        Func<MountConfiguration.Entry, int> start, TextWriter output, TextWriter error, Func<string?>? stopReason = null,
        Func<int?>? programExit = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(start);
        bool failed = false, restart = false;
        foreach (var entry in entries)
        {
            string? reason = stopReason?.Invoke();
            if (reason is not null)
            {
                failed = true;
                error.WriteLine($"Mount {entry.Label}: not started. {reason}");
                continue;
            }
            int result;
            try { result = start(entry); }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or AccessViolationException or System.Runtime.InteropServices.SEHException))
            {
                failed = true;
                error.WriteLine($"Mount {entry.Label}: failed: {SafeText.Message(ex.Message)}");
                continue;
            }
            // 3010 is success that needs a restart, as Windows uses it.
            if (result == 0) output.WriteLine($"Mount {entry.Label}: done.");
            else if (result == 3010) { restart = true; output.WriteLine($"Mount {entry.Label}: done. Restart Windows to finish it."); }
            // A --run program's own exit code: the mount worked; the run still ends 1 so a
            // script sees that a program did not return 0.
            else if (programExit?.Invoke() == result)
            {
                failed = true;
                output.WriteLine($"Mount {entry.Label}: done. The program from the WIM exited with code {result}.");
            }
            else { failed = true; error.WriteLine($"Mount {entry.Label}: failed (exit code {result}). See the messages above."); }
        }
        return failed ? 1 : restart ? 3010 : 0;
    }
}
