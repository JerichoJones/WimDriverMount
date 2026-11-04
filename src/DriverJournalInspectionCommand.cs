// A status snapshot only. It does not authenticate journal contents, prove
// inventory completeness, change storage, or authorize another driver call.
internal static class DriverJournalInspectionCommand
{
    internal static int Run(string operationId, Func<Guid, DriverJournalInventory.Result> inspect,
        TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(inspect);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if ((!Guid.TryParseExact(operationId, "N", out Guid id) && !Guid.TryParseExact(operationId, "D", out id)) || id == Guid.Empty)
        {
            error.WriteLine("That is not a driver journal ID. The ID is printed when a driver install starts, for example 1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081.");
            return 2;
        }

        DriverJournalInventory.Result result;
        try { result = inspect(id); }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException or System.Threading.ThreadAbortException or System.Runtime.InteropServices.SEHException))
        {
            // A failed inspection does not establish that no restart was needed.
            result = new(false, false, false, 0, true, true, true);
        }
        output.WriteLine(result.Consistent
            ? "The journal's records agree with each other."
            : "No complete journal was read: its records are missing, unreadable, incomplete or contradict each other. A mistyped ID looks the same.");
        if (result.Consistent)
            output.WriteLine($"Finished calls to Windows recorded: {result.CompletedCalls}. Records can be missing, so there may have been more.");
        if (result.UnfinishedIntentObserved)
            output.WriteLine("A call to Windows was started but has no recorded result, so its outcome is unknown. Check Device Manager; do not retry automatically.");
        output.WriteLine(result.RestartReported
            ? "A record says Windows asked for a restart."
            : "No record says Windows asked for a restart, but that does not prove no restart is needed.");
        output.WriteLine("This only reads the journal. It cannot prove the records are genuine or complete, and it cannot tell what Windows changed, " +
            "whether a restart is needed or whether the mount was cleaned up. Do not retry based on it.");
        // An inspection with unknown outcome is not a successful recovery.
        return 1;
    }
}
