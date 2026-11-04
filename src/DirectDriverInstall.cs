// Driver-call result, journal contracts and SetupAPI log markers shared by the install path.
internal static class DirectDriverInstall
{
    internal readonly record struct Outcome(bool Installed, int Error, bool Restart);
    // Implementations must durably publish and verify each record before returning.
    // A missing completion after an intent means that the call outcome is unknown.
    internal interface ICallJournal
    {
        void WriteIntent(int sequence);
        void WriteCompletion(int sequence, Outcome outcome);
        void WriteSelectedIntent(int sequence, string metadata) => throw new IOException("Selected-call journal details are unavailable.");
        void WriteSelectedCompletion(int sequence, string metadata, Outcome outcome) => throw new IOException("Selected-call journal details are unavailable.");
    }
    internal interface IOperationJournal : ICallJournal, IDisposable
    {
        Guid OperationId { get; }
        void WriteTerminal(bool outcomeUnknown, bool restartUnknown, bool operationFailed,
            DriverJournalRecords.Cleanup cleanup);
    }
    internal sealed record RunResult(int CallsStarted, int CallsReturned, int SuccessfulCalls, bool RestartReported,
        bool OutcomeUnknown, Exception? Error)
    {
        internal string SetupLogStatus { get; init; } = "not requested";
        // The driver report (counts, restart, error) reached the console in full.
        internal bool Reported { get; init; }
        internal int ExitCode => Error is not null || OutcomeUnknown || SetupLogStatus == "marker error" ? 1 : RestartReported ? 3010 : 0;
    }

    internal static RunResult RunWithMarkers(Func<RunResult> execute, Action start, Action<int> end)
    {
        try { start(); }
        catch (Exception ex) { return new RunResult(0, 0, 0, false, false, ex) { SetupLogStatus = "marker error" }; }
        RunResult result = execute();
        try { end(result.ExitCode); return result with { SetupLogStatus = "attempted; not confirmed" }; }
        catch (Exception) { return result with { SetupLogStatus = "marker error" }; }
    }
}
