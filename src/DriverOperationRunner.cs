// Finalizes the driver journal and reports after the caller's cleanup scopes.
// Journal inspection cannot authenticate contents or prove full recovery.
internal static class DriverOperationRunner
{
    internal sealed class State
    {
        internal DirectDriverInstall.RunResult? Result;
        internal string? EventOperation;
        internal WorkerCompletionReceipt.Closure? EventClosure;
        internal DokanSetupRestart SetupRestart;
        // The exit code of a --run program, which becomes this run's exit code.
        internal int? RunExitCode;
        internal DirectDriverInstall.IOperationJournal? Journal { get; private set; }
        internal Guid? JournalOperationId { get; private set; }
        internal void AttachJournal(DirectDriverInstall.IOperationJournal journal)
        {
            ArgumentNullException.ThrowIfNull(journal);
            if (Journal is not null || journal.OperationId == Guid.Empty)
                throw new InvalidOperationException("Invalid or repeated driver journal.");
            JournalOperationId = journal.OperationId;
            Journal = journal;
        }
    }

    internal sealed record EventRecord(string Operation, int ExitCode, int CallsReturned, int SuccessfulCalls,
        bool RestartReported, bool DriverOutcomeUnknown, WorkerCompletionReceipt.Closure? Closure,
        DokanSetupRestart SetupRestart = DokanSetupRestart.None, int? ProgramExitCode = null);

    // machineReadable adds one JSON line for scripts and logs; a person at a
    // console gets only the plain summary.
    internal static int Run(Func<State, int> operation, TextWriter error,
        Action<EventRecord>? reportEvent = null, bool machineReadable = true)
    {
        var state = new State();
        int exitCode;
        Exception? unhandled = null;
        try { exitCode = operation(state); }
        catch (Exception ex) { unhandled = ex; exitCode = 1; }
        if (state.Journal is not null && state.Result is null) exitCode = 1;
        bool journalFailure = false;
        bool terminalRecorded = false;
        if (state.Journal is { } journal)
        {
            try
            {
                bool outcomeUnknown = state.Result?.OutcomeUnknown ?? true;
                journal.WriteTerminal(outcomeUnknown, outcomeUnknown,
                    state.Result is null || unhandled is not null || (exitCode != 0 && exitCode != 3010) || state.Result?.Error is not null,
                    DriverJournalRecords.Cleanup.Unknown);
                terminalRecorded = true;
            }
            catch (Exception) { journalFailure = true; exitCode = 1; }
            finally
            {
                try { journal.Dispose(); }
                catch (Exception) { journalFailure = true; exitCode = 1; }
            }
        }
        bool eventFailure = false;
        if (state.EventOperation is { } eventOperation)
        {
            var record = new EventRecord(eventOperation, exitCode, state.Result?.CallsReturned ?? 0,
                state.Result?.SuccessfulCalls ?? 0, state.Result?.RestartReported ?? false,
                eventOperation == "driver" && (state.Result is null || state.Result.OutcomeUnknown || journalFailure), state.EventClosure, state.SetupRestart,
                state.RunExitCode is { } program && program == exitCode ? program : null);
            // The same plain summary goes to the --log file, if there is one.
            foreach (string line in WimDriveEventLog.Describe(record).Split('\n')) LogFile.Line(line.TrimEnd('\r'));
            // The Windows event log only when asked for (--evtlog); tests pass their own reporter.
            if (reportEvent is not null || Program.EventLog)
            {
                try { (reportEvent ?? WimDriveEventLog.Write)(record); }
                // The message below says the result stands, so the exit code does too
                // (otherwise a success or 3010 would become 1). The worker's 1001 is its
                // protocol for "finished, but the event entry failed", so it replaces only
                // a finish: a failure keeps its 1, which --unmount must see.
                catch (Exception) { eventFailure = true; if (eventOperation == "worker" && exitCode is 0 or 3010) exitCode = 1001; }
            }
        }
        try
        {
            if (unhandled is not null) error.WriteLine("WIM Driver Mount ERROR: " + SafeText.Message(unhandled.Message));
            if (eventFailure) error.WriteLine("This run's entry could not be confirmed in the Windows Application event log. That does not change the result above; do not run it again just for the log entry.");
            if (state.SetupRestart != DokanSetupRestart.None)
                error.WriteLine("Dokan's installer says Windows must restart. Restart Windows, then run this again.");
            if (state.Result is null && state.JournalOperationId is null) return exitCode;
            var result = state.Result;
            bool unknown = (result?.OutcomeUnknown ?? true) || journalFailure;
            bool doNotRetry = result is null || result.Error is not null || result.OutcomeUnknown || journalFailure ||
                (exitCode != 0 && exitCode != 3010);
            // The driver report already gave the counts, the restart and any error;
            // say here only what it could not (so it is not said twice).
            if (result is null) error.WriteLine("The driver install stopped before it reported a result.");
            else if (!result.Reported)
            {
                error.WriteLine($"Driver installs: {result.SuccessfulCalls} of {result.CallsReturned} call(s) to Windows succeeded" +
                    $"{(result.RestartReported ? "; Windows says a RESTART IS REQUIRED" : "")}.");
                if (result.Error is { } failed) error.WriteLine("Error: " + SafeText.Message(failed.Message));
            }
            if (result?.SetupLogStatus == "marker error")
                error.WriteLine("The --setup-log markers could not be written to the Windows setup log, so this run counts as failed.");
            if (unknown && !(result is { OutcomeUnknown: true, Reported: true } && !journalFailure))
                error.WriteLine("The outcome is UNKNOWN: Windows may have changed drivers. Check Device Manager before running again.");
            else if (doNotRetry && (result?.CallsStarted ?? 0) > 0) error.WriteLine(result is { Reported: true } ? "Review the driver report above before running this again." : "Check Device Manager before running this again.");
            if (state.JournalOperationId is { } id)
                error.WriteLine($"Driver journal {id:D} ({(!journalFailure && terminalRecorded ? "complete" : "not confirmed")}). " +
                    $"To check it later, run: .\\WimDriverMount.exe --inspect-driver-journal {id:D}");
            if (!machineReadable) return exitCode;
            error.WriteLine("WIM Driver Mount driver result: " + System.Text.Json.JsonSerializer.Serialize(new
            {
                CallsStarted = result?.CallsStarted ?? 0, CallsReturned = result?.CallsReturned ?? 0,
                SuccessfulCalls = result?.SuccessfulCalls ?? 0,
                RestartReported = result?.RestartReported ?? false,
                DokanSetupRestart = state.SetupRestart.ToString(),
                OutcomeUnknown = (result?.OutcomeUnknown ?? true) || journalFailure,
                RestartUnknown = (result?.OutcomeUnknown ?? true) || journalFailure,
                Failed = result is null || result.Error is not null || unhandled is not null || journalFailure ||
                    (exitCode != 0 && exitCode != 3010),
                SetupLogStatus = result?.SetupLogStatus ?? "not attempted",
                ErrorCode = (result?.Error as System.ComponentModel.Win32Exception)?.NativeErrorCode,
                JournalOperationId = state.JournalOperationId,
                JournalTerminalStatus = state.JournalOperationId is null ? "not created" :
                    journalFailure ? "unconfirmed" : terminalRecorded ? "recorded" : "unconfirmed",
                EventLogStatus = state.EventOperation is null || (reportEvent is null && !Program.EventLog) ? "not requested" : eventFailure ? "unconfirmed" : "write accepted; delivery unverified",
                OverallExitCode = exitCode,
                CleanupStatus = "unknown",
                Detail = result?.Error is null ? null : SafeText.Message(result.Error.Message),
                DoNotRetry = result is null || result.Error is not null || result.OutcomeUnknown || journalFailure ||
                    (exitCode != 0 && exitCode != 3010)
            }));
        }
        // The report could not be written; as with the event entry, the result itself stands.
        catch (Exception) { return exitCode; }
        return exitCode;
    }
}
