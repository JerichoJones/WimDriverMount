using System.Security.Cryptography;

internal static class WorkerUnmount
{
    internal static async Task<int> RunAsync(string value, Action<WorkerCompletionReceipt.Closure>? onClosure = null)
    {
        string letter = value.TrimEnd(':', '\\').ToUpperInvariant();
        if (letter.Length != 1 || letter[0] is < 'D' or > 'Z') throw new ArgumentException("Specify a drive letter from D to Z.");
        var reservation = NoRecord(() => WorkerRecoveryStore.ReservePrepared(letter[0]));
        if (reservation is null)
        {
            // Another account's crashed mount can leave a machine-wide Unmount entry; clear it if the letter is free.
            DriveIcon.RemoveStale(letter[0]);
            Console.Error.WriteLine($"No background mount on {letter}: was found, so there is nothing to unmount.");
            Console.Error.WriteLine($"If {letter}: belongs to another WIM Driver Mount window, press Ctrl+C in that window to unmount it.");
            Console.Error.WriteLine($"If another administrator account mounted {letter}:, approve the administrator prompt with that account.");
            Console.Error.WriteLine($"If a new mount on {letter}: says a record already exists, run: .\\WimDriverMount.exe --resume-worker-cleanup {letter}:");
            return 1;
        }
        using var _ = reservation;
        byte[] encoded = reservation.CopyEncodedRecord();
        try
        {
            using var record = WorkerRecoveryRecord.Decode(encoded);
            WorkerProcessIdentity? process = Check(reservation, record, letter[0], out bool retired, out var closure, out bool unreadable);
            if (process is null && !retired)
            {
                // Not provably stale yet (its letter is in use, or Windows would not say); a restart settles it.
                Console.Error.WriteLine($"The background mount on {letter}: could not be confirmed as ended, so its record was kept.");
                Console.Error.WriteLine($"Restart Windows, then run: .\\WimDriverMount.exe --unmount {letter}:");
                return 1;
            }
            if (process is null)
            {
                Console.WriteLine($"The background mount on {letter}: had already ended (for example, at a restart). Its leftover record was cleared; there was nothing to unmount.");
                int code = 0;
                if (closure is { } closed) { onClosure?.Invoke(closed); code = ReportClosure(closed, Console.Out, Console.Error); }
                if (unreadable) { Console.Error.WriteLine(Unreadable); code = 1; }
                return code;
            }
            using var owned = process;
            // Before any control request or stop signal: the record names a process
            // and an instance, and a forged record must reach neither.
            process.RequireElevatedSameUser();
            byte[] secret = record.CopyCapability();
            try
            {
                var result = await WorkerControlClient.UnmountAsync(record.PipeName, record.Instance, record.ProcessId,
                    record.CreationTime, process, record.CopyPublicKey(), secret, CancellationToken.None).ConfigureAwait(false);
                // The control pipe could not be reached, so no unmount request was
                // delivered. Ask through the stop signal instead; the result then
                // arrives the same way as a lost reply, through the signed receipt.
                if (result.Outcome == WorkerControlClient.Outcome.Unavailable && WorkerStopSignal.TrySignal(record.Instance))
                {
                    Console.WriteLine("The background mount did not respond, so it was told to stop another way.");
                    result = result with { Outcome = WorkerControlClient.Outcome.Unknown, Detail = "Checking whether it closed." };
                }
                return await CompleteAsync(result, process.HasConfirmedExit,
                    () => (reservation.TryVerifyClosedReceipt(out bool failed, out var dokan), failed, dokan),
                    () => reservation.RemoveAfterConfirmedExit(process),
                    () => Task.Delay(100), Console.Out, Console.Error, onClosure, process.ConfirmedExitCode, letter[0]).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(secret); }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    // Before a new background mount on this letter: a record left by one of this
    // account's mounts that provably ended (crashed, killed, closed by itself, or
    // before a restart) is cleared, with the same proof --unmount uses, instead of
    // refusing the mount, and how that mount left Dokan is reported, as
    // --resume-worker-cleanup does. Dokan is already prepared for this mount by now.
    // Best effort: a live, unconfirmed, busy or unreadable record is left, and the
    // new mount then refuses with its usual advice.
    internal static void ClearEnded(char drive)
    {
        try
        {
            using var reservation = NoRecord(() => WorkerRecoveryStore.ReservePrepared(drive));
            if (reservation is null) return;
            byte[] encoded = reservation.CopyEncodedRecord();
            try
            {
                using var record = WorkerRecoveryRecord.Decode(encoded);
                using var alive = Check(reservation, record, drive, out bool retired, out var closure, out bool unreadable);
                if (retired)
                {
                    Console.WriteLine($"Cleared the record of an earlier background mount on {drive}: that had already ended.");
                    if (closure is { } closed) _ = ReportClosure(closed, Console.Out, Console.Error);
                    if (unreadable) Console.Error.WriteLine(Unreadable);
                }
            }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
    }

    private const string Unreadable = "Its closing record could not be read, so how it left Dokan is unknown (check Settings > Apps if that matters). Nothing is left to clear.";

    // What a finished mount's closing receipt says, and the exit code for it; the same
    // for --resume-worker-cleanup and for a record cleared after its mount had ended.
    internal static int ReportClosure(WorkerCompletionReceipt.Closure closure, TextWriter output, TextWriter error)
    {
        if (closure.SourceFailed) error.WriteLine("The WIM source had failed or changed while it was mounted, so some reads from the drive may have failed.");
        if (DokanSentence(closure.Dokan) is { } sentence) (IsDokanFailure(closure.Dokan) ? error : output).WriteLine(sentence);
        return closure.SourceFailed || IsDokanFailure(closure.Dokan) ? 1 :
            closure.Dokan == WorkerCompletionReceipt.DokanStatus.RestartRequired ? 3010 : 0;
    }

    // The recorded worker if it is still running. Otherwise null, and retired says
    // whether its record was cleared: only with proof the mount cannot be alive.
    private static WorkerProcessIdentity? Check(WorkerRecoveryStore.PreparedReservation reservation, WorkerRecoveryRecord record, char drive, out bool retired,
        out WorkerCompletionReceipt.Closure? closure, out bool unreadable)
    {
        retired = false;
        closure = null;
        unreadable = false;
        try { return WorkerProcessIdentity.Open(record.ProcessId, record.CreationTime); }
        catch (Exception ex) when (ex is IOException or InvalidDataException || ex is System.ComponentModel.Win32Exception { NativeErrorCode: 87 or 5 })
        {
            // Gone: exited (IOException), PID reused by another process (InvalidDataException)
            // or no such PID (87). Access denied (5) may be a protected process now using the
            // PID, but is not proof by itself. Other errors (low resources) keep the records.
            bool gone = ex is not System.ComponentModel.Win32Exception { NativeErrorCode: 5 };
            retired = reservation.TryRetireStale(gone, out closure, out unreadable);
            if (retired) DriveIcon.RemoveStale(drive, recordRetired: true);
            return null;
        }
    }

    // Null when the drive has no record (or no store exists yet): nothing to unmount.
    private static T? NoRecord<T>(Func<T> open) where T : class
    {
        try { return open(); }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode is 2 or 3) { return null; }
    }

    internal static bool IsDokanFailure(WorkerCompletionReceipt.DokanStatus dokan) => dokan is
        WorkerCompletionReceipt.DokanStatus.Deferred or WorkerCompletionReceipt.DokanStatus.Failed or
        WorkerCompletionReceipt.DokanStatus.FailedRestart or WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated;

    // What happened to Dokan after a mount, in plain words; shared by foreground and background mounts.
    internal static string? DokanSentence(WorkerCompletionReceipt.DokanStatus dokan) => dokan switch
    {
        WorkerCompletionReceipt.DokanStatus.Kept => "Dokan stays installed.",
        WorkerCompletionReceipt.DokanStatus.Removed => "Dokan, which this program had installed, was removed.",
        WorkerCompletionReceipt.DokanStatus.RestartRequired => "RESTART REQUIRED: Dokan was removed. Restart Windows before mounting again.",
        WorkerCompletionReceipt.DokanStatus.Deferred => "Dokan was not removed, because another mount is still using it.",
        WorkerCompletionReceipt.DokanStatus.Failed => "Dokan could not be removed, or the result is unknown. It may still be installed; check Settings > Apps.",
        WorkerCompletionReceipt.DokanStatus.FailedRestart => "Dokan may not have been removed, and Windows says it needs a restart. Restart Windows, then check Settings > Apps.",
        WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated => "Dokan may not have been removed, and Windows Installer started a restart although none was asked for.",
        _ => null,
    };

    // The real delegates keep the same reservation and process handle held for
    // the whole operation. Separate delegates allow the result policy to be
    // checked without modifying real recovery records.
    internal static async Task<int> CompleteAsync(WorkerControlClient.Result result, Func<bool> hasExited,
        Func<(bool Valid, bool SourceFailed, WorkerCompletionReceipt.DokanStatus Dokan)> verifyReceipt, Action remove, Func<Task> delay,
        TextWriter output, TextWriter error, Action<WorkerCompletionReceipt.Closure>? onClosure = null,
        Func<uint>? workerExitCode = null, char? drive = null)
    {
                // A closed drive is reported below, once its closure is verified.
                if (result.Outcome is not (WorkerControlClient.Outcome.Closed or WorkerControlClient.Outcome.ClosedSourceFailed)) output.WriteLine(result.Detail);
                // A response can be lost after the worker has closed. Keep the
                // original process handle and reservation and check the signed
                // receipt instead of abandoning recoverable evidence. Explicit
                // failure or limit responses remain failures, not closure claims.
                bool responseLost = result.Outcome is WorkerControlClient.Outcome.Unknown or WorkerControlClient.Outcome.Unavailable;
                if (!responseLost && result.Outcome is not (WorkerControlClient.Outcome.Closed or WorkerControlClient.Outcome.ClosedSourceFailed)) return 1;
                // The worker writes its receipt before reporting CLOSED and
                // exits after its control response. Keep this handle until exit.
                // Removing an owned Dokan installation can wait up to five minutes
                // for the lifecycle lock and then run msiexec; allow for both.
                if (!hasExited()) output.WriteLine("Waiting for the background mount to finish. If it is removing Dokan, this can take several minutes.");
                for (int i = 0; i < 4200 && !hasExited(); i++) await delay().ConfigureAwait(false);
                if (!hasExited()) { error.WriteLine("The background mount has not ended yet, so its records were kept. Run the same --unmount command again in a few minutes."); return 1; }
                uint? exitCode = workerExitCode?.Invoke();
                bool workerEventFailure = exitCode == 1001;
                (bool receiptValid, bool sourceFailed, var dokan) = verifyReceipt();
                if (!receiptValid ||
                    (!responseLost && (sourceFailed != (result.Outcome == WorkerControlClient.Outcome.ClosedSourceFailed) || dokan != result.Dokan)))
                {
                    error.WriteLine("How the background mount says it closed does not match what it recorded, so its records were kept. Run the same --unmount command again; if this repeats, restart Windows and run it once more.");
                    return 1;
                }
                bool receiptFailure = sourceFailed || IsDokanFailure(dokan);
                uint expectedExit = receiptFailure ? 1u : dokan == WorkerCompletionReceipt.DokanStatus.RestartRequired ? 3010u : 0u;
                bool unexpectedWorkerExit = exitCode.HasValue && exitCode.Value != expectedExit && !workerEventFailure;
                onClosure?.Invoke(new(sourceFailed, dokan));
                remove();
                output.WriteLine(drive is { } letter ? $"{letter}: is unmounted." : "The drive is unmounted.");
                if (responseLost) output.WriteLine("(Confirmed from the record it left when it closed.)");
                if (sourceFailed) error.WriteLine("The WIM source failed or changed while it was mounted, so some reads from the drive may have failed.");
                if (workerEventFailure) error.WriteLine("The background mount could not confirm that it wrote its entries to the Windows Application event log. That does not change the result; do not unmount again for it.");
                if (unexpectedWorkerExit) error.WriteLine($"The background mount ended with exit code {exitCode}, which does not match how it closed. If it was started with --log or --evtlog, the reason is in that log.");
                if (DokanSentence(dokan) is { } sentence) (IsDokanFailure(dokan) ? error : output).WriteLine(sentence);
                // An event-log failure is reported above but changes no exit code, as in
                // the foreground runner (otherwise a finished unmount, or its 3010, would become 1).
                return unexpectedWorkerExit || receiptFailure ? 1 :
                    dokan == WorkerCompletionReceipt.DokanStatus.RestartRequired ? 3010 : 0;
    }
}
