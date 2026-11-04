// Explicitly resumes a previously published worker-cleanup journal. This
// does not unmount a drive or verify its current mapping.
internal static class WorkerCleanupCommand
{
    internal static int Run(char drive, Func<char, WorkerCompletionReceipt.Closure> resume, TextWriter output, TextWriter error,
        Action<WorkerCompletionReceipt.Closure>? onClosure = null)
    {
        try
        {
            var closure = resume(drive);
            onClosure?.Invoke(closure);
            output.WriteLine($"The leftover record for {drive}: was cleared. This does not unmount anything.");
            return WorkerUnmount.ReportClosure(closure, output, error);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode is 2 or 3)
        {
            error.WriteLine($"There is no leftover record for {drive}:, so there was nothing to clear.");
            return 1;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or AccessViolationException or System.Runtime.InteropServices.SEHException))
        {
            error.WriteLine($"The leftover record for {drive}: could not be cleared: {SafeText.Message(ex.Message)}");
            return 1;
        }
    }
}
