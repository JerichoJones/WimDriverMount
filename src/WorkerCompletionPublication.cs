// Capture the observed outcome before receipt publication. The callback is
// not a receipt claim; a publication failure remains an unknown recovery state.
internal static class WorkerCompletionPublication
{
    internal static void Publish(WorkerCompletionReceipt.Closure closure, Action<WorkerCompletionReceipt.Closure>? observe,
        Action persistReceipt, Action announce)
    {
        ArgumentNullException.ThrowIfNull(persistReceipt);
        ArgumentNullException.ThrowIfNull(announce);
        observe?.Invoke(closure);
        persistReceipt();
        announce();
    }
}
