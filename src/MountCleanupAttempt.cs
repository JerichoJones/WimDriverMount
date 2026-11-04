// This controls whether the application makes a second name-based removal
// attempt. It cannot prove ownership or change Dokan's disposal behavior.
internal static class MountCleanupAttempt
{
    internal static void RequestAndWait(ref bool removalAttempted, Func<bool> remove, Action waitForClosure)
    {
        ArgumentNullException.ThrowIfNull(remove);
        ArgumentNullException.ThrowIfNull(waitForClosure);
        removalAttempted = true;
        if (!remove()) throw new IOException("Dokan could not remove the mount point.");
        waitForClosure();
    }

    internal static void Run(bool removalAttempted, Func<bool> mappingChangedOrUnknown,
        Func<bool> isRunning, Func<bool> remove, Action warning)
    {
        ArgumentNullException.ThrowIfNull(mappingChangedOrUnknown);
        ArgumentNullException.ThrowIfNull(isRunning);
        ArgumentNullException.ThrowIfNull(remove);
        ArgumentNullException.ThrowIfNull(warning);
        // A failed or interrupted native request may still have changed the
        // mapping. Do not retry by name after any earlier request.
        if (removalAttempted) return;
        if (mappingChangedOrUnknown()) { warning(); return; }
        if (isRunning() && !remove())
            throw new IOException("Mount removal failed; cleanup is not confirmed.");
    }
}
