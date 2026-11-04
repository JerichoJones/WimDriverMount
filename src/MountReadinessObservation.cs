// A consistency check on a recent observation, not proof that the mounted
// drive belongs to this instance or that the mapping cannot change afterward.
internal static class MountReadinessObservation
{
    // Activation may take time. Recheck the same live instance and the
    // observed mapping after it returns, before announcing worker readiness.
    // These checks do not establish ownership or reserve the mapping.
    internal static void ActivateAndAnnounce(CancellationToken cancellation, Action activate,
        Func<bool> isRunning, Func<bool> mappingMatches, Action announce)
    {
        ArgumentNullException.ThrowIfNull(activate);
        ArgumentNullException.ThrowIfNull(isRunning);
        ArgumentNullException.ThrowIfNull(mappingMatches);
        ArgumentNullException.ThrowIfNull(announce);
        cancellation.ThrowIfCancellationRequested();
        activate();
        ConfirmAndAnnounce(cancellation, isRunning, mappingMatches, announce);
    }

    internal static void ConfirmAndAnnounce(CancellationToken cancellation, Func<bool> isRunning,
        Func<bool> mappingMatches, Action announce)
    {
        ArgumentNullException.ThrowIfNull(isRunning);
        ArgumentNullException.ThrowIfNull(mappingMatches);
        ArgumentNullException.ThrowIfNull(announce);
        cancellation.ThrowIfCancellationRequested();
        if (!isRunning()) throw new IOException("The filesystem closed before readiness was confirmed.");
        if (!mappingMatches()) throw new IOException("The drive letter changed, or could not be checked, before the drive was ready. Nothing was run on it.");
        cancellation.ThrowIfCancellationRequested();
        if (!isRunning()) throw new IOException("The filesystem closed while readiness was checked.");
        cancellation.ThrowIfCancellationRequested();
        announce();
    }
}
