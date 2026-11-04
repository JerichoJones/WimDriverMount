// Pure reconciliation of supplied record bytes. This does not enumerate storage,
// prove that an inventory is complete, authenticate it, or authorize a retry.
internal static class DriverJournalInventory
{
    internal readonly record struct Result(bool Consistent, bool HasTerminal,
        bool RestartReported, int CompletedCalls, bool OutcomeUnknown,
        bool RestartUnknown, bool CleanupUnknown, bool UnfinishedIntentObserved = false);

    internal const int MaximumEntries = 400002; // Calls, optional details, terminal, and mode marker.

    internal static Result Reconcile(IEnumerable<KeyValuePair<string, byte[]>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var calls = new List<byte[]>();
        var selectedIntents = new HashSet<int>();
        var selectedCompletions = new HashSet<int>();
        DriverJournalRecords.Terminal? terminal = null;
        bool invalid = false, restart = false, callRestart = false;
        int count = 0, successful = 0;
        bool callFailure = false, filteredMode = false;
        try
        {
            foreach (var entry in entries)
            {
                if (++count > MaximumEntries) { invalid = true; break; }
                if (entry.Value is null || entry.Key is null) { invalid = true; continue; }
                if (entry.Key.EndsWith(".wds", StringComparison.Ordinal))
                {
                    if (!names.Add(entry.Key) || entry.Value.Length is < 2 or > 65536) { invalid = true; continue; }
                    string[] parts = entry.Key.Split('-');
                    bool intent = parts.Length == 3 && parts[1] == "selected" && parts[2] == "intent.wds";
                    bool completion = parts.Length == 3 && parts[1] == "selected" && parts[2] == "completion.wds";
                    if ((!intent && !completion) || parts[0].Length != 6 || !int.TryParse(parts[0], out int sequence) || sequence < 1 ||
                        !string.Equals(parts[0], sequence.ToString("D6", System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal))
                    { invalid = true; continue; }
                    try
                    {
                        using var document = System.Text.Json.JsonDocument.Parse(entry.Value);
                        if (document.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object ||
                            !(intent ? selectedIntents : selectedCompletions).Add(sequence)) invalid = true;
                    }
                    catch (System.Text.Json.JsonException) { invalid = true; }
                    continue;
                }
                if (entry.Value.Length != 16) { invalid = true; continue; }
                byte[] data = (byte[])entry.Value.Clone();
                if (entry.Key is null || !names.Add(entry.Key)) invalid = true;
                if (string.Equals(entry.Key, "filtered-mode.wdm", StringComparison.Ordinal))
                {
                    if (!data.AsSpan().SequenceEqual(DriverJournalRecords.FilteredMode)) invalid = true;
                    else filteredMode = true;
                    continue;
                }
                if (data.AsSpan(0, 4).SequenceEqual("WDT1"u8))
                {
                    try
                    {
                        var decoded = DriverJournalRecords.DecodeTerminal(data);
                        restart |= decoded.RestartReported;
                        if (!string.Equals(entry.Key, "terminal.wdt", StringComparison.Ordinal)) invalid = true;
                        if (terminal.HasValue) invalid = true;
                        else terminal = decoded;
                    }
                    catch (InvalidDataException) { invalid = true; }
                    continue;
                }
                try
                {
                    var decoded = DriverJournalRecords.Decode(data);
                    if (decoded.Type == DriverJournalRecords.Kind.Completion)
                    {
                        restart |= decoded.Restart;
                        callRestart |= decoded.Restart;
                        if (decoded.Installed) successful++;
                        if (!decoded.Installed && decoded.Error != 259) callFailure = true;
                    }
                    string suffix = decoded.Type == DriverJournalRecords.Kind.Intent ? "intent" : "completion";
                    string expected = $"{decoded.Sequence:D6}-{suffix}.wdj";
                    if (!string.Equals(entry.Key, expected, StringComparison.Ordinal)) invalid = true;
                    calls.Add(data);
                }
                catch (InvalidDataException) { invalid = true; }
            }
        }
        // The supplied iterator may fail while opening, advancing, or disposing.
        // Preserve restart evidence already seen for every nonfatal failure;
        // fatal runtime failures cannot safely be converted to a recovery result.
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException or System.Threading.ThreadAbortException or System.Runtime.InteropServices.SEHException))
        {
            return new(false, terminal.HasValue, restart, 0, true, true, true);
        }

        int completed = 0;
        foreach (int sequence in selectedIntents)
            if (!names.Contains($"{sequence:D6}-intent.wdj") ||
                (names.Contains($"{sequence:D6}-completion.wdj") && !selectedCompletions.Contains(sequence))) invalid = true;
        foreach (int sequence in selectedCompletions)
            if (!selectedIntents.Contains(sequence) || !names.Contains($"{sequence:D6}-completion.wdj")) invalid = true;
        bool unfinishedIntentObserved = false;
        if (!terminal.HasValue) invalid = true;
        if (calls.Count != 0)
        {
            var inspection = DriverJournalRecords.Inspect(calls, filteredMode);
            restart |= inspection.RestartReported;
            completed = inspection.CompletedCalls;
            unfinishedIntentObserved = inspection.Valid && inspection.HasUnfinishedIntent;
            if (!inspection.Valid || inspection.HasUnfinishedIntent) invalid = true;
        }
        if (terminal is { } final &&
            (final.CompletedCalls != completed || final.SuccessfulCalls != successful ||
             final.RestartReported != callRestart ||
             (callFailure && (!final.Failed || !final.OutcomeUnknown || !final.RestartUnknown))))
            invalid = true;

        // Even a consistent supplied set can be incomplete or unauthenticated.
        // A handle-bound reader would establish inventory and identity; this
        // one does not, so none of these fields proves outcome, restart, or cleanup.
        return new(!invalid, terminal.HasValue, restart, invalid ? 0 : completed, true, true, true, unfinishedIntentObserved);
    }
}
