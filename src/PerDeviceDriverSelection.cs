using System.Globalization;

// Picks one driver per device the way Windows does: by rank (signer, feature
// score, how specifically the INF matched the device's IDs), and by DriverVer
// only among equally ranked candidates. Checked against Windows' own choice on
// real hardware.
internal static class PerDeviceDriverSelection
{
    internal sealed record Decision(InfIndex.ModelEntry? Candidate, string Reason);
    internal const string NoCandidate = "The WIM has no driver for this device.", NotNewer = "The installed driver is as new or newer.",
        Outranked = "The installed driver is a better match.";

    internal static Decision Select(DriverDetection.InstalledDevice device,
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete)
    {
        // Without trustworthy IDs, neither a match nor its absence is known.
        if (device.IdsUncertain) return new(null, "Device IDs could not be read.");
        if (!indexComplete) return new(null, "An INF in the WIM that names this device could not be read, so nothing was chosen.");
        // An extension is never a function driver. Callers already build this
        // matcher from function models only; refusing extensions here as well
        // means a caller that skips that step still cannot install one in a device's driver slot.
        var candidates = matches.Where(match => match.Model.PlatformApplicable && match.Model.ExtensionId is null).ToArray();
        if (candidates.Length == 0) return new(null, NoCandidate);
        if (device.CaptureError is not null) return new(null, "Device information is incomplete.");
        DateOnly installedDate = default;
        ulong installedVersion = 0;
        if (!device.Unbound && (!DateOnly.TryParseExact(device.Date, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out installedDate) || !TryVersion(device.Version, out installedVersion)))
            return new(null, "Installed driver date or version is unavailable.");
        if (candidates.Any(match => match.Model.DriverVersion?.Date is null || match.Model.DriverVersion.Version is null))
            return new(null, "A matching WIM driver has no date (DriverVer), so it cannot be compared.");

        var (winners, bestRank, newestDate, newestVersion) = Rank(candidates);
        string tie = Tie(winners.Length, "candidates");
        if (device.Unbound) return new(winners[0], "No driver is installed yet." + tie);

        // Compare against Windows' own rank for the bound driver when it gave us
        // one. Lower is better; at equal rank DriverVer decides, as in Windows.
        // Windows' figure carries the bound package's real signer score in its
        // top byte; a candidate's is assumed 00 (CandidateRank). So only the parts
        // both sides know are compared. Comparing all of it would make every driver
        // signed below WHQL lose to an older candidate: a downgrade, then the
        // same install again on every run. The cost: an older WHQL candidate is
        // not preferred over a newer non-WHQL driver, as Windows would.
        if (device.Rank is uint fullRank)
        {
            uint installedRank = fullRank & 0x00FFFFFF;
            if (installedRank < bestRank) return new(null, Outranked);
            if (installedRank > bestRank)
                return new(winners[0], "The WIM driver is a better match than the installed one." + tie);
        }

        if (newestDate < installedDate || (newestDate == installedDate && newestVersion <= installedVersion))
            return new(null, NotNewer);
        return new(winners[0], "The WIM driver is newer than the installed one." + tie);
    }

    // Microsoft: "For driver packages that have equal rank, date, and version,
    // Windows can select any driver package." Driver packs often ship one
    // driver in several per-OS folders, so refusing a tie would leave the
    // device without a driver Windows itself would install. Winners are in
    // path order, so the same one is taken on every run. The tie is on the
    // rank this tool can read (CandidateRank): if the tied packages are signed
    // differently, Windows would prefer the better-signed one.
    private static string Tie(int winners, string what) => winners < 2 ? "" :
        $" {winners} equally good {what} in the WIM (same match, date and version; signing not compared); the first in path order was used.";

    // Windows' driver rank is 0xSSGGTHHH: signer score, the INF's FeatureScore
    // (0xFF when absent), then the identifier score; lower is better.
    // Shortcut: the signer score needs the package's catalog, which the INF text
    // read from the WIM does not give us, so a candidate is ranked as signer 00
    // -- what every WHQL package measured on real hardware ranked, inbox drivers
    // included. Windows itself still refuses an unsigned package at install.
    // Catalogs are not verified as the WIM is read.
    internal static uint CandidateRank(InMemoryDriverMatcher.Match match) =>
        ((uint)(match.Model.FeatureScore ?? 0xFF) << 16) | (uint)match.IdentifierScore;

    // Windows' order, shared by function drivers and extensions so the two can
    // never drift apart: best rank first, then newest DriverVer date, then
    // highest version. Comparing dates first would pick a later-dated
    // driver over one that matched the device better. Model lines in one INF
    // that resolve to the same install section are the same driver, so winners
    // holds one entry, or several on a tie (see Tie), ordered by path.
    private static (InfIndex.ModelEntry[] Winners, uint Rank, DateOnly Date, ulong Version) Rank(
        IReadOnlyList<InMemoryDriverMatcher.Match> candidates)
    {
        uint bestRank = candidates.Min(CandidateRank);
        var ranked = candidates.Where(match => CandidateRank(match) == bestRank).ToArray();
        DateOnly newestDate = ranked.Max(match => match.Model.DriverVersion!.Date!.Value);
        ulong newestVersion = ranked.Where(match => match.Model.DriverVersion!.Date == newestDate)
            .Max(match => match.Model.DriverVersion!.Version!.Value);
        var winners = ranked.Where(match => match.Model.DriverVersion!.Date == newestDate && match.Model.DriverVersion.Version == newestVersion)
            .GroupBy(match => (match.Model.Path.ToUpperInvariant(), (match.Model.ActualInstallSection ?? match.Model.InstallSection).ToUpperInvariant()))
            .Select(group => group.First().Model)
            .OrderBy(model => model.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(model => model.ActualInstallSection ?? model.InstallSection, StringComparer.OrdinalIgnoreCase).ToArray();
        return (winners, bestRank, newestDate, newestVersion);
    }

    internal sealed record ExtensionDecision(string ExtensionId, InfIndex.ModelEntry? Candidate, string Reason);

    // Windows layers extension INFs onto the function driver: for each
    // ExtensionId it applies the single best-ranked matching extension, by the
    // same rank as function drivers. Nothing on the device records which
    // extension was applied (checked on real hardware: neither the devnode's
    // properties nor its Enum or driver keys name it), and Windows does not
    // consult such a list either -- it recomputes the winners and applying one
    // that is already present changes nothing. So this reports the extension
    // Windows would apply, not whether it is missing.
    internal static IReadOnlyList<ExtensionDecision> SelectExtensions(DriverDetection.InstalledDevice device,
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete)
    {
        if (device.IdsUncertain || device.CaptureError is not null || !indexComplete) return [];
        var result = new List<ExtensionDecision>();
        foreach (var group in matches.Where(match => match.Model.PlatformApplicable && match.Model.ExtensionId is not null)
                     .GroupBy(match => match.Model.ExtensionId!, StringComparer.OrdinalIgnoreCase))
        {
            var candidates = group.ToArray();
            if (candidates.Any(match => match.Model.DriverVersion?.Date is null || match.Model.DriverVersion.Version is null))
            {
                result.Add(new(group.Key, null, "A matching extension has no date (DriverVer), so it cannot be compared."));
                continue;
            }
            var (winners, _, _, _) = Rank(candidates);
            result.Add(new(group.Key, winners[0], "The best extension in the WIM for this device." + Tie(winners.Length, "extension candidates")));
        }
        return result;
    }

    internal static bool TryVersion(string? value, out ulong result)
    {
        result = 0;
        string[] parts = (value ?? string.Empty).Split('.');
        if (parts.Length != 4) return false;
        foreach (string part in parts)
        {
            if (!ushort.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out ushort component)) return false;
            result = (result << 16) | component;
        }
        return true;
    }
}
