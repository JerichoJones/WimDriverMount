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

    // Windows' own full ranks, signer score included (DriverRanking.cs); null
    // when Windows could not rank that driver. Candidate also gets the model's
    // CandidateRank. SignerFloor: the lowest signer score Windows gives any
    // driver in the current policy state, so no rank is below estimate + floor.
    // InstalledAsEstimated: the bound driver's rank is known to equal its
    // estimate + floor without asking (WindowsRankSource says when).
    internal sealed record WindowsRanks(Func<DriverDetection.InstalledDevice, uint?> Installed,
        Func<DriverDetection.InstalledDevice, InfIndex.ModelEntry, uint, uint?> Candidate,
        Func<DriverDetection.InstalledDevice, bool> InstalledAsEstimated, uint SignerFloor = 0);

    internal static Decision Select(DriverDetection.InstalledDevice device,
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete, WindowsRanks? windows = null)
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
        // The installed driver itself, offered again by the WIM (same INF, install section,
        // date and version), is never an upgrade: when it ranks best, Windows marks that
        // node as the installed driver and keeps it, even where the WIM's copy matches a
        // more specific ID. It still ranks, so a driver it beats is not chosen either.
        // Seen comparing with Windows' own choice on real hardware.
        Decision Final(Decision decision) => decision.Candidate is { } chosen && !device.Unbound &&
            IsInstalledDriver(chosen, device, installedDate, installedVersion) ? new(null, NotNewer) : decision;

        // The device property never carries the bound driver's signer byte, so
        // this is its rank without one, as CandidateRank is for a candidate.
        uint? installedEstimate = device.Rank is uint fullRank ? fullRank & 0x00FFFFFF : null;
        if (windows is null) return Final(Decide(device, candidates, CandidateRank, installedEstimate, installedDate, installedVersion, signed: false));

        // Windows' rank is the estimate plus a signer score of at least the
        // floor, never less. So the decision is first made with every rank
        // Windows has not yet given at that lowest value, and Windows is asked
        // only where its answer could overturn it: an install, by the chosen
        // candidates being worse; a keep, by the installed driver being worse.
        // Each answer is kept, so this ends.
        uint floor = windows.SignerFloor;
        uint Estimate(InMemoryDriverMatcher.Match match) => CandidateRank(match) | floor;
        var known = new Dictionary<InMemoryDriverMatcher.Match, uint>(ReferenceEqualityComparer.Instance);
        uint RankOf(InMemoryDriverMatcher.Match match) => known.TryGetValue(match, out uint rank) ? rank : Estimate(match);
        uint? installedLowest = installedEstimate is uint low ? low | floor : null;
        uint? installedRank = installedLowest;
        bool installedKnown = device.Unbound || (installedLowest is not null && windows.InstalledAsEstimated(device));
        bool everything = false;
        bool AskInstalled()
        {
            uint? rank = windows.Installed(device);
            // Below its lowest possible value: the shortcut's premise fails for this device.
            if (rank is uint r && installedLowest is uint e && r < e) everything = true;
            installedRank = rank;
            installedKnown = true;
            return rank is not null;
        }
        bool AskCandidate(InMemoryDriverMatcher.Match match)
        {
            if (windows.Candidate(device, match.Model, CandidateRank(match)) is not uint rank) return false;
            if (rank < Estimate(match)) everything = true;
            known[match] = rank;
            return true;
        }
        while (true)
        {
            if (!installedKnown && (installedRank is null || everything) && !AskInstalled()) return new(null, CannotRankInstalled);
            if (everything && candidates.Any(match => !known.ContainsKey(match)))
            {
                // Windows disagreed with the INF-only rank, so nothing is assumed: every rank comes from Windows.
                foreach (var match in candidates.Where(match => !known.ContainsKey(match)))
                    if (!AskCandidate(match)) return new(null, CannotRankCandidate);
                continue;
            }
            var decision = Decide(device, candidates, RankOf, installedRank, installedDate, installedVersion, signed: true);
            if (decision.Candidate is not null)
            {
                uint best = candidates.Min(RankOf);
                var unasked = candidates.Where(match => RankOf(match) == best && !known.ContainsKey(match)).ToArray();
                if (unasked.Length == 0) return Final(decision);
                foreach (var match in unasked)
                    if (!AskCandidate(match)) return new(null, CannotRankCandidate);
            }
            else if (!installedKnown)
            {
                if (!AskInstalled()) return new(null, CannotRankInstalled);
            }
            else return decision;
        }
    }

    private static bool IsInstalledDriver(InfIndex.ModelEntry model, DriverDetection.InstalledDevice device, DateOnly installedDate, ulong installedVersion) =>
        device.OriginalInf is { Length: > 0 } original && device.Section is { Length: > 0 } section &&
        string.Equals(Path.GetFileName(model.Path), original, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(model.ActualInstallSection ?? model.InstallSection, section, StringComparison.OrdinalIgnoreCase) &&
        model.DriverVersion?.Date == installedDate && model.DriverVersion.Version == installedVersion;

    private const string CannotRankInstalled = "Windows could not rank the installed driver, so nothing was chosen.",
        CannotRankCandidate = "Windows could not rank a matching WIM driver, so nothing was chosen.";

    private static Decision Decide(DriverDetection.InstalledDevice device, IReadOnlyList<InMemoryDriverMatcher.Match> candidates,
        Func<InMemoryDriverMatcher.Match, uint> rankOf, uint? installedRank, DateOnly installedDate, ulong installedVersion, bool signed)
    {
        var (winners, bestRank, newestDate, newestVersion) = Rank(candidates, rankOf);
        string tie = Tie(winners.Length, "candidates", signed);
        if (device.Unbound) return new(winners[0], "No driver is installed yet." + tie);

        // Compare against Windows' own rank for the bound driver. Lower is
        // better; at equal rank DriverVer decides, as in Windows.
        if (installedRank is uint installed)
        {
            if (installed < bestRank) return new(null, Outranked);
            if (installed > bestRank)
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
    // path order, so the same one is taken on every run. Without Windows ranks
    // the tie is on CandidateRank, which leaves signing out.
    private static string Tie(int winners, string what, bool signed = false) => winners < 2 ? "" :
        $" {winners} equally good {what} in the WIM (same {(signed ? "rank" : "match")}, date and version{(signed ? "" : "; signing not compared")}); the first in path order was used.";

    // Windows' driver rank is 0xSSGGTHHH: signer score, the INF's FeatureScore
    // (0xFF when absent), then the identifier score; lower is better.
    // Read from the INF text alone, so the signer score is taken as 00 -- what
    // Windows gives every signed package while AllSigningEqual is on. Windows'
    // own rank can only add to this, never take from it, which is what lets
    // Select ask Windows so rarely.
    internal static uint CandidateRank(InMemoryDriverMatcher.Match match) =>
        ((uint)(match.Model.FeatureScore ?? 0xFF) << 16) | (uint)match.IdentifierScore;

    // Windows' order, shared by function drivers and extensions so the two can
    // never drift apart: best rank first, then newest DriverVer date, then
    // highest version. Comparing dates first would pick a later-dated
    // driver over one that matched the device better. Model lines in one INF
    // that resolve to the same install section are the same driver, so winners
    // holds one entry, or several on a tie (see Tie), ordered by path.
    private static (InfIndex.ModelEntry[] Winners, uint Rank, DateOnly Date, ulong Version) Rank(
        IReadOnlyList<InMemoryDriverMatcher.Match> candidates, Func<InMemoryDriverMatcher.Match, uint>? rankOf = null)
    {
        rankOf ??= CandidateRank;
        uint bestRank = candidates.Min(rankOf);
        var ranked = candidates.Where(match => rankOf(match) == bestRank).ToArray();
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
    // Windows' extension rank includes the signer score (measured: the same Authenticode
    // extension ranked 00FF2001 with "Treat all digitally signed drivers equally" on and
    // 0FFF2001 with it off), but it lists no extension INF in any driver list, so it cannot
    // be asked. With the policy on (signersEqual) every signed package scores the same, so
    // rank, date and version decide, as here. With it off, extensions from different INFs
    // competing for one ExtensionId could be decided by who signed them: none is guessed.
    internal static IReadOnlyList<ExtensionDecision> SelectExtensions(DriverDetection.InstalledDevice device,
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete, bool signersEqual = true)
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
            if (!signersEqual && candidates.Select(match => match.Model.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            {
                result.Add(new(group.Key, null, "Several extensions in the WIM compete, and with \"Treat all digitally signed drivers equally\" off who signed each could decide; Windows cannot be asked to rank extensions, so none was chosen."));
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
