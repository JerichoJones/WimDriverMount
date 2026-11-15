using System.ComponentModel;
using System.Globalization;

// Picks one driver per device the way Windows does: by rank (signer, feature
// score, how specifically the INF matched the device's IDs), and by DriverVer
// only among equally ranked candidates. Checked against Windows' own choice on
// real hardware.
internal static class PerDeviceDriverSelection
{
    // Store: no WIM candidate, because a driver already in this PC's driver store beats the
    // WIM's best; Windows installs that one (what a device re-scan does).
    internal sealed record Decision(InfIndex.ModelEntry? Candidate, string Reason, IReadOnlyList<InfIndex.ModelEntry>? Winners = null,
        DriverDetection.StoreDriver? Store = null);
    internal const string NoCandidate = "The WIM has no driver for this device.", NotNewer = "The installed driver is as new or newer.",
        Outranked = "The installed driver is a better match.",
        StoreBetter = "A driver already in this PC's driver store is a better match than the WIM's; Windows installs that one.";

    // Windows' own full ranks, signer score included (DriverRanking.cs); null
    // when Windows could not rank that driver. Candidate also gets the model's
    // CandidateRank. SignerFloor: the lowest signer score Windows gives any
    // driver in the current policy state, so no rank is below estimate + floor.
    // InstalledAsEstimated: the bound driver's rank is known to equal its
    // estimate + floor without asking (WindowsRankSource says when).
    // Store: the driver Windows would install from this PC's driver store alone (null: none);
    // asked only for a device the WIM would otherwise get a driver on. May throw.
    internal sealed record WindowsRanks(Func<DriverDetection.InstalledDevice, uint?> Installed,
        Func<DriverDetection.InstalledDevice, InfIndex.ModelEntry, uint, uint?> Candidate,
        Func<DriverDetection.InstalledDevice, bool> InstalledAsEstimated, uint SignerFloor = 0,
        Func<DriverDetection.InstalledDevice, DriverDetection.StoreDriver?>? Store = null);

    internal static Decision Select(DriverDetection.InstalledDevice device,
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete, WindowsRanks? windows = null,
        Func<InfIndex.ModelEntry, DriverDetection.InstalledDevice, bool>? sameInf = null)
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
        // date and version, and sameInf: the very same file), is never an upgrade: when it
        // ranks best, Windows marks that node as the installed driver and keeps it, even
        // where the WIM's copy matches a more specific ID. It still ranks, so a driver it
        // beats is not chosen either. On a tie it is kept when any winner is the installed
        // driver, so folder names cannot flip the result. Seen comparing with Windows' own
        // choice on real hardware (ties not measured: keeping is the conservative side).
        Decision Final(Decision decision) => decision.Candidate is not null && !device.Unbound &&
            (decision.Winners ?? [decision.Candidate]).Any(chosen => IsInstalledDriver(chosen, device, installedDate, installedVersion, sameInf))
            ? new(null, NotNewer) : decision;

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
                if (unasked.Length == 0)
                {
                    var final = Final(decision);
                    return final.Candidate is null ? final : AgainstStore(final);
                }
                foreach (var match in unasked)
                    if (!AskCandidate(match)) return new(null, CannotRankCandidate);
            }
            else if (!installedKnown)
            {
                if (!AskInstalled()) return new(null, CannotRankInstalled);
            }
            else return decision;
        }

        // Windows installs from the whole driver store, not from one offered package: when a
        // driver already there beats the WIM's best (lower rank; at equal rank newer date, then
        // higher version, Windows' order), the WIM's is not installed and Windows' own choice is.
        // The installed driver is in that list too. When Windows' store choice is the installed
        // package itself (same published INF, date and version) and it beats the WIM's best, the
        // rank the decision above used for it was too low: DEVPKEY_Device_DriverRank is the rank
        // at install time, and one INF can hold a node that matches the device's current IDs
        // better than the bound one. Windows would keep that package, so the WIM's is not
        // installed. On the bound node that is a keep, as pnputil /add-driver /install leaves
        // the device; on another node of the package Windows is asked to install, as a re-scan
        // would bind that node. The bound node is kept on an exact tie with the WIM's best too
        // (same rank, date and version): Windows installs only a better match than the driver
        // in place, so a tie leaves the installed one, as Final keeps it when the WIM offers it.
        Decision AgainstStore(Decision decision)
        {
            if (windows.Store is null) return decision;
            DriverDetection.StoreDriver? store;
            try { store = windows.Store(device); }
            catch (Exception error) when (error is Win32Exception or InvalidDataException) { return new(null, CannotRankStore); }
            if (store is null) return decision;
            var chosen = candidates.First(match => ReferenceEquals(match.Model, decision.Candidate) || match.Model == decision.Candidate);
            uint rank = RankOf(chosen);
            var version = chosen.Model.DriverVersion!;
            bool storeBetter = store.Rank < rank || store.Rank == rank &&
                (store.Date > version.Date!.Value || store.Date == version.Date.Value && store.Version > version.Version!.Value);
            bool tie = store.Rank == rank && store.Date == version.Date!.Value && store.Version == version.Version!.Value;
            bool installedPackage = !device.Unbound && string.Equals(Path.GetFileName(store.Inf), device.Inf, StringComparison.OrdinalIgnoreCase) &&
                store.Date == installedDate && store.Version == installedVersion;
            if (installedPackage && (storeBetter || tie) && SameSection(device.Section, store.Section)) return new(null, store.Rank < rank ? Outranked : NotNewer);
            return storeBetter ? new(null, StoreBetter, Store: store) : decision;
        }
    }

    // Windows names a store node by its base DDInstall section; a device records the decorated
    // one it installed (InfSection + InfSectionExt, where the extension is a platform decoration:
    // .NT, .NTamd64, .NTarm64.10.0...). A base section may itself contain a period, so only a
    // remainder that is such a decoration makes the two the same node. A device whose section
    // is unknown is taken to be on the store's node: nothing is installed then. The final check
    // after a store install uses the same test (FilteredDriverInstall), so a hand-off that left the
    // device on another node of the same package is not taken as verified.
    internal static bool SameSection(string? installed, string store) => installed is null ||
        installed.StartsWith(store, StringComparison.OrdinalIgnoreCase) &&
        (installed.Length == store.Length || installed.AsSpan(store.Length).StartsWith(".NT", StringComparison.OrdinalIgnoreCase));

    private static bool IsInstalledDriver(InfIndex.ModelEntry model, DriverDetection.InstalledDevice device, DateOnly installedDate, ulong installedVersion,
        Func<InfIndex.ModelEntry, DriverDetection.InstalledDevice, bool>? sameInf) =>
        device.OriginalInf is { Length: > 0 } original && device.Section is { Length: > 0 } section &&
        string.Equals(Path.GetFileName(model.Path), original, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(model.ActualInstallSection ?? model.InstallSection, section, StringComparison.OrdinalIgnoreCase) &&
        model.DriverVersion?.Date == installedDate && model.DriverVersion.Version == installedVersion &&
        // Last: it reads both files, so only for a candidate that already looks like the installed driver.
        (sameInf is null || sameInf(model, device));

    private const string CannotRankInstalled = "Windows could not rank the installed driver, so nothing was chosen.",
        CannotRankCandidate = "Windows could not rank a matching WIM driver, so nothing was chosen.",
        CannotRankStore = "Windows could not say which driver it would take from this PC's driver store, so nothing was chosen.";

    private static Decision Decide(DriverDetection.InstalledDevice device, IReadOnlyList<InMemoryDriverMatcher.Match> candidates,
        Func<InMemoryDriverMatcher.Match, uint> rankOf, uint? installedRank, DateOnly installedDate, ulong installedVersion, bool signed)
    {
        var (winners, bestRank, newestDate, newestVersion) = Rank(candidates, rankOf);
        string tie = Tie(winners.Length, "candidates", signed);
        if (device.Unbound) return new(winners[0], "No driver is installed yet." + tie, winners);

        // Compare against Windows' own rank for the bound driver. Lower is
        // better; at equal rank DriverVer decides, as in Windows.
        if (installedRank is uint installed)
        {
            if (installed < bestRank) return new(null, Outranked);
            if (installed > bestRank)
                return new(winners[0], "The WIM driver is a better match than the installed one." + tie, winners);
        }

        if (newestDate < installedDate || (newestDate == installedDate && newestVersion <= installedVersion))
            return new(null, NotNewer);
        return new(winners[0], "The WIM driver is newer than the installed one." + tie, winners);
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
        IReadOnlyList<InMemoryDriverMatcher.Match> matches, bool indexComplete, bool signersEqual = true,
        Func<InfIndex.ModelEntry, string>? packageKey = null)
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
            if (!signersEqual && candidates.Select(match => packageKey?.Invoke(match.Model) ?? match.Model.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            {
                result.Add(new(group.Key, null, "Several extensions in the WIM compete, and with \"Treat all digitally signed drivers equally\" off who signed each could decide; Windows cannot be asked to rank extensions, so none was chosen."));
                continue;
            }
            var (winners, _, _, _) = Rank(candidates);
            result.Add(new(group.Key, winners[0], "The best extension in the WIM for this device." + Tie(winners.Length, "extension candidates")));
        }
        return result;
    }

    // How to read the WIM's files by the paths its models carry (mount-style paths for
    // files inside the image, not on disk): one file's bytes, or null when unreadable or
    // too large; and the catalogs in the same folder as an INF, read one at a time as the
    // caller enumerates them, so a folder of many catalogs is never held in memory at once.
    internal sealed record InfFiles(Func<string, byte[]?> Read, Func<string, IEnumerable<byte[]>> CatalogsBeside);

    internal static InfFiles? FilesOf(DiscUtils.Wim.WimFileSystem? image, string? mount)
    {
        if (image is null || mount is null) return null;
        const long Max = 64L << 20;
        string Image(string path) => "\\" + path[mount.Length..];
        byte[]? ReadImage(string imagePath)
        {
            try
            {
                long length = image.GetFileLength(imagePath);
                if (length > Max) return null;
                using var stream = image.OpenFile(imagePath, FileMode.Open, FileAccess.Read);
                // Never more than the length the WIM declared, as WindowsRankSource.Copy reads.
                byte[] bytes = new byte[length];
                int total = 0;
                for (int read; (read = stream.Read(bytes, total, bytes.Length - total)) > 0;) total += read;
                return total == length && stream.ReadByte() < 0 ? bytes : null;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or NotSupportedException) { return null; }
        }
        return new(path => path.StartsWith(mount, StringComparison.OrdinalIgnoreCase) ? ReadImage(Image(path)) : null, path =>
        {
            try
            {
                if (!path.StartsWith(mount, StringComparison.OrdinalIgnoreCase)) return [];
                return image.GetFiles(Path.GetDirectoryName(Image(path)) ?? "\\", "*.cat", SearchOption.TopDirectoryOnly).ToArray()
                    .Select(ReadImage).Where(bytes => bytes is not null).Select(bytes => bytes!);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return []; }
        });
    }

    // True when the WIM's INF is byte for byte the INF Windows published for the
    // device (%windir%\INF\oemN.inf, or the inbox INF itself). A catalog-signed INF is
    // identical to its published copy, so a lookalike with the same name, section and
    // DriverVer but other contents is not the installed driver.
    internal static bool SameAsPublishedInf(InfIndex.ModelEntry model, DriverDetection.InstalledDevice device, InfFiles files)
    {
        const long Max = 32L << 20;
        try
        {
            if (device.Inf is not { Length: > 0 } published || published != Path.GetFileName(published)) return false;
            var installed = new FileInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", published));
            if (!installed.Exists || installed.Length > Max || files.Read(model.Path) is not { } wim || wim.Length != installed.Length) return false;
            return File.ReadAllBytes(installed.FullName).AsSpan().SequenceEqual(wim);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }

    // One key per package: the INF's bytes and every catalog beside it. Copies of one
    // package in several folders share a key; a copy with different or missing catalogs
    // does not. An unreadable INF is its own key.
    internal static string PackageKey(InfIndex.ModelEntry model, InfFiles files)
    {
        if (files.Read(model.Path) is not { } inf) return model.Path;
        string Hash(byte[] bytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        return Hash(inf) + "|" + string.Join(",", files.CatalogsBeside(model.Path).Select(Hash).Order(StringComparer.Ordinal));
    }

    // PackageKey once per INF path: the same extension is asked about for every device it
    // matches and on every pass, and the WIM does not change during a run.
    internal static Func<InfIndex.ModelEntry, string> CachedPackageKeys(InfFiles files)
    {
        var keys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        return model => keys.TryGetValue(model.Path, out string? key) ? key : keys[model.Path] = PackageKey(model, files);
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
