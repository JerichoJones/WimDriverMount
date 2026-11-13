using System.ComponentModel;
using DiscUtils.Wim;

// Asks Windows to rank the WIM drivers that compete for a device. Windows needs
// a package's INF on disk with its catalogs beside it to score the signature, so
// only those files -- never the driver binaries -- are copied, for only the
// packages a device actually compares, once each, into a private temporary
// folder removed afterwards. The single in-memory pass over the WIM's INFs
// still finds every device's candidates; this only orders the ones it found.
internal sealed class WindowsRankSource : IDisposable
{
    // A catalog larger than this is not copied; the package is then unrankable
    // and its devices are left undecided rather than guessed.
    private const int MaxCatalogBytes = 256 * 1024 * 1024;
    private readonly WimFileSystem image;
    private readonly string mount, folder;
    private readonly Dictionary<string, string?> staged = new(StringComparer.OrdinalIgnoreCase);
    // A package's signer score, once Windows has scored it. It belongs to the
    // package, not the device, so one answer serves every device; it is kept
    // only when the rest of Windows' rank matched the estimate, as the
    // shortcut needs. Keyed by WIM path, or by the installed driver's published INF.
    private readonly Dictionary<string, uint> candidateSigner = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, uint> installedSigner = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool allSigningEqual;

    private WindowsRankSource(WimFileSystem image, string mount)
    {
        this.image = image;
        this.mount = mount;
        folder = Path.Combine(Path.GetTempPath(), "WimDriverMount-rank-" + Guid.NewGuid().ToString("N"));
        allSigningEqual = AllSigningEqual();
    }

    // Null when the index was not read from a WIM (tests).
    internal static WindowsRankSource? For(InfCollectedIndex index) =>
        index.Image is { } image && index.Mount is { } mount ? new(image, mount) : null;

    // The lowest signer score Windows gives any driver in this policy state,
    // per the WDK's SIGNERSCORE_* values (Microsoft's "Driver Matching
    // Criteria"): with the policy on, 00 for every signed driver; with it off,
    // 0D for inbox, WHQL and other Microsoft signatures, 0F for Authenticode,
    // 80 and up unsigned. Measured the same, both states.
    private uint SignerFloor => allSigningEqual ? 0u : 0x0D000000u;

    internal PerDeviceDriverSelection.WindowsRanks Ranks => new(Installed, Candidate, InstalledAsEstimated, SignerFloor);

    // The "Treat all digitally signed drivers equally" policy (DeviceInstallation.admx:
    // 1 enabled, 0 disabled). Not configured behaves as enabled since Windows 7.
    // Checked against Windows' own ranks in all three states.
    private static bool AllSigningEqual()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings");
        return key?.GetValue("AllSigningEqual") is not int value || value != 0;
    }

    // An inbox driver (an INF that is not oemN.inf) is signed by Windows
    // (SIGNERSCORE_INBOX, 0x0D000003), which is the floor in either policy
    // state: its rank is then exactly the device property's plus the floor,
    // with nothing to ask. Measured on all 42 inbox drivers of a test machine.
    private static bool InstalledAsEstimated(DriverDetection.InstalledDevice device) =>
        device.Inf is { Length: > 0 } inf &&
        !System.Text.RegularExpressions.Regex.IsMatch(inf, @"^oem\d+\.inf$", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private uint? Installed(DriverDetection.InstalledDevice device)
    {
        uint? estimate = device.Rank is uint full ? full & 0x00FFFFFF : null;
        // The published INF, date and version name one package; an install
        // mid-run binds a different one.
        string key = $"{device.Inf}|{device.Date}|{device.Version}";
        if (estimate is uint e && installedSigner.TryGetValue(key, out uint signer)) return signer << 24 | e;
        uint? rank = Try(() => DriverDetection.InstalledDriverRank(device.InstanceId));
        if (rank is uint r && estimate is uint est && (r & 0x00FFFFFF) == est) installedSigner[key] = r >> 24;
        return rank;
    }

    private uint? Candidate(DriverDetection.InstalledDevice device, InfIndex.ModelEntry model, uint estimate)
    {
        if (candidateSigner.TryGetValue(model.Path, out uint signer)) return signer << 24 | estimate;
        if (Stage(model.Path) is not { } inf) return null;
        uint? rank = Try(() => DriverDetection.CandidateDriverRank(device.InstanceId, inf, model));
        if (rank is uint r && (r & 0x00FFFFFF) == estimate) candidateSigner[model.Path] = r >> 24;
        return rank;
    }

    private static uint? Try(Func<uint?> rank)
    {
        try { return rank(); }
        catch (Exception error) when (error is Win32Exception or InvalidDataException) { return null; }
    }

    // The model's INF and every catalog in its folder, copied from the WIM.
    // Returns the copy's INF path, or null if it could not be copied.
    private string? Stage(string modelPath)
    {
        if (staged.TryGetValue(modelPath, out string? done)) return done;
        string? result = null;
        try
        {
            string root = mount.EndsWith('\\') ? mount : mount + "\\";
            if (!modelPath.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("INF is outside the WIM.");
            string imageInf = "\\" + modelPath[root.Length..];
            string imageFolder = Path.GetDirectoryName(imageInf) ?? "\\";
            string target = Path.Combine(folder, staged.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Directory.CreateDirectory(target);
            Copy(imageInf, Path.Combine(target, Path.GetFileName(imageInf)), int.MaxValue);
            foreach (string catalog in image.GetFiles(imageFolder, "*.cat", SearchOption.TopDirectoryOnly))
                Copy(catalog, Path.Combine(target, Path.GetFileName(catalog)), MaxCatalogBytes);
            result = Path.Combine(target, Path.GetFileName(imageInf));
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException) { }
        staged[modelPath] = result;
        return result;
    }

    private void Copy(string imagePath, string destination, int maxBytes)
    {
        if (image.GetFileLength(imagePath) > maxBytes) throw new InvalidDataException("File is too large to rank.");
        using var source = image.OpenFile(imagePath, FileMode.Open, FileAccess.Read);
        using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        source.CopyTo(target);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
