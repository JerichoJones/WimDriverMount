using System.ComponentModel;
using DiscUtils.Wim;

// Asks Windows to rank the WIM drivers that compete for a device. Windows needs
// a package's INF on disk with its catalog beside it to score the signature, so
// only those two files -- never the driver binaries -- are copied, for only the
// packages a device actually compares, once each. They go into a new folder only
// Administrators and SYSTEM can open (DokanInstaller.CreateStagingFolder), never
// the user's temp folder, so no program without administrator rights can swap a
// file or plant a link while Windows reads them (security review, 2026-11-13).
// The single in-memory pass over the WIM's INFs still finds every device's
// candidates; this only orders the ones it found.
internal sealed class WindowsRankSource : IDisposable
{
    // Over a limit, the package is unrankable and its devices are left undecided
    // rather than guessed. The INF limit is the one the INF index reads under
    // (WimFileSystem.CollectInfFiles). Catalogs measured on a Windows 11 driver
    // store of 888 packages: one each, the largest 5.3 MiB. The run limit stops a
    // WIM that names one large catalog from many INFs (stored once, so costing it
    // nothing) from filling the disk.
    private const long MaxInfBytes = 32L << 20, MaxCatalogBytes = 64L << 20, MaxRunBytes = 1L << 30;
    // Each copy must leave this much free: as much again as a whole run can
    // write, so staging never takes the drive below 1 GiB free, yet a small
    // system drive with a couple of GiB free still ranks. (Capture's 5 GiB
    // margin is sized for writing a WIM, not a few KB of INF and catalog.)
    private const long FreeAfterCopy = MaxRunBytes;
    internal const string FolderPrefix = "WimDriverMount-rank-";
    private readonly WimFileSystem image;
    private readonly string mount;
    private string? folder;
    private FileStream? held;
    private bool folderFailed;
    private long copied;
    private readonly Dictionary<string, string?> staged = new(StringComparer.OrdinalIgnoreCase);
    // A package's signer score, once Windows has scored it. It belongs to the
    // package, not the device, so one answer serves every device; it is kept
    // only when the rest of Windows' rank matched the estimate, as the
    // shortcut needs. Keyed by WIM path, or by the installed driver's published INF.
    private readonly Dictionary<string, uint> candidateSigner = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, uint> installedSigner = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool allSigningEqual;

    internal WindowsRankSource(WimFileSystem image, string mount)
    {
        this.image = image;
        this.mount = mount;
        allSigningEqual = AllSigningEqual();
    }

    // The staging folder, made on first use. Held open by a lock file, as
    // capture's is, so a later run's sweep leaves it alone; folders a killed run
    // left are swept here.
    internal string? Folder
    {
        get
        {
            if (folder is not null || folderFailed) return folder;
            try
            {
                DriverCapture.SweepInterrupted(Environment.SystemDirectory, DateTime.UtcNow.AddHours(-12), TextWriter.Null, FolderPrefix + "*");
                folder = DokanInstaller.CreateStagingFolder(FolderPrefix, "The folder used to rank drivers");
                held = new FileStream(Path.Combine(folder, DriverCapture.LockName), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { folderFailed = true; }
            return folderFailed ? null : folder;
        }
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

    // The model's INF and the catalog it names, copied from the WIM.
    // Returns the copy's INF path, or null if it could not be copied.
    internal string? Stage(string modelPath)
    {
        if (staged.TryGetValue(modelPath, out string? done)) return done;
        string? result = null;
        try
        {
            string root = mount.EndsWith('\\') ? mount : mount + "\\";
            if (!modelPath.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("INF is outside the WIM.");
            string imageInf = "\\" + modelPath[root.Length..];
            string imageFolder = Path.GetDirectoryName(imageInf) ?? "\\";
            if (Folder is not { } staging) throw new IOException("The folder used to rank drivers is unavailable.");
            // Made inside the private folder, so it inherits its permissions.
            // Numbered names are never reused, so anything already there (a
            // junction or link included) is refused, never followed.
            string target = Path.Combine(staging, staged.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (Path.Exists(target)) throw new IOException("The folder used to rank a driver already exists.");
            Directory.CreateDirectory(target);
            string inf = Path.Combine(target, Path.GetFileName(imageInf));
            Copy(imageInf, inf, MaxInfBytes);
            // Only the catalog the INF names for this platform: the one Windows
            // checks its signature against. None named, the package is unsigned,
            // as Windows will also find; named but absent, the same.
            if (DriverDetection.InfCatalog(inf) is { Length: > 0 } catalog)
            {
                if (Path.GetFileName(catalog) != catalog || catalog.Contains(':')) throw new InvalidDataException("The INF names an invalid catalog.");
                // By name, as Windows finds it on the mounted drive, in any letter case.
                string[] found = image.GetFiles(imageFolder, "*.cat", SearchOption.TopDirectoryOnly)
                    .Where(path => string.Equals(Path.GetFileName(path), catalog, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (found.Length > 1) throw new InvalidDataException("The INF's catalog name is ambiguous.");
                if (found.Length == 1) Copy(found[0], Path.Combine(target, catalog), MaxCatalogBytes);
            }
            result = inf;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or Win32Exception) { }
        staged[modelPath] = result;
        return result;
    }

    // Into a new file only, refusing any name already there. A plain CreateNew
    // follows a symbolic link to a file not there yet and creates its target, so
    // the link itself is opened (FILE_FLAG_OPEN_REPARSE_POINT), as the recovery
    // store's records are.
    internal void Copy(string imagePath, string destination, long maxBytes)
    {
        const uint GenericWrite = 0x40000000, CreateNew = 1, OpenReparsePoint = 0x00200000;
        long length = image.GetFileLength(imagePath);
        if (length > maxBytes) throw new InvalidDataException("File is too large to rank.");
        if (copied + length > MaxRunBytes) throw new InvalidDataException("Too much has been copied to rank drivers in this run.");
        if (new DriveInfo(Path.GetPathRoot(destination)!).AvailableFreeSpace < length + FreeAfterCopy)
            throw new IOException("Not enough free space to rank drivers.");
        copied += length;
        using var source = image.OpenFile(imagePath, FileMode.Open, FileAccess.Read);
        var handle = TrustedFile.OpenFileW(destination, GenericWrite, 0, IntPtr.Zero, CreateNew, OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("A file used to rank drivers could not be created: " + new Win32Exception(error).Message);
        }
        using var target = new FileStream(handle, FileAccess.Write);
        byte[] buffer = new byte[81920];
        long total = 0;
        for (int read; (read = source.Read(buffer)) > 0;)
        {
            // Never more than the length the WIM declared.
            if ((total += read) > length) throw new InvalidDataException("A WIM file is longer than its entry says.");
            target.Write(buffer, 0, read);
        }
    }

    public void Dispose()
    {
        held?.Dispose();
        try { if (folder is not null && Directory.Exists(folder)) DeleteTree(folder); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }

    // A link is removed as a link, never entered. Directory.Delete(recursive)
    // removes a junction too, but first tries it as a volume mount point, fails
    // with "The parameter is incorrect" and leaves the folder behind.
    private static void DeleteTree(string path)
    {
        foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos())
        {
            if (entry is DirectoryInfo directory && (directory.Attributes & FileAttributes.ReparsePoint) == 0) DeleteTree(directory.FullName);
            else entry.Delete();
        }
        Directory.Delete(path);
    }
}
