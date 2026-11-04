// --capture-drivers: this PC's third-party driver packages into a new WIM, written by
// Windows' own wimgapi.dll and read back through this program's reader before success.
//
// Which packages (Jericho, 2026-11-04): the oemNN.inf packages that present and non-present
// ("ghost") hardware devices, printers and scanners use, as their driver or as an
// extension INF, with their CopyINF sub-packages and print-queue drivers. Packages only
// app-made devices or services use are left out and named; so are superseded versions. Only new WIMs are written; an existing file is refused
// (a failed append would leave dead bytes in it). Compression: none, fast (XPRESS) or
// maximum (LZX), the kinds the reader already handles. Findings behind each step are in
// WIMDriveMount-private\RESEARCH-0.8.0-driver-capture.md.
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

internal static partial class DriverCapture
{
    internal enum Compression : uint { None = 0, Fast = 1, Maximum = 2 }

    internal static Compression ParseCompression(string value) => value.ToLowerInvariant() switch
    {
        "none" => Compression.None,
        "fast" => Compression.Fast,
        "maximum" => Compression.Maximum,
        _ => throw new ArgumentException("--compression takes none, fast or maximum."),
    };

    // Via: why it is captured when no device uses it ("printer driver ...", "service ...",
    // "sub-package of ..."); null when a device does.
    internal sealed record Package(string Inf, string Folder, long Bytes, int Files, string? Via = null);

    // Kept free on each volume beyond what the capture needs (project rule).
    internal const long Margin = 5L << 30;
    // wimgapi's temporary files: 13-66 MB measured for 300-450 MB of drivers.
    internal const long TempAllowance = 256L << 20;

    internal static string Store => Path.Combine(Environment.SystemDirectory, "DriverStore", "FileRepository");

    [GeneratedRegex(@"^oem\d+\.inf$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    internal static partial Regex PublishedName();

    internal static int Run(string wim, Compression compression, bool whatIf, TextWriter output, TextWriter errors)
    {
        try
        {
            ValidateTarget(wim);
            var started = System.Diagnostics.Stopwatch.StartNew();
            var (inUse, appMade, devices) = DriverDetection.ThirdPartyInfsInUse();
            var (printers, services, unknown, serviceImages) = OtherUses();
            foreach (string note in unknown) errors.WriteLine("WARNING: " + SafeText.Message(note));
            var leftOutUses = new Dictionary<string, string>(services, StringComparer.OrdinalIgnoreCase);
            foreach (var (inf, device) in appMade) leftOutUses.TryAdd(inf, $"app-made device {device}");
            var (packages, leftOut, missing, notKept, unused, unusedBytes) = FindPackages(inUse, Store, printers, leftOutUses, serviceImages);
            output.WriteLine($"Devices using third-party drivers (present or not): {devices}.");
            foreach (string inf in missing)
                errors.WriteLine($"WARNING: a device uses {inf}, but it is not in the driver store; it is left out.");
            foreach (string name in notKept)
                output.WriteLine($"NOTE: sub-package {SafeText.Path(name)} is not in this PC's driver store, so it cannot be captured.");
            foreach (string note in UncapturedIncludes(packages, Store, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF")))
                errors.WriteLine("WARNING: " + note);
            void ListLeftOut()
            {
                if (leftOut.Count == 0) return;
                output.WriteLine($"Left out, as no hardware needs them ({Count(leftOut.Count, "package")}, {Size(leftOut.Sum(p => p.Bytes))}):");
                foreach (var p in leftOut.OrderBy(p => p.Folder, StringComparer.OrdinalIgnoreCase))
                    output.WriteLine($"  {p.Inf,-11} {SafeText.Path(p.Folder)}  {Size(p.Bytes)}  ({SafeText.Message(p.Via!)})");
                output.WriteLine("  App-made: the device hangs from no hardware in the device tree (Windows has no flag for this; printers and scanners are kept).");
            }
            void ListUnused()
            {
                if (unused > 0)
                    output.WriteLine($"Also not captured: {Count(unused, "third-party package")} ({Size(unusedBytes)}) that nothing on this PC uses " +
                        "(older versions, drivers added but never used, drivers of devices removed from this PC).");
            }
            if (packages.Count == 0)
            {
                ListLeftOut();
                ListUnused();
                output.WriteLine("No third-party driver packages are in use on this PC, so there is nothing to capture. No file was written.");
                return 0;
            }
            long bytes = packages.Sum(p => p.Bytes);
            int files = packages.Sum(p => p.Files);
            output.WriteLine("To capture:");
            foreach (var p in packages.OrderBy(p => p.Folder, StringComparer.OrdinalIgnoreCase))
                output.WriteLine($"  {p.Inf,-11} {SafeText.Path(p.Folder)}  {Size(p.Bytes)}" + (p.Via is null ? "" : $"  ({SafeText.Message(p.Via)})"));
            output.WriteLine($"{Count(packages.Count, "driver package")}, {Count(files, "file")}, {Size(bytes)} before compression.");
            ListLeftOut();
            ListUnused();
            string? shortage = SpaceShortage(wim, bytes);
            if (shortage is not null) { errors.WriteLine("WIM Driver Mount: " + shortage); return 1; }
            string mode = compression == Compression.None ? "no compression" : $"{compression.ToString().ToLowerInvariant()} compression";
            if (whatIf)
            {
                // That the folder is the one named (no link, short name or mount point). Whether it
                // can be written is left to the real run: an unelevated preview cannot tell for a
                // folder only administrators may write (red team 8).
                OpenTargetFolder(Path.GetDirectoryName(wim)!, write: false).Dispose();
                output.WriteLine($"WHATIF: would write {SafeText.Path(wim)} ({mode}). Nothing was written.");
                return 0;
            }
            var (sha256, size) = WriteAndVerify(wim, compression, mode, packages, output, errors);
            output.WriteLine($"Captured {Count(packages.Count, "driver package")} ({Count(files, "file")}, {Size(bytes)}) into {SafeText.Path(wim)}, " +
                $"{Size(size)}, in {started.Elapsed.TotalSeconds:F0} s. Every file read back matches its original, and the copy matches the WIM checked.");
            output.WriteLine($"SHA-256 of the WIM: {sha256}");
            output.WriteLine("To install them on another PC, refusing a WIM changed since this capture:");
            // SafeText.Argument: PowerShell also reads typographic quotes as quotes (red team 7).
            output.WriteLine($"  .\\WimDriverMount.exe --wim {SafeText.Argument(wim)} --wim-sha256 {sha256} --install-drivers");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException or InvalidDataException or OperationCanceledException)
        {
            errors.WriteLine($"WIM Driver Mount: capture failed: {SafeText.Message(ex.Message)}");
            return 1;
        }
    }

    // Written, with wimgapi's working files, and checked in a new folder only Administrators
    // and SYSTEM can open, then copied into the target, opened before the capture (OpenTarget).
    // Nothing is created or deleted by a path anyone else can change: the private folder is
    // the only thing deleted by path (security review, 2026-11-04).
    private static (string Sha256, long Size) WriteAndVerify(string wim, Compression compression, string mode, List<Package> packages, TextWriter output, TextWriter errors)
    {
        var state = new CaptureState(Store, new HashSet<string>(packages.Select(p => p.Folder), StringComparer.OrdinalIgnoreCase), output);
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; state.Cancelled = true; };
        Console.CancelKeyPress += cancel;
        SweepInterrupted(Environment.SystemDirectory, DateTime.UtcNow.AddHours(-12), output);
        using Target target = OpenTarget(wim);
        output.WriteLine($"Writing the WIM ({mode})...");
        string staging = DokanInstaller.CreateStagingFolder("WimDriverMount-capture-", "The folder used to write the WIM");
        // Held unshared for the whole capture, so a sweep by another capture leaves this
        // folder alone however long it runs; the handle closes when this process ends.
        FileStream? held = null;
        try
        {
            held = new FileStream(Path.Combine(staging, LockName), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
            string staged = Path.Combine(staging, "capture.wim"), temp = Path.Combine(staging, "temp");
            Directory.CreateDirectory(temp);
            Write(staged, temp, compression, packages.Count, state);
            if (state.Cancelled) throw new OperationCanceledException("Cancelled with Ctrl+C.");
            output.WriteLine("Reading every file back through this program's reader...");
            Verify(staged, packages, state);
            long size = new FileInfo(staged).Length;
            string folder = Path.GetDirectoryName(wim)!;
            long free = FreeBytes(folder);
            if (free < size + Margin)
                throw new IOException($"not enough free space for {SafeText.Path(folder)}: the WIM is {Size(size)}, plus {Size(Margin)} kept free, and {Size(free)} is free. Nothing was written there.");
            output.WriteLine($"Copying it to {SafeText.Path(wim)}...");
            return (Fill(target, staged, () => state.Cancelled), size);
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
            held?.Dispose();
            try { Directory.Delete(staging, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { errors.WriteLine($"WARNING: the working folder {SafeText.Path(staging)} could not be deleted ({SafeText.Message(ex.Message)}); delete it yourself."); }
        }
    }

    private const string LockName = "capture.lock";

    // Working folders a killed capture left (only administrators can make them there):
    // older than the cutoff, and with no lock a running capture holds. Its lock cannot be
    // deleted while held; 0.7.12's folders have none.
    internal static void SweepInterrupted(string parent, DateTime cutoffUtc, TextWriter output)
    {
        foreach (var old in new DirectoryInfo(parent).EnumerateDirectories("WimDriverMount-capture-*"))
            if ((old.Attributes & FileAttributes.ReparsePoint) == 0 && old.CreationTimeUtc < cutoffUtc)
                try
                {
                    File.Delete(Path.Combine(old.FullName, LockName));
                    old.Delete(recursive: true);
                    output.WriteLine($"Removed {SafeText.Path(old.FullName)}, left by an interrupted capture.");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    // The target is made new inside its folder, which is opened once (links followed) and must
    // resolve to exactly the folder named, so no link anywhere in the path can redirect it. The
    // file is created relative to that open folder, never by path, and, if the copy or its read
    // back fails, deleted through its own handle. Held without delete sharing, the folder
    // cannot be renamed meanwhile. Opened before the capture starts, so a target that cannot
    // be written (a link, read-only media, the name taken meanwhile) fails at once, not after
    // the WIM is written and checked (red team 7).
    internal sealed class Target(SafeFileHandle directory, FileStream file, string wim) : IDisposable
    {
        internal readonly FileStream File = file;
        internal readonly string Wim = wim;
        public void Dispose() { File.Dispose(); directory.Dispose(); }
    }

    // The target's folder, opened and checked to be exactly the folder named.
    // write: false only checks which folder it is (for --whatif).
    internal static SafeFileHandle OpenTargetFolder(string folder, bool write = true)
    {
        const uint Traverse = 0x20, AddFile = 0x2, ReadAttributes = 0x80, Synchronize = 0x100000;
        const uint ShareRead = 1, ShareWrite = 2, OpenExisting = 3, BackupSemantics = 0x02000000, Anonymous = 0x00100000;
        SafeFileHandle directory = TrustedFile.OpenFileW(folder, (write ? AddFile : 0) | Traverse | ReadAttributes | Synchronize, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, BackupSemantics | Anonymous, IntPtr.Zero);
        if (directory.IsInvalid) { int error = Marshal.GetLastWin32Error(); directory.Dispose(); throw new Win32Exception(error, $"Cannot open {folder}: {new Win32Exception(error).Message}"); }
        try
        {
            string real = TrustedFile.FinalPath(directory);
            if (!string.Equals(real.TrimEnd('\\'), folder.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException($"{folder} resolves to {real} (a short name, link or mount point). Name the real folder.");
            return directory;
        }
        catch { directory.Dispose(); throw; }
    }

    internal static Target OpenTarget(string wim)
    {
        SafeFileHandle directory = OpenTargetFolder(Path.GetDirectoryName(wim)!);
        try
        {
            SafeFileHandle file = CreateRelative(directory, Path.GetFileName(wim));
            try
            {
                // Deleted when closed, however this process ends (a closed window, Task
                // Manager), until it has been read back and matches.
                SetDelete(file, true, wim);
                return new Target(directory, new FileStream(file, FileAccess.ReadWrite, 1 << 20), wim);
            }
            catch { file.Dispose(); throw; }
        }
        catch { directory.Dispose(); throw; }
    }

    // Copies the staged WIM into the opened target, reads it back, and keeps it. Returns the
    // copy's SHA-256.
    internal static string Fill(Target target, string staged, Func<bool> cancelled)
    {
        var file = target.File;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using (var source = new FileStream(staged, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
        {
            byte[] buffer = new byte[1 << 20];
            for (int read; (read = source.Read(buffer)) > 0;)
            {
                if (cancelled()) throw new OperationCanceledException("Cancelled with Ctrl+C.");
                hash.AppendData(buffer, 0, read);
                file.Write(buffer, 0, read);
            }
        }
        file.Flush(flushToDisk: true);
        byte[] written = hash.GetHashAndReset();
        file.Position = 0;
        if (!SHA256.HashData(file).AsSpan().SequenceEqual(written))
            throw new InvalidDataException($"{target.Wim} does not read back as written.");
        SetDelete(file.SafeFileHandle, false, target.Wim);
        return Convert.ToHexString(written);
    }

    internal static string CopyToTarget(string staged, string wim, Func<bool> cancelled)
    {
        using var target = OpenTarget(wim);
        return Fill(target, staged, cancelled);
    }
    private static void SetDelete(SafeFileHandle file, bool delete, string wim)
    {
        byte value = delete ? (byte)1 : (byte)0;
        if (!SetFileInformationByHandle(file, 4 /* FileDispositionInfo */, ref value, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Windows could not {(delete ? "mark" : "keep")} {wim}.");
    }

    // A new file (fails if anything has the name, a link included) inside an open folder.
    private static SafeFileHandle CreateRelative(SafeFileHandle directory, string name)
    {
        const uint GenericReadWrite = 0xC0000000, Delete = 0x00010000, Synchronize = 0x00100000;
        const uint CaseInsensitive = 0x40, Normal = 0x80, Create = 2, NonDirectory = 0x40, SynchronousIo = 0x20, OpenReparsePoint = 0x00200000;
        IntPtr buffer = Marshal.StringToHGlobalUni(name);
        bool added = false;
        try
        {
            directory.DangerousAddRef(ref added);
            var text = new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = buffer };
            IntPtr textPointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            try
            {
                Marshal.StructureToPtr(text, textPointer, false);
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(), RootDirectory = directory.DangerousGetHandle(),
                    ObjectName = textPointer, Attributes = CaseInsensitive,
                };
                int status = NtCreateFile(out SafeFileHandle file, GenericReadWrite | Delete | Synchronize, ref attributes, out _, IntPtr.Zero,
                    Normal, 0, Create, NonDirectory | SynchronousIo | OpenReparsePoint, IntPtr.Zero, 0);
                if (status < 0)
                {
                    file.Dispose();
                    int error = RtlNtStatusToDosError(status);
                    throw new Win32Exception(error, $"Cannot create {name}: {new Win32Exception(error).Message}");
                }
                return file;
            }
            finally { Marshal.FreeHGlobal(textPointer); }
        }
        finally
        {
            if (added) directory.DangerousRelease();
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public IntPtr Status, Information; }
    [DllImport("ntdll.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes, out IoStatusBlock status,
        IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr extendedAttributes, uint extendedAttributesLength);
    [DllImport("ntdll.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, ref byte info, uint size);
    // A new file in an existing folder, named .wim, on a plain path.
    internal static void ValidateTarget(string wim)
    {
        if (wim.StartsWith(@"\\?\", StringComparison.Ordinal) || wim.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw new ArgumentException(@"--capture-drivers does not accept a device or extended path beginning \\?\ or \\.\.");
        string root = Path.GetPathRoot(wim) ?? throw new ArgumentException("--capture-drivers needs a full path.");
        DokanSource.ValidateFileComponents(wim, root, "--capture-drivers");
        // "file.txt:s.wim" would write into a hidden stream of an existing file.
        if (wim[root.Length..].Contains(':'))
            throw new ArgumentException("--capture-drivers takes a plain file path, without ':' after the drive.");
        if (!string.Equals(Path.GetExtension(wim), ".wim", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(@"--capture-drivers writes a .wim file, such as C:\Drivers\this-pc.wim.");
        if (File.Exists(wim) || Directory.Exists(wim))
            throw new ArgumentException($"{wim} already exists. Capture writes a new WIM only; choose a new name.");
        string? folder = Path.GetDirectoryName(wim);
        if (folder is null || !Directory.Exists(folder))
            throw new ArgumentException($"The folder for {wim} does not exist.");
    }

    // Package folders whose INF Windows published as one of the wanted oemNN.inf names, plus
    // their sub-packages: a package can install others with CopyINF (AMD's display driver
    // installs amdwin-*.inf that way), which no device need use. Those are followed, again
    // and again, to every third-party store package of that INF name. A sub-package Windows
    // did not keep on this PC cannot be captured; it is returned in NotKept to be named.
    // SetupGetInfPublishedNameW maps a store INF to its published name (checked on a PC with
    // 163 packages: all found, no errors).
    // printers: packages a print queue uses without a device, by store folder name or
    // oemNN.inf, with the reason to show. They are captured.
    // leftOutUses: packages in use that no hardware needs (app-made devices, services), by
    // oemNN.inf or folder name, with the reason; the oemNN.inf (a device's) is asked first. They are left out and returned in LeftOut,
    // unless something captured needs them too.
    // serviceImages: services' programs outside the store; a package holding a file of the
    // same name and content is in use by that service (left out like the rest). The
    // service's display name (@oemNN.inf,...) is no proof: Windows reuses oemNN names.
    // Unused: third-party packages nothing above uses (older versions, drivers staged but never
    // used, devices removed from this PC), by count and size; they are not captured.
    internal static (List<Package> Packages, List<Package> LeftOut, List<string> Missing, List<string> NotKept, int Unused, long UnusedBytes) FindPackages(IReadOnlySet<string> wanted, string store,
        IReadOnlyDictionary<string, string>? printers = null, IReadOnlyDictionary<string, string>? leftOutUses = null,
        IReadOnlyList<(string Path, string Service)>? serviceImages = null)
    {
        var thirdParty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // folder -> oemNN.inf
        var folders = Directory.GetDirectories(store);
        foreach (string folder in folders)
        {
            foreach (string inf in Directory.EnumerateFiles(folder, "*.inf"))
            {
                var name = new char[MaxPath];
                if (!SetupGetInfPublishedNameW(inf, name, (uint)name.Length, out _)) continue;
                string published = Path.GetFileName(new string(name).TrimEnd('\0'));
                if (PublishedName().IsMatch(published)) thirdParty.TryAdd(folder, published);
            }
        }
        string? Use(IReadOnlyDictionary<string, string>? uses, string folder) =>
            uses is not null && (uses.TryGetValue(thirdParty[folder], out string? why) || uses.TryGetValue(Path.GetFileName(folder), out why)) ? why : null;
        var chosen = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase); // folder -> why, null for a device's
        var leftOut = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string folder in thirdParty.Keys)
        {
            if (wanted.Contains(thirdParty[folder])) chosen.TryAdd(folder, null);
            else if (Use(printers, folder) is { } printer) chosen.TryAdd(folder, printer);
            else if (Use(leftOutUses, folder) is { } why) leftOut.TryAdd(folder, why);
        }
        if (serviceImages is { Count: > 0 })
        {
            var byName = serviceImages.GroupBy(s => Path.GetFileName(s.Path), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            foreach (string folder in thirdParty.Keys.Where(f => !chosen.ContainsKey(f) && !leftOut.ContainsKey(f)))
                foreach (var file in new DirectoryInfo(folder).EnumerateFiles("*", AllFiles))
                    if (byName.TryGetValue(file.Name, out var services))
                        foreach (var (image, service) in services)
                            if (!leftOut.ContainsKey(folder) && SameContent(image, file.FullName)) leftOut.TryAdd(folder, $"service {service}");
        }
        var notKept = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>(chosen.Keys);
        while (queue.Count > 0)
        {
            string parent = queue.Dequeue();
            foreach (string child in CopyInfNames(parent))
            {
                var matches = folders.Where(f => Path.GetFileName(f).StartsWith(child + "_", StringComparison.OrdinalIgnoreCase)).ToList();
                if (matches.Count == 0) { notKept.Add($"{child} (named by {Path.GetFileName(parent)})"); continue; }
                // CopyINF names a file, not a version. A version already chosen covers it;
                // otherwise the newest third-party one, as Windows ranks by DriverVer (or
                // every one, if a DriverVer cannot be read). Older copies stay out.
                var candidates = matches.Where(thirdParty.ContainsKey).ToList();
                if (candidates.Count == 0 || candidates.Any(chosen.ContainsKey)) continue;
                var versions = candidates.Select(c => (Folder: c, Version: DriverVer(c))).ToList();
                var take = versions.Any(v => v.Version is null) ? candidates
                    : [versions.MaxBy(v => v.Version!.Value)!.Folder];
                foreach (string folder in take)
                    if (chosen.TryAdd(folder, "sub-package of " + Path.GetFileName(parent))) queue.Enqueue(folder);
            }
        }
        foreach (string folder in chosen.Keys) leftOut.Remove(folder);
        Package Measure(string folder, string? via)
        {
            long bytes = 0; int files = 0;
            foreach (var file in new DirectoryInfo(folder).EnumerateFiles("*", AllFiles)) { bytes += file.Length; files++; }
            return new Package(thirdParty[folder].ToLowerInvariant(), Path.GetFileName(folder), bytes, files, via);
        }
        var packages = chosen.Select(c => Measure(c.Key, c.Value)).ToList();
        var found = chosen.Keys.Select(f => thirdParty[f]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missing = wanted.Where(inf => !found.Contains(inf)).OrderBy(i => i, StringComparer.OrdinalIgnoreCase).ToList();
        var unused = thirdParty.Keys.Where(f => !chosen.ContainsKey(f) && !leftOut.ContainsKey(f)).Select(f => Measure(f, null)).ToList();
        return (packages, leftOut.Select(l => Measure(l.Key, l.Value)).ToList(), missing, [.. notKept], unused.Count, unused.Sum(u => u.Bytes));
    }

    // Driver packages in use without a device, keyed by store folder name or oemNN.inf:
    // - Printers: a printer driver that a print queue uses (a printer added by IP address
    //   has no device; "Microsoft Print to PDF" is one): EnumPrinters, then
    //   EnumPrinterDrivers' INF path. These are captured.
    // - Services: a service (a filter or other non-Plug and Play driver, or a component's
    //   service) whose program is inside a store package (its documented ImagePath). No
    //   hardware needs these, so they are left out and named (Jericho, 2026-11-04).
    // Anything that could not be read is returned in Unknown, to be warned about.
    // ServiceImages: the programs of services outside the store (many packages copy their
    // driver to System32\drivers), for FindPackages to match to a package by name and hash.
    internal static (Dictionary<string, string> Printers, Dictionary<string, string> Services, List<string> Unknown, List<(string Path, string Service)> ServiceImages) OtherUses()
    {
        var printers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unknown = new List<string>();
        var images = new List<(string Path, string Service)>();
        using (var serviceKeys = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
        {
            foreach (string name in serviceKeys?.GetSubKeyNames() ?? [])
            {
                try
                {
                    using var key = serviceKeys!.OpenSubKey(name);
                    if (key?.GetValue("ImagePath", null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames) is not string image) continue;
                    if (StoreFolder().Match(image) is { Success: true } m) services.TryAdd(m.Groups[1].Value, $"service {name}");
                    else if (ServiceImagePath(image) is { } path) images.Add((path, name));
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
                { unknown.Add($"service {name} could not be read, so a driver it runs may be missing."); }
            }
        }
        try
        {
            // Read out while each buffer is held: its strings point into it.
            var queues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Spooler((IntPtr buffer, uint size, out uint needed, out uint count) => EnumPrintersW(2 | 4 /* local, connections */, null, 2, buffer, size, out needed, out count),
                Marshal.SizeOf<PrinterInfo2>(), entry =>
                {
                    if (Marshal.PtrToStringUni(Marshal.PtrToStructure<PrinterInfo2>(entry).DriverName) is { } driver) queues.Add(driver);
                });
            Spooler((IntPtr buffer, uint size, out uint needed, out uint count) => EnumPrinterDriversW(null, null, 8, buffer, size, out needed, out count),
                Marshal.SizeOf<DriverInfo8>(), entry =>
                {
                    var info = Marshal.PtrToStructure<DriverInfo8>(entry);
                    if (Marshal.PtrToStringUni(info.Name) is not { } driver || !queues.Contains(driver)) return;
                    string inf = Marshal.PtrToStringUni(info.InfPath) ?? "";
                    if (StoreFolder().Match(inf) is { Success: true } m) printers.TryAdd(m.Groups[1].Value, $"printer driver {driver}");
                    else if (PublishedName().IsMatch(Path.GetFileName(inf))) printers.TryAdd(Path.GetFileName(inf), $"printer driver {driver}");
                });
        }
        catch (Win32Exception ex)
        { unknown.Add($"the printers could not be listed ({ex.Message}), so a printer driver used by no device may be missing."); }
        return (printers, services, unknown, images);
    }

    // A service's program as a full path, from its ImagePath: quoted or followed by
    // arguments, \SystemRoot\..., \??\C:\..., %SystemRoot%\..., or relative to Windows
    // (System32\drivers\x.sys). Null when it is none of these or not a file.
    internal static string? ServiceImagePath(string image)
    {
        string path = image.Trim();
        if (path.StartsWith('"'))
        {
            int end = path.IndexOf('"', 1);
            if (end < 0) return null;
            path = path[1..end];
        }
        else if (path.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase) is >= 0 and int cut) path = path[..(cut + 4)];
        path = Environment.ExpandEnvironmentVariables(path);
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = Path.Combine(windows, path[12..]);
        else if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        else if (!Path.IsPathRooted(path)) path = Path.Combine(windows, path);
        return Path.IsPathFullyQualified(path) && File.Exists(path) ? path : null;
    }

    private static bool SameContent(string first, string second)
    {
        try
        {
            using var a = new FileStream(first, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var b = new FileStream(second, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return a.Length == b.Length && SHA256.HashData(a).AsSpan().SequenceEqual(SHA256.HashData(b));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private delegate bool SpoolerCall(IntPtr buffer, uint size, out uint needed, out uint count);

    // Runs a winspool enumeration with a buffer sized by asking first, and hands each
    // entry to `read` while the buffer is held.
    private static void Spooler(SpoolerCall call, int entrySize, Action<IntPtr> read)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (call(IntPtr.Zero, 0, out uint needed, out _)) return; // Nothing to list.
            int error = Marshal.GetLastWin32Error();
            if (error != InsufficientBuffer || needed == 0) throw new Win32Exception(error);
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (call(buffer, needed, out _, out uint count))
                {
                    for (int i = 0; i < count; i++) read(buffer + i * entrySize);
                    return;
                }
                error = Marshal.GetLastWin32Error();
                if (error != InsufficientBuffer) throw new Win32Exception(error); // Otherwise it grew meanwhile: ask again.
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new Win32Exception(InsufficientBuffer, "The list kept growing while it was read.");
    }

    private const int InsufficientBuffer = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct PrinterInfo2
    {
        public IntPtr ServerName, PrinterName, ShareName, PortName, DriverName, Comment, Location, DevMode, SepFile, PrintProcessor, Datatype, Parameters, SecurityDescriptor;
        public uint Attributes, Priority, DefaultPriority, StartTime, UntilTime, Status, Jobs, AveragePpm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DriverInfo8
    {
        public uint Version;
        public IntPtr Name, Environment, DriverPath, DataFile, ConfigFile, HelpFile, DependentFiles, MonitorName, DefaultDataType, PreviousNames;
        public uint DriverDateLow, DriverDateHigh;
        public ulong DriverVersion;
        public IntPtr MfgName, OemUrl, HardwareId, Provider, PrintProcessor, VendorSetup, ColorProfiles, InfPath;
        public uint PrinterDriverAttributes;
        public IntPtr CoreDriverDependencies;
        public uint MinInboxDriverDateLow, MinInboxDriverDateHigh;
        public ulong MinInboxDriverVersion;
    }

    [DllImport("winspool.drv", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumPrintersW(uint flags, string? name, uint level, IntPtr buffer, uint size, out uint needed, out uint count);
    [DllImport("winspool.drv", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumPrinterDriversW(string? server, string? environment, uint level, IntPtr buffer, uint size, out uint needed, out uint count);
    [GeneratedRegex(@"DriverStore\\FileRepository\\([^\\]+)\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StoreFolder();

    // The INF names a package installs with CopyINF, from every INF at its top level.
    // CopyINF = a.inf[, b.inf ...]; a name may carry a folder (.\amdwin\amdwin-x.inf).
    internal static IEnumerable<string> CopyInfNames(string folder) => InfNames(folder, CopyInfLine());

    private static IEnumerable<string> InfNames(string folder, Regex directive)
    {
        foreach (string inf in Directory.EnumerateFiles(folder, "*.inf"))
            // An INF line ending in '\' continues on the next one.
            foreach (Match line in directive.Matches(Continuation().Replace(File.ReadAllText(inf), " ")))
                foreach (string item in line.Groups[1].Value.Split(';')[0].Split(','))
                    if (Path.GetFileName(item.Trim().Trim('"')) is { Length: > 0 } name) yield return name.ToLowerInvariant();
    }

    [GeneratedRegex(@"^[ \t]*CopyINF[ \t]*=(.*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline)]
    private static partial Regex CopyInfLine();

    [GeneratedRegex(@"\\[ \t]*\r?\n")]
    private static partial Regex Continuation();

    // A package's INFs can pull in another INF with Include= (Needs= then names sections in
    // it). An included INF that is not in Windows' INF folder (in-box INFs keep their names
    // there; installed third-party ones are renamed oemNN.inf), not in the package itself, not
    // captured, but in this PC's driver store (a third-party package) would be missing on another
    // PC. One found nowhere on this PC is not warned about: the driver installed here without it
    // (viogpudo includes msdv.inf, absent from ARM64 Windows; 010, 2026-11-04).
    internal static List<string> UncapturedIncludes(IReadOnlyList<Package> packages, string store, string infFolder)
    {
        var notes = new List<string>();
        foreach (var p in packages)
            foreach (string name in InfNames(Path.Combine(store, p.Folder), IncludeLine()).Distinct())
                if (!File.Exists(Path.Combine(infFolder, name)) && !File.Exists(Path.Combine(store, p.Folder, name)) &&
                    !packages.Any(q => q.Folder.StartsWith(name + "_", StringComparison.OrdinalIgnoreCase)) &&
                    Directory.EnumerateDirectories(store, name + "_*").Any())
                    notes.Add($"{p.Inf} ({SafeText.Path(p.Folder)}) includes {SafeText.Path(name)}, a third-party INF in this PC's driver store that is not captured; " +
                        $"installing {p.Inf} from this WIM may fail on a PC without it.");
        return notes;
    }

    [GeneratedRegex(@"^[ \t]*Include[ \t]*=(.*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline)]
    private static partial Regex IncludeLine();

    // A package's DriverVer (date, then version), for choosing the newest copy; null if
    // its INF has none that reads cleanly.
    private static (DateTime Date, Version Number)? DriverVer(string folder)
    {
        foreach (string inf in Directory.EnumerateFiles(folder, "*.inf"))
        {
            var m = DriverVerLine().Match(File.ReadAllText(inf));
            if (m.Success && DateTime.TryParseExact(m.Groups[1].Value.Trim(), ["MM/dd/yyyy", "M/d/yyyy"], System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var date) && Version.TryParse(m.Groups[2].Value.Trim(), out var number))
                return (date, number);
        }
        return null;
    }

    [GeneratedRegex(@"^[ \t]*DriverVer[ \t]*=[ \t]*([^,;\r\n]+),[ \t]*([0-9.]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline)]
    private static partial Regex DriverVerLine();
    private static readonly EnumerationOptions AllFiles = new()
    {
        RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false, ReturnSpecialDirectories = false,
    };

    // Asked of the folders themselves, so a folder that is another volume (a mount point
    // or junction) counts that volume. The WIM is written in a private folder on the
    // Windows drive with wimgapi's working files, then copied to the target folder; the
    // drivers' full size is assumed for it (no compression). Each keeps the margin free.
    // If both are one volume, the check before the copy, with the WIM's real size, decides.
    private static string? SpaceShortage(string wim, long bytes)
    {
        foreach (var (folder, need, what) in new[]
        {
            (Environment.SystemDirectory, bytes + TempAllowance, $"the drivers' {Size(bytes)} and {Size(TempAllowance)} of working files, while the WIM is written and checked"),
            (Path.GetDirectoryName(wim)!, bytes, $"the drivers' {Size(bytes)}"),
        })
        {
            long free = FreeBytes(folder);
            if (free < need + Margin)
                return $"not enough free space for {SafeText.Path(folder)}: the capture needs {Size(need + Margin)} ({what}, plus {Size(Margin)} kept free), " +
                    $"and {Size(free)} is free. Nothing was written.";
        }
        return null;
    }
    private static long FreeBytes(string folder)
    {
        // A UNC folder needs the trailing backslash.
        if (!GetDiskFreeSpaceExW(Path.TrimEndingDirectorySeparator(folder) + "\\", out ulong available, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"The free space for {folder} could not be read.");
        return (long)Math.Min(available, long.MaxValue);
    }

    private static string Count(int n, string what) => n == 1 ? $"1 {what}" : $"{n} {what}s";

    internal static string Size(long bytes) => bytes >= 1L << 30 ? $"{bytes / (double)(1L << 30):F2} GB" : $"{bytes / (double)(1L << 20):F1} MB";

    // ---- Writing, with wimgapi.dll ----

    private const uint GenericWrite = 0x40000000, CreateNew = 1, FlagVerify = 0x2;
    private const uint MsgBase = 0x8000 + 0x1476, MsgProgress = MsgBase + 2, MsgProcess = MsgBase + 3, MsgError = MsgBase + 9;
    private const uint MsgSuccess = 0, MsgAbortImage = 0xFFFFFFFF;
    private const int MaxPath = 260;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint MessageCallback(uint id, IntPtr wParam, IntPtr lParam, IntPtr user);

    // One capture per process; the callback reaches its state through here.
    private static CaptureState? current;
    private static readonly MessageCallback Callback = OnMessage;

    private sealed class CaptureState(string root, HashSet<string> folders, TextWriter output)
    {
        internal readonly string Root = root;
        internal readonly HashSet<string> Folders = folders;
        internal readonly TextWriter Output = output;
        internal string? Error;
        internal int LastTenth = -1;
        internal volatile bool Cancelled;
    }

    private static void Write(string wim, string temp, Compression compression, int count, CaptureState state)
    {
        string root = state.Root;
        current = state;
        IntPtr handle = WIMCreateFile(wim, GenericWrite, CreateNew, FlagVerify, (uint)compression, out _);
        if (handle == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            current = null;
            throw new Win32Exception(error, $"Windows could not create {wim}: {new Win32Exception(error).Message}");
        }
        bool captured = false;
        try
        {
            if (!WIMSetTemporaryPath(handle, temp))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not use the temporary folder.");
            if (WIMRegisterMessageCallback(handle, Callback, IntPtr.Zero) == 0xFFFFFFFF)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not report the capture's progress.");
            try
            {
                IntPtr image = WIMCaptureImage(handle, root, FlagVerify);
                int error = Marshal.GetLastWin32Error();
                if (image == IntPtr.Zero)
                {
                    if (state.Cancelled) throw new OperationCanceledException("Cancelled with Ctrl+C.");
                    string detail = state.Error is null ? "" : $" ({state.Error})";
                    throw new Win32Exception(error, $"Windows could not capture the drivers: {new Win32Exception(error).Message}{detail}");
                }
                try { SetImageInformation(image, count, state.Output); }
                finally { WIMCloseHandle(image); }
            }
            finally { WIMUnregisterMessageCallback(handle, Callback); }
            captured = true;
        }
        finally
        {
            current = null;
            // Closing the WIM handle writes its tables. After a failed capture the first
            // error is the one to report, so only a successful capture checks it.
            bool closed = WIMCloseHandle(handle);
            int error = Marshal.GetLastWin32Error();
            if (captured && !closed)
                throw new Win32Exception(error, $"Windows could not finish writing {wim}: {new Win32Exception(error).Message}");
        }
    }

    // Decides, path by path, what goes in: the store folder itself and the chosen package
    // folders. Leaving a folder out leaves out everything in it (checked in a VM).
    private static uint OnMessage(uint id, IntPtr wParam, IntPtr lParam, IntPtr user)
    {
        var state = current;
        if (state is null) return MsgSuccess;
        if (state.Cancelled) return MsgAbortImage;
        if (id == MsgProcess)
        {
            string path = (Marshal.PtrToStringUni(wParam) ?? "").TrimEnd('\\');
            if (!Included(path, state.Root, state.Folders)) Marshal.WriteInt32(lParam, 0);
        }
        else if (id == MsgError)
        {
            // Never skipped: a file that cannot be read fails the capture.
            string path = Marshal.PtrToStringUni(wParam) ?? "";
            state.Error ??= $"{SafeText.Path(path)}: {new Win32Exception((int)lParam.ToInt64()).Message}";
        }
        else if (id == MsgProgress)
        {
            int tenth = (int)Math.Clamp(wParam.ToInt64() / 10, 0, 10);
            if (tenth > state.LastTenth) { state.LastTenth = tenth; state.Output.WriteLine($"  {tenth * 10}%"); }
        }
        return MsgSuccess;
    }

    internal static bool Included(string path, string root, IReadOnlySet<string> folders)
    {
        if (path.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
        if (!path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) return false;
        string rest = path[(root.Length + 1)..];
        int slash = rest.IndexOf('\\');
        return folders.Contains(slash < 0 ? rest : rest[..slash]);
    }

    // Name and description; wimgapi keeps the counts it wrote. Its XML must start with a
    // byte-order mark (without one it fails with 1465; checked in a VM).
    private static void SetImageInformation(IntPtr image, int count, TextWriter output)
    {
        string version = typeof(DriverCapture).Assembly.GetName().Version?.ToString(3) ?? "?";
        string xml = $"\uFEFF<IMAGE><NAME>Third-party drivers</NAME><DESCRIPTION>{Count(count, "driver package")}, captured " +
            $"{DateTime.Now:yyyy-MM-dd} by WIM Driver Mount {version}</DESCRIPTION></IMAGE>";
        byte[] bytes = Encoding.Unicode.GetBytes(xml);
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            if (!WIMSetImageInformation(image, buffer, (uint)bytes.Length))
                output.WriteLine($"NOTE: the image's name could not be set ({new Win32Exception(Marshal.GetLastWin32Error()).Message}); the drivers are unaffected.");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    // Every file of every package, read back through this program's own reader and
    // compared by SHA-256 with the original; nothing missing and nothing extra.
    private static void Verify(string wim, IReadOnlyList<Package> packages, CaptureState state)
    {
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in packages)
        {
            string folder = Path.Combine(Store, p.Folder);
            foreach (var file in new DirectoryInfo(folder).EnumerateFiles("*", AllFiles))
                expected[p.Folder + file.FullName[folder.Length..]] = file.FullName;
        }
        using var stream = new FileStream(wim, FileMode.Open, FileAccess.Read, FileShare.Read);
        var reader = new DiscUtils.Wim.WimFile(stream);
        if (reader.ImageCount != 1) throw new InvalidDataException($"The new WIM has {reader.ImageCount} images, not 1.");
        using var image = reader.GetImage(0);
        var inWim = image.GetFiles(@"\", "*", SearchOption.AllDirectories).Select(f => f.TrimStart('\\'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var extra = inWim.Where(f => !expected.ContainsKey(f)).ToList();
        var absent = expected.Keys.Where(k => !inWim.Contains(k)).ToList();
        if (extra.Count != 0 || absent.Count != 0)
            throw new InvalidDataException($"The new WIM does not hold exactly the captured files: {absent.Count} missing" +
                (absent.Count > 0 ? $" (such as {SafeText.Path(absent[0])})" : "") + $", {extra.Count} extra" +
                (extra.Count > 0 ? $" (such as {SafeText.Path(extra[0])})" : "") + ".");
        foreach (var (inside, original) in expected)
        {
            if (state.Cancelled) throw new OperationCanceledException("Cancelled with Ctrl+C.");
            byte[] fromWim, fromDisk;
            using (var s = image.OpenFile(@"\" + inside, FileMode.Open, FileAccess.Read)) fromWim = SHA256.HashData(s);
            // Some drivers keep a file in their own package open for writing (an AMD log);
            // reading it needs every kind of sharing. A change to it fails the check.
            using (var s = new FileStream(original, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) fromDisk = SHA256.HashData(s);
            if (!fromWim.AsSpan().SequenceEqual(fromDisk))
                throw new InvalidDataException($"{SafeText.Path(inside)} in the new WIM does not match the original.");
        }
    }

    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr WIMCreateFile(string path, uint access, uint disposition, uint flags, uint compression, out uint result);
    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WIMSetTemporaryPath(IntPtr wim, string path);
    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr WIMCaptureImage(IntPtr wim, string path, uint flags);
    [DllImport("wimgapi.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WIMCloseHandle(IntPtr handle);
    [DllImport("wimgapi.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WIMRegisterMessageCallback(IntPtr wim, MessageCallback callback, IntPtr user);
    [DllImport("wimgapi.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WIMUnregisterMessageCallback(IntPtr wim, MessageCallback callback);
    [DllImport("wimgapi.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WIMSetImageInformation(IntPtr image, IntPtr info, uint size);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupGetInfPublishedNameW(string storeInf, char[] name, uint size, out uint required);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetDiskFreeSpaceExW(string root, out ulong available, out ulong total, out ulong free);
}

internal static partial class DriverDetection
{
    // DEVPKEY_Device_DriverInfPath (string) and DEVPKEY_Device_ExtendedConfigurationIds
    // (string list, "oem47.inf:PCI\VEN_...,section,date,version"), from devpkey.h (SDK 10.0.26100).
    private static readonly Guid ExtensionProperties = new("540b947e-8b40-45bc-a8a2-6a0b894cbda2");
    private const uint DriverInfPathProperty = 5, ExtendedConfigurationIdsProperty = 15, DevPropStringList = 0x2012;

    // DEVPKEY_Device_Parent (string), from devpkey.h.
    private static readonly Guid ParentProperties = new("4340a6c5-93fa-4706-972c-7b648008a5a7");
    private const uint ParentProperty = 8;
    // Printers and scanners are kept whatever they hang from: a network (WSD) printer or a
    // vendor's scanner is often a software device (Jericho, 2026-11-04).
    private static readonly Guid PrinterClass = new("4d36e979-e325-11ce-bfc1-08002be10318"), ImageClass = new("6bdd1fc6-810f-11d0-bec7-08002be2092f");

    // The oemNN.inf names that devices on this PC use, connected now or not: their driver
    // and their extension INFs. In-box INFs keep their own names and are left out.
    // Infs: used by real hardware (FromHardware), a printer or a scanner. AppMade: used
    // only by devices software made, each with one such device, to name it.
    internal static (HashSet<string> Infs, Dictionary<string, string> AppMade, int Devices) ThirdPartyInfsInUse()
    {
        var parents = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var users = new List<(string Id, bool PrinterOrScanner, List<string> Names)>();
        IntPtr set = SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, AllClasses);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot enumerate devices.");
        try
        {
            for (uint index = 0; ; index++)
            {
                var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
                if (!SetupDiEnumDeviceInfo(set, index, ref device))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == NoMoreItems) break;
                    throw new Win32Exception(error, "Cannot enumerate a device.");
                }
                var id = new StringBuilder(MaxDeviceIdLength);
                if (!SetupDiGetDeviceInstanceIdW(set, ref device, id, (uint)id.Capacity, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read a device's ID.");
                parents[id.ToString()] = ReadStrings(set, ref device, ParentProperties, ParentProperty).FirstOrDefault();
                var names = ReadStrings(set, ref device, DriverProperties, DriverInfPathProperty)
                    .Concat(ReadStrings(set, ref device, ExtensionProperties, ExtendedConfigurationIdsProperty).Select(e => e.Split(':')[0]))
                    .Where(name => DriverCapture.PublishedName().IsMatch(name)).ToList();
                if (names.Count != 0) users.Add((id.ToString(), device.ClassGuid == PrinterClass || device.ClassGuid == ImageClass, names));
            }
        }
        finally
        {
            if (!SetupDiDestroyDeviceInfoList(set)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot close device list.");
        }
        var infs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appMade = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, printerOrScanner, names) in users)
            foreach (string name in names)
                if (printerOrScanner || FromHardware(id, parents)) infs.Add(name);
                else appMade.TryAdd(name, id);
        foreach (string name in infs) appMade.Remove(name);
        return (infs, appMade, users.Count);
    }

    private const int MaxDeviceIdLength = 200; // MAX_DEVICE_ID_LEN

    // Read from the device tree; Windows has no flag for it. A device is hardware when its
    // topmost ancestor below the tree's root (HTREE\ROOT\0) is the HAL node (ROOT\ACPI_HAL,
    // ROOT\ARM64_HAL), which all of
    // the PC's buses hang from, SWD\COMPUTER (the PC itself), or anything not root- or
    // software-enumerated. Any other
    // ROOT\ or SWD\ top was made by an app or a service (Steam audio, ViGEm, Wintun). How
    // deep does not matter: AMD's SWD\DRIVERENUM components hang off the GPU. A parent
    // this list does not hold counts as the top.
    [System.Text.RegularExpressions.GeneratedRegex(@"^ROOT\\[A-Z0-9]+_HAL\\", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex HalNode();

    internal static bool FromHardware(string id, IReadOnlyDictionary<string, string?> parents)
    {
        string top = id;
        for (int depth = 0; depth < 64; depth++)
        {
            if (!parents.TryGetValue(top, out string? up) || up is null || up.StartsWith(@"HTREE\", StringComparison.OrdinalIgnoreCase)) break;
            top = up;
        }
        // The HAL node all buses hang from: ROOT\ACPI_HAL on x64, ROOT\ARM64_HAL on ARM64 (010, 2026-11-04).
        return HalNode().IsMatch(top) ||
            // Windows' device for the PC itself; model-specific packages (an ASUS board's audio
            // effects here) hang from it (Jericho, 2026-11-04).
            top.StartsWith(@"SWD\COMPUTER\", StringComparison.OrdinalIgnoreCase) ||
            !(top.StartsWith(@"ROOT\", StringComparison.OrdinalIgnoreCase) || top.StartsWith(@"SWD\", StringComparison.OrdinalIgnoreCase));
    }

    // A string or string-list device property; empty when the device has none.
    private static IEnumerable<string> ReadStrings(IntPtr set, ref DeviceInfo device, Guid format, uint id)
    {
        var key = new PropertyKey { Format = format, Id = id };
        if (SetupDiGetDevicePropertyW(set, ref device, ref key, out _, null, 0, out uint required, 0)) return [];
        int error = Marshal.GetLastWin32Error();
        if (error == 1168 /* ERROR_NOT_FOUND */) return [];
        if (error != InsufficientBuffer) throw new Win32Exception(error, "Cannot read a device's driver.");
        if (required < 2 || required > 64 * 1024 || (required & 1) != 0) throw new InvalidDataException("A device's driver property has an invalid size.");
        byte[] buffer = new byte[(int)required];
        if (!SetupDiGetDevicePropertyW(set, ref device, ref key, out uint type, buffer, required, out _, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read a device's driver.");
        if (type != DevPropString && type != DevPropStringList) throw new InvalidDataException("A device's driver property has an unexpected type.");
        return Encoding.Unicode.GetString(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }
}
