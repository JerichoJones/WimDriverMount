using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

// --install copies the program to a folder only administrators can change, and
// --uninstall removes what it copied. The program runs as administrator and
// starts its background mount again from its own file, so wherever it lives
// decides who can choose what runs elevated.
//
// A folder that is already safe is left exactly as it is: rewriting
// permissions that are already right can only break what an administrator set
// up on purpose. A new one is created with owner Administrators, full control
// for Administrators and SYSTEM, read and run for Users, and nothing inherited.
// An existing one that another account can change is refused, not fixed: a
// handle opened while it was open keeps its access after any change, so its
// owner could still add a file beside the program. After copying, every entry
// is checked again.
internal static class ProgramInstall
{
    internal const string ProgramName = "WimDriverMount.exe";
    // What was installed, one relative path per line; --uninstall removes those and nothing else.
    internal const string ManifestName = "WimDriverMount.install";
    private static readonly string[] Folders = ["licenses", "artwork", "WimReader"];
    // The installers DokanInstaller looks for beside the program.
    private static readonly string[] DokanInstallers = ["Dokan_x64.msi", "Dokan_ARM64.msi"];
    private const string SafeFolder = "O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)";

    internal static string DefaultFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WimDriverMount");

    internal static int Install(string target, bool force, TextWriter output)
    {
        string source = AppContext.BaseDirectory.TrimEnd('\\');
        target = CheckTarget(target);
        if (string.Equals(Path.GetFullPath(source), target, StringComparison.OrdinalIgnoreCase))
            throw new IOException($"This copy is already in {SafeText.Path(target)}. Run --install from the copy you want to install.");
        var files = SourceFiles(source);

        string installed = Path.Combine(target, ProgramName);
        string? reinstall = null;
        // An existing folder is checked before anything in it is read, and must
        // be empty or an earlier install: --install never overwrites another program's files.
        if (Directory.Exists(target))
        {
            RequireSafeFolder(target);
            // A program an uninstall renamed, waiting for Windows to delete it at restart, is ours too.
            if (!File.Exists(Path.Combine(target, ManifestName)) && Directory.EnumerateFileSystemEntries(target).Any(e => !PendingRemoval(e)))
                throw new IOException($"{SafeText.Path(target)} already holds files that --install did not put there. Choose a new or empty folder.");
        }
        if (File.Exists(installed) && !force)
        {
            Version ours = typeof(ProgramInstall).Assembly.GetName().Version ?? new Version(0, 0);
            string? found = FileVersionInfo.GetVersionInfo(installed).FileVersion;
            if (!Version.TryParse(found, out var theirs))
                throw new IOException($"{SafeText.Path(installed)} exists but its version cannot be read. To replace it, add --force.");
            if (theirs >= ours)
            {
                // Kept only if it is still safe: the menu is about to point at it.
                if (IsSafeTree(target))
                {
                    output.WriteLine($"WIM Driver Mount {theirs.ToString(3)} is already installed in {SafeText.Path(target)}; nothing was changed. " +
                        "To replace it anyway, add --force.");
                    return 0;
                }
                reinstall = $"WIM Driver Mount {theirs.ToString(3)} is installed in {SafeText.Path(target)}, but another account could change it; installing again.";
            }
        }

        // Only the last folder is ever made, and made with its permissions in
        // place: one created first and fixed after could be opened by others in between.
        if (!Directory.Exists(target))
        {
            if (!Directory.Exists(Path.GetDirectoryName(target)))
                throw new IOException($"{SafeText.Path(Path.GetDirectoryName(target))} does not exist. Install into an existing folder, such as {SafeText.Path(DefaultFolder)}.");
            // Checked again now the parent exists: one someone else made a moment
            // ago is theirs, and refused before anything is made in it. A refused
            // install later leaves the new folder in place, empty or part filled:
            // deleting as administrator in a path an attacker races is the worse risk.
            CheckTarget(target);
            CreateSafe(target);
        }
        CheckTarget(target);
        RequireSafeFolder(target);
        foreach (string folder in files.Select(f => Path.GetDirectoryName(f.Relative)).OfType<string>().Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string sub = Path.Combine(target, folder);
            if (Directory.Exists(sub)) RequireSafeFolder(sub);
            else CreateSafe(sub);
        }
        if (reinstall is not null) output.WriteLine(reinstall);
        // Files an earlier version installed stay on the list, so --uninstall still removes them.
        var listed = files.Select(f => f.Relative).ToList();
        string previous = Path.Combine(target, ManifestName);
        if (File.Exists(previous) && new FileInfo(previous).Length <= 64 * 1024)
            listed.AddRange(File.ReadAllLines(previous).Where(line => Allowed(line) && File.Exists(Path.Combine(target, line))));
        listed = listed.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // Dokan's installer first, being the one part that can be refused; the
        // program last, so a copy that stops part way never leaves a new program
        // beside old notices; the list of what was installed after it.
        foreach (var file in files.OrderBy(f => f.Check is not null ? 0 : f.Relative == ProgramName ? 2 : 1))
            using (var input = file.Open()) CopyVerified(input, Path.Combine(target, file.Relative), file.Check);
        using (var list = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", listed) + "\n")))
            CopyVerified(list, Path.Combine(target, ManifestName));
        RequireSafeTree(target);
        output.WriteLine($"Installed WIM Driver Mount {typeof(ProgramInstall).Assembly.GetName().Version?.ToString(3)} in {SafeText.Path(target)} ({files.Count} files, each checked after copying).");
        return 0;
    }

    // beforeRemoving runs once the checks pass and before any file is touched.
    // Renaming the running program below ends this process's access to its own
    // file, and a single-file program loads code it has not used yet from there.
    internal static int Uninstall(string target, TextWriter output, Action? beforeRemoving = null)
    {
        target = CheckTarget(target);
        string manifest = Path.Combine(target, ManifestName);
        if (!File.Exists(manifest))
        {
            beforeRemoving?.Invoke();
            output.WriteLine(Directory.Exists(target)
                ? $"{SafeText.Path(target)} has no {ManifestName}, so it was not installed by --install; nothing was removed."
                : $"Nothing is installed in {SafeText.Path(target)}.");
            return 0;
        }
        // The list says what to delete, so it is believed only from a folder
        // nobody but administrators can change.
        RequireSafeTree(target);
        if (new FileInfo(manifest).Length > 64 * 1024) throw new IOException($"{SafeText.Path(manifest)} is too large to be an install list.");
        var entries = File.ReadAllLines(manifest).Where(line => line.Length > 0).ToList();
        foreach (string entry in entries)
            if (!Allowed(entry)) throw new IOException($"{SafeText.Path(manifest)} names {SafeText.Path(entry)}, which --install never writes; nothing was removed.");
        beforeRemoving?.Invoke();
        string? self = Environment.ProcessPath;
        string? pending = null;
        // The program first: if a background mount is running from it, nothing else is touched.
        foreach (string entry in entries.OrderBy(e => e != ProgramName).Append(ManifestName))
        {
            string path = Path.Combine(target, entry);
            if (!File.Exists(path)) continue;
            if (string.Equals(path, self, StringComparison.OrdinalIgnoreCase))
            {
                // Renamed first, so a removal Windows does at restart can only ever
                // take this file, not a program installed here again before then.
                pending = Path.Combine(target, $".{ProgramName}.{Guid.NewGuid():N}.removed");
                File.Move(path, pending);
                DeleteAtRestart(pending);
                continue;
            }
            try { File.Delete(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new IOException($"{SafeText.Path(path)} could not be removed ({SafeText.Message(ex.Message)}). " +
                    "If a drive is mounted with WIM Driver Mount, unmount it first, then run --uninstall again.");
            }
        }
        foreach (string folder in Folders) DeleteIfEmpty(Path.Combine(target, folder));
        // Another account's menu may still run the program from here. Where
        // ordinary accounts can create folders beside it, an empty folder is
        // left, administrator-only, so nobody can make a new one of that name.
        string parent = Path.GetDirectoryName(target)!;
        bool keepFolder;
        using (SafeFileHandle above = OpenFolder(parent))
            keepFolder = TrustedFile.WhoElseCanChange(Security(above), FileSystemRights.AppendData) is not null;
        bool onlyPending = pending is not null && Directory.EnumerateFileSystemEntries(target).All(PendingRemoval);
        // Windows removes a folder at restart only if it is empty then (MoveFileEx),
        // so an --install before the restart keeps the folder and its new files.
        if (!keepFolder && onlyPending) DeleteAtRestart(target);
        else if (!keepFolder && pending is null) DeleteIfEmpty(target);
        if (keepFolder) output.WriteLine($"The folder {SafeText.Path(target)} is kept: other accounts can create folders in {SafeText.Path(parent)}, and could put a program of their own where a menu still points.");
        output.WriteLine(pending is not null
            ? $"Removed WIM Driver Mount from {SafeText.Path(target)}. The running program is removed when Windows restarts" +
              (onlyPending && !keepFolder ? ", with its folder." : onlyPending ? "." : "; files it did not install were left there.")
            : !Directory.Exists(target) ? $"Removed WIM Driver Mount and its folder {SafeText.Path(target)}."
            : Directory.EnumerateFileSystemEntries(target).Any(e => !PendingRemoval(e)) ? $"Removed WIM Driver Mount from {SafeText.Path(target)}. Files it did not install were left there."
            : $"Removed WIM Driver Mount from {SafeText.Path(target)}.");
        return 0;
    }

    // The name Uninstall gives the running program before Windows deletes it at restart:
    // .WimDriverMount.exe.<32 hex digits>.removed, a file.
    private static bool PendingRemoval(string path)
    {
        string name = Path.GetFileName(path);
        string prefix = $".{ProgramName}.", suffix = ".removed";
        return name.Length == prefix.Length + 32 + suffix.Length &&
            name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) &&
            name.AsSpan(prefix.Length, 32).ToString().All(Uri.IsHexDigit) && File.Exists(path);
    }

    // A plain local path on an internal fixed disk, reached through no link,
    // under folders whose contents nobody else can rename.
    internal static string CheckTarget(string target)
    {
        string full = Path.GetFullPath(target).TrimEnd('\\');
        // A % would be expanded by Explorer in the menu's command.
        if (full.Contains('%'))
            throw new IOException($"{SafeText.Path(full)} contains %, which File Explorer would change in the menu's command. Choose another folder.");
        if (full.StartsWith(@"\\", StringComparison.Ordinal) || full.Length < 3 || full[1] != ':' || !char.IsAsciiLetter(full[0]))
            throw new IOException($"{SafeText.Path(full)} is not a folder on a local drive. Install to a folder such as {SafeText.Path(DefaultFolder)}.");
        if (Path.GetPathRoot(full)!.TrimEnd('\\').Length == full.Length)
            throw new IOException($"{SafeText.Path(full)} is a drive root. Install to a folder of its own, such as {SafeText.Path(DefaultFolder)}.");
        string? existing = full;
        while (existing is not null && !Directory.Exists(existing))
        {
            if (File.Exists(existing)) throw new IOException($"{SafeText.Path(existing)} is a file, not a folder.");
            existing = Path.GetDirectoryName(existing);
        }
        if (existing is null) throw new IOException($"The drive of {SafeText.Path(full)} does not exist.");
        // Each existing folder, root to target: no links, and nobody else may
        // rename or delete what is inside the ones above.
        for (string? folder = existing; folder is not null; folder = Path.GetDirectoryName(folder))
        {
            using SafeFileHandle handle = OpenFolder(folder);
            string real = TrustedFile.FinalPath(handle);
            if (!string.Equals(real.TrimEnd('\\'), folder.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException($"{SafeText.Path(folder)} resolves to {SafeText.Path(real)}. Name the real path.");
            if (!TrustedFile.OnLocalFixedDrive(handle))
                throw new IOException($"{SafeText.Path(full)} is not on a local fixed drive. On a share, an external or removable drive, or a virtual disk, " +
                    "its permissions may have been set on another machine and prove nothing here.");
            if (!string.Equals(folder, full, StringComparison.OrdinalIgnoreCase) &&
                TrustedFile.WhoElseCanChange(Security(handle), TrustedFile.Rename) is { } why)
                throw new IOException($"Refusing to install in {SafeText.Path(full)}: in {SafeText.Path(folder)}, {why.Replace(" can change it", " can rename or delete folders", StringComparison.Ordinal)}. " +
                    $"So the program's folder could be replaced. Choose a folder such as {SafeText.Path(DefaultFolder)}.");
        }
        return full;
    }

    private sealed record Source(string Relative, Func<Stream> Open, Action<string>? Check = null);

    // What is installed, and where each part is read from. Only the program
    // itself and Dokan's installer come from the folder this copy runs from,
    // which its user may control; the notices are inside the program. A file
    // read from there by this elevated process and published readable by Users
    // could otherwise be any file that user can move but not read.
    private static List<Source> SourceFiles(string source)
    {
        const string Prefix = "Install/";
        var assembly = typeof(ProgramInstall).Assembly;
        var files = new List<Source> { new(ProgramName, OpenRunningProgram) };
        foreach (string name in assembly.GetManifestResourceNames().Where(n => n.StartsWith(Prefix, StringComparison.Ordinal)))
            files.Add(new(name[Prefix.Length..].Replace('/', '\\'), () => assembly.GetManifestResourceStream(name)!));
        if (!files.Any(f => f.Relative.StartsWith(@"licenses\", StringComparison.OrdinalIgnoreCase)))
            throw new IOException("This build carries no license notices, so it cannot install itself.");
        // Only a genuine signed Dokan installer is copied, so what gets published
        // is Dokan's public package and nothing else. Checked once copied, on the
        // copy this process holds, which is the file kept.
        string msi = Path.Combine(source, DokanPackage.MsiName);
        if (File.Exists(msi))
            files.Add(new(DokanPackage.MsiName, () =>
            {
                var file = File.Open(msi, FileMode.Open, FileAccess.Read, FileShare.Read);
                try
                {
                    // Dokan's installer is a few megabytes; anything far larger is not it, and is not copied first to find out.
                    if (file.Length > 64L * 1024 * 1024) throw new IOException($"{SafeText.Path(msi)} is too large to be Dokan's installer; nothing was installed.");
                    return file;
                }
                catch { file.Dispose(); throw; }
            }, copy =>
            {
                DokanPackage.RequireTrusted(copy);
                DokanPackage.ReadIdentity(copy);
            }));
        return files;
    }

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetMappedFileNameW(IntPtr process, IntPtr address, [Out] char[] name, uint size);

    private static string RunningImage()
    {
        using var self = Process.GetCurrentProcess();
        char[] name = new char[32768];
        uint length = GetMappedFileNameW(self.Handle, self.MainModule!.BaseAddress, name, (uint)name.Length);
        return length == 0 ? throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot find this program's own file.") : new string(name, 0, (int)length);
    }

    [DllImport("ntdll.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtAreMappedFilesTheSame(IntPtr first, IntPtr second);

    // The file this process is running from, not whatever now has its name: an
    // unelevated program may rename the running program, or a folder above it,
    // and put another file at the old path. So the file opened is mapped and
    // Windows is asked whether that mapping and the running image are views of
    // one file; a name proves nothing. Held without write or delete sharing, it
    // stays that file while it is copied.
    private static FileStream OpenRunningProgram()
    {
        // SQOS anonymous: a path that leads to a named pipe gets no usable identity of this process.
        const uint GenericRead = 0x80000000, ShareRead = 1, OpenExisting = 3, OpenReparsePoint = 0x00200000, Anonymous = 0x00100000;
        var handle = TrustedFile.OpenFileW(@"\\?\GLOBALROOT" + RunningImage(), GenericRead, ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint | Anonymous, IntPtr.Zero);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "Cannot open this program's own file."); }
        var stream = new FileStream(handle, FileAccess.Read);
        try
        {
            using var map = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(stream, null, 0,
                System.IO.MemoryMappedFiles.MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
            using var view = map.CreateViewAccessor(0, 0, System.IO.MemoryMappedFiles.MemoryMappedFileAccess.Read);
            using var self = Process.GetCurrentProcess();
            if (NtAreMappedFilesTheSame(self.MainModule!.BaseAddress, view.SafeMemoryMappedViewHandle.DangerousGetHandle()) != 0)
                throw new IOException("This program's file was renamed or replaced while it was being installed; nothing was installed from it.");
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    // Only names --install itself writes: no folder above, no other folder, no stream.
    internal static bool Allowed(string entry)
    {
        string[] parts = entry.Split('\\');
        bool plain = parts.All(p => p.Length > 0 && p is not ("." or "..") && p.IndexOfAny([':', '/', '\0']) < 0 && p == p.Trim());
        return plain && (parts.Length == 1
            ? string.Equals(entry, ProgramName, StringComparison.OrdinalIgnoreCase) || DokanInstallers.Contains(entry, StringComparer.OrdinalIgnoreCase)
            : parts.Length == 2 && Folders.Contains(parts[0], StringComparer.OrdinalIgnoreCase));
    }

    internal static void RequireSafeFolder(string folder)
    {
        using SafeFileHandle handle = OpenFolder(folder);
        // Rules for what is created inside count too: each file copied in takes them.
        if (TrustedFile.WhoElseCanChange(Security(handle), inheritable: true) is { } why)
            throw new IOException($"Refusing to install in {SafeText.Path(folder)}: {why}. Someone who has it open keeps that access " +
                $"whatever its permissions become, so it cannot be made safe. Delete it and run --install again, or choose a new folder.");
    }

    private static bool IsSafeTree(string folder)
    {
        try { RequireSafeTree(folder); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception) { return false; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);

    // Made with its permissions in one step, and refused if it already exists:
    // a folder someone else made in the moment before is theirs, not this run's.
    private static void CreateSafe(string folder)
    {
        var descriptor = new RawSecurityDescriptor(SafeFolder);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject() };
            if (CreateDirectory(folder, ref attributes)) return;
            int error = Marshal.GetLastWin32Error();
            if (error == 183) throw new IOException($"{SafeText.Path(folder)} was created by someone else while installing; nothing was installed.");
            throw new Win32Exception(error, $"Cannot create {SafeText.Path(folder)}.");
        }
        finally { pinned.Free(); }
    }

    // Every entry below the folder, the folder included: a file another account
    // put there before the permissions were fixed is still that account's.
    private static void RequireSafeTree(string folder)
    {
        var pending = new Stack<string>([folder]);
        while (pending.Count > 0)
        {
            string current = pending.Pop();
            using (SafeFileHandle handle = OpenFolder(current))
                if (TrustedFile.WhoElseCanChange(Security(handle)) is { } why)
                    throw new IOException($"{SafeText.Path(current)} is not safe: {why}. Remove it or fix its permissions, then run this again.");
            foreach (string entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException($"{SafeText.Path(entry)} is a link. Remove it, then run this again.");
                if ((attributes & FileAttributes.Directory) != 0) { pending.Push(entry); continue; }
                if (TrustedFile.WhoElseCanChange(new FileInfo(entry).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)) is { } why)
                    throw new IOException($"{SafeText.Path(entry)} is not safe: {why}. Remove it or fix its permissions, then run this again.");
            }
        }
    }

    // Written beside the target under a new name, administrators and SYSTEM
    // only, read back and compared, checked, and moved over it; only then does it
    // take the folder's permissions. Until a file is known to be what it should
    // be, Users cannot open it, so a refused one is never readable on the way.
    private static void CopyVerified(Stream input, string destination, Action<string>? check = null)
    {
        string temp = Path.Combine(Path.GetDirectoryName(destination)!, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        var privateFile = new FileSecurity();
        privateFile.SetSecurityDescriptorSddlForm("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)");
        try
        {
            byte[] expected;
            using (var output = new FileInfo(temp).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read, FileShare.None, 81920, FileOptions.None, privateFile))
            using (var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256))
            {
                byte[] buffer = new byte[81920];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0) { hash.AppendData(buffer, 0, read); output.Write(buffer, 0, read); }
                output.Flush(flushToDisk: true);
                expected = hash.GetHashAndReset();
            }
            using (var written = new FileStream(temp, FileMode.Open, FileAccess.Read, FileShare.Read))
                if (!System.Security.Cryptography.SHA256.HashData(written).AsSpan().SequenceEqual(expected))
                    throw new IOException($"{SafeText.Path(destination)} did not read back as written.");
            try { check?.Invoke(temp); }
            catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or System.Security.Cryptography.CryptographicException)
            {
                throw new IOException($"{SafeText.Path(Path.GetFileName(destination))} beside this program was not installed: {SafeText.Message(ex.Message)}");
            }
            try { File.Move(temp, destination, overwrite: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new IOException($"{SafeText.Path(destination)} could not be replaced ({SafeText.Message(ex.Message)}). " +
                    "If a drive is mounted with WIM Driver Mount, unmount it first, then run --install again.");
            }
            // Now the folder's: no rules of its own, inheriting the folder's.
            var inherit = new FileSecurity();
            inherit.SetAccessRuleProtection(false, false);
            try { new FileInfo(destination).SetAccessControl(inherit); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                throw new IOException($"{SafeText.Path(destination)} is in place but Users cannot read it yet ({SafeText.Message(ex.Message)}). Run --install again.");
            }
        }
        finally { try { File.Delete(temp); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { } }
    }

    private static void DeleteIfEmpty(string folder)
    {
        if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any()) Directory.Delete(folder);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "MoveFileExW")]
    private static extern bool MoveFileEx(string existing, string? replacement, uint flags);

    // A running program cannot delete its own file; Windows can at the next start.
    private static void DeleteAtRestart(string path)
    {
        const uint DelayUntilReboot = 0x4;
        if (!MoveFileEx(path, null, DelayUntilReboot))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"{SafeText.Path(path)} could not be set to be removed at restart.");
    }

    // Opened without following a link, and refused if it is one, so the folder
    // checked is the folder changed; not shared for delete, so it cannot be
    // renamed or replaced while held.
    private static SafeFileHandle OpenFolder(string path)
    {
        const uint ReadControl = 0x00020000;
        const uint ShareRead = 1, ShareWrite = 2, OpenExisting = 3, OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000, Anonymous = 0x00100000;
        SafeFileHandle handle = TrustedFile.OpenFileW(path, ReadControl, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics | Anonymous, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Cannot open {SafeText.Path(path)}.");
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            handle.Dispose();
            throw new IOException($"{SafeText.Path(path)} is a link (a symbolic link or junction). Name the real path.");
        }
        return handle;
    }

    private static DirectorySecurity Security(SafeFileHandle handle)
    {
        var raw = TrustedFile.Security(handle);
        byte[] bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access | AccessControlSections.Owner);
        return security;
    }
}
