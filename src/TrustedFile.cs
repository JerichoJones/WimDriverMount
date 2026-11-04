using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

// A file this program takes instructions from, rather than data.
//
// The settings file decides what an elevated process does: which WIMs to mount,
// whether to install drivers out of them, whether to run a program from one. So
// whoever can write that file can choose what runs as administrator. If it sits
// anywhere an ordinary user can write — a Documents folder, a share, a
// ProgramData directory left with default permissions — then running it is
// handing that user the elevation the operator just approved.
//
// A format that could only name a drive letter and a path would be its own
// limit. A settings file can say install-drivers or run, so the permissions
// have to be the limit instead.
//
// A file whose permissions cannot be read at all is refused too. "Unreadable"
// is not "safe", and the operator can always copy the file somewhere local.
internal static class TrustedFile
{
    private const uint AttributeReparsePoint = 0x400;

    // Rights that let someone change what this file says, or replace it. For a
    // directory, WriteData and AppendData are create-file and create-directory,
    // which together with Delete are enough to substitute the file.
    private const FileSystemRights Dangerous =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    // The generic rights need no entry of their own. Windows maps GENERIC_WRITE
    // and GENERIC_ALL to the specific rights above when the access list is
    // written, not when it is checked, so a file's stored entry never carries
    // them: an entry authored as 0xC0000000 reads back as 0x12019F, which the
    // mask above already matches. Verified, and covered by a regression that
    // writes one through SDDL, because the managed API refuses to make one.

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public FileTime Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    internal static extern SafeFileHandle OpenFileW(string name, uint access, uint share, IntPtr attributes,
        uint disposition, uint flags, IntPtr template);

    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    // Without this, opening a symbolic link opens its target, so the attribute
    // check below would inspect the target and find nothing, and a
    // settings file reached through a link would be accepted. With it, the handle is
    // the link itself and the check sees what it is meant to see. It also
    // closes the gap between testing the path and opening it: there is only one
    // open, and the thing checked is the thing read.
    private const uint FlagOpenReparsePoint = 0x00200000;

    // Opens the file for reading, having established that only administrators
    // can change it. The handle is returned still open and shared for reading
    // only, so it cannot be rewritten while it is being read.
    internal static FileStream OpenInstructions(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        SafeFileHandle handle = OpenFileW(path, GenericRead, ShareRead, IntPtr.Zero, OpenExisting,
            FlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            // 2 is ERROR_FILE_NOT_FOUND, 3 ERROR_PATH_NOT_FOUND.
            if (error is 2 or 3) throw new FileNotFoundException("No settings file at that path.", path);
            if (error == 5) throw new UnauthorizedAccessException($"Access to {SafeText.Path(path)} is denied.");
            throw new Win32Exception(error, $"Cannot open {SafeText.Path(path)}.");
        }
        FileStream file = new(handle, FileAccess.Read);
        try
        {
            if (!GetFileInformationByHandle(file.SafeFileHandle, out FileInformation info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot inspect {SafeText.Path(path)}.");
            // A reparse point means the real target, and its permissions, are
            // decided elsewhere and can be redirected after this check.
            if ((info.Attributes & AttributeReparsePoint) != 0)
                throw new IOException($"{SafeText.Path(path)} is a link (a symbolic link or junction). Name the settings file's real path.");
            RequireLocalFixedDrive(file.SafeFileHandle, path);
            RequireAdministratorsOnly(path, () => file.GetAccessControl(), "settings file", path);
            // Replacing the file only needs write access to the folder holding it.
            //
            // Only the immediate parent is checked, not every folder above it.
            // That is enough ONLY because of the owner check: substituting a
            // folder higher up means creating one, and anything an ordinary
            // account creates is owned by that account, which the owner check
            // refuses. If the set of trusted owners is ever widened — to any
            // member of Administrators, say — this stops being sufficient and
            // the whole ancestor chain has to be walked.
            string? parent = Path.GetDirectoryName(Path.GetFullPath(path));
            if (parent is not null)
                RequireAdministratorsOnly(parent, () => new DirectoryInfo(parent).GetAccessControl(
                    AccessControlSections.Access | AccessControlSections.Owner), "folder holding the settings file", path);
            return file;
        }
        catch { file.Dispose(); throw; }
    }

    // Makes a settings file acceptable: its folder, and the file in it, become
    // writable by administrators and SYSTEM only, with no inherited rules.
    //
    // This exists so the refusal above is something the operator can act on
    // without being sent to another tool. It is never done automatically:
    // rewriting the permissions on a folder can lock out whatever else lives
    // there, which has to be a decision rather than a side effect.
    //
    // Everything is done on handles, never by name. The folder is opened once,
    // not following reparse points and without delete sharing, so it cannot be
    // renamed or swapped for a junction while it is being changed; the file is
    // opened shared for reading only, so a writer that opened it earlier makes
    // this refuse, and none can open it until the new permissions are in place.
    // A handle that can change permissions is not stopped by sharing and keeps
    // that power afterwards, so a file or folder another account could
    // re-permission is refused rather than protected. Permissions are written to
    // those handles without propagation, so nothing beyond the folder and the
    // file itself is ever touched. Only a local fixed drive is accepted.
    internal static void Protect(string path, TextWriter output)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(output);
        string full = Path.GetFullPath(path);
        string folderPath = Path.GetDirectoryName(full) ?? throw new ArgumentException("The settings file has no folder.");
        RefuseDangerousTarget(folderPath); // By name first, so nothing is opened for a refused folder.

        using SafeFileHandle folder = OpenForProtect(folderPath, directory: true);
        string folderReal = FinalPath(folder);
        if (!string.Equals(folderReal, folderPath.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new IOException($"{SafeText.Path(folderPath)} resolves to {SafeText.Path(folderReal)}. Name the real path.");
        RefuseDangerousTarget(folderReal);
        using SafeFileHandle file = OpenForProtect(full, directory: false);
        string fileReal = FinalPath(file);
        if (!string.Equals(Path.GetDirectoryName(fileReal), folderReal, StringComparison.OrdinalIgnoreCase))
            throw new IOException($"{SafeText.Path(full)} is not in {SafeText.Path(folderReal)}. Name the real path.");

        RequireLocalFixedDrive(folder, folderPath);
        RefuseIfOthersCouldRepermission(folder, folderReal);
        RefuseIfOthersCouldRepermission(file, fileReal);

        output.WriteLine($"Folder: {SafeText.Path(folderReal)}");
        output.WriteLine("Before: (anyone listed here with write access could have changed the file)");
        Describe(folder, output);
        Lock(folder, directory: true);
        Lock(file, directory: false);
        output.WriteLine("After:");
        Describe(folder, output);
        // Protecting says the file may be trusted from now on; it cannot say the
        // file was not changed before. Show exactly what is being approved.
        using (var content = new FileStream(new SafeFileHandle(file.DangerousGetHandle(), ownsHandle: false), FileAccess.Read))
        {
            if (content.Length > 1024 * 1024) throw new IOException("This file is too large to be a settings file.");
            byte[] bytes = new byte[content.Length];
            content.ReadExactly(bytes);
            output.WriteLine($"Settings file SHA-256: {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))}");
            output.WriteLine("Review its contents before using it with --mount-config:");
            foreach (string line in System.Text.Encoding.UTF8.GetString(bytes).Split('\n'))
                output.WriteLine("  | " + SafeText.Path(line.TrimEnd('\r')));
        }
        output.WriteLine($"{SafeText.Path(fileReal)} and its folder are now writable by administrators and SYSTEM only.");
    }

    private const uint ReadControl = 0x00020000, WriteDac = 0x00040000, WriteOwner = 0x00080000;
    private const uint ShareWrite = 0x00000002;
    private const uint FlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[] descriptor);

    // Opens without following a reparse point, and refuses one. The folder is not
    // shared for delete, so it cannot be renamed or replaced while held; the file
    // is shared for reading only, so an open writer makes this fail.
    private static SafeFileHandle OpenForProtect(string path, bool directory)
    {
        uint access = ReadControl | WriteDac | WriteOwner | (directory ? 0 : GenericRead);
        uint share = directory ? ShareRead | ShareWrite : ShareRead;
        uint flags = FlagOpenReparsePoint | (directory ? FlagBackupSemantics : 0);
        SafeFileHandle handle = OpenFileW(path, access, share, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error is 2 or 3) throw new FileNotFoundException(directory ? "No such folder." : "No settings file at that path.", path);
            if (error == 32) throw new IOException(
                $"{SafeText.Path(path)} is open for writing in another program. Close that program, then run the same --protect-config command again. " +
                "(A program that keeps it open could change it after it is protected.)");
            throw new Win32Exception(error, $"Cannot open {SafeText.Path(path)}.");
        }
        try
        {
            if (!GetFileInformationByHandle(handle, out FileInformation info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot inspect {SafeText.Path(path)}.");
            if ((info.Attributes & AttributeReparsePoint) != 0)
                throw new IOException(
                    $"{SafeText.Path(path)} is a link (a symbolic link or junction). Name the real path, so the permissions " +
                    "are changed on the settings file and not on whatever it points at.");
            if (((info.Attributes & 0x10) != 0) != directory)
                throw new IOException($"{SafeText.Path(path)} is not a {(directory ? "folder" : "file")}.");
            if (!directory && info.Links != 1)
                throw new IOException($"{SafeText.Path(path)} has other names (hard links); give the settings file its own file.");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    internal static string FinalPath(SafeFileHandle handle)
    {
        char[] buffer = new char[32768];
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the real path.");
        string path = new(buffer, 0, (int)length);
        if (path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + path[8..];
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }

    // Owner Administrators, protected access list of Administrators and SYSTEM,
    // written to the handle with no propagation to anything else.
    private static void Lock(SafeFileHandle handle, bool directory)
    {
        string inherit = directory ? "OICI" : "";
        var descriptor = new RawSecurityDescriptor($"O:BAD:P(A;{inherit};FA;;;BA)(A;{inherit};FA;;;SY)");
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        const uint Owner = 0x1, Dacl = 0x4, ProtectedDacl = 0x80000000;
        if (SetKernelObjectSecurity(handle, Owner | Dacl | ProtectedDacl, bytes)) return;
        // Giving ownership to Administrators needs an elevated token. Without it the
        // access rules are still set; only another administrator would be told the
        // file is not trustworthy, never someone else let in.
        int error = Marshal.GetLastWin32Error();
        if (error is not (1307 or 5)) throw new Win32Exception(error, "Cannot set the settings file's permissions.");
        if (!SetKernelObjectSecurity(handle, Dacl | ProtectedDacl, bytes))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot set the settings file's permissions.");
        Console.Error.WriteLine($"WARNING: Windows did not let this program make the Administrators group the owner (error {error}).");
        Console.Error.WriteLine("  The permissions are set, but --mount-config will still refuse the file while your account owns it.");
        Console.Error.WriteLine("  Make Administrators the owner in the file's Properties > Security > Advanced, then run this again.");
    }

    // Locking a folder other things use would break them rather than secure a
    // settings file. Only the folder and the file are changed (nothing below), so
    // a dedicated folder anywhere is fine; shared ones are refused.
    private static void RefuseDangerousTarget(string folder)
    {
        folder = folder.TrimEnd('\\');
        static ArgumentException Refuse(string folder, string why) => new(
            $"Refusing to change the permissions on {SafeText.Path(folder)}: {why}. " +
            "Put the settings file in a folder of its own, such as C:\\Config.");
        static bool Same(string a, string b) => string.Equals(a, b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        static bool Inside(string a, string root) => root.Length != 0 &&
            (Same(a, root) || a.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));

        if (string.Equals(folder + "\\", Path.GetPathRoot(folder + "\\"), StringComparison.OrdinalIgnoreCase))
            throw Refuse(folder, "it is a drive root");
        foreach (var tree in new[] { Environment.SpecialFolder.Windows, Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            if (Inside(folder, Environment.GetFolderPath(tree)))
                throw Refuse(folder, $"it is inside {SafeText.Path(Environment.GetFolderPath(tree))}");
        foreach (var shared in new[] { Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.MyDocuments, Environment.SpecialFolder.Desktop })
            if (Environment.GetFolderPath(shared) is { Length: > 0 } path && Same(folder, path))
                throw Refuse(folder, "other programs use it");
        if (Same(folder, Path.GetTempPath())) throw Refuse(folder, "other programs use it");
        // The profiles folder, any profile, and the folders directly in one
        // (Downloads, Documents, AppData...).
        string? profiles = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\'));
        if (profiles is not null && Inside(folder, profiles) && folder[profiles.TrimEnd('\\').Length..].Count(c => c == '\\') <= 2)
            throw Refuse(folder, "it is a user profile or a folder directly in one");
        if (Directory.Exists(folder) && Directory.EnumerateDirectories(folder).Any())
            throw Refuse(folder, "it contains other folders, so the settings file does not have a folder of its own");
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[]? descriptor, uint length, out uint needed);

    // Owner and access rules of the object behind the handle, as Windows has them.
    internal static RawSecurityDescriptor Security(SafeFileHandle handle)
    {
        const uint Owner = 0x1, Dacl = 0x4;
        GetKernelObjectSecurity(handle, Owner | Dacl, null, 0, out uint needed);
        byte[] bytes = new byte[needed];
        if (needed == 0 || !GetKernelObjectSecurity(handle, Owner | Dacl, bytes, needed, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the permissions.");
        return new RawSecurityDescriptor(bytes, 0);
    }

    // Rights on a handle are fixed when it is opened, and sharing rules do not
    // stop a handle that can neither read nor write. So anyone who could change
    // this object's permissions before it was protected may still hold a handle
    // that can, and protecting cannot take that away: later they could reopen
    // the file, rewrite it, and put the protected permissions back. Such an
    // object is refused rather than protected. (Permissions tightened by hand
    // earlier, while someone held such a handle, cannot be seen here.)
    private static void RefuseIfOthersCouldRepermission(SafeFileHandle handle, string path)
    {
        const int WriteDacOrOwner = 0x000C0000, GenericAll = 0x10000000;
        var security = Security(handle);
        string? who = security.Owner is not { } owner ? "its owner cannot be determined"
            : !IsTrusted(owner, includeCaller: true) ? $"it is owned by {Describe(owner)}"
            : security.DiscretionaryAcl is null ? "it has no access list, so everyone may change it" : null;
        if (who is null)
            foreach (GenericAce entry in security.DiscretionaryAcl!)
            {
                if ((entry.AceFlags & AceFlags.InheritOnly) != 0 || entry.AceType is AceType.AccessDenied or AceType.AccessDeniedObject) continue;
                if (entry is not CommonAce ace) { who = "it has a permission entry of an unexpected kind"; break; }
                if ((ace.AccessMask & (WriteDacOrOwner | GenericAll)) != 0 && !IsTrusted(ace.SecurityIdentifier, includeCaller: true))
                { who = $"{Describe(ace.SecurityIdentifier)} can change its permissions"; break; }
            }
        if (who is not null)
            throw new IOException($"Refusing to protect {SafeText.Path(path)}: {who}, and may still hold a handle that keeps " +
                "that power after protecting. Have an administrator create a new folder (such as C:\\Config) and a new file in it.");
    }

    // A file on a share or a removable drive carries permissions set on another
    // machine: a hostile server can report any owner, and "Administrators" on a
    // stick means another computer's. Only a drive Windows reports as local and
    // fixed, on an internal bus, is believed.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathNameW(string path, [Out] char[] volume, uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, [Out] char[] name, uint length);

    [StructLayout(LayoutKind.Sequential)]
    private struct StoragePropertyQuery { public int PropertyId, QueryType; public byte Additional; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, ref StoragePropertyQuery input, int inputSize,
        byte[] output, int outputSize, out int returned, IntPtr overlapped);

    // USB and FireWire hard disks, and many USB sticks, report themselves as
    // fixed drives, so the drive type alone would let a disk prepared on another machine
    // through. The disk's bus says where it really is. A volume Windows will not
    // describe (one spanning several disks, say) is refused rather than guessed.
    private static bool OnInternalBus(string volumeRoot)
    {
        const uint QueryStorageProperty = 0x002D1400;
        char[] name = new char[64];
        if (!GetVolumeNameForVolumeMountPointW(volumeRoot, name, (uint)name.Length)) return false;
        using SafeFileHandle volume = OpenFileW(new string(name, 0, Array.IndexOf(name, '\0')).TrimEnd('\\'), 0,
            ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (volume.IsInvalid) return false;
        var query = new StoragePropertyQuery(); // StorageDeviceProperty, PropertyStandardQuery
        byte[] descriptor = new byte[1024];
        if (!DeviceIoControl(volume, QueryStorageProperty, ref query, Marshal.SizeOf<StoragePropertyQuery>(),
                descriptor, descriptor.Length, out int returned, IntPtr.Zero) || returned < 32) return false;
        bool removableMedia = descriptor[10] != 0;
        uint bus = BitConverter.ToUInt32(descriptor, 28); // STORAGE_DEVICE_DESCRIPTOR.BusType
        // A VHD/VHDX, virtual or iSCSI disk was also written on another machine.
        return !removableMedia && bus is not (4 /* 1394 */ or 7 /* USB */ or 9 /* iSCSI */ or 12 /* SD */ or
            13 /* MMC */ or 14 /* Virtual */ or 15 /* FileBackedVirtual */);
    }

    internal static bool OnLocalFixedDrive(SafeFileHandle handle)
    {
        const uint Fixed = 3;
        string real = FinalPath(handle);
        char[] volume = new char[32768];
        return !real.StartsWith(@"\\", StringComparison.Ordinal) && GetVolumePathNameW(real, volume, (uint)volume.Length) &&
            new string(volume, 0, Array.IndexOf(volume, '\0')) is { } root && GetDriveTypeW(root) == Fixed && OnInternalBus(root);
    }

    private static void RequireLocalFixedDrive(SafeFileHandle handle, string path)
    {
        if (OnLocalFixedDrive(handle)) return;
        throw new IOException($"{SafeText.Path(path)} is not on a local fixed drive. On a share, an external or removable " +
            "drive, or a virtual disk (VHD or VHDX), its permissions may have been set on another machine and prove nothing " +
            $"here. Copy it to a local folder, such as C:\\Config, then run: .\\WimDriverMount.exe --protect-config " +
            SafeText.Argument(System.IO.Path.Combine(@"C:\Config", System.IO.Path.GetFileName(path))));
    }

    private static void Describe(SafeFileHandle handle, TextWriter output)
    {
        var security = Security(handle);
        output.WriteLine($"  owner {(security.Owner is null ? "unknown" : Describe(security.Owner))}");
        if (security.DiscretionaryAcl is null) { output.WriteLine("  no access list: everyone has full access"); return; }
        foreach (GenericAce entry in security.DiscretionaryAcl)
            output.WriteLine(entry is CommonAce ace
                ? $"  {(ace.AceQualifier == AceQualifier.AccessAllowed ? "Allow" : ace.AceQualifier.ToString())} {Describe(ace.SecurityIdentifier)} {(FileSystemRights)ace.AccessMask}" +
                  ((ace.AceFlags & AceFlags.Inherited) != 0 ? " (inherited)" : "")
                : $"  {entry.AceType} entry");
    }

    private static void RequireAdministratorsOnly(string what, Func<FileSystemSecurity> read, string role, string settingsFile)
    {
        FileSystemSecurity security;
        try { security = read(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException or
            PlatformNotSupportedException or NotSupportedException or IOException)
        {
            throw new IOException(
                $"The permissions on the {role} {SafeText.Path(what)} cannot be read, so it cannot be " +
                $"shown to be safe to act on ({SafeText.Message(ex.Message)}). Copy it to a local folder that " +
                "only administrators can write, and name that copy instead.");
        }

        if (WhoElseCanChange(security) is { } why) throw Refuse(what, role, why, settingsFile);
    }

    // Why an account other than administrators could change this object, in plain
    // words ("it is owned by PC\user"), or null if none can. The owner can
    // rewrite the permissions whatever they say, so it is checked first. An entry
    // this program cannot read is not one it may ignore: an unusual entry is
    // exactly the shape a deliberately confusing one would take.
    // inheritable: also count rules that apply only to what is created inside,
    // for a folder whose new files must be as safe as the folder itself.
    internal static string? WhoElseCanChange(FileSystemSecurity security, FileSystemRights dangerous = Dangerous, bool inheritable = false)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner) return "its owner cannot be determined";
        if (!IsTrusted(owner)) return $"it is owned by {Describe(owner)}";
        AuthorizationRuleCollection rules;
        try { rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return "its permissions could not be interpreted"; }
        foreach (var entry in rules)
        {
            if (entry is not FileSystemAccessRule rule) return "it has a permission entry of an unexpected kind";
            // An inherit-only entry gives nothing on this object itself.
            if (rule.AccessControlType != AccessControlType.Allow || (!inheritable && (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) ||
                (rule.FileSystemRights & dangerous) == 0) continue;
            if (rule.IdentityReference is SecurityIdentifier sid && IsTrusted(sid)) continue;
            // Program Files gives CREATOR OWNER full control of what is created inside;
            // --install creates its files owned by Administrators, so that is them.
            if (inheritable && (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 &&
                rule.IdentityReference is SecurityIdentifier creator && creator.IsWellKnown(WellKnownSidType.CreatorOwnerSid)) continue;
            return $"{Describe(rule.IdentityReference)} can change it";
        }
        return null;
    }



    // Rights on a folder that let someone rename or delete what is inside it,
    // and so put another folder in place of one below.
    internal const FileSystemRights Rename = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    // The program runs as administrator, and its background worker is started
    // again from the same file. If other accounts can change the program or its
    // folder, they can change what runs as administrator. A warning, not a
    // refusal: running from a USB stick or a download folder is legitimate, and
    // the operator should know what it means.
    internal static void WarnIfProgramFolderOpen(TextWriter error)
    {
        string folder = AppContext.BaseDirectory.TrimEnd('\\');
        string? program = Environment.ProcessPath;
        const AccessControlSections Sections = AccessControlSections.Access | AccessControlSections.Owner;
        string? Check(Func<FileSystemSecurity> read, FileSystemRights dangerous = Dangerous)
        {
            try { return WhoElseCanChange(read(), dangerous); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException or IOException or NotSupportedException)
            { return "its permissions cannot be read"; }
        }
        string? why = Check(() => new DirectoryInfo(folder).GetAccessControl(Sections));
        string what = "The folder";
        string? shown = folder;
        if (why is null && program is not null) { why = Check(() => new FileInfo(program).GetAccessControl(Sections)); what = "The program"; shown = program; }
        // A folder above it matters too: whoever may delete or rename what is inside
        // a folder can rename the program's folder and put another in its place,
        // whatever the program's folder itself allows.
        for (string? parent = Path.GetDirectoryName(folder); why is null && parent is not null; parent = Path.GetDirectoryName(parent))
        {
            string above = parent;
            why = Check(() => new DirectoryInfo(above).GetAccessControl(Sections), Rename);
            what = "This folder"; shown = above;
        }
        if (why is null) return;
        error.WriteLine("WARNING: WimDriverMount may be changeable without administrator rights.");
        error.WriteLine($"  {SafeText.Path(shown)}");
        // "it is owned by X" -> "The folder is owned by X."; "its owner ..." -> "The folder's owner ...";
        // "X can change it" -> "X can change the folder."
        error.WriteLine("  " + (why.StartsWith("it ", StringComparison.Ordinal) ? what + why[2..]
            : why.StartsWith("its ", StringComparison.Ordinal) ? what + "'s" + why[3..]
            : why[..^2] + what.ToLowerInvariant()) + ".");
        if (what == "This folder")
            error.WriteLine("  So the folders inside it, including WimDriverMount's own, could be renamed or replaced.");
        error.WriteLine("  A program running without elevation could replace it, and it would then run as");
        error.WriteLine("  administrator the next time it is used. Keep WimDriverMount in a folder only");
        error.WriteLine("  administrators can change, such as C:\\Program Files\\WimDriverMount.");
    }

    // The account this elevated process is running as. It is trusted only by
    // --protect-config, where the operator approves the contents it prints, and
    // never when a settings file is acted on: the same account also runs
    // unelevated, and any unelevated process of it could otherwise rewrite the
    // file and choose what runs as administrator next time. The unelevated half
    // of a sign-in is treated as an attacker.
    // Windows gives a file an administrator creates to that administrator's own
    // account, so such a file needs one --protect-config, which makes the
    // Administrators group its owner.
    private static readonly SecurityIdentifier? Caller = Current();

    private static SecurityIdentifier? Current()
    {
        try { using var identity = WindowsIdentity.GetCurrent(); return identity.User; }
        catch (SystemException) { return null; }
    }

    // Deny rules are deliberately not consulted. Ignoring them can only make
    // this stricter, and the alternative is reasoning about ACL evaluation
    // order to decide whether to run someone's instructions as administrator.
    private static bool IsTrusted(SecurityIdentifier sid, bool includeCaller = false) =>
        sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
        sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" || // TrustedInstaller
        (includeCaller && Caller is not null && sid == Caller);

    // An account name as a person would write it: no quotes, single backslashes.
    private static string Describe(IdentityReference identity)
    {
        try { return SafeText.Path(identity.Translate(typeof(NTAccount)).Value); }
        catch (SystemException) { return SafeText.Path(identity.Value); }
    }

    // The fix is two commands, each printed on its own line so it can be copied alone.
    private static AdviceException Refuse(string what, string role, string why, string settingsFile) => new(
        $"Refusing to act on the {role} {SafeText.Path(what)} because {why}. A settings file can install " +
        "drivers and run programs with administrator rights, so only administrators may be able to change it.",
        "If the file is alone in a folder with no other folders in it, run:",
        $"  .\\WimDriverMount.exe --protect-config {SafeText.Argument(settingsFile)}",
        "Otherwise move it to a new folder, such as C:\\Config, and run:",
        $"  .\\WimDriverMount.exe --protect-config {SafeText.Argument(System.IO.Path.Combine(@"C:\Config", System.IO.Path.GetFileName(settingsFile)))}");
}

// An error whose fix is a few lines of its own (commands to copy), printed after the message.
internal sealed class AdviceException(string message, params string[] lines) : IOException(message)
{
    internal IReadOnlyList<string> Lines { get; } = lines;
}
