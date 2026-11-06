using System.Runtime.InteropServices;
using Microsoft.Win32;

// Drive letters other sign-ins use. A letter mapped only in another logon session (the
// signed-in user's non-elevated half, another account, a subst) is invisible to this
// process's QueryDosDevice, and a mount there would sit under that mapping.
internal static class DriveLetters
{
    private const int AccessDenied = unchecked((int)0xC0000022), NotFound = unchecked((int)0xC0000034), NoMoreEntries = unchecked((int)0x8000001A), MoreEntries = 0x105;
    private const uint DirectoryQuery = 1, DirectoryTraverse = 2, SymbolicLinkQuery = 1;

    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct DirectoryEntry { public UnicodeString Name, TypeName; }

    [DllImport("ntdll.dll")] private static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
    [DllImport("ntdll.dll")] private static extern int NtOpenSymbolicLinkObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
    [DllImport("ntdll.dll")] private static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer, int length, byte single, byte restart, ref uint context, out int returned);
    [DllImport("ntdll.dll")] private static extern int NtClose(IntPtr handle);

    // Letters seen by any logon session, plus saved network drives of every loaded profile
    // (they come back at the next sign-in). Administrators only: others cannot list sessions,
    // so a non-elevated caller gets only its own saved network drives and the elevated copy checks again.
    // A session or profile its user has closed to administrators is skipped and reported in
    // `skipped` (Jericho, 2026-11-06): failing instead would let any standard user stop every
    // mount on the machine, while a mount under a skipped letter is hidden only from that user.
    internal static HashSet<char> UsedElsewhere(bool administrator, out bool skipped)
    {
        var used = new HashSet<char>();
        skipped = false;
        if (!administrator)
        {
            skipped = !AddSaved(Registry.CurrentUser, "Network", used);
            return used;
        }
        const string root = @"\Sessions\0\DosDevices";
        foreach (string session in Names(root))
        {
            // Each session's directory is its user's to fill, so it is never listed: the kernel
            // walks it from the start on every query call, and 100k names stalled every mount
            // for 62 s on 0.9.3. Only A: to Z: matter, so look those up by name: 26 lookups,
            // whatever else is there.
            int status = Open(IntPtr.Zero, $@"{root}\{session}", DirectoryTraverse, link: false, out IntPtr directory);
            if (status == NotFound) continue; // signed out while listed
            if (status != 0) { skipped = true; continue; }
            try
            {
                for (char letter = 'A'; letter <= 'Z'; letter++)
                {
                    // Anything but "not found" means a name is there (a link, another object
                    // type, or one closed to administrators): the letter is taken.
                    status = Open(directory, $"{letter}:", SymbolicLinkQuery, link: true, out IntPtr found);
                    if (status == 0) NtClose(found);
                    if (status != NotFound) used.Add(letter);
                }
            }
            finally { NtClose(directory); }
        }
        using (RegistryKey users = Registry.Users)
            foreach (string sid in users.GetSubKeyNames())
                if (!AddSaved(users, $@"{sid}\Network", used)) skipped = true;
        return used;
    }

    // False when the key exists but cannot be read (its user denied administrators).
    private static bool AddSaved(RegistryKey hive, string path, HashSet<char> used)
    {
        try
        {
            using RegistryKey? network = hive.OpenSubKey(path);
            if (network is null) return true;
            foreach (string name in network.GetSubKeyNames())
                if (name.Length == 1 && char.ToUpperInvariant(name[0]) is >= 'A' and <= 'Z' and char letter) used.Add(letter);
            return true;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    // Opens a directory or symbolic link by name, relative to `root` when it is not zero.
    private static int Open(IntPtr root, string path, uint access, bool link, out IntPtr handle)
    {
        IntPtr text = Marshal.StringToHGlobalUni(path), name = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(path.Length * 2), MaximumLength = (ushort)(path.Length * 2), Buffer = text }, name, false);
            var attributes = new ObjectAttributes { Length = Marshal.SizeOf<ObjectAttributes>(), RootDirectory = root, ObjectName = name, Attributes = 0x40 }; // OBJ_CASE_INSENSITIVE
            return link ? NtOpenSymbolicLinkObject(out handle, access, ref attributes) : NtOpenDirectoryObject(out handle, access, ref attributes);
        }
        finally { Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(text); }
    }

    // Names in the system's \Sessions\0\DosDevices: one directory per logon session, made by the
    // system, so a short list. It must be readable, else this throws.
    private static List<string> Names(string path)
    {
        var names = new List<string>();
        IntPtr buffer = IntPtr.Zero;
        int status = Open(IntPtr.Zero, path, DirectoryQuery, link: false, out IntPtr handle);
        if (status != 0) throw new IOException($"Cannot check which drive letters other sign-ins use ({path}: 0x{status:X8}{(status == AccessDenied ? ", access denied" : "")}).");
        try
        {
            // 128 KiB holds any single entry (a name is at most 64 KiB).
            const int size = 0x20000;
            buffer = Marshal.AllocHGlobal(size);
            uint context = 0;
            int entrySize = Marshal.SizeOf<DirectoryEntry>();
            for (byte restart = 1; ; restart = 0)
            {
                status = NtQueryDirectoryObject(handle, buffer, size, 0, restart, ref context, out _);
                if (status == NoMoreEntries) return names;
                if (status != 0 && status != MoreEntries) throw new IOException($"Cannot list {path} (0x{status:X8}).");
                // The entries end with an all-zero one; their names follow them in the buffer.
                int before = names.Count;
                for (int offset = 0; offset + entrySize <= size; offset += entrySize)
                {
                    var entry = Marshal.PtrToStructure<DirectoryEntry>(buffer + offset);
                    if (entry.Name.Buffer == IntPtr.Zero) break;
                    names.Add(Marshal.PtrToStringUni(entry.Name.Buffer, entry.Name.Length / 2));
                }
                if (status == 0) return names;
                // More to come but nothing returned: stop rather than ask forever.
                if (names.Count == before) throw new IOException($"Cannot list {path} (no entries returned).");
            }
        }
        finally
        {
            NtClose(handle);
            Marshal.FreeHGlobal(buffer);
        }
    }
}
