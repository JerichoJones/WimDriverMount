using System.Runtime.InteropServices;
using Microsoft.Win32;

// Drive letters other sign-ins use. A letter mapped only in another logon session (the
// signed-in user's non-elevated half, another account, a subst) is invisible to this
// process's QueryDosDevice, and a mount there would sit under that mapping.
internal static class DriveLetters
{
    private const int AccessDenied = unchecked((int)0xC0000022), NotFound = unchecked((int)0xC0000034), NoMoreEntries = unchecked((int)0x8000001A);

    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct DirectoryEntry { public UnicodeString Name, TypeName; }

    [DllImport("ntdll.dll")] private static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
    [DllImport("ntdll.dll")] private static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer, int length, byte single, byte restart, ref uint context, out int returned);
    [DllImport("ntdll.dll")] private static extern int NtClose(IntPtr handle);

    // Letters seen by any logon session, plus saved network drives of every loaded profile
    // (they come back at the next sign-in). Administrators only: others cannot list sessions,
    // so a non-elevated caller gets an empty set and the elevated copy checks again.
    internal static HashSet<char> UsedElsewhere()
    {
        var used = new HashSet<char>();
        if (!Program.IsAdministrator()) return used;
        const string root = @"\Sessions\0\DosDevices";
        foreach (string session in Names(root, required: true))
            foreach (string name in Names($@"{root}\{session}", required: false))
                if (name.Length == 2 && name[1] == ':' && char.ToUpperInvariant(name[0]) is >= 'A' and <= 'Z' and char letter) used.Add(letter);
        using (RegistryKey users = Registry.Users)
            foreach (string sid in users.GetSubKeyNames())
            {
                using RegistryKey? network = users.OpenSubKey($@"{sid}\Network");
                if (network is null) continue;
                foreach (string name in network.GetSubKeyNames())
                    if (name.Length == 1 && char.ToUpperInvariant(name[0]) is >= 'A' and <= 'Z' and char letter) used.Add(letter);
            }
        return used;
    }

    // A session that signs out while listed is gone (not found); anything else fails loudly,
    // because a letter we could not check might be in use.
    private static List<string> Names(string path, bool required)
    {
        var names = new List<string>();
        IntPtr text = Marshal.StringToHGlobalUni(path), name = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>()), buffer = IntPtr.Zero, handle = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(path.Length * 2), MaximumLength = (ushort)(path.Length * 2), Buffer = text }, name, false);
            var attributes = new ObjectAttributes { Length = Marshal.SizeOf<ObjectAttributes>(), ObjectName = name, Attributes = 0x40 }; // OBJ_CASE_INSENSITIVE
            int status = NtOpenDirectoryObject(out handle, 1, ref attributes); // DIRECTORY_QUERY
            if (status == NotFound && !required) return names;
            if (status != 0) throw new IOException($"Cannot check which drive letters other sign-ins use ({path}: 0x{status:X8}{(status == AccessDenied ? ", access denied" : "")}).");
            const int size = 4096;
            buffer = Marshal.AllocHGlobal(size);
            uint context = 0;
            for (byte restart = 1; ; restart = 0)
            {
                status = NtQueryDirectoryObject(handle, buffer, size, 1, restart, ref context, out _);
                if (status == NoMoreEntries) return names;
                if (status != 0) throw new IOException($"Cannot list {path} (0x{status:X8}).");
                var entry = Marshal.PtrToStructure<DirectoryEntry>(buffer);
                names.Add(Marshal.PtrToStringUni(entry.Name.Buffer, entry.Name.Length / 2));
            }
        }
        finally
        {
            if (handle != IntPtr.Zero) NtClose(handle);
            Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(text);
        }
    }
}
