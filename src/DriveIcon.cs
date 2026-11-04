using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

// Shows the application icon for a mounted drive letter in Explorer, using the
// drive icon key under Software\Classes (Explorer\DriveIcons). A setting that
// points elsewhere is the user's and is left alone; one left by this program (a
// crashed mount) is reused and removed. Cosmetic only: failures are ignored.
//
// A background mount also gets "Unmount with WIM Driver Mount" on that drive's
// right-click menu: a per-user Drive verb limited to the one letter by AppliesTo
// (System.ParsingPath: shown on that drive and no other).
//
// Both are machine-wide (HKLM) when the running program is the one the machine-wide
// Mount menu runs (ExplorerMenu.Registered): the drive letter is every account's,
// and the account that clicked Mount may not be the administrator this runs as, so
// a per-user entry would be missing for it. Pointing one more machine entry at the
// program --install put in an administrators-only folder trusts nothing new. Any
// copy other than the installed one keeps them per user (HKCU): a machine entry
// would have every account run a file its owner can replace.
// It runs --unmount, which asks for administrator rights as usual. Windows 11
// lists such entries under "Show more options". Anything the user's unelevated
// programs could add here they could already add as a verb of their own, so the
// entry itself opens nothing new.
//
// The per-user keys are the user's, and this code runs elevated: an unelevated program
// could make one of them a registry link to a key only administrators may
// change, so values are written, and keys deleted, only through a handle
// whose real name is checked first, and nothing is deleted recursively.
// The most a link can still do is have an empty key created at its target.
internal sealed class DriveIcon : IDisposable
{
    private const string Classes = @"Software\Classes\";
    private const string Root = Classes + @"Applications\Explorer.exe\Drives";
    private const string Verbs = Classes + @"Drive\shell";
    private const string ExeName = "WimDriverMount.exe";
    private readonly RegistryKey hive;
    private readonly string? key;
    private readonly string? verb;

    [DllImport("shell32.dll")] private static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);
    [DllImport("ntdll.dll")] private static extern int NtQueryKey(SafeRegistryHandle key, int informationClass, byte[] buffer, int length, out int needed);
    [DllImport("ntdll.dll")] private static extern int NtDeleteKey(SafeRegistryHandle key);

    // HKCU\Software\Classes is the user's own classes hive.
    private static readonly string? ClassesHive = UserSid() is { } sid ? $@"\REGISTRY\USER\{sid}_Classes\" : null;

    private static string? UserSid()
    {
        try { using var identity = WindowsIdentity.GetCurrent(); return identity.User?.Value; }
        catch (SystemException) { return null; }
    }

    // Throws unless the open key really is HKCU\<path>, with no link on the way.
    internal static void RequireReal(RegistryKey key, string path)
    {
        if (!path.StartsWith(Classes, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException(@"Only keys under HKCU\Software\Classes are checked.");
        var buffer = new byte[4096];
        if (ClassesHive is null || NtQueryKey(key.Handle, 3 /* KeyNameInformation */, buffer, buffer.Length, out _) != 0)
            throw new IOException("The registry key's real name cannot be read.");
        int length = BitConverter.ToInt32(buffer, 0);
        if (length < 0 || length > buffer.Length - 4) throw new IOException("The registry key's name is malformed.");
        string real = System.Text.Encoding.Unicode.GetString(buffer, 4, length);
        if (!string.Equals(real, ClassesHive + path[Classes.Length..], StringComparison.OrdinalIgnoreCase))
            throw new IOException("The registry key is a link to another key.");
    }

    private static RegistryKey Create(string path)
    {
        var key = Registry.CurrentUser.CreateSubKey(path);
        try { RequireReal(key, path); return key; }
        catch { key.Dispose(); throw; }
    }

    // Deletes one key, never a tree; one that still holds subkeys stays.
    internal static void Delete(string path, bool onlyIfEmpty = false)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path, RegistryRights.Delete | RegistryRights.ReadKey);
        if (key is null) return;
        RequireReal(key, path);
        if (!onlyIfEmpty || (key.SubKeyCount == 0 && key.ValueCount == 0)) NtDeleteKey(key.Handle);
    }

    private DriveIcon(RegistryKey hive, string? key, string? verb) { this.hive = hive; this.key = key; this.verb = verb; }

    // Only administrators can change HKLM\Software\Classes, so it needs no link checks (as ExplorerMenu).
    private static RegistryKey Make(RegistryKey hive, string path) => hive == Registry.LocalMachine ? hive.CreateSubKey(path) : Create(path);

    private static void Drop(RegistryKey hive, string path, bool onlyIfEmpty = false)
    {
        if (hive != Registry.LocalMachine) { Delete(path, onlyIfEmpty); return; }
        using (var key = hive.OpenSubKey(path))
            if (key is null || (onlyIfEmpty && (key.SubKeyCount > 0 || key.ValueCount > 0))) return;
        try { hive.DeleteSubKey(path, throwOnMissingSubKey: false); }
        catch (InvalidOperationException) { } // Holds another subkey: not only ours.
    }

    private static string VerbKey(char drive) => $@"{Verbs}\WimDriverMount.Unmount.{char.ToUpperInvariant(drive)}";

    internal static DriveIcon Set(char drive, bool unmountMenu = false)
    {
        string? exe = Environment.ProcessPath;
        if (exe is null) return new(Registry.CurrentUser, null, null);
        // shortcut: written before Dokan takes the letter, so in that moment another
        // administrator's mount on the same letter, --unmount or --uninstall can remove this
        // machine entry; a lost entry only, never a wrong one. Move this after the letter is
        // confirmed if that is ever seen.
        RegistryKey hive = ExplorerMenu.Registered(exe) ? Registry.LocalMachine : Registry.CurrentUser;
        // An older per-user entry for this letter would win over the machine one in Explorer.
        if (hive == Registry.LocalMachine) RemoveOurs(Registry.CurrentUser, drive);
        string? icon = null, verb = null;
        try
        {
            string path = $@"{Root}\{drive}";
            bool foreign;
            using (var existing = hive.OpenSubKey(path)) foreign = existing is not null && !IsOurs(hive, drive);
            if (!foreign)
            {
                using var iconKey = Make(hive, path + @"\DefaultIcon");
                iconKey.SetValue(null, $"\"{exe}\",0");
                icon = path;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
        if (unmountMenu)
        {
            try
            {
                string path = VerbKey(drive);
                using var entry = Make(hive, path);
                entry.SetValue(null, "Unmount with WIM Driver Mount");
                entry.SetValue("AppliesTo", $"System.ParsingPath:=\"{char.ToUpperInvariant(drive)}:\\\"");
                entry.SetValue("Icon", $"\"{exe}\",0");
                using var command = Make(hive, path + @"\command");
                // Through Windows' own console host with no window (conhost --headless), so the
                // right-click Unmount shows nothing but the administrator prompt; --from-menu
                // makes a failure or a needed restart appear as a message box instead.
                string host = Path.Combine(Environment.SystemDirectory, "conhost.exe");
                command.SetValue(null, $"\"{host}\" --headless \"{exe}\" --unmount {char.ToUpperInvariant(drive)}: --from-menu");
                verb = path;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
        }
        Refresh();
        return new(hive, icon, verb);
    }

    // Removes an icon setting or menu entry this program left for a drive whose
    // mount ended without cleanup, in either place (versions before 0.7.6 used only HKCU).
    // Not while the letter is in use: the machine entry may be another account's live mount.
    // recordRetired: this account's own record for the letter was just retired, so its own
    // per-user entry is stale even if another drive has the letter now.
    internal static void RemoveStale(char drive, bool recordRetired = false)
    {
        bool inUse = WorkerRecoveryStore.PreparedReservation.DriveLetterAssigned(drive);
        if (!inUse) RemoveOurs(Registry.LocalMachine, drive);
        if (!inUse || recordRetired) RemoveOurs(Registry.CurrentUser, drive);
    }

    // Every free letter's leftovers, for --uninstall. One on a letter in use (a live mount,
    // or a crashed one's letter since taken by another drive) is left: it may be live.
    internal static void RemoveAllStale()
    {
        for (char drive = 'D'; drive <= 'Z'; drive++) RemoveStale(drive);
    }

    private static void RemoveOurs(RegistryKey hive, char drive)
    {
        try { if (IsOurs(hive, drive)) Remove(hive, $@"{Root}\{drive}"); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
        try { if (VerbIsOurs(hive, drive)) RemoveVerb(hive, VerbKey(drive)); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
    }

    // Removes only the icon; the drive key goes too only if nothing else (such as a label) is in it.
    private static void Remove(RegistryKey hive, string driveKey)
    {
        Drop(hive, driveKey + @"\DefaultIcon");
        Drop(hive, driveKey, onlyIfEmpty: true);
        Refresh();
    }

    private static void RemoveVerb(RegistryKey hive, string verbKey)
    {
        Drop(hive, verbKey + @"\command");
        Drop(hive, verbKey);
        Refresh();
    }

    private static bool IsOurs(RegistryKey hive, char drive)
    {
        using var icon = hive.OpenSubKey($@"{Root}\{drive}\DefaultIcon");
        return icon?.GetValue(null) is string value && value.Contains(ExeName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool VerbIsOurs(RegistryKey hive, char drive)
    {
        using var command = hive.OpenSubKey(VerbKey(drive) + @"\command");
        return command?.GetValue(null) is string value && value.Contains(ExeName, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        try { if (key is not null) Remove(hive, key); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
        try { if (verb is not null) RemoveVerb(hive, verb); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
    }

    internal static void Refresh() => SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero); // SHCNE_ASSOCCHANGED
}
