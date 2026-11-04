using Microsoft.Win32;

// "Mount with WIM Driver Mount" on the right-click menu of .wim, .swm and .esd
// files, as Windows offers Mount on an ISO. A verb under SystemFileAssociations
// adds to the menu without taking over the file type: double-click, and whatever
// other program owns .wim, are left as they are. The verb runs the installed
// program through Windows' own console host with no window, as the drive's
// Unmount entry does (DriveIcon).
//
// Machine-wide, written by the elevated --install: the program is installed for
// every account in a folder only administrators can change, so every account gets
// the menu. By default only administrators can change HKLM\Software\Classes, so
// these writes use no link checks; where something has opened that key to others,
// they could equally add a verb of their own there. Versions before 0.7.4 wrote the entry per user
// (HKCU); RemoveUserEntry clears that leftover.
internal static class ExplorerMenu
{
    internal static readonly string[] Extensions = [".wim", ".swm", ".esd"];
    internal const string DefaultRoot = @"Software\Classes\SystemFileAssociations";
    internal const string MountFlag = "--mount-from-menu";
    private const string VerbName = "WimDriverMount.Mount";

    private static string VerbKey(string root, string extension) => $@"{root}\{extension}\shell\{VerbName}";

    internal static string Command(string program) =>
        $"\"{Path.Combine(Environment.SystemDirectory, "conhost.exe")}\" --headless \"{program}\" {MountFlag} \"%1\" --from-menu";

    // hive: HKLM in use; tests pass HKCU with a root of their own.
    internal static void Register(string program, string root = DefaultRoot, RegistryKey? hive = null)
    {
        hive ??= Registry.LocalMachine;
        foreach (string extension in Extensions)
        {
            string path = VerbKey(root, extension);
            using (var entry = hive.CreateSubKey(path))
            {
                entry.SetValue(null, "Mount with WIM Driver Mount");
                entry.SetValue("Icon", $"\"{program}\",0");
                // One file at a time: several mounts started together would each
                // pick the same free letter before any of them took it.
                entry.SetValue("MultiSelectModel", "Single");
            }
            using var command = hive.CreateSubKey(path + @"\command");
            command.SetValue(null, Command(program));
        }
        DriveIcon.Refresh();
    }

    // Removes only entries that run this program from this folder: one of the
    // same name pointing anywhere else is another program's, or another install's.
    // The extension's own keys stay, and a key that still holds anything else is
    // left. Returns how many were removed.
    internal static int Unregister(string program, string root = DefaultRoot, RegistryKey? hive = null)
    {
        hive ??= Registry.LocalMachine;
        int removed = 0;
        foreach (string extension in Extensions)
        {
            string path = VerbKey(root, extension);
            if (!Ours(hive, path, program)) continue;
            hive.DeleteSubKey(path + @"\command", throwOnMissingSubKey: false);
            try { hive.DeleteSubKey(path, throwOnMissingSubKey: false); }
            catch (InvalidOperationException) { } // Holds another subkey: not only ours.
            removed++;
        }
        DriveIcon.Refresh();
        return removed;
    }

    // The per-user entry versions before 0.7.4 wrote, in this account. These keys are
    // the user's and this may run elevated, so they are deleted through DriveIcon, which
    // refuses a key that is a link to another one.
    internal static int RemoveUserEntry(string program, string root = DefaultRoot)
    {
        int removed = 0;
        foreach (string extension in Extensions)
        {
            string path = VerbKey(root, extension);
            if (!Ours(Registry.CurrentUser, path, program)) continue;
            DriveIcon.Delete(path + @"\command");
            DriveIcon.Delete(path);
            removed++;
        }
        if (removed > 0) DriveIcon.Refresh();
        return removed;
    }

    // Whether the machine-wide entry runs this program, for every extension.
    internal static bool Registered(string program, string root = DefaultRoot, RegistryKey? hive = null) =>
        Extensions.All(extension => Ours(hive ?? Registry.LocalMachine, VerbKey(root, extension), program));

    private static bool Ours(RegistryKey hive, string path, string program)
    {
        using var command = hive.OpenSubKey(path + @"\command");
        return string.Equals(command?.GetValue(null) as string, Command(program), StringComparison.OrdinalIgnoreCase);
    }
}
