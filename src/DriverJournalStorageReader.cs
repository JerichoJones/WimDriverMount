using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

// Disconnected read-only driver journal inspection. It never opens the worker
// recovery namespace, creates objects, or establishes a trustworthy result.
internal static partial class WorkerRecoveryStore
{
    private const int JournalDirectoryBufferLength = 65536;
    internal const int JournalDirectoryLimit = DriverJournalInventory.MaximumEntries + 2; // Inventory and dot entries.
    internal static bool JournalDirectoryCountAllowed(int count) => count >= 0 && count <= JournalDirectoryLimit;
    private const int JournalNoMoreFiles = 18;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, IntPtr buffer, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder? volumeName,
        uint volumeNameSize, out uint serial, out uint maximumComponentLength, out uint flags,
        StringBuilder fileSystemName, uint fileSystemNameSize);

    internal static DriverJournalInventory.Result ReadDriverJournalOperation(Guid operationId)
        => ReadDriverJournalOperationCore(operationId, legacyProgramData: false);

    // Explicit inspection only. Never move, delete, or silently fall back to
    // legacy journals. The same strict ancestor policy still applies there.
    internal static DriverJournalInventory.Result ReadLegacyDriverJournalOperation(Guid operationId)
        => ReadDriverJournalOperationCore(operationId, legacyProgramData: true);

    private static DriverJournalInventory.Result ReadDriverJournalOperationCore(Guid operationId, bool legacyProgramData)
    {
        if (operationId == Guid.Empty) throw new ArgumentException("Operation ID is required.", nameof(operationId));
        // The reconciler converts nonfatal iterator failures to unknown while
        // retaining restart indications from entries it already observed.
        return DriverJournalInventory.Reconcile(EnumerateDriverJournalOperation(operationId, legacyProgramData));
    }

    private static IEnumerable<KeyValuePair<string, byte[]>> EnumerateDriverJournalOperation(Guid operationId, bool legacyProgramData)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) throw new PlatformNotSupportedException();
        using WindowsIdentity? ambient = WindowsIdentity.GetCurrent(true);
        if (ambient is not null) throw new InvalidOperationException("Journal inspection requires a non-impersonated caller.");
        using WindowsIdentity owner = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = owner.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        string basePath = GetRecoveryBasePath(driverJournal: true, legacyDriverJournal: legacyProgramData);
        string root = System.IO.Path.GetPathRoot(basePath) ?? throw new IOException("Journal storage root is unavailable.");
        if (root.Length != 3 || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed)
            throw new IOException("Driver journal requires a local fixed drive.");
        string privatePath = System.IO.Path.Combine(basePath, "WimDrive-DriverJournal-" + sid.Value);
        string operationPath = System.IO.Path.Combine(privatePath, operationId.ToString("N"));
        using var parents = new DirectoryHandles(privatePath);
        string current = root;
        parents.Add(OpenDirectory(current, false, rejectReparseWrites: true, pinAgainstRename: true));
        foreach (string part in basePath[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            current = System.IO.Path.Combine(current, part);
            parents.Add(OpenDirectory(current, false, rejectReparseWrites: true, pinAgainstRename: true));
        }
        SafeFileHandle privateDir = OpenDirectory(privatePath, true, rejectReparseWrites: true, pinAgainstRename: true);
        parents.Add(privateDir);
        // Journals are written without an integrity label, so an elevated
        // inspection must not demand one the way the worker store does.
        RequirePrivateSecurity(privateDir, sid, labelled: false);
        using SafeFileHandle operation = OpenDirectory(operationPath, true, rejectReparseWrites: true, pinAgainstRename: true);
        RequirePrivateSecurity(operation, sid, labelled: false);
        foreach (var entry in EnumerateHeldDriverJournalOperation(operationPath, operation, sid))
            yield return entry;
    }

    // The caller must retain the strict operation and ancestor handles for the
    // entire enumeration and must establish the path's trusted identity first.
    private static IEnumerable<KeyValuePair<string, byte[]>> EnumerateHeldDriverJournalOperation(
        string operationPath, SafeFileHandle operation, SecurityIdentifier sid)
    {
        if (!GetFileInformationByHandle(operation, out FileInformation operationInfo))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect journal operation identity.");
        var fileSystem = new StringBuilder(261);
        if (!GetVolumeInformationByHandleW(operation, null, 0, out uint serial, out _, out _, fileSystem, 261))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect journal volume.");
        if (!string.Equals(fileSystem.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase) || serial != operationInfo.Volume)
            throw new IOException("Journal inspection requires the verified NTFS volume.");

        IntPtr native = Marshal.AllocHGlobal(JournalDirectoryBufferLength);
        try
        {
            var buffer = new byte[JournalDirectoryBufferLength];
            var ids = new HashSet<ulong>();
            int total = 0;
            bool restart = true;
            while (true)
            {
                Array.Clear(buffer);
                Marshal.Copy(buffer, 0, native, buffer.Length);
                if (!GetFileInformationByHandleEx(operation, restart ? 11 : 10, native, (uint)buffer.Length))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == JournalNoMoreFiles) yield break;
                    throw new Win32Exception(error, "Cannot enumerate journal operation.");
                }
                restart = false;
                Marshal.Copy(native, buffer, 0, buffer.Length);
                foreach (var entry in DriverJournalDirectoryBuffer.Parse(buffer))
                {
                    if (!JournalDirectoryCountAllowed(++total)) throw new InvalidDataException("Journal inventory exceeds its limit.");
                    if (entry.Name is "." or "..") continue;
                    bool unique = entry.FileId != 0 && ids.Add(entry.FileId);
                    yield return new(entry.Name, unique
                        ? TryReadJournalEntry(operationPath, entry, operationInfo.Volume, sid)
                        : Array.Empty<byte>());
                }
            }
        }
        finally { Marshal.FreeHGlobal(native); }
    }

    private static byte[] TryReadJournalEntry(string directory, DriverJournalDirectoryBuffer.Entry entry, uint volume, SecurityIdentifier sid)
    {
        try
        {
            if (entry.Name.Length == 0 || entry.Name.IndexOfAny(new[] { '\\', '/', ':', '\0' }) >= 0 ||
                (entry.Attributes & (DirectoryAttribute | ReparseAttribute)) != 0)
                throw new InvalidDataException("Invalid journal entry.");
            string path = System.IO.Path.Combine(directory, entry.Name);
            using SafeFileHandle file = OpenFileW(path, GenericRead | ReadControl, 0, IntPtr.Zero,
                OpenExisting, OpenReparsePoint, IntPtr.Zero);
            RequireValid(file, "Cannot open journal record.");
            RequireRegularFile(file);
            RequirePrivateSecurity(file, sid, labelled: false);
            if (!GetFileInformationByHandle(file, out FileInformation info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect journal record identity.");
            ulong fileId = ((ulong)info.IndexHigh << 32) | info.IndexLow;
            if (info.Volume != volume || fileId != entry.FileId) throw new IOException("Journal record identity changed.");
            using var stream = new FileStream(file, FileAccess.Read, 1, isAsync: false);
            if (stream.Length is < 2 or > 65536) throw new InvalidDataException("Invalid journal record length.");
            var data = new byte[checked((int)stream.Length)];
            stream.ReadExactly(data);
            return data;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException or System.Threading.ThreadAbortException or SEHException))
        {
            // Keep enumerating: a later valid completion may report restart.
            // An empty value makes the reconciliation result inconsistent.
            return Array.Empty<byte>();
        }
    }
}
