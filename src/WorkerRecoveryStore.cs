// Recovery storage used by worker startup and control.
// The per-user file ACL does not protect against hostile processes in that user.
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal static partial class WorkerRecoveryStore
{
    private const uint ReadAttributes = 0x80, ReadControl = 0x20000, DeleteAccess = 0x10000;
    private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000;
    private const uint ShareRead = 1, ShareWrite = 2;
    private const uint OpenExisting = 3, CreateNew = 1;
    private const uint BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000, WriteThrough = 0x80000000;
    private const uint DirectoryAttribute = 0x10, ReparseAttribute = 0x400;
    private const int MaximumRecord = 4096;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int InheritHandle; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public FileTime Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileDisposition { public byte DeleteFile; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, ref SecurityAttributes attributes,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string name, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle OpenFileW(string name, uint access, uint share, IntPtr attributes,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass,
        ref FileDisposition information, uint size);

    // Each drive has prepared, ready, staged/closed receipt and staged/final
    // journal slots. Exclusive creation bounds the store to 138 files.
    // Keep both slots until authenticated cleanup permits their safe removal.
    // Successful flush is not a guarantee against every power-loss scenario.
    internal static string WritePrepared(WorkerRecoveryRecord record) => WriteNewCore(record, ready: false);

    private static string WriteNewCore(WorkerRecoveryRecord record, bool ready)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (ready != (record.ObservedMapping is not null)) throw new ArgumentException("Record state does not match its file.");
        using var directories = OpenRecoveryDirectory();
        string path = RecordPath(directories.Path, record.Drive, ready);
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        string sddl = PrivateSddl(sid);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out IntPtr descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create recovery file security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, InheritHandle = 0 };
            using SafeFileHandle handle = CreateFileW(path, GenericRead | GenericWrite | ReadControl | DeleteAccess, 0, ref attributes,
                CreateNew, OpenReparsePoint | WriteThrough, IntPtr.Zero);
            if (handle.IsInvalid && Marshal.GetLastWin32Error() is 80 or 183) // already exists: a leftover record
                throw new IOException(SlotTaken(record.Drive));
            RequireValid(handle, "Cannot create recovery record.");
            byte[]? encoded = null, check = null;
            FileStream? stream = null;
            try
            {
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid);
                if (!ready)
                {
                    RequireSlotEmpty(RecordPath(directories.Path, record.Drive, ready: true), record.Drive);
                    RequireSlotEmpty(ReceiptPath(directories.Path, record.Drive), record.Drive);
                    RequireSlotEmpty(ReceiptStagePath(directories.Path, record.Drive), record.Drive);
                    RequireSlotEmpty(JournalPath(directories.Path, record.Drive), record.Drive);
                    RequireSlotEmpty(JournalStagePath(directories.Path, record.Drive), record.Drive);
                }
                encoded = record.Encode();
                stream = new FileStream(handle, FileAccess.ReadWrite, 1, isAsync: false);
                stream.Write(encoded);
                stream.Flush(flushToDisk: true);
                if (stream.Length != encoded.Length) throw new IOException("Recovery record length changed.");
                stream.Position = 0;
                check = new byte[encoded.Length];
                stream.ReadExactly(check);
                if (!CryptographicOperations.FixedTimeEquals(encoded, check)) throw new IOException("Recovery record verification failed.");
                return path;
            }
            catch (Exception original)
            {
                // This handle is the file created by this call. A prepared
                // write is required to finish before GO. Never delete by path.
                try
                {
                    var disposition = new FileDisposition { DeleteFile = 1 };
                    if (!SetFileInformationByHandle(handle, 4, ref disposition, (uint)Marshal.SizeOf<FileDisposition>()))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot roll back recovery record.");
                }
                catch (Exception rollback) { throw new AggregateException("Recovery write and handle-bound rollback failed; the slot remains unknown.", original, rollback); }
                throw;
            }
            finally
            {
                try { stream?.Dispose(); }
                finally
                {
                    if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
                    if (check is not null) CryptographicOperations.ZeroMemory(check);
                }
            }
        }
        finally { LocalFree(descriptor); }
    }

    // Retain this reservation across any operation that relies on the prepared
    // identity. Recovery derives its authority from the held record.
    internal static PreparedReservation ReservePrepared(char drive) => PreparedReservation.Open(drive);

    // Startup must match the record it actually wrote before sending GO.
    internal static PreparedReservation ReserveExpectedPrepared(WorkerRecoveryRecord expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (expected.ObservedMapping is not null) throw new ArgumentException("Expected a prepared record.");
        PreparedReservation reservation;
        for (int attempt = 0; ; attempt++)
        {
            try { reservation = PreparedReservation.Open(expected.Drive); break; }
            // Another mount on this letter may hold the record for a moment while it
            // checks whether it is left from an ended mount (WorkerUnmount.ClearEnded).
            catch (Win32Exception ex) when (ex.NativeErrorCode == 32 && attempt < 100) { Thread.Sleep(20); }
        }
        try { reservation.RequireExpected(expected); return reservation; }
        catch { reservation.Dispose(); throw; }
    }

    private static RecordLease OpenRecord(char drive, bool ready, bool forDeletion = false)
    {
        if (drive is < 'D' or > 'Z') throw new ArgumentException("Invalid recovery drive.");
        DirectoryHandles directories = OpenRecoveryDirectory();
        SafeFileHandle? handle = null;
        FileStream? stream = null;
        WorkerRecoveryRecord? record = null;
        try
        {
            string path = RecordPath(directories.Path, drive, ready);
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
            handle = OpenFileW(path, GenericRead | ReadControl | (forDeletion ? DeleteAccess : 0), 0,
                IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
            RequireValid(handle, "Cannot open recovery record.");
            RequireRegularFile(handle);
            RequirePrivateSecurity(handle, sid);
            stream = new FileStream(handle, FileAccess.Read, 1, isAsync: false);
            if (stream.Length <= 0 || stream.Length > MaximumRecord) throw new InvalidDataException("Invalid recovery record size.");
            byte[] data = new byte[checked((int)stream.Length)];
            try { stream.ReadExactly(data); record = WorkerRecoveryRecord.Decode(data); }
            finally { CryptographicOperations.ZeroMemory(data); }
            if (record.Drive != drive || ready != (record.ObservedMapping is not null))
                throw new InvalidDataException("Recovery record identity or state does not match its path.");
            return new RecordLease(directories, handle, stream, record);
        }
        catch
        {
            record?.Dispose();
            try { stream?.Dispose(); }
            finally { handle?.Dispose(); directories.Dispose(); }
            throw;
        }
    }

    // A ready observation cannot replace the prepared identity or capability.
    private static void RequireSameIdentity(WorkerRecoveryRecord prepared, WorkerRecoveryRecord ready)
    {
        byte[]? preparedKey = null, readyKey = null, preparedSecret = null, readySecret = null;
        try
        {
            preparedKey = prepared.CopyPublicKey();
            readyKey = ready.CopyPublicKey();
            preparedSecret = prepared.CopyCapability();
            readySecret = ready.CopyCapability();
            if (prepared.Instance != ready.Instance || prepared.Drive != ready.Drive || prepared.ProcessId != ready.ProcessId ||
                prepared.CreationTime != ready.CreationTime || prepared.PipeName != ready.PipeName ||
                !CryptographicOperations.FixedTimeEquals(preparedKey, readyKey) ||
                !CryptographicOperations.FixedTimeEquals(preparedSecret, readySecret))
                throw new InvalidDataException("Ready record does not match the prepared record.");
        }
        finally
        {
            if (preparedKey is not null) CryptographicOperations.ZeroMemory(preparedKey);
            if (readyKey is not null) CryptographicOperations.ZeroMemory(readyKey);
            if (preparedSecret is not null) CryptographicOperations.ZeroMemory(preparedSecret);
            if (readySecret is not null) CryptographicOperations.ZeroMemory(readySecret);
        }
    }

    private static string RecordPath(string directory, char drive, bool ready) =>
        System.IO.Path.Combine(directory, $"WimDrive-{drive}-{(ready ? "ready" : "prepared")}.wdr");

    private static string ReceiptPath(string directory, char drive) =>
        System.IO.Path.Combine(directory, $"WimDrive-{drive}-closed.wdr");
    private static string ReceiptStagePath(string directory, char drive) =>
        System.IO.Path.Combine(directory, $"WimDrive-{drive}-closed-stage.wdr");
    private static string JournalPath(string directory, char drive) =>
        System.IO.Path.Combine(directory, $"WimDrive-{drive}-cleanup.wdr");
    private static string JournalStagePath(string directory, char drive) =>
        System.IO.Path.Combine(directory, $"WimDrive-{drive}-cleanup-stage.wdr");

    // Called while holding the newly created exclusive prepared slot. Stale
    // ready or receipt slots must not be mistaken for the new worker's state.
    private static string SlotTaken(char drive) =>
        $"{drive}: already has a background mount record. If it is left from before a restart, run: .\\WimDriverMount.exe --unmount {drive}: " +
        $"(and if that finds nothing to unmount: .\\WimDriverMount.exe --resume-worker-cleanup {drive}:)";

    private static void RequireSlotEmpty(string path, char drive, string? advice = null)
    {
        using SafeFileHandle handle = OpenFileW(path, ReadAttributes,
            ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        // ResumeJournalCleanup deletes the prepared record before the journal, so
        // "journal present, prepared absent" is reachable after a crash. In that
        // state --unmount fails before its own catch with "Cannot open recovery
        // record", so naming only --unmount here would send the operator to the one
        // command that cannot clear it.
        if (!handle.IsInvalid) throw new IOException(advice ?? SlotTaken(drive));
        int error = Marshal.GetLastWin32Error();
        if (error != 2) throw new Win32Exception(error, "Cannot check the recovery slot.");
    }

    private static void MarkForDeletion(SafeFileHandle handle)
    {
        var disposition = new FileDisposition { DeleteFile = 1 };
        if (!SetFileInformationByHandle(handle, 4, ref disposition, (uint)Marshal.SizeOf<FileDisposition>()))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot mark the held recovery file for deletion.");
    }

    // Called only with a journal produced from verified evidence while the
    // prepared reservation is held. Never expose this as a general writer.
    private static void PublishJournalBytes(string directory, char drive, byte[] journal)
    {
        if (journal.Length == 0 || journal.Length > WorkerCleanupJournal.MaximumLength)
            throw new InvalidDataException("Invalid cleanup journal size.");
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PrivateSddl(sid), 1, out IntPtr descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create journal security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, InheritHandle = 0 };
            using SafeFileHandle handle = CreateFileW(JournalStagePath(directory, drive), GenericRead | GenericWrite | ReadControl | DeleteAccess,
                0, ref attributes, CreateNew, OpenReparsePoint | WriteThrough, IntPtr.Zero);
            RequireValid(handle, "Cannot create cleanup journal.");
            FileStream? stream = null;
            byte[]? check = null;
            try
            {
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid);
                stream = new FileStream(handle, FileAccess.ReadWrite, 1, isAsync: false);
                stream.Write(journal);
                stream.Flush(flushToDisk: true);
                if (stream.Length != journal.Length) throw new IOException("Cleanup journal length changed.");
                stream.Position = 0;
                check = new byte[journal.Length];
                stream.ReadExactly(check);
                if (!CryptographicOperations.FixedTimeEquals(journal, check)) throw new IOException("Cleanup journal verification failed.");
            }
            catch (Exception original)
            {
                try { MarkForDeletion(handle); }
                catch (Exception rollback) { throw new AggregateException("Journal write and rollback failed; state is unknown.", original, rollback); }
                throw;
            }
            finally
            {
                try { stream?.Dispose(); }
                finally { if (check is not null) CryptographicOperations.ZeroMemory(check); }
            }
            // The stage was flushed, checked and closed. The directory remains
            // pinned and checked, and an existing final journal is never replaced.
            File.Move(JournalStagePath(directory, drive), JournalPath(directory, drive), overwrite: false);
        }
        finally { LocalFree(descriptor); }
    }

    // A protected, successfully published journal records that this program
    // checked the original worker's exit and signed receipt before publication.
    // It is not proof against a hostile current-user, SYSTEM or administrator.
    // Hold its exclusive handle until every matching slot has been removed.
    internal static WorkerCompletionReceipt.Closure ResumeJournalCleanup(char drive)
    {
        if (drive is < 'D' or > 'Z') throw new ArgumentException("Invalid recovery drive.");
        using var directories = OpenRecoveryDirectory();
        RequireSlotEmpty(JournalStagePath(directories.Path, drive), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
        RequireSlotEmpty(ReceiptStagePath(directories.Path, drive), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        using SafeFileHandle journalHandle = OpenFileW(JournalPath(directories.Path, drive),
            GenericRead | ReadControl | DeleteAccess, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        RequireValid(journalHandle, "Cannot open cleanup journal.");
        RequireRegularFile(journalHandle);
        RequirePrivateSecurity(journalHandle, sid);
        WorkerCompletionReceipt.Closure journalClosure;
        using (var journalStream = new FileStream(journalHandle, FileAccess.Read, 1, isAsync: false))
        {
            if (journalStream.Length <= 0 || journalStream.Length > WorkerCleanupJournal.MaximumLength)
                throw new InvalidDataException("Invalid cleanup journal size.");
            byte[] bytes = new byte[checked((int)journalStream.Length)];
            WorkerRecoveryRecord journalRecord;
            try { journalStream.ReadExactly(bytes); journalRecord = WorkerCleanupJournal.Decode(bytes, out journalClosure); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            using (journalRecord)
            {
                if (journalRecord.Drive != drive) throw new InvalidDataException("Cleanup journal drive mismatch.");
                RecordLease? prepared = null, ready = null;
                try
                {
                    try { prepared = OpenRecord(drive, ready: false, forDeletion: true); }
                    catch (Win32Exception ex) when (ex.NativeErrorCode == 2) { }
                    try { ready = OpenRecord(drive, ready: true, forDeletion: true); }
                    catch (Win32Exception ex) when (ex.NativeErrorCode == 2) { }
                    if (prepared is not null) RequireSameIdentity(journalRecord, prepared.Record);
                    if (ready is not null) RequireSameIdentity(journalRecord, ready.Record);
                    using SafeFileHandle receiptHandle = OpenFileW(ReceiptPath(directories.Path, drive),
                        GenericRead | ReadControl | DeleteAccess, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
                    if (receiptHandle.IsInvalid)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != 2) throw new Win32Exception(error, "Cannot inspect completion receipt.");
                    }
                    else
                    {
                        RequireRegularFile(receiptHandle);
                        RequirePrivateSecurity(receiptHandle, sid);
                        using var receiptStream = new FileStream(receiptHandle, FileAccess.Read, 1, isAsync: false);
                        if (receiptStream.Length != 100) throw new InvalidDataException("Invalid completion receipt size.");
                        byte[] receipt = new byte[100];
                        receiptStream.ReadExactly(receipt);
                        if (!WorkerCompletionReceipt.TryVerifyClosed(receipt, journalRecord, out bool receiptSourceFailed, out var receiptDokan) ||
                            new WorkerCompletionReceipt.Closure(receiptSourceFailed, receiptDokan) != journalClosure)
                            throw new InvalidDataException("Completion receipt does not match the journal.");
                        MarkForDeletion(receiptHandle);
                    }
                    if (ready is not null) { ready.MarkForDeletion(); ready.Dispose(); ready = null; }
                    if (prepared is not null) { prepared.MarkForDeletion(); prepared.Dispose(); prepared = null; }
                    RequireSlotEmpty(ReceiptPath(directories.Path, drive), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
                    RequireSlotEmpty(RecordPath(directories.Path, drive, ready: true), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
                    RequireSlotEmpty(RecordPath(directories.Path, drive, ready: false), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
                    RequireSlotEmpty(ReceiptStagePath(directories.Path, drive), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
                    RequireSlotEmpty(JournalStagePath(directories.Path, drive), drive, $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
                    MarkForDeletion(journalHandle);
                }
                finally { try { ready?.Dispose(); } finally { prepared?.Dispose(); } }
            }
        }
        RequireSlotEmpty(JournalPath(directories.Path, drive), drive,
            $"Leftover records for {drive}: are in an unexpected state, so the cleanup could not finish.");
        return journalClosure;
    }

    // The worker calls this only after all cleanup succeeds. The prepared
    // record supplied by the caller must come from its authenticated startup.
    // The recovery client later verifies again under its held reservation.
    internal static void WriteClosedReceipt(WorkerRecoveryRecord prepared, byte[] receipt)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.Length != 100) throw new InvalidDataException("Invalid completion receipt size.");
        byte[] stable = (byte[])receipt.Clone();
        if (!WorkerCompletionReceipt.VerifyClosed(stable, prepared)) throw new InvalidDataException("Completion receipt does not match the worker.");
        using var directories = OpenRecoveryDirectory();
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PrivateSddl(sid), 1, out IntPtr descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create receipt security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, InheritHandle = 0 };
            using SafeFileHandle handle = CreateFileW(ReceiptStagePath(directories.Path, prepared.Drive),
                GenericRead | GenericWrite | ReadControl | DeleteAccess, 0, ref attributes, CreateNew,
                OpenReparsePoint | WriteThrough, IntPtr.Zero);
            RequireValid(handle, "Cannot create completion receipt.");
            FileStream? stream = null;
            try
            {
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid);
                stream = new FileStream(handle, FileAccess.ReadWrite, 1, isAsync: false);
                stream.Write(stable);
                stream.Flush(flushToDisk: true);
                if (stream.Length != stable.Length) throw new IOException("Completion receipt length changed.");
                stream.Position = 0;
                byte[] check = new byte[stable.Length];
                stream.ReadExactly(check);
                if (!CryptographicOperations.FixedTimeEquals(stable, check)) throw new IOException("Completion receipt verification failed.");
            }
            catch (Exception original)
            {
                try
                {
                    var disposition = new FileDisposition { DeleteFile = 1 };
                    if (!SetFileInformationByHandle(handle, 4, ref disposition, (uint)Marshal.SizeOf<FileDisposition>()))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot roll back completion receipt.");
                }
                catch (Exception rollback) { throw new AggregateException("Receipt write and handle-bound rollback failed; state is unknown.", original, rollback); }
                throw;
            }
            finally { stream?.Dispose(); }
            // Publish only after successful flush, read-back and close. The
            // protected, pinned directory prevents untrusted path replacement;
            // same-user and privileged interference remain outside this model.
            // Never overwrite a receipt. An ambiguous move remains unknown.
            File.Move(ReceiptStagePath(directories.Path, prepared.Drive),
                ReceiptPath(directories.Path, prepared.Drive), overwrite: false);
        }
        finally { LocalFree(descriptor); }
    }

    // Driver journals and worker records both use the current user's local
    // application-data directory. In shared ProgramData any user can create
    // folders, so another account could create WimDrive-<this SID> first: it is
    // refused (RequirePrivateSecurity), but that alone would block every background
    // mount. Only the explicit legacy journal inspection still reads ProgramData.
    //
    // The per-user folder is found from the profile path Windows keeps in the
    // machine's ProfileList (GetUserProfileDirectory), not from the known-folder
    // lookup: that reads the user's own "User Shell Folders" key, which the
    // unelevated half of the sign-in can point anywhere.
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserProfileDirectoryW(IntPtr token, [Out] char[]? profile, ref uint size);

    private static string GetRecoveryBasePath(bool driverJournal, bool legacyDriverJournal = false)
    {
        string folder;
        if (driverJournal && legacyDriverJournal) folder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        else
        {
            using var identity = WindowsIdentity.GetCurrent();
            char[] buffer = new char[1024];
            uint size = (uint)buffer.Length;
            if (!GetUserProfileDirectoryW(identity.AccessToken.DangerousGetHandle(), buffer, ref size) || size == 0 || size > buffer.Length)
                throw new IOException("The user profile directory is unavailable.");
            folder = System.IO.Path.Combine(new string(buffer, 0, (int)size - 1), "AppData", "Local");
        }
        if (string.IsNullOrEmpty(folder) || !System.IO.Path.IsPathFullyQualified(folder))
            throw new IOException("Recovery storage base directory is unavailable.");
        return System.IO.Path.GetFullPath(folder).TrimEnd('\\');
    }

    // Keep every ancestor open without delete sharing and reject reparse points.
    // Create or verify the private per-user directory only after those checks.
    private static DirectoryHandles OpenRecoveryDirectory(bool driverJournal = false, bool pin = false)
    {
#if JOURNAL_STORAGE_TEST
        // Exists only in the isolated regression executable. All nested store
        // opens use the same verified test directory while this scope is active.
        if (!driverJournal && testWorkerRecoveryPath is not null)
            return OpenTestWorkerRecoveryDirectory(testWorkerRecoveryPath);
#endif
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using WindowsIdentity? ambient = WindowsIdentity.GetCurrent(true);
        if (ambient is not null) throw new InvalidOperationException("Recovery storage requires a non-impersonated caller.");
        string basePath = GetRecoveryBasePath(driverJournal);
        using WindowsIdentity owner = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = owner.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        string prefix = driverJournal ? "WimDrive-DriverJournal-" : "WimDrive-";
        string path = System.IO.Path.Combine(basePath, prefix + sid.Value);
        string root = System.IO.Path.GetPathRoot(path) ?? throw new IOException("Local profile directory has no root.");
        if (root.Length != 3 || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed)
            throw new IOException("Recovery records require a local fixed drive.");
        var handles = new DirectoryHandles(path);
        try
        {
            string current = root;
            handles.Add(OpenDirectory(current, false, rejectReparseWrites: driverJournal, pinAgainstRename: driverJournal));
            foreach (string component in basePath[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
            {
                current = System.IO.Path.Combine(current, component);
                handles.Add(OpenDirectory(current, false, rejectReparseWrites: driverJournal, pinAgainstRename: driverJournal));
            }
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PrivateSddl(sid, label: !driverJournal), 1, out IntPtr descriptor, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create recovery directory security descriptor.");
            try
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, InheritHandle = 0 };
                if (!CreateDirectoryW(path, ref attributes))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 183) throw new Win32Exception(error, "Cannot create recovery directory.");
                }
            }
            finally { LocalFree(descriptor); }
            SafeFileHandle privateDirectory = OpenDirectory(path, true, rejectReparseWrites: driverJournal, pinAgainstRename: driverJournal || pin);
            handles.Add(privateDirectory);
            if (!driverJournal) EnsureHighLabel(path);
            // An existing directory (183 above) must be exactly what we create.
            RequirePrivateSecurity(privateDirectory, sid, labelled: !driverJournal);
            return handles;
        }
        catch { handles.Dispose(); throw; }
    }

    // Separate from the background-worker slots. Records are retained on every
    // error and are not recovery evidence: there is no independent inventory or
    // terminal protocol. Administrators and the current user,
    // elevated or not, remain inside this store's trust boundary (it is read by
    // --inspect-driver-journal from either); flush cannot guarantee every power-loss case.
    internal static DriverJournalWriter CreateDriverJournal(bool continueAfterReturnedFailure = false)
    {
        var directories = OpenRecoveryDirectory(driverJournal: true);
        SafeFileHandle? operation = null;
        string? path = null;
        bool created = false;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
            Guid operationId = Guid.NewGuid();
            path = System.IO.Path.Combine(directories.Path, operationId.ToString("N"));
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PrivateSddl(sid, label: false), 1, out IntPtr descriptor, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create driver journal security descriptor.");
            try
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
                if (!CreateDirectoryW(path, ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create driver journal directory.");
                created = true;
            }
            finally { LocalFree(descriptor); }
            operation = OpenDirectory(path, true, rejectReparseWrites: true, pinAgainstRename: true);
            RequirePrivateSecurity(operation, sid, labelled: false);
            var result = new DriverJournalWriter(directories, operation, path, sid, operationId, continueAfterReturnedFailure);
            if (continueAfterReturnedFailure) result.WriteFilteredMode();
            operation = null;
            return result;
        }
        catch (Exception ex)
        {
            operation?.Dispose(); directories.Dispose();
            if (created) throw new IOException($"Driver journal directory requires investigation: {SafeText.Path(path!)}.", ex);
            throw;
        }
    }

    internal sealed partial class DriverJournalWriter : DirectDriverInstall.IOperationJournal
    {
        private readonly DirectoryHandles directories;
        private readonly SafeFileHandle operation;
        private readonly string path;
        private readonly SecurityIdentifier sid;
        private readonly object sync = new();
        private int next = 1;
        private bool pending, failed, disposed, terminal, terminalAllowedAfterCallFailure;
        private bool restartReported, returnedOutcomeUnknown;
        private int successfulCalls;
        private readonly bool continueAfterReturnedFailure;
        public Guid OperationId { get; }
        internal string Path { get { lock (sync) return !disposed ? path : throw new ObjectDisposedException(nameof(DriverJournalWriter)); } }

        internal DriverJournalWriter(DirectoryHandles directories, SafeFileHandle operation, string path, SecurityIdentifier sid, Guid operationId, bool continueAfterReturnedFailure = false)
        {
            if (operationId == Guid.Empty) throw new ArgumentException("Invalid journal operation ID.", nameof(operationId));
            this.directories = directories; this.operation = operation; this.path = path; this.sid = sid; OperationId = operationId;
            this.continueAfterReturnedFailure = continueAfterReturnedFailure;
        }

        internal void WriteFilteredMode() => WriteBytes("filtered-mode.wdm", DriverJournalRecords.FilteredMode);

        public void WriteSelectedIntent(int sequence, string metadata)
        {
            lock (sync)
            {
                try
                {
                    if (disposed || failed || terminal || pending || sequence != next) throw new InvalidOperationException("Invalid selected intent sequence.");
                    WriteBytes($"{sequence:D6}-selected-intent.wds", EncodeSelectedMetadata(metadata));
                    WriteIntent(sequence);
                }
                catch { failed = true; terminalAllowedAfterCallFailure = false; throw; }
            }
        }

        public void WriteSelectedCompletion(int sequence, string metadata, DirectDriverInstall.Outcome outcome)
        {
            lock (sync)
            {
                try
                {
                    if (disposed || failed || terminal || !pending || sequence != next) throw new InvalidOperationException("Invalid selected completion sequence.");
                    WriteBytes($"{sequence:D6}-selected-completion.wds", EncodeSelectedMetadata(metadata));
                    WriteCompletion(sequence, outcome);
                }
                catch { failed = true; terminalAllowedAfterCallFailure = false; throw; }
            }
        }

        private static byte[] EncodeSelectedMetadata(string metadata)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(metadata);
            if (bytes.Length is < 2 or > 65536) throw new InvalidDataException("Selected-call details exceed the journal limit.");
            using var document = System.Text.Json.JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) throw new InvalidDataException("Invalid selected-call details.");
            return bytes;
        }

        public void WriteIntent(int sequence)
        {
            lock (sync)
            {
            try
            {
                if (disposed || failed || terminal || pending || sequence != next) throw new InvalidOperationException("Invalid journal intent sequence.");
                Write(new(DriverJournalRecords.Kind.Intent, sequence, false, 0, false)); pending = true;
            }
            catch { failed = true; terminalAllowedAfterCallFailure = false; throw; }
            }
        }

        public void WriteCompletion(int sequence, DirectDriverInstall.Outcome outcome)
        {
            lock (sync)
            {
            try
            {
                if (disposed || failed || terminal || !pending || sequence != next) throw new InvalidOperationException("Invalid journal completion sequence.");
                Write(new(DriverJournalRecords.Kind.Completion, sequence, outcome.Installed, outcome.Error, outcome.Restart));
                pending = false;
                restartReported |= outcome.Restart;
                if (outcome.Installed) successfulCalls++;
                // 259 is Windows' "nothing to change" (an extension already applied):
                // not a failure in either mode.
                if (!outcome.Installed && outcome.Error != 259)
                {
                    returnedOutcomeUnknown = true;
                    if (!continueAfterReturnedFailure) { failed = true; terminalAllowedAfterCallFailure = true; }
                }
                next = checked(next + 1);
            }
            catch { failed = true; terminalAllowedAfterCallFailure = false; throw; }
            }
        }

        // Drive mapping checks do not prove the origin of every file Windows opens.
        // Terminal publication cannot repair a failed/partial journal write.
        // A returned Windows failure may be recorded as unknown, but no later
        // call is allowed. Unknown cleanup and restart must stay explicit.
        public void WriteTerminal(bool outcomeUnknown, bool restartUnknown, bool operationFailed,
            DriverJournalRecords.Cleanup cleanup)
        {
            lock (sync)
            {
                try
                {
                    if (disposed || terminal || pending || (failed && !terminalAllowedAfterCallFailure))
                        throw new InvalidOperationException("Journal cannot publish a terminal record.");
                    var result = new DriverJournalRecords.Terminal(next - 1, successfulCalls, restartReported,
                        restartUnknown || outcomeUnknown || returnedOutcomeUnknown, outcomeUnknown || returnedOutcomeUnknown,
                        operationFailed || returnedOutcomeUnknown, cleanup);
                    WriteBytes("terminal.wdt", DriverJournalRecords.EncodeTerminal(result));
                    terminal = true;
                }
                catch { failed = true; terminalAllowedAfterCallFailure = false; throw; }
            }
        }

        private void Write(DriverJournalRecords.Record record)
        {
            byte[] data = DriverJournalRecords.Encode(record);
            WriteBytes($"{record.Sequence:D6}-{(record.Type == DriverJournalRecords.Kind.Intent ? "intent" : "completion")}.wdj", data);
        }

        private void WriteBytes(string name, byte[] data)
        {
            string file = System.IO.Path.Combine(path, name);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PrivateSddl(sid, label: false), 1, out IntPtr descriptor, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create journal file security descriptor.");
            try
            {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
                using SafeFileHandle handle = CreateFileW(file, GenericRead | GenericWrite | ReadControl
#if JOURNAL_STORAGE_TEST
                    | (testState is null ? 0u : DeleteAccess)
#endif
                    , 0, ref attributes,
                    CreateNew, OpenReparsePoint | WriteThrough, IntPtr.Zero);
                RequireValid(handle, "Cannot create driver journal record.");
#if JOURNAL_STORAGE_TEST
                testState?.RetainRecord(handle);
                testState?.Inject("created");
#endif
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid, labelled: false);
                using var stream = new FileStream(handle, FileAccess.ReadWrite, 1, isAsync: false);
#if JOURNAL_STORAGE_TEST
                testState?.Inject("write");
#endif
                stream.Write(data);
#if JOURNAL_STORAGE_TEST
                testState?.Inject("flush");
#endif
                stream.Flush(flushToDisk: true);
                if (stream.Length != data.Length) throw new IOException("Driver journal record length changed.");
                stream.Position = 0;
                byte[] check = new byte[data.Length];
                stream.ReadExactly(check);
#if JOURNAL_STORAGE_TEST
                testState?.Inject("verify");
#endif
                if (!CryptographicOperations.FixedTimeEquals(data, check)) throw new IOException("Driver journal record verification failed.");
            }
            finally { LocalFree(descriptor); }
        }

        public void Dispose()
        {
            lock (sync)
            {
            if (disposed) return;
            disposed = true;
            try { operation.Dispose(); }
            finally { directories.Dispose(); }
            }
        }
    }

    internal static SafeFileHandle OpenDirectory(string path, bool recordDirectory, bool stagingAncestor = false, bool rejectReparseWrites = false, bool pinAgainstRename = false)
    {
        SafeFileHandle handle = OpenFileW(path, ReadAttributes | ReadControl | (pinAgainstRename ? 1u : 0u), ShareRead | ShareWrite, IntPtr.Zero,
            OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        try
        {
            RequireValid(handle, "Cannot inspect recovery directory.");
            if (!GetFileInformationByHandle(handle, out FileInformation info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & DirectoryAttribute) == 0 || (info.Attributes & ReparseAttribute) != 0)
                throw new IOException("Recovery directory is not a regular directory.");
            RequireTrustedDirectorySecurity(handle, recordDirectory, stagingAncestor, rejectReparseWrites);
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    // Conservative check: only this user, SYSTEM and local administrators are
    // trusted to change directory security or remove a child. Complex ACEs and
    // unfamiliar owners fail closed. This does not protect against those trusted
    // principals; the unelevated half of the current user is kept out of the worker
    // store by its integrity label and pin (see HighLabel), not by this check. Staging
    // ancestors also trust the Windows TrustedInstaller service SID.
    private static void RequireTrustedDirectorySecurity(SafeFileHandle handle, bool recordDirectory, bool stagingAncestor = false, bool rejectReparseWrites = false)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var trustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        bool Trusted(SecurityIdentifier? sid) => sid is not null && (sid.Equals(user) || sid.Equals(system) || sid.Equals(administrators));
        uint error = GetSecurityInfo(handle, 1, 0x5, out _, out _, out _, out _, out IntPtr native);
        if (error != 0) throw new Win32Exception(checked((int)error), "Cannot inspect recovery directory security.");
        try
        {
            uint length = GetSecurityDescriptorLength(native);
            if (length == 0 || length > 65536) throw new InvalidDataException("Invalid directory security descriptor.");
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            var security = new RawSecurityDescriptor(bytes, 0);
            // No owner is never trusted (said here, not left to Equals' null handling).
            if (security.Owner is not { } owner || (!Trusted(owner) && !trustedInstaller.Equals(owner)) || security.DiscretionaryAcl is null)
                throw new UnauthorizedAccessException("Recovery directory owner or access is not trusted.");
            const uint replacementOrChange = 0x00010000 | 0x00040000 | 0x00080000 | 0x00000040 | 0x10000000 | 0x40000000 | 0x02000000;
            uint dangerous = replacementOrChange | (recordDirectory ? 0x6u : 0u) | ((stagingAncestor || rejectReparseWrites) ? 0x102u : 0u);
            bool systemExplicitTraverse = false;
            foreach (GenericAce entry in security.DiscretionaryAcl)
            {
                if (entry is not CommonAce ace || ace.IsCallback)
                    throw new UnauthorizedAccessException("Recovery directory has an unsupported access entry.");
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
                if (ace.AceType == AceType.AccessDenied)
                {
                    // Conservative: group membership for SYSTEM is not evaluated here.
                    if (stagingAncestor) throw new UnauthorizedAccessException("A staging ancestor has a deny entry; SYSTEM access is unverified.");
                    continue;
                }
                if (ace.AceType != AceType.AccessAllowed)
                    throw new UnauthorizedAccessException("Recovery directory has an unsupported access entry.");
                uint mask = unchecked((uint)ace.AccessMask);
                if (stagingAncestor && system.Equals(ace.SecurityIdentifier) &&
                    ((mask & 0x10000000u) != 0 || (mask & 0x20000000u) != 0 || (mask & 0xa0u) == 0xa0u))
                    systemExplicitTraverse = true;
                if (!Trusted(ace.SecurityIdentifier) && !(stagingAncestor && trustedInstaller.Equals(ace.SecurityIdentifier)) &&
                    (unchecked((uint)ace.AccessMask) & dangerous) != 0)
                    throw new UnauthorizedAccessException("Recovery directory can be changed by another principal.");
            }
            if (stagingAncestor && !systemExplicitTraverse)
                throw new UnauthorizedAccessException("A staging ancestor does not explicitly grant SYSTEM traversal and attribute access.");
        }
        finally { if (native != IntPtr.Zero) LocalFree(native); }
    }

    private static void RequireRegularFile(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out FileInformation info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & (DirectoryAttribute | ReparseAttribute)) != 0 || info.Links != 1)
            throw new IOException("Recovery record is not a regular single-link file.");
    }

    // The unelevated half of a sign-in is treated as an attacker.
    // The worker store is labelled High integrity, no write-up and
    // no read-up: an unelevated process of the same user then
    // cannot open a record at all -- so cannot hold one to block --unmount -- nor
    // delete one, nor add a file to the directory. It can still rename the
    // directory through its parent while no worker runs, so a running worker pins
    // it (PinRecoveryDirectory), an unlabelled directory is adopted only if empty,
    // and every record file read elevated must carry the label. Only an elevated process can set this label; the
    // store is used unelevated only by tests, which get no label. Driver journals
    // are read by --inspect-driver-journal, elevated or not, and are not labelled.
    private const string HighLabel = "S:(ML;;NWNR;;;HI)";
    private static readonly bool ElevatedProcess = IsElevated();
#if JOURNAL_STORAGE_TEST
    // Lets an unelevated regression take the elevated checks.
    internal static bool? ElevatedForTest;
    private static bool Elevated => ElevatedForTest ?? ElevatedProcess;
#else
    private static bool Elevated => ElevatedProcess;
#endif
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    private static string PrivateSddl(SecurityIdentifier sid, bool label = true) =>
        $"O:{sid.Value}D:P(A;;FA;;;{sid.Value})" + (label && Elevated ? HighLabel : "");

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, IntPtr descriptor);

    // A directory without the label gets it here, once.
    private static void EnsureHighLabel(string path)
    {
        if (!Elevated) return;
        const uint WriteOwner = 0x00080000, LabelInformation = 0x10;
        using SafeFileHandle handle = OpenFileW(path, ReadControl | WriteOwner, ShareRead | ShareWrite, IntPtr.Zero,
            OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        RequireValid(handle, "Cannot open the recovery directory to label it.");
        if (HasHighLabel(handle)) return;
        // An unlabelled directory may have been made, and filled, by the unelevated
        // half of the sign-in (it can rename the real one away while no worker runs).
        // Only an empty one is adopted.
        if (Directory.EnumerateFileSystemEntries(path).Any())
            throw new UnauthorizedAccessException($"The recovery directory {SafeText.Path(path)} has no integrity label and is not empty, so it cannot be trusted. Check that no background mount is running, then delete it as administrator.");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(HighLabel, 1, out IntPtr label, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create the recovery directory label.");
        try
        {
            if (!SetKernelObjectSecurity(handle, LabelInformation, label))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot label the recovery directory.");
        }
        finally { LocalFree(label); }
        if (!HasHighLabel(handle)) throw new UnauthorizedAccessException("The recovery directory did not keep its integrity label.");
    }

    internal static bool HasHighLabel(SafeFileHandle handle)
    {
        uint error = GetSecurityInfo(handle, 1, 0x10, out _, out _, out _, out _, out IntPtr native);
        if (error != 0) throw new Win32Exception(checked((int)error), "Cannot read the recovery integrity label.");
        try
        {
            uint length = GetSecurityDescriptorLength(native);
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            if (new RawSecurityDescriptor(bytes, 0).SystemAcl is not { } sacl) return false;
            foreach (GenericAce ace in sacl)
            {
                // SYSTEM_MANDATORY_LABEL_ACE (0x11): an access mask, then the level's SID.
                if ((byte)ace.AceType != 0x11 || ace is not CustomAce label || label.GetOpaque() is not { Length: >= 12 } body) continue;
                uint policy = BitConverter.ToUInt32(body, 0);
                if ((policy & 0x3) == 0x3 && new SecurityIdentifier(body, 4).Value == "S-1-16-12288") return true;
            }
            return false;
        }
        finally { if (native != IntPtr.Zero) LocalFree(native); }
    }

    // Held by a running worker: the recovery directory cannot be renamed away while
    // it serves the drive, so --unmount always finds it. Only the labelled leaf is
    // pinned with read access -- unelevated code cannot open it to block the pin --
    // and its ancestors cannot be renamed while anything inside them is open.
    internal static IDisposable PinRecoveryDirectory() => OpenRecoveryDirectory(pin: true);
    private static void RequirePrivateSecurity(SafeFileHandle handle, SecurityIdentifier sid, bool labelled = true)
    {
        // Elevated, every worker-store object must carry the label: an unlabelled
        // file could have been written by the unelevated half of the sign-in.
        if (labelled && Elevated && !HasHighLabel(handle))
            throw new UnauthorizedAccessException("Recovery record has no integrity label; it was not written by an elevated WIM Driver Mount.");
        // SE_FILE_OBJECT; request owner and DACL from the opened handle.
        uint error = GetSecurityInfo(handle, 1, 0x5, out _, out _, out _, out _, out IntPtr native);
        if (error != 0) throw new Win32Exception(checked((int)error), "Cannot inspect recovery file security.");
        try
        {
            uint length = GetSecurityDescriptorLength(native);
            if (length == 0 || length > 65536) throw new InvalidDataException("Invalid recovery security descriptor.");
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(native, bytes, 0, bytes.Length);
            var security = new RawSecurityDescriptor(bytes, 0);
            if (security.Owner is not { } owner || !sid.Equals(owner) || (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                security.DiscretionaryAcl is not { Count: 1 } acl || acl[0] is not CommonAce ace ||
                ace.AceType != AceType.AccessAllowed || ace.AceFlags != AceFlags.None || !sid.Equals(ace.SecurityIdentifier) ||
                ace.AccessMask != 0x1f01ff)
                throw new UnauthorizedAccessException("Recovery record security is not restricted to the current user.");
        }
        finally { if (native != IntPtr.Zero) LocalFree(native); }
    }

    private static void RequireValid(SafeFileHandle handle, string message)
    {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), message);
    }

    internal sealed class DirectoryHandles : IDisposable
    {
        private readonly List<SafeFileHandle> handles = new();
        internal string Path { get; }
        internal DirectoryHandles(string path) => Path = path;
        internal void Add(SafeFileHandle handle) => handles.Add(handle);
        public void Dispose() { for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose(); }
    }

    // An exclusive file handle prevents deletion or slot reuse until the
    // dependent operation finishes. The record itself remains caller-owned
    // only after DetachRecord; it never transfers the locked file handle.
    private sealed class RecordLease : IDisposable
    {
        private readonly DirectoryHandles directories;
        private readonly SafeFileHandle handle;
        private readonly FileStream stream;
        private WorkerRecoveryRecord? record;
        internal WorkerRecoveryRecord Record => record ?? throw new ObjectDisposedException(nameof(RecordLease));
        internal RecordLease(DirectoryHandles directories, SafeFileHandle handle, FileStream stream, WorkerRecoveryRecord record)
        { this.directories = directories; this.handle = handle; this.stream = stream; this.record = record; }
        internal WorkerRecoveryRecord DetachRecord()
        {
            WorkerRecoveryRecord result = Record;
            record = null;
            return result;
        }
        internal void MarkForDeletion() => WorkerRecoveryStore.MarkForDeletion(handle);
        public void Dispose()
        {
            record?.Dispose();
            record = null;
            try { stream.Dispose(); }
            finally { handle.Dispose(); directories.Dispose(); }
        }
    }

    internal sealed class PreparedReservation : IDisposable
    {
        private readonly object sync = new();
        private RecordLease? lease;
        private PreparedReservation(RecordLease lease) => this.lease = lease;
        internal static PreparedReservation Open(char drive) => new(OpenRecord(drive, ready: false, forDeletion: true));

        // Returned bytes contain the capability. The caller owns and must clear
        // them. Keeping a snapshot does not extend the reservation's lifetime.
        internal byte[] CopyEncodedRecord()
        {
            lock (sync) return RequireLease().Record.Encode();
        }

        internal string WriteReady(WorkerRecoveryRecord record)
        {
            ArgumentNullException.ThrowIfNull(record);
            lock (sync)
            {
                RequireSameIdentity(RequireLease().Record, record);
                return WriteNewCore(record, ready: true);
            }
        }

        internal void RequireExpected(WorkerRecoveryRecord expected)
        {
            ArgumentNullException.ThrowIfNull(expected);
            lock (sync) RequireSameIdentity(RequireLease().Record, expected);
        }

        // Only the starter may call this before it has attempted to send GO.
        // The held handle identifies the prepared file created for this run.
        internal void RemoveBeforeGo()
        {
            lock (sync)
            {
                RecordLease current = RequireLease();
                current.MarkForDeletion();
                lease = null;
                current.Dispose();
            }
        }

        // The caller owns the returned record. The reservation remains held;
        // the returned record by itself is not authority for later operations.
        internal WorkerRecoveryRecord ReadReady()
        {
            lock (sync)
            {
                WorkerRecoveryRecord? result = null;
                try
                {
                    WorkerRecoveryRecord prepared = RequireLease().Record;
                    using RecordLease ready = OpenRecord(prepared.Drive, ready: true);
                    RequireSameIdentity(prepared, ready.Record);
                    result = ready.DetachRecord();
                }
                catch { result?.Dispose(); throw; }
                return result;
            }
        }

        // Missing, inaccessible or malformed storage throws and must be treated
        // as unknown. A true result is the worker's past signed cleanup claim.
        internal bool VerifyClosedReceipt()
            => TryVerifyClosedReceipt(out _);

        internal bool TryVerifyClosedReceipt(out bool sourceFailed)
            => TryVerifyClosedReceipt(out sourceFailed, out _);

        internal bool TryVerifyClosedReceipt(out bool sourceFailed, out WorkerCompletionReceipt.DokanStatus dokan)
        {
            lock (sync)
            {
                WorkerRecoveryRecord prepared = RequireLease().Record;
                using var directories = OpenRecoveryDirectory();
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
                using SafeFileHandle handle = OpenFileW(ReceiptPath(directories.Path, prepared.Drive),
                    GenericRead | ReadControl, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
                RequireValid(handle, "The background mount left no record of how it closed.");
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid);
                using var stream = new FileStream(handle, FileAccess.Read, 1, isAsync: false);
                if (stream.Length != 100) throw new InvalidDataException("Invalid completion receipt size.");
                byte[] receipt = new byte[100];
                stream.ReadExactly(receipt);
                return WorkerCompletionReceipt.TryVerifyClosed(receipt, prepared, out sourceFailed, out dokan);
            }
        }

        // The final journal is evidence only under the protected-store trust
        // boundary. Publication happens inside the reservation after receipt and
        // retained-process exit checks; its bytes never leave this method.
        internal void PublishCleanupJournal(WorkerProcessIdentity worker)
        {
            ArgumentNullException.ThrowIfNull(worker);
            lock (sync)
            {
                WorkerRecoveryRecord prepared = RequireLease().Record;
                using var directories = OpenRecoveryDirectory();
                RequireSlotEmpty(ReceiptStagePath(directories.Path, prepared.Drive), prepared.Drive);
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
                using SafeFileHandle handle = OpenFileW(ReceiptPath(directories.Path, prepared.Drive),
                    GenericRead | ReadControl, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
                RequireValid(handle, "Cannot open completion receipt for journal.");
                RequireRegularFile(handle);
                RequirePrivateSecurity(handle, sid);
                using var stream = new FileStream(handle, FileAccess.Read, 1, isAsync: false);
                if (stream.Length != 100) throw new InvalidDataException("Invalid completion receipt size.");
                byte[] receipt = new byte[100];
                stream.ReadExactly(receipt);
                byte[] journal = WorkerCleanupJournal.Create(prepared, receipt, worker);
                try { PublishJournalBytes(directories.Path, prepared.Drive, journal); }
                finally { CryptographicOperations.ZeroMemory(journal); }
            }
        }

        // Only a matching process handle retained while the worker was alive,
        // its confirmed exit, and its signed receipt permit slot removal. The
        // worker must not delegate receipt publication to another process.
        // Any exception, including a close failure, leaves the result unknown.
        internal void RemoveAfterConfirmedExit(WorkerProcessIdentity worker)
        {
            ArgumentNullException.ThrowIfNull(worker);
            lock (sync)
            {
                RecordLease preparedLease = RequireLease();
                char drive = preparedLease.Record.Drive;
                // Publication checks the matching retained process and signed
                // receipt before the first deletion. The final journal blocks
                // slot reuse while cleanup runs or resumes after interruption.
                PublishCleanupJournal(worker);
                lease = null;
                preparedLease.Dispose();
                _ = ResumeJournalCleanup(drive);
            }
        }

        // Retires records only with proof that the mount cannot be alive. A closing
        // receipt the worker left is read first and handed back (closure), so how it
        // left Dokan is reported, not lost; receiptUnreadable when one is there but
        // cannot be verified. workerGone: the recorded process is confirmed absent (no such PID,
        // exited, or the PID belongs to another process). Retire when it is gone and
        // either it started before this boot or its drive letter no longer exists
        // (covers Fast Startup and crashes, with no clock involved). Without that
        // proof (access denied), both the earlier boot and the free letter are needed.
        internal bool TryRetireStale(bool workerGone, out WorkerCompletionReceipt.Closure? closure, out bool receiptUnreadable)
        {
            closure = null;
            receiptUnreadable = false;
            lock (sync)
            {
                RecordLease preparedLease = RequireLease();
                WorkerRecoveryRecord prepared = preparedLease.Record;
                bool beforeBoot = StartedBeforeBoot(prepared.CreationTime), letterFree = !DriveLetterAssigned(prepared.Drive);
                if (!(workerGone ? beforeBoot || letterFree : beforeBoot && letterFree)) return false;
                char drive = prepared.Drive;
                using var directories = OpenRecoveryDirectory();
                // A published cleanup journal carries the worker's verified
                // closure -- a failed source, or a Dokan removal that failed or
                // needs a restart. Deleting it here would throw that away and report
                // success, so a recorded failure would become exit 0 and the operator
                // would mount again on a machine with broken Dokan state. Refuse to
                // retire while one exists; --resume-worker-cleanup consumes it
                // properly. Only the stage file is safe to delete.
                RequireSlotEmpty(JournalPath(directories.Path, drive), drive,
                    $"{drive}: has a finished cleanup record that must be applied first. Run: .\\WimDriverMount.exe --resume-worker-cleanup {drive}:");
                try
                {
                    if (TryVerifyClosedReceipt(out bool sourceFailed, out var dokan)) closure = new(sourceFailed, dokan);
                    else receiptUnreadable = true;
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == 2) { } // No receipt.
                catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception) { receiptUnreadable = true; }
                RecordLease? ready = null;
                try { ready = OpenRecord(drive, ready: true, forDeletion: true); }
                catch (Win32Exception ex) when (ex.NativeErrorCode == 2) { }
                using (ready)
                {
                    if (ready is not null) { RequireSameIdentity(prepared, ready.Record); ready.MarkForDeletion(); }
                }
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                SecurityIdentifier sid = identity.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
                foreach (string path in new[] { ReceiptPath(directories.Path, drive), ReceiptStagePath(directories.Path, drive),
                    JournalStagePath(directories.Path, drive) })
                {
                    using SafeFileHandle handle = OpenFileW(path, ReadControl | DeleteAccess, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
                    if (handle.IsInvalid)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 2) continue;
                        throw new Win32Exception(error, "Cannot open a stale recovery file.");
                    }
                    RequireRegularFile(handle);
                    RequirePrivateSecurity(handle, sid);
                    WorkerRecoveryStore.MarkForDeletion(handle);
                }
                preparedLease.MarkForDeletion();
                lease = null;
                preparedLease.Dispose();
                return true;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(string device, char[] target, int capacity);
        // True unless Windows confirms the letter has no mapping (ERROR_FILE_NOT_FOUND).
        internal static bool DriveLetterAssigned(char drive)
        {
            var buffer = new char[1024];
            return QueryDosDeviceW($"{drive}:", buffer, buffer.Length) != 0 || Marshal.GetLastWin32Error() != 2;
        }

        // FILETIME comparison against the boot time. A clock step alone cannot retire
        // a live mount: the caller also requires proof the worker is gone.
        internal static bool StartedBeforeBoot(ulong creation)
        {
            long now = DateTime.UtcNow.ToFileTimeUtc();
            long boot = now - checked(Environment.TickCount64 * 10_000);
            return creation != 0 && (long)creation < boot;
        }

        private RecordLease RequireLease() => lease ?? throw new ObjectDisposedException(nameof(PreparedReservation));
        public void Dispose()
        {
            lock (sync)
            {
                RecordLease? owned = lease;
                lease = null;
                owned?.Dispose();
            }
        }
    }
}
