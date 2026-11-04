using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

// Coordinates this application's mounts. Other Dokan applications do not
// participate in the lock; the mount list is a snapshot, not a reservation.
internal static class DokanLifecycle
{
    private const string StatePath = @"SOFTWARE\WimDriverMount\DokanOwnership";
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int MsiQueryProductStateW(string product);

    internal sealed class Lease : IDisposable
    {
        private Mutex? mutex;
        internal Lease(Mutex value) => mutex = value;
        public void Dispose()
        {
            Mutex? held = Interlocked.Exchange(ref mutex, null);
            if (held is null) return;
            try { held.ReleaseMutex(); } finally { held.Dispose(); }
        }
    }

    // Administrators and SYSTEM only, stated outright rather than inherited from
    // the creating token's defaults, so that whether a non-elevated process could
    // take this lock -- and stall every mount for the five-minute wait below --
    // does not rest on what Windows happens to put in a default DACL.
    private const string LockDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr SecurityDescriptor; public int InheritHandle; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern Microsoft.Win32.SafeHandles.SafeWaitHandle CreateMutexW(ref SecurityAttributes attributes,
        [MarshalAs(UnmanagedType.Bool)] bool initialOwner, string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CreateBoundaryDescriptorW(string name, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddIntegrityLabelToBoundaryDescriptor(ref IntPtr boundary, byte[] label);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddSIDToBoundaryDescriptor(ref IntPtr boundary, byte[] sid);
    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void DeleteBoundaryDescriptor(IntPtr boundary);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CreatePrivateNamespaceW(IntPtr attributes, IntPtr boundary, string alias);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenPrivateNamespaceW(IntPtr boundary, string alias);

    // The lock lives in a private namespace whose boundary requires the High
    // integrity label and the Administrators group. Any user can create objects
    // under Global\, so a fixed Global\ name would let another account create the lock
    // first and block every mount; a process that is not elevated cannot create
    // this namespace (checked from a medium-integrity process: access denied).
    // The handle stays open for the process: the namespace, and the lock's name
    // in it, exist only while some process holds it.
    private const string NamespaceAlias = "WimDriverMount-Dokan";
    private static readonly object NamespaceGate = new();
    private static IntPtr lifecycleNamespace;

    internal static string LockInNamespace(string boundaryName, string objectName)
    {
        lock (NamespaceGate)
        {
            if (lifecycleNamespace == IntPtr.Zero)
            {
                IntPtr boundary = CreateBoundaryDescriptorW(boundaryName, 0);
                if (boundary == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Cannot create the lifecycle lock boundary.");
                try
                {
                    if (!AddIntegrityLabelToBoundaryDescriptor(ref boundary, Sid("S-1-16-12288")) || !AddSIDToBoundaryDescriptor(ref boundary, Sid("S-1-5-32-544")))
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Cannot build the lifecycle lock boundary.");
                    IntPtr opened = CreatePrivateNamespaceW(IntPtr.Zero, boundary, NamespaceAlias);
                    int error = Marshal.GetLastWin32Error();
                    if (opened == IntPtr.Zero && error == 183) { opened = OpenPrivateNamespaceW(boundary, NamespaceAlias); error = Marshal.GetLastWin32Error(); }
                    if (opened == IntPtr.Zero)
                        throw error == 5 ? new UnauthorizedAccessException("This needs administrator rights. Run it from an administrator console.")
                            : new System.ComponentModel.Win32Exception(error, "Cannot open the lifecycle lock namespace.");
                    lifecycleNamespace = opened;
                }
                finally { DeleteBoundaryDescriptor(boundary); }
            }
            return NamespaceAlias + @"\" + objectName;
        }
    }

    private static byte[] Sid(string value)
    {
        var sid = new System.Security.Principal.SecurityIdentifier(value);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        return bytes;
    }

    internal static Mutex CreateLock(string name)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(LockDescriptor, 1, out IntPtr descriptor, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Cannot create the Dokan lifecycle lock security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), SecurityDescriptor = descriptor };
            var handle = CreateMutexW(ref attributes, false, name);
            if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Cannot create the Dokan lifecycle lock.");
            var mutex = new Mutex(false);
            mutex.SafeWaitHandle.Dispose(); // The unnamed placeholder; replaced, not leaked.
            mutex.SafeWaitHandle = handle;
            return mutex;
        }
        finally { LocalFree(descriptor); }
    }

    internal static Lease Acquire()
    {
        var mutex = CreateLock(LockInNamespace("WimDriverMount-Dokan-Lifecycle-v1", "Lifecycle"));
        try
        {
            // An abandoned owner can have interrupted an installation or
            // state write. Do not infer ownership or start cleanup from it.
            try { if (!mutex.WaitOne(TimeSpan.FromMinutes(5))) throw new TimeoutException("Another copy of WIM Driver Mount has been installing or removing Dokan for 5 minutes. Wait for it to finish, then try again."); }
            catch (AbandonedMutexException) { mutex.ReleaseMutex(); throw new IOException("Another copy of WIM Driver Mount stopped while installing or removing Dokan. If Dokan is listed in Settings > Apps, uninstall it there, then run this again."); }
            return new Lease(mutex);
        }
        catch { mutex.Dispose(); throw; }
    }

    internal readonly record struct State(bool Exists, bool Valid, bool Keep, bool RemovalStarted, bool RestartReported, bool RestartInitiated = false);
    internal interface IBackend
    {
        State Read(); int ProductState(); bool FilesPresent();
        DokanInstaller.CheckResult Ensure(); void SaveOwnership(bool keep); void SaveKeep();
        uint ActiveMounts(); void MarkRemovalStarted(); int Remove(Action<int> observe); void SaveRestart(bool initiated); void Forget();
    }

    // Caller holds the lifecycle lease until its new mount reaches readiness.
    internal static DokanInstaller.CheckResult Prepare(bool keep, Func<DokanInstaller.CheckResult> ensure) =>
        PrepareCore(keep, new Backend(ensure));

    internal static DokanInstaller.CheckResult PrepareCore(bool keep, IBackend backend)
    {
        State state = backend.Read();
        int before = backend.ProductState();
        // Dokan we owned is gone -- uninstalled from Settings, or removed by us
        // before the record could be cleared. There is nothing left to own, so
        // the record goes and setup starts afresh; a fresh install reports any
        // restart it needs through Ensure, as usual.
        if (state.Exists && state.Valid && before == -1)
        {
            backend.Forget();
            state = default;
        }
        if (state.Exists && (!state.Valid || state.RemovalStarted || before != 5))
            throw new IOException("An earlier Dokan install or removal by WIM Driver Mount did not finish. If Dokan is still listed in Settings > Apps, uninstall it there, then mount again.");
        if (!state.Exists && before != -1 && !backend.FilesPresent())
            throw new IOException("Windows lists Dokan as installed, but its files are missing. Uninstall Dokan in Settings > Apps, then run this again.");
        var result = backend.Ensure();
        if (result.InstallerReportedSuccess)
        {
            if (before != -1 || backend.ProductState() != 5 || state.Exists)
            {
                OwnershipUnconfirmed = true; // A settings-file run stops its later mounts too.
                throw new IOException("Dokan was installed, but WIM Driver Mount could not confirm that it installed it, so it will never remove it. This mount was not made. Run the same command again.");
            }
            backend.SaveOwnership(keep);
        }
        // An installation this tool owns follows the latest request: keeping is the
        // default, and --remove-dokan switches an earlier "keep" to removal.
        else if (state.Exists && keep) backend.SaveKeep();
        else if (state.Exists && state.Keep) backend.SaveOwnership(false);
        return result;
    }

    internal static WorkerCompletionReceipt.DokanStatus Finish()
    {
        WorkerCompletionReceipt.DokanStatus observed = WorkerCompletionReceipt.DokanStatus.Failed;
        try
        {
            using var lease = Acquire();
            observed = FinishCore(new Backend(null));
            return observed;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or AccessViolationException or SEHException))
        {
            WorkerDiagnostics.Log("Dokan lifecycle", ex);
            return observed == WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated ? observed :
                observed is WorkerCompletionReceipt.DokanStatus.FailedRestart or WorkerCompletionReceipt.DokanStatus.RestartRequired
                    ? WorkerCompletionReceipt.DokanStatus.FailedRestart : WorkerCompletionReceipt.DokanStatus.Failed;
        }
    }

    // Set when Dokan was installed this run but its ownership could not be recorded.
    internal static bool OwnershipUnconfirmed;

    internal static WorkerCompletionReceipt.DokanStatus FinishCore(IBackend backend)
    {
        bool restart = false, initiated = false;
        try
        {
            State state = backend.Read(); restart = state.RestartReported; initiated = state.RestartInitiated;
            if (!state.Exists) return WorkerCompletionReceipt.DokanStatus.None;
            if (!state.Valid || state.RemovalStarted || backend.ProductState() != 5)
                return initiated ? WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated : restart ? WorkerCompletionReceipt.DokanStatus.FailedRestart : WorkerCompletionReceipt.DokanStatus.Failed;
            if (state.Keep) return WorkerCompletionReceipt.DokanStatus.Kept;
            if (backend.ActiveMounts() != 0) return WorkerCompletionReceipt.DokanStatus.Deferred;
            backend.MarkRemovalStarted(); // persisted before starting MSI; no automatic retry after uncertainty
            int exit = backend.Remove(code =>
            {
                initiated |= code == 1641;
                restart |= code is 3010 or 1641;
                if (restart) backend.SaveRestart(initiated);
            });
            if (exit is not (0 or 3010) || backend.ProductState() != -1)
                return initiated ? WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated : restart ? WorkerCompletionReceipt.DokanStatus.FailedRestart : WorkerCompletionReceipt.DokanStatus.Failed;
            backend.Forget();
            return restart ? WorkerCompletionReceipt.DokanStatus.RestartRequired : WorkerCompletionReceipt.DokanStatus.Removed;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException or AccessViolationException or SEHException))
        {
            WorkerDiagnostics.Log("Dokan lifecycle", ex);
            return initiated ? WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated : restart ? WorkerCompletionReceipt.DokanStatus.FailedRestart : WorkerCompletionReceipt.DokanStatus.Failed;
        }
    }

    private sealed class Backend(Func<DokanInstaller.CheckResult>? ensure) : IBackend
    {
        // The product code of the release this tool installed, if it recorded one.
        private static string? Recorded()
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(StatePath);
            return key?.GetValue("ProductCode") as string;
        }

        public State Read()
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(StatePath);
            if (key is null) return default;
            // A recorded product code must look like one; which Dokan version it names
            // is not fixed, since any official release may have been installed.
            bool valid = key.GetValue("ProductCode") is string code && Guid.TryParse(code, out _) &&
                key.GetValue("Keep") is int keep && keep is 0 or 1 &&
                key.GetValue("RemovalStarted", 0) is int started && started is 0 or 1 &&
                key.GetValue("RestartReported", 0) is int restart && restart is 0 or 1 or 2;
            // "as" so a value of the wrong registry type reads as invalid state, not a crash.
            return new(true, valid, key.GetValue("Keep") as int? == 1,
                key.GetValue("RemovalStarted", 0) as int? == 1, key.GetValue("RestartReported", 0) as int? is 1 or 2,
                key.GetValue("RestartReported", 0) as int? == 2);
        }
        // The state of the product this tool owns; with none recorded, the state of any
        // installed Dokan, so one that was already there is still detected.
        public int ProductState()
        {
            string? product = Recorded() ?? DokanPackage.InstalledProductCode();
            return product is null ? -1 : MsiQueryProductStateW(product);
        }
        public bool FilesPresent() => File.Exists(Path.Combine(Environment.SystemDirectory, "drivers", "dokan2.sys")) && File.Exists(Path.Combine(Environment.SystemDirectory, "dokan2.dll"));
        public DokanInstaller.CheckResult Ensure() => (ensure ?? throw new InvalidOperationException())();
        public void SaveOwnership(bool keep)
        {
            // Record the version that is actually installed, found through Dokan's
            // upgrade code, so removal targets exactly it.
            string installed = DokanPackage.InstalledProductCode()
                ?? throw new IOException("No installed Dokan was found; ownership was not recorded.");
            using RegistryKey key = Registry.LocalMachine.CreateSubKey(StatePath, writable: true) ?? throw new IOException("Cannot save Dokan ownership.");
            key.SetValue("ProductCode", installed, RegistryValueKind.String);
            key.SetValue("Keep", keep ? 1 : 0, RegistryValueKind.DWord); key.Flush();
        }
        private static void Set(string name, int value)
        {
            using RegistryKey key = Registry.LocalMachine.OpenSubKey(StatePath, writable: true) ?? throw new IOException("Dokan ownership is unavailable.");
            key.SetValue(name, value, RegistryValueKind.DWord); key.Flush();
        }
        public void SaveKeep() => Set("Keep", 1);
        public uint ActiveMounts() => DokanMountListProbe.ActiveMounts();
        public void MarkRemovalStarted() => Set("RemovalStarted", 1);
        public int Remove(Action<int> observe)
        {
            var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe")) { UseShellExecute = false, CreateNoWindow = true };
            // Keep Restart Manager from closing the caller that loaded Dokan.
            // /norestart separately suppresses an operating-system restart.
            string owned = Recorded() ?? throw new IOException("No Dokan ownership is recorded; nothing was removed.");
            foreach (string value in new[] { "/x", owned, "/qn", "/norestart", "MSIRESTARTMANAGERCONTROL=Disable" }) info.ArgumentList.Add(value);
            using Process process = Process.Start(info) ?? throw new IOException("Cannot start Dokan removal.");
            process.WaitForExit();
            int exit = process.ExitCode;
            observe(exit);
            return exit;
        }
        public void SaveRestart(bool initiated) => Set("RestartReported", initiated ? 2 : 1);
        public void Forget() => Registry.LocalMachine.DeleteSubKey(StatePath, throwOnMissingSubKey: false);
    }

}
