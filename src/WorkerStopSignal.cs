using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// A second way to ask a background worker to unmount, alongside the control pipe.
//
// The pipe is the authenticated path with a signed reply, but a pipe cannot be
// kept available against another process of the same user (see WorkerPipe). This event can:
// signalling it needs EVENT_MODIFY_STATE, which its DACL grants only to SYSTEM and
// elevated Administrators, and there is nothing to hold open in the meantime. It
// carries no payload and needs none: anyone allowed to signal it could already
// end the worker outright. The outcome still comes back the usual way -- the
// worker writes its signed closed receipt and exits, and --unmount verifies that.
internal static class WorkerStopSignal
{
    // Global\ so --unmount from any session reaches it. A standard user can
    // create events there, but the name carries the worker's fresh random
    // instance, unknown until the worker has already created it, and Create
    // refuses a name that exists. Tests use Local\.
    internal const string GlobalPrefix = @"Global\", LocalPrefix = @"Local\";
    private const string Descriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    private const uint EventModifyState = 0x0002;
    private const int AlreadyExists = 183;

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
    private static extern SafeWaitHandle CreateEventW(ref SecurityAttributes attributes, [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeWaitHandle OpenEventW(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEvent(SafeWaitHandle handle);

    internal static string Name(Guid instance, string prefix = GlobalPrefix)
    {
        if (instance == Guid.Empty) throw new ArgumentException("Invalid worker instance.", nameof(instance));
        if (prefix is not (GlobalPrefix or LocalPrefix)) throw new ArgumentException("Invalid namespace.", nameof(prefix));
        return prefix + "WimDriverMount-Stop-" + instance.ToString("N");
    }

    // Created by the worker before it reports anything, so it exists for the
    // worker's whole life. A name that already exists is refused outright.
    internal static EventWaitHandle Create(Guid instance, string prefix = GlobalPrefix)
    {
        string name = Name(instance, prefix);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Descriptor, 1, out IntPtr descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create stop signal security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), SecurityDescriptor = descriptor };
            SafeWaitHandle handle = CreateEventW(ref attributes, true, false, name);
            int error = Marshal.GetLastWin32Error();
            if (handle.IsInvalid) throw new Win32Exception(error, "Cannot create the worker stop signal.");
            if (error == AlreadyExists)
            {
                handle.Dispose();
                throw new InvalidOperationException("The worker stop signal already exists; refusing to start.");
            }
            var signal = new EventWaitHandle(false, EventResetMode.ManualReset);
            signal.SafeWaitHandle.Dispose(); // The unnamed placeholder; replaced, not leaked.
            signal.SafeWaitHandle = handle;
            return signal;
        }
        finally { LocalFree(descriptor); }
    }

    // True when the signal was set. False when it does not exist or this
    // process may not signal it; the caller then reports what it knows.
    internal static bool TrySignal(Guid instance, string prefix = GlobalPrefix)
    {
        using SafeWaitHandle handle = OpenEventW(EventModifyState, false, Name(instance, prefix));
        return !handle.IsInvalid && SetEvent(handle);
    }
}
