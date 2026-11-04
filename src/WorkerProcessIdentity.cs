// Practical stale-process checks for a local control client.
// These checks do not authenticate a worker against a hostile same-user process.
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal sealed class WorkerProcessIdentity : IDisposable
{
    private const uint QueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const uint WaitObject0 = 0, WaitTimeout = 258;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low, High; }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out NativeFileTime creation, out NativeFileTime exit,
        out NativeFileTime kernel, out NativeFileTime user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    private readonly SafeProcessHandle process;
    private readonly uint expectedPid;
    private readonly ulong expectedCreation;
    internal uint ProcessId => expectedPid;
    internal ulong CreationTime => expectedCreation;

    private WorkerProcessIdentity(SafeProcessHandle process, uint pid, ulong creation)
    {
        this.process = process;
        expectedPid = pid;
        expectedCreation = creation;
    }

    // Capture while the original Process object is retained by the starter.
    // The child process handle is held while the identity is opened and checked.
    internal static WorkerProcessIdentity CaptureChild(Process child)
    {
        ArgumentNullException.ThrowIfNull(child);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        SafeProcessHandle original = child.SafeHandle;
        uint pid = GetProcessId(original);
        if (pid == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read child process ID.");
        if (!GetProcessTimes(original, out NativeFileTime created, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read child process creation time.");
        return Open(pid, ((ulong)created.High << 32) | created.Low);
    }

    // Creation is the raw FILETIME captured from a trusted initial handshake,
    // not just an untrusted discovery record. The returned handle pins this
    // process object for the duration of an exchange. Never use it to terminate.
    internal static WorkerProcessIdentity Open(uint pid, ulong creation)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (pid == 0 || creation == 0) throw new ArgumentException("Invalid worker identity.");
        SafeProcessHandle handle = OpenProcess(QueryLimitedInformation | Synchronize, false, pid);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Cannot open the recorded worker process.");
        }
        var identity = new WorkerProcessIdentity(handle, pid, creation);
        try { identity.RequireAlive(); return identity; }
        catch { identity.Dispose(); throw; }
    }

    // Call before and after the bounded request/response. These checks detect
    // ordinary stale records and PID reuse; identity, session, message framing,
    // and a safe outcome after a timeout need separate verification.
    internal void RequirePipeServer(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!pipe.IsConnected) throw new InvalidOperationException("Control pipe is not connected.");
        RequireAlive();
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint peer))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot identify pipe server process.");
        if (peer != expectedPid) throw new InvalidDataException("Control pipe server does not match the recorded process.");
        RequireElevatedSameUser();
        RequireAlive();
    }

    // The recorded process must run as this user, elevated. Its process ID comes
    // from a recovery record, so without this a record naming an unelevated process
    // of the same user could have that process answer as the worker.
    internal void RequireElevatedSameUser()
    {
        const uint TokenQuery = 0x0008;
        if (!OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect the worker process.");
        using (token)
        {
            using var worker = new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle());
            using var me = System.Security.Principal.WindowsIdentity.GetCurrent();
            if (worker.User is null || me.User is null || !worker.User.Equals(me.User) || !WorkerPeer.ReadElevation(token))
                throw new UnauthorizedAccessException("The recorded worker is not an elevated process of this user.");
        }
    }

    internal void RequirePipeClient(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!pipe.IsConnected) throw new InvalidOperationException("Startup pipe is not connected.");
        RequireAlive();
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint peer))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot identify startup pipe client process.");
        if (peer != expectedPid) throw new InvalidDataException("Startup pipe client does not match the child process.");
        RequireAlive();
    }

    // The handle must have been obtained and checked while the recorded
    // process was alive, then retained without interruption. A missing PID or
    // failure to open a process later is not evidence of exit. This checks the
    // same pinned process object; it never terminates a process. The caller
    // must also verify the receipt and hold the corresponding record lease.
    internal bool HasConfirmedExit()
    {
        uint pid = GetProcessId(process);
        if (pid == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read retained worker process ID.");
        if (!GetProcessTimes(process, out NativeFileTime created, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read retained worker process creation time.");
        ulong creation = ((ulong)created.High << 32) | created.Low;
        if (pid != expectedPid || creation != expectedCreation)
            throw new InvalidDataException("Retained worker identity does not match the record.");
        uint wait = WaitForSingleObject(process, 0);
        if (wait == WaitObject0) return true;
        if (wait == WaitTimeout) return false;
        throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot check retained worker exit.");
    }

    internal uint ConfirmedExitCode()
    {
        if (!HasConfirmedExit()) throw new IOException("Worker exit is not confirmed.");
        if (!GetExitCodeProcess(process, out uint code))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read worker exit status.");
        return code;
    }

    private void RequireAlive()
    {
        uint wait = WaitForSingleObject(process, 0);
        if (wait == WaitObject0) throw new IOException("The recorded worker process has exited.");
        if (wait != WaitTimeout) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot check worker process state.");
        uint pid = GetProcessId(process);
        if (pid == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read worker process ID.");
        if (!GetProcessTimes(process, out NativeFileTime created, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read worker process creation time.");
        ulong creation = ((ulong)created.High << 32) | created.Low;
        if (pid != expectedPid || creation != expectedCreation)
            throw new InvalidDataException("Recorded worker identity does not match the process.");
        wait = WaitForSingleObject(process, 0);
        if (wait == WaitObject0) throw new IOException("The recorded worker process exited during verification.");
        if (wait != WaitTimeout) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot recheck worker process state.");
    }

    public void Dispose() => process.Dispose();
}
