// Background workers must inherit no caller handles, including redirected
// output handles that are not the caller's current standard-handle slots.
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class WorkerProcessLaunch
{
    private const uint CreateNoWindow = 0x08000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint Size;
        public string? Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, ReservedBytes;
        public IntPtr ReservedPointer, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low, High; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string application, StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint flags, IntPtr environment, string? directory, ref StartupInfo startup, out ProcessInformation process);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out NativeFileTime creation,
        out NativeFileTime exit, out NativeFileTime kernel, out NativeFileTime user);

    // The returned Process already owns an opened handle to the exact process
    // created here. Keep the native creation handle until that check completes.
    internal static Process Start(string executable, IReadOnlyList<string> arguments)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        string command = BuildCommandLine(executable, arguments);
        var startup = new StartupInfo { Size = (uint)Marshal.SizeOf<StartupInfo>() };
        if (!CreateProcessW(executable, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero,
            false, CreateNoWindow, IntPtr.Zero, null, ref startup, out ProcessInformation created))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot start background worker without inherited handles.");

        using var original = new SafeProcessHandle(created.Process, ownsHandle: true);
        using var thread = new SafeWaitHandle(created.Thread, ownsHandle: true);
        Process? child = null;
        try
        {
            uint pid = GetProcessId(original);
            if (pid == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read created worker process ID.");
            if (pid != created.ProcessId || pid > int.MaxValue)
                throw new InvalidDataException("Created worker process ID does not match.");
            ulong creation = ReadCreation(original);
            child = Process.GetProcessById((int)pid);
            _ = child.Handle; // Force the .NET handle open while original remains held.
            if (GetProcessId(child.SafeHandle) != pid || ReadCreation(child.SafeHandle) != creation)
                throw new InvalidDataException("Opened worker process does not match the created process.");
            Process result = child;
            child = null;
            return result;
        }
        finally { child?.Dispose(); }
    }

    private static ulong ReadCreation(SafeProcessHandle process)
    {
        if (!GetProcessTimes(process, out NativeFileTime created, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read created worker process time.");
        return ((ulong)created.High << 32) | created.Low;
    }

    // Use Windows C runtime quoting. Always quote each argument, double runs
    // of backslashes before a quote/end, and escape literal quotes. No shell.
    internal static string BuildCommandLine(string executable, IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrEmpty(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        if (!Path.IsPathFullyQualified(executable) || executable.IndexOfAny(['\0', '"']) >= 0)
            throw new ArgumentException("Worker executable must be an absolute path without quotes or NUL.");
        var command = new StringBuilder();
        command.Append('"').Append(executable).Append('"');
        foreach (string argument in arguments)
        {
            ArgumentNullException.ThrowIfNull(argument);
            if (argument.Contains('\0')) throw new ArgumentException("Worker arguments cannot contain NUL.");
            command.Append(' ').Append('"');
            int backslashes = 0;
            foreach (char value in argument)
            {
                if (value == '\\') { backslashes++; continue; }
                if (value == '"') command.Append('\\', checked(backslashes * 2 + 1));
                else command.Append('\\', backslashes);
                command.Append(value);
                backslashes = 0;
            }
            command.Append('\\', checked(backslashes * 2)).Append('"');
            if (command.Length >= 32767) throw new ArgumentException("Worker command line is too long.");
        }
        if (command.Length >= 32767) throw new ArgumentException("Worker command line is too long.");
        return command.ToString();
    }
}
