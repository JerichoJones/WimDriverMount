// A background worker must not keep the caller's redirected pipes open.
// Call before accessing Console or starting worker threads. The worker uses
// its existing diagnostic file and Application Event Log for reports.
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static class WorkerStandardHandles
{
    private const int Input = -10, Output = -11, Error = -12;
    private static SafeFileHandle? nullInput, nullOutput;

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetStdHandle(int kind, IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    internal static void DetachInherited()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (nullInput is not null || nullOutput is not null)
            throw new InvalidOperationException("Worker standard handles were already detached.");
        var inherited = new HashSet<IntPtr> { GetStdHandle(Input), GetStdHandle(Output), GetStdHandle(Error) };
        // A null security pointer makes the replacement handles noninheritable.
        // Keep them rooted until process exit because SetStdHandle does not own them.
        nullInput = CreateFileW("NUL", 0x80000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (nullInput.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open worker null input.");
        nullOutput = CreateFileW("NUL", 0x40000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (nullOutput.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open worker null output.");
        if (!SetStdHandle(Input, nullInput.DangerousGetHandle()) ||
            !SetStdHandle(Output, nullOutput.DangerousGetHandle()) ||
            !SetStdHandle(Error, nullOutput.DangerousGetHandle()))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot detach worker standard handles.");
        Console.SetIn(TextReader.Null);
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        foreach (IntPtr handle in inherited)
        {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) continue;
            if (handle == nullInput.DangerousGetHandle() || handle == nullOutput.DangerousGetHandle()) continue;
            // stdout and stderr can be the same native handle: close it once.
            if (!CloseHandle(handle))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot release inherited worker standard handle.");
        }
    }
}
