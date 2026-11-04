// Bounded messages for the background worker's pipes: both the startup handshake
// and the control channel use it, on every background mount.
//
// A pipe cannot be protected from being occupied by the same user. The DACL
// grants only the user's SID, so another account is refused even a zero-access
// open (error 5). But any process of the same user,
// at any integrity level -- the unelevated half of the same sign-in -- can
// connect and hold the only instance, after
// which a normal client gets ERROR_PIPE_BUSY. Anything that must not be
// blockable by such a process therefore cannot depend on a pipe alone.
// Callers must serialize operations in each direction and close the connection
// after any failed or canceled frame; a partial frame cannot be safely reused.
// CurrentUserOnly does not authenticate a particular same-user process.
// The native server DACL grants the user SID; the managed client's owner check
// can reject valid same-user connections when owner SIDs differ. It does not
// establish same elevation or logon session for this native server.
// Callers must impose finite deadlines on connection, read and write operations,
// close on timeout, and account for operations that do not stop promptly.
using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class WorkerPipe
{
    private const int MaxMessageBytes = 4096;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr SecurityDescriptor; public int InheritHandle; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint maxInstances,
        uint outputBufferSize, uint inputBufferSize, uint defaultTimeout, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DisconnectNamedPipe(SafePipeHandle pipe);

    // Makes the server instance ready to listen again after a client it turned
    // away, or one that came and went before the wait (ERROR_NO_DATA). .NET's
    // Disconnect only works on a pipe it counts as connected, which the second
    // kind is not, so that case goes to Windows directly.
    internal static void Reset(NamedPipeServerStream server)
    {
        if (server.IsConnected) { server.Disconnect(); return; }
        if (!DisconnectNamedPipe(server.SafePipeHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot reset the pipe.");
    }

    internal static NamedPipeServerStream CreateServer(string name)
    {
        ValidateName(name);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        string sid = identity.User?.Value ?? throw new InvalidOperationException("Current user SID is unavailable.");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;GA;;;{sid})", 1, out IntPtr descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create pipe security descriptor.");
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), SecurityDescriptor = descriptor, InheritHandle = 0 };
            // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
            // byte mode with PIPE_REJECT_REMOTE_CLIENTS, one server instance.
            SafePipeHandle handle = CreateNamedPipeW(@"\\.\pipe\" + name, 0x40080003, 0x8, 1, 4096, 4096, 0, ref attributes);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Cannot create local control pipe.");
            }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { LocalFree(descriptor); }
    }

    internal static NamedPipeClientStream CreateClient(string name)
    {
        ValidateName(name);
        return new NamedPipeClientStream(".", name, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    }

    internal static async Task WriteAsync(Stream stream, string message, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);
        int length = Utf8.GetByteCount(message);
        if (length == 0 || length > MaxMessageBytes) throw new InvalidDataException("Invalid control message size.");
        byte[] bytes = new byte[4 + length];
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0, 4), length);
            Utf8.GetBytes(message.AsSpan(), bytes.AsSpan(4));
            await stream.WriteAsync(bytes, cancellation).ConfigureAwait(false);
            await stream.FlushAsync(cancellation).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static async Task<string> ReadAsync(Stream stream, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(stream);
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellation).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes) throw new InvalidDataException("Invalid control message size.");
        byte[] bytes = new byte[length];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellation).ConfigureAwait(false);
            return Utf8.GetString(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 128 || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("Invalid control pipe name.", nameof(name));
    }
}
