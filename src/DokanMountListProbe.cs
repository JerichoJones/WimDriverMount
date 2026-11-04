using System.ComponentModel;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

// Dokan 2.3's public list helper returns NULL for both an empty list and an
// error. Query the same driver control directly so a successful zero-byte
// response can be distinguished from failure. A nonempty or too-small result
// means only that cleanup must wait; it is not mount ownership proof.
internal static class DokanMountListProbe
{
    // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
    // https://github.com/dokan-dev/dokany/blob/v2.3.1.1000/sys/public.h (unchanged since 2.3.0)
    private const uint MountPointListControl = 0x00092034;
    private const int MoreData = 234, InsufficientBuffer = 122;
    private const uint BufferSize = 32768;
    internal readonly record struct Response(bool Success, uint Bytes, int Error);
    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { internal uint Low; internal int High; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputSize,
        [Out] byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", ExactSpelling = true)] private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool LookupPrivilegeValueW(string? system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind,
        [Out] byte[]? buffer, uint length, out uint returned);

    internal static uint ActiveMounts()
    {
        // The pinned driver filters other sessions unless this privilege is
        // enabled. Check the effective non-impersonated process token around
        // the query; no privilege is enabled or changed by this method.
        bool before = HasImpersonatePrivilege();
        Response response = Query();
        bool after = HasImpersonatePrivilege();
        return Interpret(response, before && after);
    }

    internal static uint Interpret(Response response, bool allSessionsVisible)
    {
        if (response.Success)
        {
            if (response.Bytes > BufferSize) throw new InvalidDataException("Dokan mount list returned an invalid length.");
            if (response.Bytes != 0) return 1;
            if (!allSessionsVisible) throw new UnauthorizedAccessException("Dokan mount inventory may omit other sessions.");
            return 0;
        }
        // A short buffer cannot prove an empty list. Do not remove Dokan.
        if (response.Error is MoreData or InsufficientBuffer) return 1;
        throw new Win32Exception(response.Error, "Cannot inspect Dokan mounts.");
    }

    private static bool HasImpersonatePrivilege()
    {
        using WindowsIdentity? ambient = WindowsIdentity.GetCurrent(true);
        if (ambient is not null) throw new UnauthorizedAccessException("Dokan inventory requires a non-impersonated process.");
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out SafeAccessTokenHandle token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect process privileges.");
        using (token)
        {
            if (!LookupPrivilegeValueW(null, "SeImpersonatePrivilege", out Luid id))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot resolve Dokan inventory privilege.");
            if (GetTokenInformation(token, 3, null, 0, out uint needed) || Marshal.GetLastWin32Error() != 122 || needed is < 4 or > 65536)
                throw new IOException("Cannot size process privilege inventory.");
            byte[] buffer = new byte[needed];
            if (!GetTokenInformation(token, 3, buffer, needed, out uint returned))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot check process privileges.");
            if (returned > needed) throw new InvalidDataException("Invalid process privilege inventory size.");
            return ContainsEnabledPrivilege(buffer.AsSpan(0, checked((int)returned)), id.Low, id.High);
        }
    }

    internal static bool ContainsEnabledPrivilege(ReadOnlySpan<byte> data, uint low, int high)
    {
        if (data.Length < 4) throw new InvalidDataException("Invalid process privilege inventory.");
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (count > (data.Length - 4) / 12) throw new InvalidDataException("Invalid process privilege inventory length.");
        for (int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> item = data.Slice(4 + i * 12, 12);
            if (BinaryPrimitives.ReadUInt32LittleEndian(item) == low && BinaryPrimitives.ReadInt32LittleEndian(item[4..]) == high)
                return (BinaryPrimitives.ReadUInt32LittleEndian(item[8..]) & 2) != 0;
        }
        return false;
    }

    private static Response Query()
    {
        using SafeFileHandle handle = CreateFileW(@"\\.\Dokan_2", 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open Dokan control device.");
        byte[] output = new byte[BufferSize];
        bool success = DeviceIoControl(handle, MountPointListControl, IntPtr.Zero, 0, output, BufferSize, out uint returned, IntPtr.Zero);
        int error = success ? 0 : Marshal.GetLastWin32Error();
        return new Response(success, returned, error);
    }
}
