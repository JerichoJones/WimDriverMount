using System.Runtime.InteropServices;

// Writes an identifiable marker outside Windows' installation sections.
// SetupAPI may filter entries and provides no success result.
internal static class SetupDeviceLog
{
    private const ulong DeviceLog = 3; // LOGTOKEN_SETUPAPI_DEVLOG
    private const uint DeviceInstall = 1; // TXTLOG_DEVINST
    private const uint SummaryTimestamp = 0x10004; // TXTLOG_SUMMARY | TXTLOG_TIMESTAMP

    // SetupWriteTextLog is variadic; these fixed messages contain no format
    // specifiers. Windows x64 and ARM64 pass these four integer arguments in the same
    // registers to a variadic callee as to a fixed one, so the fixed declaration holds.
    [DllImport("setupapi.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void SetupWriteTextLog(ulong token, uint category, uint flags, string message);

    internal static void MarkStart(Guid operation)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) throw new PlatformNotSupportedException();
        SetupWriteTextLog(DeviceLog, DeviceInstall, SummaryTimestamp, $"WIM Driver Mount: starting driver operation {operation:N}");
    }

    internal static void MarkExit(Guid operation, uint exitCode)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) throw new PlatformNotSupportedException();
        SetupWriteTextLog(DeviceLog, DeviceInstall, SummaryTimestamp, $"WIM Driver Mount: driver operation {operation:N} returned code {exitCode}");
    }
}
