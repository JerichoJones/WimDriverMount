using System.ComponentModel;
using System.Runtime.InteropServices;

// Windows' own rank for a driver on a device, as Windows computes it at this
// moment: signer score, feature score and identifier score (0xSSGGTHHH). The
// signer score follows the AllSigningEqual policy -- 00 for every signed
// package while it is on (the default), the real score (inbox and WHQL 0D,
// Authenticode 0F) while it is off -- so this tool never has to read the policy
// or judge a catalog itself. Measured against Windows' own choice in both policy
// states. The device property DEVPKEY_Device_DriverRank cannot stand in for the
// bound driver: it never carries the signer byte.
internal static partial class DriverDetection
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DriverInstallParams { public uint Size, Rank, Flags; public UIntPtr PrivateData; public uint Reserved; }
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDriverInstallParamsW(IntPtr set, ref DeviceInfo device, ref DriverInfo driver, ref DriverInstallParams parameters);

    // The bound driver's rank. Null when Windows lists no installed driver node.
    internal static uint? InstalledDriverRank(string instanceId) => BestRank(instanceId, null, null);

    // The rank of one WIM model line on this device. inf is a copy of the
    // model's INF on disk with its catalogs beside it, so Windows can check the
    // signature. Null when Windows lists no node for that model line.
    internal static uint? CandidateDriverRank(string instanceId, string inf, InfIndex.ModelEntry model) => BestRank(instanceId, inf, model);

    private static uint? BestRank(string instanceId, string? inf, InfIndex.ModelEntry? model)
    {
        IntPtr set = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create device set.");
        var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
        bool listBuilt = false;
        try
        {
            if (!SetupDiOpenDeviceInfoW(set, instanceId, IntPtr.Zero, 0, ref device))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open device.");
            var parameters = new InstallParams { Size = (uint)Marshal.SizeOf<InstallParams>(), DriverPath = string.Empty };
            if (!SetupDiGetDeviceInstallParamsW(set, ref device, ref parameters))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read device installation parameters.");
            parameters.FlagsEx &= ~(RecursiveSearch | InstalledDriverOnly | UseClassForCompat);
            parameters.FlagsEx |= AllowExcludedDrivers;
            if (inf is null) parameters.FlagsEx |= InstalledDriverOnly;
            else
            {
                parameters.DriverPath = inf;
                parameters.Flags &= ~0x00080000u;
                parameters.Flags |= 0x00010000u; // DI_ENUMSINGLEINF: this INF only, not the driver store.
            }
            if (!SetupDiSetDeviceInstallParamsW(set, ref device, ref parameters) ||
                !SetupDiBuildDriverInfoList(set, ref device, CompatibleDriver))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot build the device's driver list.");
            listBuilt = true;
            uint? best = null;
            for (uint i = 0; ; i++)
            {
                if (i >= 1_000_000) throw new InvalidDataException("Driver node limit exceeded.");
                var driver = new DriverInfo { Size = (uint)Marshal.SizeOf<DriverInfo>() };
                if (!SetupDiEnumDriverInfoW(set, ref device, CompatibleDriver, i, ref driver))
                {
                    int enumError = Marshal.GetLastWin32Error();
                    if (enumError == NoMoreItems) break;
                    throw new Win32Exception(enumError, "Cannot enumerate driver nodes.");
                }
                if (model is not null)
                {
                    // The same identity InstallSelectedDevice uses to find the node it installs.
                    IndexedMatch detail;
                    try { detail = GetIndexedDetail(set, ref device, ref driver); }
                    catch (InvalidDataException) { continue; }
                    if (!string.Equals(detail.Section, model.InstallSection, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(detail.HardwareId, model.HardwareId, StringComparison.OrdinalIgnoreCase)) continue;
                    string[] compatible = detail.CompatibleIds.Length == 0 ? Array.Empty<string>() : detail.CompatibleIds[..^2].Split('\0');
                    if (!compatible.SequenceEqual(model.CompatibleIds, StringComparer.OrdinalIgnoreCase)) continue;
                }
                var install = new DriverInstallParams { Size = (uint)Marshal.SizeOf<DriverInstallParams>() };
                if (!SetupDiGetDriverInstallParamsW(set, ref device, ref driver, ref install))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read a driver node's rank.");
                // One node per manufacturer line: Windows takes the best.
                if (best is not uint b || install.Rank < b) best = install.Rank;
            }
            return best;
        }
        finally
        {
            if (listBuilt) SetupDiDestroyDriverInfoList(set, ref device, CompatibleDriver);
            SetupDiDestroyDeviceInfoList(set);
        }
    }
}
