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

    [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiCallClassInstaller(uint function, IntPtr set, ref DeviceInfo device);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetSelectedDriverW(IntPtr set, ref DeviceInfo device, ref DriverInfo driver);
    private const uint DifSelectBestCompatDrv = 0x17, AppendDriverList = 0x00040000;
    private const int NoCompatDrivers = unchecked((int)0xE0000228), NoDriverSelected = unchecked((int)0xE0000212);

    // The bound driver's rank. Null when Windows lists no installed driver node.
    internal static uint? InstalledDriverRank(string instanceId) => BestRank(instanceId, null, null);

    // The driver Windows would install on this device from the packages already in this
    // PC's driver store: its published INF (the oemN.inf path Device Manager shows), the
    // name its package gave that INF (the same file name for an inbox INF), install
    // section, rank, date and version.
    internal sealed record StoreDriver(string Inf, string OriginalInf, string Section, uint Rank, DateOnly Date, ulong Version);

    // What a device re-scan, or pnputil /add-driver /install, ends with: Windows' own
    // choice over every published INF (%SystemRoot%\inf, the driver store) plus the
    // installed driver. The WIM is not in that list; the caller compares. Null when
    // Windows selects nothing there; a failure to ask throws. Measured: ~50 ms a device.
    // (Jericho, 2026-11-15: the tool does what Windows does when the store already holds
    // a better driver than the WIM's, instead of installing the WIM's as DiInstallDriver would.)
    internal static StoreDriver? StoreBest(string instanceId)
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
            parameters.Flags &= ~0x00010000u; // not DI_ENUMSINGLEINF: the default INF location is the store
            parameters.FlagsEx &= ~(RecursiveSearch | InstalledDriverOnly | UseClassForCompat | AppendDriverList);
            parameters.FlagsEx |= AllowExcludedDrivers;
            if (!SetupDiSetDeviceInstallParamsW(set, ref device, ref parameters) ||
                !SetupDiBuildDriverInfoList(set, ref device, CompatibleDriver))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot build the driver store's list for the device.");
            listBuilt = true;
            // The installed driver joins the same list, as it does when Windows re-scans.
            if (SetupDiGetDeviceInstallParamsW(set, ref device, ref parameters))
            {
                parameters.FlagsEx |= AppendDriverList | InstalledDriverOnly;
                if (SetupDiSetDeviceInstallParamsW(set, ref device, ref parameters)) SetupDiBuildDriverInfoList(set, ref device, CompatibleDriver);
            }
            if (!SetupDiCallClassInstaller(DifSelectBestCompatDrv, set, ref device))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == NoCompatDrivers || error == NoMoreItems) return null;
                throw new Win32Exception(error, "Windows could not select a driver from the store.");
            }
            var selected = new DriverInfo { Size = (uint)Marshal.SizeOf<DriverInfo>() };
            if (!SetupDiGetSelectedDriverW(set, ref device, ref selected))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == NoMoreItems || error == NoDriverSelected) return null;
                throw new Win32Exception(error, "Cannot read the driver Windows selected.");
            }
            var detail = GetIndexedDetail(set, ref device, ref selected);
            var install = new DriverInstallParams { Size = (uint)Marshal.SizeOf<DriverInstallParams>() };
            if (!SetupDiGetDriverInstallParamsW(set, ref device, ref selected, ref install))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the selected driver's rank.");
            if (detail.DriverDate <= 0) throw new InvalidDataException("The selected driver has no date.");
            // The package's own name for the INF is how a person knows the driver (the device
            // table shows it too); it is informational, so the published name stands in when
            // Windows cannot give it, as CaptureInstalledDevices does for the installed driver.
            string original;
            try { original = OriginalInfOf(detail.Inf); }
            catch (Exception error) when (error is Win32Exception or InvalidDataException) { original = Path.GetFileName(detail.Inf); }
            return new(detail.Inf, original, detail.Section, install.Rank, DateOnly.FromDateTime(DateTime.FromFileTimeUtc(detail.DriverDate)), detail.DriverVersion);
        }
        finally
        {
            if (listBuilt) SetupDiDestroyDriverInfoList(set, ref device, CompatibleDriver);
            SetupDiDestroyDeviceInfoList(set);
        }
    }

    // The catalog an INF names for this platform ([Version] CatalogFile, with its
    // decorations), as Windows reads it; empty when it names none.
    internal static string InfCatalog(string inf)
    {
        if (!SetupGetInfInformationW(inf, InfNameIsAbsolute, null, 0, out uint size) || size == 0 || size > 32 * 1024 * 1024)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot query the INF.");
        byte[] information = new byte[(int)size];
        if (!SetupGetInfInformationW(inf, InfNameIsAbsolute, information, size, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the INF's information.");
        var original = new OriginalFileInfo { Size = (uint)Marshal.SizeOf<OriginalFileInfo>(), Inf = "", Catalog = "" };
        if (!SetupQueryInfOriginalFileInformationW(information, 0, IntPtr.Zero, ref original))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read the INF's catalog name.");
        return original.Catalog ?? "";
    }

    // The rank of one WIM model line on this device. inf is a copy of the
    // model's INF on disk with its catalog beside it, so Windows can check the
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
