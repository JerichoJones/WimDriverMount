using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal static partial class DriverDetection
{
    private const uint DeviceDriverPropertyId = 11;
    private const uint InfNameIsAbsolute = 2;
    [DllImport("setupapi.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr SetupDiOpenDevRegKey(IntPtr set, ref DeviceInfo device, uint scope, uint profile, uint keyType, uint access);
    [DllImport("cfgmgr32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint device, uint flags);
    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyKey { internal Guid Format; internal uint Id; }
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDevicePropertyW(IntPtr set, ref DeviceInfo device, ref PropertyKey key,
        out uint type, byte[]? buffer, uint size, out uint required, uint flags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OriginalFileInfo
    {
        internal uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string Inf;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string Catalog;
    }
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupGetInfInformationW(string path, uint search, byte[]? buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupQueryInfOriginalFileInformationW(byte[] information, uint index, IntPtr platform, ref OriginalFileInfo original);

    internal sealed record InstalledDevice(string InstanceId, IReadOnlyList<string> HardwareIds,
        IReadOnlyList<string> CompatibleIds, string? Inf, string? Version, string? Date,
        uint? Problem, bool Restart, string? CaptureError, bool IdsUncertain = false, string? OriginalInf = null, bool Unbound = false,
        string? Section = null, uint? Rank = null, string? MatchedDeviceId = null, string? Name = null);

    // The name Device Manager shows: the friendly name, else the description.
    // For the report only; it comes from driver INFs, so it is escaped on output.
    private static string? ReadName(IntPtr set, ref DeviceInfo device)
    {
        foreach (uint property in new uint[] { 12 /* SPDRP_FRIENDLYNAME */, 0 /* SPDRP_DEVICEDESC */ })
        {
            byte[] buffer = new byte[1024];
            if (SetupDiGetDeviceRegistryPropertyW(set, ref device, property, out uint type, buffer, (uint)buffer.Length, out uint used) &&
                type == 1 /* REG_SZ */ && used >= 2)
            {
                string name = Encoding.Unicode.GetString(buffer, 0, (int)used & ~1).TrimEnd('\0').Trim();
                if (name.Length != 0) return name;
            }
        }
        return null;
    }

    // The driver-scoped DEVPROPKEY class. Both ids were read back from Windows
    // on real hardware rather than taken from a header: on ACPI\PNP0A03\3F,
    // pid 14 returned 0x00FF0002 and pid 8 returned "*PNP0A03", matching exactly
    // what pnputil /enum-devices /drivers reported for the same device.
    private static readonly Guid DriverProperties = new("a8b865dd-2e3d-4094-ad97-e593a70c75d6");
    private const uint MatchingDeviceIdProperty = 8, DriverRankProperty = 14;
    private const uint DevPropUInt32 = 7, DevPropString = 18;

    // Windows' own rank for the driver currently bound to this device: the low
    // word is how specifically its INF matched, the high bytes its signer class.
    // Lower is better. Null when the device has no bound driver or the property
    // is unavailable, which callers must treat as "no basis to compare".
    private static uint? ReadDriverRank(IntPtr set, ref DeviceInfo device)
    {
        var key = new PropertyKey { Format = DriverProperties, Id = DriverRankProperty };
        byte[] buffer = new byte[sizeof(uint)];
        if (!SetupDiGetDevicePropertyW(set, ref device, ref key, out uint type, buffer, (uint)buffer.Length, out _, 0))
            return null;
        return type == DevPropUInt32 ? BitConverter.ToUInt32(buffer) : null;
    }

    // Which of the device's ids the bound driver actually matched on.
    private static string? ReadMatchedDeviceId(IntPtr set, ref DeviceInfo device)
    {
        var key = new PropertyKey { Format = DriverProperties, Id = MatchingDeviceIdProperty };
        if (SetupDiGetDevicePropertyW(set, ref device, ref key, out _, null, 0, out uint required, 0)) return null;
        if (Marshal.GetLastWin32Error() != InsufficientBuffer || required < 2 || required > 64 * 1024 || (required & 1) != 0)
            return null;
        byte[] buffer = new byte[(int)required];
        if (!SetupDiGetDevicePropertyW(set, ref device, ref key, out uint type, buffer, required, out _, 0) || type != DevPropString)
            return null;
        return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
    }

    private static bool PropertyAbsent(IntPtr set, ref DeviceInfo device, uint id)
    {
        var key = new PropertyKey { Format = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), Id = id };
        bool found = SetupDiGetDevicePropertyW(set, ref device, ref key, out uint type, null, 0, out _, 0);
        return !found && Marshal.GetLastWin32Error() == 1168 && type == 0;
    }

    private static string OriginalInfName(string published)
    {
        if (Path.GetFileName(published) != published) throw new InvalidDataException("Invalid published INF name.");
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", published);
        if (!SetupGetInfInformationW(path, InfNameIsAbsolute, null, 0, out uint size) || size == 0 || size > 32 * 1024 * 1024)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot query published INF.");
        byte[] information = new byte[(int)size];
        if (!SetupGetInfInformationW(path, InfNameIsAbsolute, information, size, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read published INF information.");
        var original = new OriginalFileInfo { Size = (uint)Marshal.SizeOf<OriginalFileInfo>(), Inf = "", Catalog = "" };
        if (!SetupQueryInfOriginalFileInformationW(information, 0, IntPtr.Zero, ref original) || string.IsNullOrWhiteSpace(original.Inf))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot determine original INF name.");
        return original.Inf;
    }

    private static IReadOnlyList<string> ReadOptionalIds(IntPtr set, ref DeviceInfo device, uint property, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        bool ok = SetupDiGetDeviceRegistryPropertyW(set, ref device, property, out _, null, 0, out uint size);
        int error = ok ? 0 : Marshal.GetLastWin32Error();
        if (!ok && error == 13)
        {
            if (PropertyAbsent(set, ref device, property == HardwareIds ? 3u : 4u)) return Array.Empty<string>();
            throw new InvalidDataException("Device ID property could not be confirmed absent.");
        }
        if (!ok && error != InsufficientBuffer) throw new Win32Exception(error, "Cannot read device IDs.");
        if (size < 4 || size > MaxDeviceIdsBytes || (size & 1) != 0) throw new InvalidDataException("Invalid device ID property size.");
        var bytes = new byte[(int)size];
        if (!SetupDiGetDeviceRegistryPropertyW(set, ref device, property, out uint registryType, bytes, size, out uint actual))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read device IDs.");
        if (registryType != RegistryMultiString || actual != size) throw new InvalidDataException("Device IDs changed or have an invalid type.");
        string value = DeviceIdEncoding.Decode(bytes);
        if (!value.EndsWith("\0\0", StringComparison.Ordinal)) throw new InvalidDataException("Device IDs are not terminated.");
        string[] ids = value[..^2].Split('\0');
        if (ids.Length == 1 && ids[0].Length == 0) return Array.Empty<string>();
        if (ids.Any(string.IsNullOrEmpty)) throw new InvalidDataException("Device ID is empty.");
        return ids;
    }

    internal static IReadOnlyList<InstalledDevice> CaptureInstalledDevices(CancellationToken cancellation)
    {
        IntPtr set = SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, Present | AllClasses);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot enumerate present devices.");
        var result = new List<InstalledDevice>();
        try
        {
            for (uint index = 0; ; index++)
            {
                cancellation.ThrowIfCancellationRequested();
                var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
                if (!SetupDiEnumDeviceInfo(set, index, ref device))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == NoMoreItems) break;
                    throw new Win32Exception(error, "Cannot enumerate a present device.");
                }
                var instance = new StringBuilder(1024);
                if (!SetupDiGetDeviceInstanceIdW(set, ref device, instance, (uint)instance.Capacity, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read a device instance ID.");
                IReadOnlyList<string> hardware = Array.Empty<string>(), compatible = Array.Empty<string>();
                string? errorText = null, inf = null, version = null, date = null, originalInf = null, section = null;
                bool idsUncertain = false, unbound = false;
                try
                {
                    hardware = ReadOptionalIds(set, ref device, HardwareIds, cancellation);
                }
                catch (Exception error) when (error is Win32Exception or InvalidDataException)
                {
                    errorText = error.Message; idsUncertain = true;
                }
                try { compatible = ReadOptionalIds(set, ref device, CompatibleIds, cancellation); }
                catch (Exception error) when (error is Win32Exception or InvalidDataException)
                { errorText = (errorText is null ? "" : errorText + "; ") + error.Message; idsUncertain = true; }
                IntPtr key = SetupDiOpenDevRegKey(set, ref device, 1, 0, 2, 0x20019);
                if (key != new IntPtr(-1))
                {
                    try
                    {
                        using var handle = new SafeRegistryHandle(key, true);
                        using var registry = RegistryKey.FromHandle(handle);
                        inf = registry.GetValue("InfPath") as string;
                        string? baseSection = registry.GetValue("InfSection") as string;
                        string? sectionExtension = registry.GetValue("InfSectionExt") as string;
                        if (!string.IsNullOrWhiteSpace(baseSection)) section = baseSection + (sectionExtension ?? string.Empty);
                        version = registry.GetValue("DriverVersion") as string;
                        if (registry.GetValue("DriverDateData") is byte[] dateBytes && dateBytes.Length == 8)
                            date = DateTime.FromFileTimeUtc(BitConverter.ToInt64(dateBytes)).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
                        if (string.IsNullOrWhiteSpace(inf) || string.IsNullOrWhiteSpace(version) || date is null)
                            throw new InvalidDataException("Installed driver metadata is missing or invalid.");
                        // Informational only; a missing published INF must not block selection.
                        try { originalInf = OriginalInfName(inf); }
                        catch (Exception error) when (error is Win32Exception or InvalidDataException) { }
                    }
                    catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or ArgumentException)
                    { errorText = (errorText is null ? "" : errorText + "; ") + error.Message; }
                }
                else if (PropertyAbsent(set, ref device, DeviceDriverPropertyId)) unbound = true;
                else errorText = (errorText is null ? "" : errorText + "; ") + "Cannot read installed driver key.";
                uint cm = CM_Get_DevNode_Status(out uint status, out uint problem, device.DevInst, 0);
                if (cm != 0) errorText = (errorText is null ? "" : errorText + "; ") + $"Device status error {cm}.";
                var parameters = new InstallParams { Size = (uint)Marshal.SizeOf<InstallParams>(), DriverPath = string.Empty };
                // A pending restart persists on the devnode (DN_NEED_RESTART = DN_LIAR,
                // 0x100, or CM_PROB_NEED_RESTART = 14); DI_NEEDRESTART/DI_NEEDREBOOT only
                // live in one set. (0x01000000 is DN_NT_DRIVER, set on most devices.)
                bool restart = cm == 0 && ((status & 0x00000100) != 0 || problem == 14);
                if (SetupDiGetDeviceInstallParamsW(set, ref device, ref parameters)) restart |= (parameters.Flags & 0x180) != 0;
                else errorText = (errorText is null ? "" : errorText + "; ") + $"Device restart status error {Marshal.GetLastWin32Error()}.";
                uint? rank = unbound ? null : ReadDriverRank(set, ref device);
                string? matchedDeviceId = unbound ? null : ReadMatchedDeviceId(set, ref device);
                result.Add(new(instance.ToString(), hardware, compatible, inf, version, date, cm == 0 ? problem : null, restart, errorText, idsUncertain, originalInf, unbound, section, rank, matchedDeviceId, ReadName(set, ref device)));
            }
            return result;
        }
        finally
        {
            if (!SetupDiDestroyDeviceInfoList(set)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot close device list.");
        }
    }
}
