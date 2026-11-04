// Read-only device/driver matching through the Windows SetupAPI.
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

internal static partial class DriverDetection
{
    private const uint Present = 0x2, AllClasses = 0x4, CompatibleDriver = 2;
    private const uint AllowExcludedDrivers = 0x800, RecursiveSearch = 0x40000000;
    private const uint InstalledDriverOnly = 0x04000000, UseClassForCompat = 0x00002000;
    private const int NoMoreItems = 259, InsufficientBuffer = 122;
    private const uint HardwareIds = 1, CompatibleIds = 2, RegistryMultiString = 7;
    private const uint MaxDeviceIdsBytes = 1024 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceInfo { public uint Size; public Guid ClassGuid; public uint DevInst; public UIntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct InstallParams
    {
        public uint Size, Flags, FlagsEx;
        public IntPtr Parent, Callback, CallbackContext, FileQueue;
        public UIntPtr ClassReserved;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DriverPath;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DriverInfo
    {
        public uint Size, DriverType;
        public UIntPtr Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Manufacturer;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Provider;
        public System.Runtime.InteropServices.ComTypes.FILETIME DriverDate;
        public ulong DriverVersion;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DriverDetail
    {
        public uint Size;
        public System.Runtime.InteropServices.ComTypes.FILETIME InfDate;
        public uint CompatibleOffset, CompatibleLength;
        public UIntPtr Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string SectionName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string InfFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string DriverDescription;
        public char HardwareId;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevsW(IntPtr classGuid, string? enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr classGuid, IntPtr parent);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string instanceId, IntPtr parent, uint flags, ref DeviceInfo device);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref DeviceInfo device);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref DeviceInfo device, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref DeviceInfo device, uint property, out uint type, [Out] byte[]? buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDeviceInstallParamsW(IntPtr set, ref DeviceInfo device, ref InstallParams parameters);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiSetDeviceInstallParamsW(IntPtr set, ref DeviceInfo device, ref InstallParams parameters);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiBuildDriverInfoList(IntPtr set, ref DeviceInfo device, uint kind);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiDestroyDriverInfoList(IntPtr set, ref DeviceInfo device, uint kind);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiEnumDriverInfoW(IntPtr set, ref DeviceInfo device, uint kind, uint index, ref DriverInfo driver);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupDiGetDriverInfoDetailW(IntPtr set, ref DeviceInfo device, ref DriverInfo driver, IntPtr detail, uint size, out uint required);

    private sealed record IndexedMatch(string Inf, string Section, string HardwareId, string CompatibleIds,
        string Description, string Manufacturer, string Provider, ulong DriverVersion, long DriverDate);

    private static IndexedMatch GetIndexedDetail(IntPtr set, ref DeviceInfo device, ref DriverInfo driver)
    {
        bool ok = SetupDiGetDriverInfoDetailW(set, ref device, ref driver, IntPtr.Zero, 0, out uint required);
        if (!ok && Marshal.GetLastWin32Error() != InsufficientBuffer)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot size driver details.");
        int headerSize = Marshal.SizeOf<DriverDetail>();
        if (required < headerSize || required > 1024 * 1024)
            throw new InvalidDataException("Driver details size is invalid or exceeds the limit.");
        IntPtr buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            for (int i = 0; i < required; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteInt32(buffer, headerSize);
            if (!SetupDiGetDriverInfoDetailW(set, ref device, ref driver, buffer, required, out uint actual))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot retrieve complete driver details.");
            if (actual != required) throw new InvalidDataException("Driver details changed during retrieval.");
            var detail = Marshal.PtrToStructure<DriverDetail>(buffer);
            int offset = Marshal.OffsetOf<DriverDetail>(nameof(DriverDetail.HardwareId)).ToInt32();
            if (((int)actual - offset) % 2 != 0) throw new InvalidDataException("Driver ID data has an invalid size.");
            int availableChars = checked(((int)required - offset) / 2);
            uint compatOffset = detail.CompatibleOffset, compatLength = detail.CompatibleLength;
            if (compatOffset > availableChars || compatLength > availableChars - compatOffset)
                throw new InvalidDataException("Driver ID offsets exceed the detail buffer.");
            string hardware = string.Empty;
            if (compatOffset > 1)
            {
                string raw = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset), checked((int)compatOffset))!;
                if (raw[^1] != '\0' || raw[..^1].Contains('\0'))
                    throw new InvalidDataException("Driver hardware ID is malformed.");
                hardware = raw[..^1];
            }
            string compatible = string.Empty;
            if (compatLength != 0)
            {
                // Only CompatIDsOffset/CompatIDsLength bound the list; its terminators
                // are not assumed. The result is normalized to a double-NUL list.
                string span = Marshal.PtrToStringUni(IntPtr.Add(buffer, checked(offset + (int)compatOffset * 2)), checked((int)compatLength))!;
                string[] ids = span.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                if (ids.Length != 0) compatible = string.Join('\0', ids) + "\0\0";
            }
            long date = ((long)(uint)driver.DriverDate.dwHighDateTime << 32) | (uint)driver.DriverDate.dwLowDateTime;
            var strictUnicode = new UnicodeEncoding(false, false, true);
            foreach (string value in new[] { detail.InfFileName, detail.SectionName, hardware, compatible,
                driver.Description, driver.Manufacturer, driver.Provider })
                _ = strictUnicode.GetByteCount(value);
            return new IndexedMatch(detail.InfFileName, detail.SectionName, hardware, compatible,
                driver.Description, driver.Manufacturer, driver.Provider, driver.DriverVersion, date);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

}
