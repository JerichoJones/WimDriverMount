using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

internal static partial class DriverDetection
{
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupCopyOEMInfW(string source, string? media, uint mediaType, uint style,
        StringBuilder destination, uint destinationSize, out uint required, IntPtr component);

    [DllImport("newdev.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DiInstallDevice(IntPtr parent, IntPtr set, ref DeviceInfo device,
        ref DriverInfo driver, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool reboot);

    [DllImport("newdev.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DiInstallDriverW(IntPtr parent, string infPath, uint flags,
        [MarshalAs(UnmanagedType.Bool)] out bool reboot);

    // NothingToChange is Windows' own "already as good as it gets": the package was
    // staged but is not a better match for any device. Neither installed nor failed.
    internal sealed record ExtensionInstallResult(bool Installed, int Error, bool Restart, string? ErrorDetail, bool NothingToChange = false)
    {
        internal DirectDriverInstall.Outcome JournalOutcome => new(Installed, Error, Restart);
    }

    // Hands an extension INF to Windows' own installer, exactly as
    // pnputil /add-driver /install does: Windows stages the package and applies
    // it to every present device where it ranks best. No DIIRFLAG_FORCE_INF, so
    // Windows -- not this program -- decides where it goes, and handing over one
    // that is already applied changes nothing. Windows still enforces the
    // package's signature; nothing here relaxes that.
    internal static ExtensionInstallResult InstallExtension(InfIndex.ModelEntry extension)
    {
        if (extension.ExtensionId is null) throw new ArgumentException("Not an extension INF.", nameof(extension));
        // Known failures before any call to Windows: reported as such, not as an
        // unknown outcome, because nothing was handed over.
        if (!Path.IsPathFullyQualified(extension.Path)) return new(false, 0, false, "Extension INF path is invalid.");
        if (extension.Path.Length >= 260)
            return new(false, 0, false, "The mounted extension INF path exceeds the documented DiInstallDriver limit of 259 characters; select a shorter mounted path.");
        if (DiInstallDriverW(IntPtr.Zero, extension.Path, 0, out bool reboot)) return new(true, 0, reboot, null);
        int error = Marshal.GetLastWin32Error();
        // ERROR_NO_MORE_ITEMS from DiInstallDriver means the package was staged
        // but is not a better match for any present device -- for an extension
        // already applied, exactly "nothing to change". This happens on a second
        // run against the same device. Reported as such,
        // with the true code kept for the journal, not dressed up as installed.
        if (error == NoMoreItems)
            return new(false, error, reboot, "Windows reported nothing to change: the extension is already in place, or is not a better match for any device.", NothingToChange: true);
        return new(false, error, reboot, new Win32Exception(error).Message);
    }

    // This stages one selected package, then locates exactly one corresponding
    // compatible node for the selected device. It must be covered by the call
    // journal: staging may have effects even if a later operation fails.
    internal sealed record SelectedInstallResult(bool Staged, string? PublishedInf, bool InstallationAttempted,
        bool Installed, int Error, bool Restart, string? ErrorDetail, bool InstallationOutcomeUnknown, bool StagingOutcomeUnknown)
    {
        internal DirectDriverInstall.Outcome JournalOutcome => new(Installed, Error, Restart);
    }

    internal static SelectedInstallResult InstallSelectedDevice(string instanceId, InfIndex.ModelEntry selected)
    {
        bool staged = false, attempted = false, installed = false, restart = false, inFlight = false, stagingInFlight = false;
        string? published = null;
        int error = 0;
        Exception? failure = null;
        IntPtr set = new(-1);
        var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
        bool listBuilt = false;
        try
        {
        if (string.IsNullOrWhiteSpace(instanceId) || instanceId.Contains('\0') || instanceId.Length >= 1024 ||
            string.IsNullOrWhiteSpace(selected.Path) || selected.Path.Contains('\0') || !Path.IsPathFullyQualified(selected.Path))
            throw new InvalidDataException("Device or selected INF path is invalid.");
        if (selected.Path.Length >= 260)
            throw new PathTooLongException("The selected mounted INF path exceeds the documented SetupCopyOEMInf limit of 259 characters; select a shorter mounted path.");
        // The returned name is a Windows INF-store path. DriverPath is a fixed
        // MAX_PATH field, but the output buffer need not share that limitation.
        var destination = new StringBuilder(32768);
        stagingInFlight = true;
        bool copied = SetupCopyOEMInfW(selected.Path, null, 1, 0, destination, (uint)destination.Capacity, out _, IntPtr.Zero);
        int copyError = copied ? 0 : Marshal.GetLastWin32Error();
        stagingInFlight = false;
        if (!copied) throw new Win32Exception(copyError, $"Cannot stage the selected INF (error 0x{copyError:X8}).");
        staged = true;
        published = destination.ToString();
        if (!Path.IsPathFullyQualified(published) || published.Length >= 260)
            throw new InvalidDataException("Windows returned an invalid staged INF path.");
        set = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create device set.");
            if (!SetupDiOpenDeviceInfoW(set, instanceId, IntPtr.Zero, 0, ref device))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open selected device.");
            var parameters = new InstallParams { Size = (uint)Marshal.SizeOf<InstallParams>(), DriverPath = string.Empty };
            if (!SetupDiGetDeviceInstallParamsW(set, ref device, ref parameters))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read device installation parameters.");
            parameters.DriverPath = published;
            parameters.Flags &= ~0x00080000u;
            parameters.Flags |= 0x00010000u;
            parameters.FlagsEx &= ~(RecursiveSearch | InstalledDriverOnly | UseClassForCompat);
            parameters.FlagsEx |= AllowExcludedDrivers;
            if (!SetupDiSetDeviceInstallParamsW(set, ref device, ref parameters) ||
                !SetupDiBuildDriverInfoList(set, ref device, CompatibleDriver))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot build the selected INF device list.");
            listBuilt = true;
                DriverInfo? chosen = null;
                int malformed = 0;
                for (uint i = 0; ; i++)
                {
                    if (i >= 1_000_000) throw new InvalidDataException("Selected INF driver node limit exceeded.");
                    var driver = new DriverInfo { Size = (uint)Marshal.SizeOf<DriverInfo>() };
                    if (!SetupDiEnumDriverInfoW(set, ref device, CompatibleDriver, i, ref driver))
                    {
                        int enumError = Marshal.GetLastWin32Error();
                        if (enumError == NoMoreItems) break;
                        throw new Win32Exception(enumError, "Cannot enumerate selected INF nodes.");
                    }
                    IndexedMatch detail;
                    try { detail = GetIndexedDetail(set, ref device, ref driver); }
                    catch (InvalidDataException) { malformed++; continue; } // Cannot be the selected node; keep looking.
                    // The node is identified by its INF, base section, IDs, date and version.
                    // The description is not compared: SetupAPI truncates it to 255 characters.
                    if (!string.Equals(Path.GetFullPath(detail.Inf), Path.GetFullPath(published), StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(detail.Section, selected.InstallSection, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(detail.HardwareId, selected.HardwareId, StringComparison.OrdinalIgnoreCase)) continue;
                    if (selected.DriverVersion?.Date is null || selected.DriverVersion.Version is null ||
                        detail.DriverVersion != selected.DriverVersion.Version.Value || detail.DriverDate <= 0 ||
                        DateOnly.FromDateTime(DateTime.FromFileTimeUtc(detail.DriverDate)) != selected.DriverVersion.Date.Value)
                        continue;
                    string[] compatible = detail.CompatibleIds.Length == 0 ? Array.Empty<string>() : detail.CompatibleIds[..^2].Split('\0');
                    if (!compatible.SequenceEqual(selected.CompatibleIds, StringComparer.OrdinalIgnoreCase))
                        continue;
                    // SetupAPI makes one node per manufacturer line, so the same section
                    // can appear twice. Every compared field is equal,
                    // so they install the same driver: take the first.
                    chosen = driver;
                    break;
                }
                if (!chosen.HasValue) throw new InvalidDataException("Selected INF node was not found for the device" +
                    (malformed == 0 ? "." : $"; {malformed} node(s) had unreadable details."));
                var node = chosen.Value;
                attempted = true;
                inFlight = true;
                installed = DiInstallDevice(IntPtr.Zero, set, ref device, ref node, 0, out restart);
                inFlight = false;
                if (!installed) throw new Win32Exception(Marshal.GetLastWin32Error(), "Selected device installation failed.");
        }
        catch (Exception ex) { failure = ex; error = ex is Win32Exception win ? win.NativeErrorCode : 0; }
        finally
        {
            if (listBuilt && !SetupDiDestroyDriverInfoList(set, ref device, CompatibleDriver))
            {
                var ex = new Win32Exception(Marshal.GetLastWin32Error(), "Cannot destroy selected driver list.");
                failure = failure is null ? ex : new AggregateException(failure, ex);
                if (error == 0) error = ex.NativeErrorCode;
            }
            if (set != new IntPtr(-1) && !SetupDiDestroyDeviceInfoList(set))
            {
                var ex = new Win32Exception(Marshal.GetLastWin32Error(), "Cannot destroy selected device set.");
                failure = failure is null ? ex : new AggregateException(failure, ex);
                if (error == 0) error = ex.NativeErrorCode;
            }
        }
        return new(staged, published, attempted, installed, error, restart, failure?.Message, inFlight, stagingInFlight);
    }
}
