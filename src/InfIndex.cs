// Parsed INF model records shared by the parser, matcher and installer.
internal sealed class InfIndex
{
    // Section retains the target decoration; IDs retain their INF order.
    // Null date is Windows' documented zero-date default; null version is unknown.
    internal sealed record DriverVersionInfo(DateOnly? Date, ulong? Version);
    // ExtensionId is set only for an extension INF (Class=Extension): such a
    // driver layers onto a device's function driver instead of replacing it,
    // and Windows picks the best-ranked one per ExtensionId independently.
    internal sealed record ModelEntry(string Path, string ManufacturerSection, string Section, string InstallSection, string HardwareId, IReadOnlyList<string> CompatibleIds, bool PlatformApplicable, string? ActualInstallSection, byte? FeatureScore, DriverVersionInfo? DriverVersion, string? Description = null, int? SourceLine = null, string? ExtensionId = null);
}
