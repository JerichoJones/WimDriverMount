using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using DiscUtils.Wim;

// Retained INF collection, parsed once for per-device selection. An INF that
// cannot be parsed blocks only devices whose IDs appear anywhere in its text.
internal sealed class InfCollectedIndex
{
    // Ids are the field values found in the unparsed file; null means the file
    // could affect any device.
    internal sealed record Unresolved(string ImagePath, string Reason, IReadOnlySet<string>? Ids = null);
    private readonly List<InfIndex.ModelEntry> models = new();
    // Kept apart from models on purpose: everything that matches, ranks or
    // installs function drivers reads models only, so an extension can never be
    // chosen as a device's function driver.
    private readonly List<InfIndex.ModelEntry> extensions = new();
    private readonly List<Unresolved> unresolved = new();
    private readonly List<(string Path, string Reason, IReadOnlyList<string> Ids)> scopedUnresolved = new();
    // Every ID named by scopedUnresolved, so a device costs one lookup per ID.
    private readonly HashSet<string> scopedIds = new(StringComparer.OrdinalIgnoreCase);
    // Characters of unparsed-INF ID sets still allowed to be kept (16M, about 32 MB).
    private long scopeCharactersLeft = 16L * 1024 * 1024;
    internal IReadOnlyList<Unresolved> UnresolvedFiles => unresolved.AsReadOnly();
    internal IReadOnlyList<(string Path, string Reason, IReadOnlyList<string> Ids)> ScopedUnresolved => scopedUnresolved.AsReadOnly();
    internal IReadOnlyList<InfIndex.ModelEntry> Models => models.AsReadOnly();
    internal IReadOnlyList<InfIndex.ModelEntry> Extensions => extensions.AsReadOnly();
    internal bool SelectionComplete => unresolved.Count == 0 && scopedUnresolved.Count == 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeOsVersion
    {
        internal uint Size, Major, Minor, Build, Platform;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] internal string ServicePack;
        internal ushort ServicePackMajor, ServicePackMinor, Suite;
        internal byte ProductType, Reserved;
    }
    [DllImport("ntdll.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RtlGetVersion(ref NativeOsVersion information);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern ushort GetSystemDefaultUILanguage();

    internal static Version ValidateTarget(int status, uint platform, byte product, uint major, uint minor, uint build)
    {
        if (status != 0 || platform != 2 || product is < 1 or > 3 ||
            major > int.MaxValue || minor > int.MaxValue || build > int.MaxValue)
            throw new InvalidDataException("Windows target information is unavailable.");
        return new Version((int)major, (int)minor, (int)build);
    }

    internal static InfCollectedIndex Build(WimFileSystem image, string mount, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows target information is required.");
        var target = new NativeOsVersion { Size = (uint)Marshal.SizeOf<NativeOsVersion>(), ServicePack = string.Empty };
        int status = RtlGetVersion(ref target);
        var version = ValidateTarget(status, target.Platform, target.ProductType, target.Major, target.Minor, target.Build);
        // Device installation selects INF strings by the system UI language, not the caller's.
        int locale = GetSystemDefaultUILanguage(), codePage = InfRawParser.CurrentAnsiCodePage();
        var result = new InfCollectedIndex();
        var budget = new InfRawParser.Budget(); // Retained memory is limited across the whole WIM.
        // This is the only image walk and the only WIM content read in this path.
        foreach (var file in image.CollectInfFiles(cancellation))
        {
            cancellation.ThrowIfCancellationRequested();
            string mountedPath = Path.Combine(mount, file.ImagePath.TrimStart('\\'));
            result.Add(mountedPath, file.OpenRead, budget.NextFile(), RuntimeInformation.OSArchitecture, version, target.ProductType, target.Suite, locale, codePage, cancellation);
        }
        return result;
    }

    // Extension INFs that were not used, and why; reported, never blocking.
    internal sealed record SkippedExtension(string Path, string Reason);
    private readonly List<SkippedExtension> skippedExtensions = new();
    internal IReadOnlyList<SkippedExtension> SkippedExtensions => skippedExtensions.AsReadOnly();

    // Parses one INF. A file-level failure is kept as unresolved, scoped to the
    // field values in its text.
    internal void Add(string path, Func<Stream> open, InfRawParser.Budget budget, Architecture architecture, Version os, byte? productType,
        ushort? suiteMask, int locale, int codePage, CancellationToken cancellation)
    {
        var extensionSeen = new System.Runtime.CompilerServices.StrongBox<bool>();
        // This file's model-level errors are kept only if the file is: one that
        // fails as a whole is covered by its file-level entry, whose IDs include them.
        var fileScoped = new List<(string Path, string Reason, IReadOnlyList<string> Ids)>();
        try
        {
            using var source = open();
            foreach (var entry in InfRawParser.Parse(source, path, architecture, budget, cancellation, os, productType, suiteMask,
                locale: locale, ansiCodePage: codePage, scopedErrors: fileScoped, includeExtensions: true, extensionSeen: extensionSeen))
                (entry.ExtensionId is null ? models : extensions).Add(entry);
            budget.Commit();
            scopedUnresolved.AddRange(fileScoped);
            foreach (var item in fileScoped) scopedIds.UnionWith(item.Ids);
        }
        catch (Exception error) when ((error is InvalidDataException or InfRawParser.BudgetExceededException) && extensionSeen.Value)
        {
            // A broken extension is skipped, as Windows would reject the package.
            // Recording it as unresolved would block function-driver selection for
            // every device it names, which no extension could ever have changed.
            // It is still named in the reports, so a skip is never silent.
            skippedExtensions.Add(new(path, error.Message));
        }
        catch (Exception error) when (error is InvalidDataException or InfRawParser.BudgetExceededException)
        {
            IReadOnlySet<string>? ids = null;
            try { using var again = open(); ids = InfRawParser.DeviceIdTokens(again); }
            catch (Exception scan) when (scan is InvalidDataException or IOException) { }
            // Each set is kept for the whole run. Past a shared allowance a file
            // blocks every device instead, which is safe: one unparsable INF
            // stored once and listed under hundreds of paths could keep gigabytes.
            // Each kept ID costs its characters plus a string object and a set
            // slot -- about 32 characters' worth; counting characters alone would let
            // sets of one-character IDs hold ~0.9 GB.
            long characters = ids?.Sum(id => id.Length + 32L) ?? 0;
            if (ids is not null && characters > scopeCharactersLeft) ids = null;
            else scopeCharactersLeft -= characters;
            unresolved.Add(new(path, error.Message, ids));
        }
    }

    internal InMemoryDriverMatcher CreateMatcher(CancellationToken cancellation) => new(models, cancellation);
    internal InMemoryDriverMatcher CreateExtensionMatcher(CancellationToken cancellation) => new(extensions, cancellation);

    internal bool IsSelectionCompleteFor(IEnumerable<string> hardwareIds, IEnumerable<string> compatibleIds)
    {
        var ids = new HashSet<string>(hardwareIds.Concat(compatibleIds), StringComparer.OrdinalIgnoreCase);
        return !unresolved.Any(item => item.Ids is null || ids.Any(item.Ids.Contains)) && !ids.Any(scopedIds.Contains);
    }
}

// Initial conservative syntax subset; anything outside it remains unresolved.
internal static class InfRawParser
{
    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetACP();
    internal static int CurrentAnsiCodePage() => OperatingSystem.IsWindows() ? checked((int)GetACP()) : CultureInfo.CurrentCulture.TextInfo.ANSICodePage;
    internal sealed class BudgetExceededException(string message) : InvalidOperationException(message) { }
    internal sealed class Budget
    {
        private const long DefaultWork = 100_000_000, DefaultRetained = 128L * 1024 * 1024, DefaultTemporaryStrings = 64L * 1024 * 1024;
        private readonly long maxWork, maxRetained;
        internal long MaxTemporaryStrings { get; }
        private long work, pending;
        private readonly long[] retained = new long[1]; // Committed bytes, shared by NextFile budgets.
        // Work across every file. Per file alone, one crafted INF repeated under
        // thousands of paths would cost minutes of CPU before mounting. Far above a large
        // real driver pack; past it, the remaining INFs are unresolved, which is safe.
        private const long TotalWork = 4_000_000_000;
        private readonly long[] totalWork = new long[1];
        internal Budget(long maxWork = DefaultWork, long maxRetained = DefaultRetained, long maxTemporaryStrings = DefaultTemporaryStrings)
        {
            if (maxWork < 0 || maxWork > DefaultWork || maxRetained < 0 || maxRetained > DefaultRetained ||
                maxTemporaryStrings < 0 || maxTemporaryStrings > DefaultTemporaryStrings)
                throw new ArgumentOutOfRangeException(nameof(maxWork));
            this.maxWork = maxWork; this.maxRetained = maxRetained;
            MaxTemporaryStrings = maxTemporaryStrings;
        }
        private Budget(Budget whole)
        {
            maxWork = whole.maxWork; maxRetained = whole.maxRetained;
            MaxTemporaryStrings = whole.MaxTemporaryStrings; retained = whole.retained; totalWork = whole.totalWork;
        }
        // A fresh work allowance for the next file; retained memory stays shared.
        // A file's bytes count toward the shared total only once it is kept (Commit).
        internal Budget NextFile() => new(this);
        internal void Commit() { retained[0] = checked(retained[0] + pending); pending = 0; }
        internal void Charge(long operations, long bytes = 0)
        {
            work = checked(work + operations); pending = checked(pending + bytes);
            totalWork[0] = checked(totalWork[0] + operations);
            if (work > maxWork || totalWork[0] > TotalWork || retained[0] + pending > maxRetained)
                throw new BudgetExceededException("Raw INF index work or memory limit exceeded.");
        }
    }
    internal static IReadOnlyList<InfIndex.ModelEntry> Parse(Stream source, string path, Architecture architecture, Budget budget, CancellationToken cancellation, Version? osVersion = null, byte? productType = null, ushort? suiteMask = null, int? locale = null, int? ansiCodePage = null, List<(string Path, string Reason, IReadOnlyList<string> Ids)>? scopedErrors = null, bool includeExtensions = false, System.Runtime.CompilerServices.StrongBox<bool>? extensionSeen = null)
    {
        cancellation.ThrowIfCancellationRequested();
        if (!source.CanSeek || source.Length < 0 || source.Length > 32L * 1024 * 1024)
            throw new InvalidDataException("INF byte limit exceeded or length unavailable.");
        byte[] raw = new byte[checked((int)source.Length)];
        int offset = 0;
        while (offset < raw.Length)
        {
            cancellation.ThrowIfCancellationRequested();
            int read = source.Read(raw, offset, Math.Min(65536, raw.Length - offset));
            if (read == 0) throw new InvalidDataException("INF data ended early.");
            offset += read;
        }
        budget.Charge(raw.Length);
        string text = Decode(raw, ansiCodePage);
        if (text.Contains('\u0001')) throw new InvalidDataException("INF contains unsupported control characters.");
        var sections = new Dictionary<string, List<(string Key, string Value, int Line)>>(StringComparer.OrdinalIgnoreCase);
        List<(string Key, string Value, int Line)>? current = null;
        using var lines = new StringReader(text);
        int lineCount = 0;
        while (lines.ReadLine() is string original)
        {
            cancellation.ThrowIfCancellationRequested();
            if (++lineCount > 100_000 || original.Length > 32768) throw new InvalidDataException("INF line limit exceeded.");
            int sourceLine = lineCount;
            while (StripComment(original).TrimEnd().EndsWith('\\'))
            {
                cancellation.ThrowIfCancellationRequested();
                string currentLine = StripComment(original).TrimEnd();
                string? next = lines.ReadLine();
                if (next is null) { original = currentLine[..^1]; break; }
                if (++lineCount > 100_000 || currentLine.Length + next.Length > 32768) throw new InvalidDataException("INF continuation limit exceeded.");
                // Charge before each scan and concatenation, not only once for the
                // final logical line. Repeated continuations otherwise amplify work.
                budget.Charge(checked(3L * currentLine.Length + next.Length + 1));
                original = currentLine[..^1] + next.TrimStart();
            }
            budget.Charge(original.Length + 1L);
            string line = StripComment(original).Trim();
            if (line.Length == 0) continue;
            if (line[0] == '[')
            {
                // Text after the closing bracket is ignored, as SetupAPI does.
                int close = line.IndexOf(']');
                if (close < 2) throw new InvalidDataException("Invalid INF section header.");
                string name = line[1..close].Trim();
                if (name.Length >= 2 && name[0] == '"' && name[^1] == '"') name = name[1..^1];
                if (name.Length == 0 || name != name.Trim() || name.IndexOfAny(['[', ']', '"', '%', '\0']) >= 0)
                    throw new InvalidDataException("Invalid or unsupported INF section header.");
                if (!sections.TryGetValue(name, out current)) sections.Add(name, current = new());
                continue;
            }
            if (current is null) continue; // Windows ignores lines before the first section.
            int equal = FindUnquoted(line, '=');
            if (equal == 0) continue; // No key; not an entry this parser consumes.
            current.Add(equal < 0 ? (string.Empty, line, sourceLine) : (line[..equal].Trim(), line[(equal + 1)..].Trim(), sourceLine));
        }
        void RequireKeys(List<(string Key, string Value, int Line)> entries)
        {
            foreach (var line in entries)
            {
                cancellation.ThrowIfCancellationRequested();
                budget.Charge(line.Key.Length + (long)line.Value.Length + 1);
            }
        }
        long stringMapBytes = 0;
        void ChargeStringMap(long bytes)
        {
            stringMapBytes = checked(stringMapBytes + bytes);
            if (stringMapBytes > budget.MaxTemporaryStrings)
                throw new BudgetExceededException("Raw INF string map memory limit exceeded.");
        }
        Dictionary<string, string> ReadStrings(List<(string Key, string Value, int Line)> stringLines)
        {
            RequireKeys(stringLines);
            ChargeStringMap(256);
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value, _) in stringLines)
            {
                cancellation.ThrowIfCancellationRequested();
                if (key.Length == 0) continue;
                ChargeStringMap(checked(2L * (key.Length + (long)value.Length) + 128));
                result.TryAdd(Unquote(key), Unquote(value)); // The first definition of a repeated key is kept.
            }
            return result;
        }
        int language = (locale ?? CultureInfo.CurrentUICulture.LCID) & 0xffff;
        int primary = language & 0x3ff;
        string exact = $"Strings.{language:x4}", neutral = $"Strings.{primary:x4}";
        string? selectedStrings = sections.ContainsKey(exact) ? exact :
            sections.ContainsKey(neutral) ? neutral :
            sections.Keys.FirstOrDefault(name => name.StartsWith("Strings.", StringComparison.OrdinalIgnoreCase) &&
                ushort.TryParse(name.AsSpan(8), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort id) &&
                (id & 0x3ff) == primary);
        // The selected localized section wins per key; other keys fall back to [Strings] (verified against SetupAPI).
        var strings = selectedStrings is not null && sections.TryGetValue(selectedStrings, out var localized)
            ? ReadStrings(localized) : new(StringComparer.OrdinalIgnoreCase);
        if (sections.TryGetValue("Strings", out var defaults))
            foreach (var (key, value) in ReadStrings(defaults)) strings.TryAdd(key, value);
        // One left-to-right pass: %key% becomes its Strings value, %% becomes %,
        // and substituted values are not expanded again. An undefined key is
        // kept literally, so it can never equal a real device ID.
        string Expand(string input)
        {
            string value = Unquote(input);
            budget.Charge(value.Length + 1L);
            if (value.IndexOf('%') < 0) return value;
            var result = new StringBuilder(value.Length);
            for (int i = 0; i < value.Length; i++)
            {
                int end = value[i] == '%' ? value.IndexOf('%', i + 1) : -1;
                if (end < 0) { result.Append(value[i]); continue; }
                if (end == i + 1) result.Append('%');
                else if (strings.TryGetValue(value[(i + 1)..end], out string? replacement)) result.Append(replacement);
                else result.Append(value, i, end - i + 1);
                i = end;
                if (result.Length > 32768) throw new InvalidDataException("INF string expansion limit exceeded.");
            }
            budget.Charge(result.Length + 1L);
            return result.ToString();
        }
        if (!sections.TryGetValue("Version", out var mainVersion))
            throw new InvalidDataException("INF Version section is missing.");
        var signatureLines = mainVersion.Where(line => line.Key.Equals("Signature", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (signatureLines.Length != 1 || Expand(signatureLines[0].Value).ToUpperInvariant() is not ("$WINDOWS NT$" or "$CHICAGO$" or "$WINDOWS 95$"))
            throw new InvalidDataException("INF signature declaration is missing or unsupported.");
        // Extension INFs are layered on a device's function driver by Windows and
        // are never compatible-list candidates (verified against SetupAPI), so
        // they are never function-driver candidates here either. Windows ranks
        // them separately, per ExtensionId, and only callers that ask get them,
        // tagged so they cannot be mistaken for a function driver.
        string? Version(string key) => mainVersion.Where(line => line.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Select(line => Expand(line.Value).Trim()).FirstOrDefault();
        string? extensionId = null;
        if (string.Equals(Version("Class"), "Extension", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Version("ClassGuid"), "{e2f84ce7-8efa-411c-aa69-97454ca4cb57}", StringComparison.OrdinalIgnoreCase))
        {
            if (!includeExtensions) return Array.Empty<InfIndex.ModelEntry>();
            if (extensionSeen is not null) extensionSeen.Value = true;
            // Windows rejects an extension package without a GUID ExtensionId.
            // Thrown, not dropped, so the caller names it as a skipped extension.
            if (!Guid.TryParse(Version("ExtensionId"), out Guid parsedId))
                throw new InvalidDataException("Extension INF has no GUID ExtensionId.");
            extensionId = parsedId.ToString("D");
            // A broken model in a function INF blocks selection for the devices it
            // names. A broken model in an extension must not: it can only ever
            // have added settings, so it is dropped, as Windows would drop it.
            scopedErrors = new List<(string Path, string Reason, IReadOnlyList<string> Ids)>();
        }
        string target = architecture switch { Architecture.X64 => "NTamd64", Architecture.X86 => "NTx86", Architecture.Arm64 => "NTarm64", _ => throw new InvalidDataException("Unsupported processor architecture.") };
        Version os = osVersion ?? Environment.OSVersion.Version;
        if (os.Major < 0 || os.Minor < 0 || os.Build < 0) throw new InvalidDataException("Operating system version is unavailable.");
        // Without a Manufacturer section an INF has no device models (class or component INFs).
        if (!sections.TryGetValue("Manufacturer", out var manufacturers)) return Array.Empty<InfIndex.ModelEntry>();
        var output = new List<InfIndex.ModelEntry>();
        // Sorted ignoring case, names sharing a prefix are contiguous.
        string[] sortedSections = sections.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray();
        IEnumerable<string> WithPrefix(string prefix)
        {
            int i = Array.BinarySearch(sortedSections, prefix, StringComparer.OrdinalIgnoreCase);
            for (i = i < 0 ? ~i : i; i < sortedSections.Length && sortedSections[i].StartsWith(prefix, StringComparison.OrdinalIgnoreCase); i++)
                yield return sortedSections[i];
        }
        var installCache = new Dictionary<string, (string Section, byte Feature, string? DriverVer)>(StringComparer.OrdinalIgnoreCase);
        bool versionScanned = false;
        string? globalDriverVer = null;
        foreach (var (manufacturerKey, rawValue, _) in manufacturers.Where(line => line.Key.Length != 0)) // SetupAPI ignores keyless lines here.
        {
            cancellation.ThrowIfCancellationRequested();
            string[] fields = SplitFields(rawValue).Select(Expand).ToArray();
            if (fields.Length < 1 || string.IsNullOrWhiteSpace(fields[0]))
                throw new InvalidDataException("INF manufacturer models section name is missing.");
            string? selected = null;
            bool ambiguous = false;
            // Build outranks product type and suite (verified against SetupAPI).
            (int Architecture, int Major, int Minor, int Build, int Product, int Suite) best = (-1, -1, -1, -1, -1, -1);
            foreach (string decoration in fields.Skip(1).Select(field => field.Trim()).Where(field => field.Length != 0).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellation.ThrowIfCancellationRequested();
                budget.Charge(fields[0].Length + (long)decoration.Length + 1);
                string[] parts = decoration.Split('.');
                // Decorations for other architectures are never opened, so they
                // cannot affect this target and are not validated.
                bool exactArchitecture = parts[0].Equals(target, StringComparison.OrdinalIgnoreCase);
                if (!exactArchitecture && !(architecture == Architecture.X86 && parts[0].Equals("NT", StringComparison.OrdinalIgnoreCase))) continue;
                if (parts.Length > 6)
                    throw new InvalidDataException("INF manufacturer platform decorations are unsupported.");
                int major = 0, minor = 0, build = 0;
                if ((parts.Length > 1 && parts[1].Length != 0 && !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out major)) ||
                    (parts.Length > 2 && parts[2].Length != 0 && !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out minor)))
                    throw new InvalidDataException("INF manufacturer platform decorations are unsupported.");
                int? requestedProduct = null, requestedSuite = null;
                if (parts.Length > 3 && parts[3].Length != 0)
                {
                    bool hexProduct = parts[3].StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                    if (!int.TryParse(hexProduct ? parts[3][2..] : parts[3], hexProduct ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
                        CultureInfo.InvariantCulture, out int product) || product is < 1 or > 3)
                        throw new InvalidDataException("INF manufacturer platform decorations are unsupported.");
                    requestedProduct = product;
                }
                if (parts.Length > 4 && parts[4].Length != 0)
                {
                    string value = parts[4];
                    bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
                    if (!int.TryParse(hex ? value[2..] : value, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
                        CultureInfo.InvariantCulture, out int suite) || suite < 0 || suite > ushort.MaxValue)
                        throw new InvalidDataException("INF manufacturer platform decorations are unsupported.");
                    requestedSuite = suite;
                }
                if (parts.Length == 6 && (!int.TryParse(parts[5], NumberStyles.None, CultureInfo.InvariantCulture, out build) ||
                    parts[1].Length == 0 || parts[2].Length == 0 ||
                    major < 10 || (major == 10 && minor == 0 && build < 14310)))
                    throw new InvalidDataException("INF manufacturer platform decorations are unsupported.");
                if ((requestedProduct.HasValue && !productType.HasValue) || (requestedSuite.HasValue && !suiteMask.HasValue))
                    throw new InvalidDataException("Windows product or suite information is unavailable.");
                if ((requestedProduct.HasValue && requestedProduct != productType) ||
                    (requestedSuite.HasValue && (suiteMask!.Value & requestedSuite.Value) != requestedSuite.Value)) continue;
                if (major > os.Major || (major == os.Major && minor > os.Minor) ||
                    (major == os.Major && minor == os.Minor && build > os.Build)) continue;
                var candidate = (exactArchitecture ? 1 : 0, major, minor, build, requestedProduct.HasValue ? 1 : 0, requestedSuite.HasValue ? 1 : 0);
                if (candidate.CompareTo(best) > 0) { best = candidate; selected = decoration; ambiguous = false; }
                else if (candidate == best) ambiguous = true;
            }
            if (ambiguous) throw new InvalidDataException("Ambiguous INF manufacturer platform decorations.");
            if (selected is null && (architecture != Architecture.X86 || !sections.ContainsKey(fields[0]))) continue;
            string modelSection = selected is null ? fields[0] : fields[0] + "." + selected;
            if (!sections.TryGetValue(modelSection, out var modelLines)) throw new InvalidDataException("INF model section is missing.");
            RequireKeys(modelLines);
            foreach (var (modelKey, rawModel, modelLine) in modelLines)
            {
                cancellation.ThrowIfCancellationRequested();
                if (modelKey.Length == 0) continue; // Not a model entry.
                string[] model = SplitFields(rawModel).Select(field => Expand(field).Trim()).ToArray();
                // Empty optional ID fields are skipped, as Windows does.
                string hardwareId = model.Length > 1 ? model[1] : string.Empty;
                string[] compatibleIds = model.Skip(2).Where(id => id.Length != 0).ToArray();
                if (hardwareId.Length == 0 && compatibleIds.Length == 0) continue; // Can never match a device.
                try
                {
                if (model[0].Length == 0) throw new InvalidDataException("INF model install section is missing.");
                if (!installCache.TryGetValue(model[0], out var metadata))
                {
                    // DDInstall decorations are platform only (verified against SetupAPI):
                    // .NT<arch> beats .NT, which beats the undecorated section.
                    string? Stored(string name) => WithPrefix(name).FirstOrDefault(found => found.Length == name.Length);
                    budget.Charge(3L * model[0].Length + 16);
                    string install = Stored(model[0] + "." + target) ?? Stored(model[0] + ".NT") ?? Stored(model[0]) ?? model[0];
                    if (!sections.TryGetValue(install, out var installLines)) throw new InvalidDataException("INF install section is missing.");
                    RequireKeys(installLines);
                    string? feature = null, installVer = null;
                    foreach (var line in installLines)
                    {
                        cancellation.ThrowIfCancellationRequested();
                        budget.Charge(line.Key.Length + (long)line.Value.Length + 1);
                    if (feature is null && line.Key.Equals("FeatureScore", StringComparison.OrdinalIgnoreCase)) feature = line.Value;
                        if (installVer is null && line.Key.Equals("DriverVer", StringComparison.OrdinalIgnoreCase)) installVer = line.Value;
                    }
                    // Part of the driver's rank (PerDeviceDriverSelection.CandidateRank).
                    byte featureValue = 0xff;
                    if (feature is not null)
                    {
                        string hex = Expand(feature);
                        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
                        else if (hex.StartsWith('x') || hex.StartsWith('X')) hex = hex[1..];
                        if (!byte.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out featureValue)) featureValue = 0xff;
                    }
                    if (installVer is null && !versionScanned)
                    {
                        versionScanned = true;
                        if (sections.TryGetValue("Version", out var versionLines))
                        {
                            RequireKeys(versionLines);
                            foreach (var line in versionLines)
                            {
                                cancellation.ThrowIfCancellationRequested();
                                budget.Charge(line.Key.Length + (long)line.Value.Length + 1);
                                if (globalDriverVer is null && line.Key.Equals("DriverVer", StringComparison.OrdinalIgnoreCase)) globalDriverVer = line.Value;
                            }
                        }
                    }
                    metadata = (install, featureValue, installVer ?? globalDriverVer);
                    installCache.Add(model[0], metadata);
                }
                string? driverVer = metadata.DriverVer;
                DateOnly? date = null; ulong? version = null;
                if (driverVer is not null) (date, version) = ParseDriverVer(SplitFields(driverVer).Select(field => Expand(field).Trim()).ToArray());
                budget.Charge(model.Sum(x => (long)x.Length) + 1, 2L * (path.Length + modelSection.Length + metadata.Section.Length + model.Sum(x => (long)x.Length)) + 256L + 64L * model.Length);
                output.Add(new(path, fields[0], modelSection, model[0], hardwareId, compatibleIds, true, metadata.Section, metadata.Feature, new(date, version), Expand(modelKey), modelLine, extensionId));
                }
                catch (InvalidDataException error) when (scopedErrors is not null)
                {
                    string[] ids = compatibleIds.Prepend(hardwareId).Where(id => id.Length != 0).ToArray();
                    // Kept for the whole run, so it counts like any kept model;
                    // uncounted, one crafted INF could keep hundreds of MB this way.
                    budget.Charge(ids.Length + 1, 2L * ids.Sum(id => (long)id.Length) + 64L * ids.Length + 256);
                    scopedErrors.Add((path, error.Message, ids));
                }
            }
        }
        return output.AsReadOnly();
    }

    // DriverVer = mm/dd/yyyy[,w.x.y.z]. One- or two-digit month and day; the
    // version is optional and missing components are zero.
    internal static (DateOnly Date, ulong Version) ParseDriverVer(string[] fields)
    {
        if (fields.Length is < 1 or > 2 || !DateOnly.TryParseExact(fields[0], ["M/d/yyyy", "M-d-yyyy"],
            CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            throw new InvalidDataException("Unsupported INF DriverVer date.");
        ulong version = 0;
        string[] parts = fields.Length == 2 && fields[1].Length != 0 ? fields[1].Split('.') : [];
        if (parts.Length > 4) throw new InvalidDataException("Unsupported INF DriverVer version.");
        for (int i = 0; i < 4; i++)
        {
            ushort component = 0;
            if (i < parts.Length && !ushort.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out component))
                throw new InvalidDataException("Unsupported INF DriverVer version.");
            version = (version << 16) | component;
        }
        return (date, version);
    }

    private static string Decode(byte[] raw, int? ansiCodePage)
    {
        // Undecodable bytes become U+FFFD: they can only occur in text that is
        // not an ASCII device ID, so they cannot create a false ID match.
        string text;
        if (raw.Length >= 2 && raw[0] == 0xff && raw[1] == 0xfe) text = Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
        else if (raw.Length >= 2 && raw[0] == 0xfe && raw[1] == 0xff) text = Encoding.BigEndianUnicode.GetString(raw, 2, raw.Length - 2);
        else if (raw.Length >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf) text = Encoding.UTF8.GetString(raw, 3, raw.Length - 3);
        else
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            text = Encoding.GetEncoding(ansiCodePage ?? CurrentAnsiCodePage()).GetString(raw);
        }
        int eof = text.IndexOf('\u001a'); // Ctrl+Z ends legacy text files.
        if (eof >= 0) text = text[..eof];
        return text.Replace("\0", string.Empty);
    }

    // Scopes an INF that failed to parse: every field value in its text, after
    // joining continuation lines (including "\ ; comment"). A device is blocked
    // if any of its IDs is one of them. Null blocks every device: an ID could be
    // assembled from a string key (a non-numeric %key% inside a longer field;
    // a whole "%key%" is fine because its value is itself a field, and numeric
    // %13%-style directory IDs never form device IDs), or the file is too
    // large or has too many fields to scan.
    internal const int MaxScopeTokens = 65536;
    // NonBacktracking: linear time whatever the text. A backtracking engine would take
    // quadratic time on a crafted INF of 4 million `\;` with no newline -- hours,
    // before mounting, with Ctrl+C held off by the install.
    private static readonly System.Text.RegularExpressions.Regex Continuation = new(@"\\[ \t]*(;[^\r\n]*)?\r?\n[ \t]*", System.Text.RegularExpressions.RegexOptions.NonBacktracking);
    private static readonly System.Text.RegularExpressions.Regex StringKey = new(@"%([^%\r\n]+)%", System.Text.RegularExpressions.RegexOptions.NonBacktracking);
    internal static IReadOnlySet<string>? DeviceIdTokens(Stream source)
    {
        if (!source.CanSeek || source.Length > 8L * 1024 * 1024) return null;
        var raw = new byte[source.Length];
        source.ReadExactly(raw);
        string text = Continuation.Replace(Decode(raw, null), string.Empty);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string field in text.Split([',', '=', '\r', '\n', ';', '[', ']'], StringSplitOptions.RemoveEmptyEntries))
        {
            string token = field.Trim(' ', '\t', '"');
            if (token.Length == 0) continue;
            foreach (System.Text.RegularExpressions.Match key in StringKey.Matches(token))
                if (key.Length != token.Length && !key.Groups[1].Value.All(char.IsAsciiDigit)) return null;
            if (ids.Add(token) && ids.Count > MaxScopeTokens) return null;
        }
        return ids;
    }

    private static string StripComment(string value)
    {
        int at = FindUnquoted(value, ';');
        return at < 0 ? value : value[..at];
    }
    private static int FindUnquoted(string value, char needle)
    {
        bool quote = false;
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '"')
            {
                if (quote && i + 1 < value.Length && value[i + 1] == '"') { i++; continue; }
                quote = !quote;
            }
            else if (!quote && value[i] == needle) return i;
        }
        return -1; // An unclosed quote ends at the end of the line.
    }
    private static string Unquote(string value)
    {
        value = value.Trim();
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') value = value[1..^1];
        return value.Replace("\"\"", "\"");
    }
    private static string[] SplitFields(string value)
    {
        var fields = new List<string>();
        bool quote = false;
        int start = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '"')
            {
                if (quote && i + 1 < value.Length && value[i + 1] == '"') { i++; continue; }
                quote = !quote;
            }
            else if (!quote && value[i] == ',') { fields.Add(value[start..i]); start = i + 1; }
            if (fields.Count > 4096) throw new InvalidDataException("INF field limit exceeded.");
        }
        fields.Add(value[start..]);
        return fields.ToArray();
    }
}
