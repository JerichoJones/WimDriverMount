using System.Runtime.InteropServices;
using System.Text.Json;

internal static class FilteredDriverInstall
{
    private const int MaxRounds = 8;
    private const uint SettleTimeoutMs = 120000;
    [DllImport("setupapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupSetNonInteractiveMode([MarshalAs(UnmanagedType.Bool)] bool nonInteractive);
    [DllImport("setupapi.dll", EntryPoint = "CMP_WaitNoPendingInstallEvents", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint CM_WaitNoPendingInstallEvents(uint timeout);

    // The injected operations are the same ones used by the production path.
    internal sealed record Dependencies(
        Func<CancellationToken, IReadOnlyList<DriverDetection.InstalledDevice>> Capture,
        // The middle argument says whether a candidate may still be chosen: a
        // package Windows refused to stage is not offered again.
        Func<DriverDetection.InstalledDevice, Func<InfIndex.ModelEntry, bool>, CancellationToken, PerDeviceDriverSelection.Decision> Select,
        Func<string, InfIndex.ModelEntry, DriverDetection.SelectedInstallResult> Install,
        Func<uint, uint> Wait,
        Func<bool, bool> SetNonInteractive,
        // Both null means "no extensions".
        // The middle argument is the same filter as Select's.
        Func<DriverDetection.InstalledDevice, Func<InfIndex.ModelEntry, bool>, CancellationToken, IReadOnlyList<PerDeviceDriverSelection.ExtensionDecision>>? SelectExtensions = null,
        Func<InfIndex.ModelEntry, DriverDetection.ExtensionInstallResult>? InstallExtension = null);

    private static string DeviceState(DriverDetection.InstalledDevice device) => JsonSerializer.Serialize(new
    {
        Instance = device.InstanceId.ToUpperInvariant(), Hardware = device.HardwareIds.Select(x => x.ToUpperInvariant()).ToArray(),
        Compatible = device.CompatibleIds.Select(x => x.ToUpperInvariant()).ToArray(), device.Inf, device.OriginalInf,
        device.Date, device.Version, device.Section, device.Unbound, device.IdsUncertain, device.CaptureError, device.Problem
    });

    private static string CandidateState(InfIndex.ModelEntry model) => JsonSerializer.Serialize(new
    {
        model.Path, model.ManufacturerSection, model.Section, model.InstallSection, model.ActualInstallSection,
        model.HardwareId, model.CompatibleIds, model.DriverVersion
    });

    private static Func<DriverDetection.InstalledDevice, Func<InfIndex.ModelEntry, bool>, CancellationToken, PerDeviceDriverSelection.Decision> Selector(
        InfCollectedIndex index, CancellationToken cancellation)
    {
        var matcher = index.CreateMatcher(cancellation);
        return (device, allowed, token) => PerDeviceDriverSelection.Select(device,
            matcher.Find(device.HardwareIds, device.CompatibleIds, token).Where(match => allowed(match.Model)).ToList(),
            index.IsSelectionCompleteFor(device.HardwareIds, device.CompatibleIds));
    }

    private static Func<DriverDetection.InstalledDevice, Func<InfIndex.ModelEntry, bool>, CancellationToken, IReadOnlyList<PerDeviceDriverSelection.ExtensionDecision>> ExtensionSelector(
        InfCollectedIndex index, CancellationToken cancellation)
    {
        var matcher = index.CreateExtensionMatcher(cancellation);
        return (device, allowed, token) => PerDeviceDriverSelection.SelectExtensions(device,
            matcher.Find(device.HardwareIds, device.CompatibleIds, token).Where(match => allowed(match.Model)).ToList(),
            index.IsSelectionCompleteFor(device.HardwareIds, device.CompatibleIds));
    }

    // Windows' own verdict on a package: SetupAPI's errors (0xE000xxxx; a tampered
    // INF gives 0xE000024B, "INF hash not in catalog") and trust errors
    // (0x800Bxxxx). Any other code is a failure to get the package to Windows.
    internal static bool PackageVerdict(int error) =>
        ((uint)error & 0xF0000000) == 0xE0000000 || ((uint)error & 0xFFFF0000) == 0x800B0000;

    private static string Version(ulong? v) => v is ulong x ? $"{x >> 48}.{(x >> 32) & 0xffff}.{(x >> 16) & 0xffff}.{x & 0xffff}" : "?";
    private static string Driver(InfIndex.ModelEntry model) =>
        $"{SafeText.Path(Path.GetFileName(model.Path))} {Version(model.DriverVersion?.Version)}";

    // A preview mounts nothing, so a WIM path is shown from the WIM's root, not on a drive letter.
    private static string InWim(string path) =>
        path.Length > 3 && path[1] == ':' && path[2] == '\\' ? SafeText.Path(path[2..]) + " (in the WIM)" : SafeText.Path(path);

    // The same capture and selection as Run, without staging or installing.
    internal static int Preview(InfCollectedIndex index, TextWriter output, CancellationToken cancellation)
    {
        foreach (var item in index.UnresolvedFiles)
            output.WriteLine($"Unparsed INF {SafeText.Path(item.ImagePath)}: {item.Reason} It blocks {(item.Ids is null ? "every device" : $"devices with any of its {item.Ids.Count} IDs")}.");
        foreach (var item in index.ScopedUnresolved)
            output.WriteLine($"Unparsed model in {InWim(item.Path)}: {item.Reason} It blocks devices with IDs {SafeText.Path(string.Join(", ", item.Ids))}.");
        foreach (var item in index.SkippedExtensions)
            output.WriteLine($"Skipped extension INF {InWim(item.Path)}: {item.Reason} It is not applied to any device.");
        var select = Selector(index, cancellation);
        var selectExtensions = ExtensionSelector(index, cancellation);
        int devices = 0, install = 0, undecided = 0, extend = 0;
        foreach (var device in DriverDetection.CaptureInstalledDevices(cancellation))
        {
            devices++;
            // Extensions are reported on their own lines and never count as the
            // device's driver: they layer onto whatever the function driver is.
            foreach (var ext in selectExtensions(device, _ => true, cancellation))
            {
                if (ext.Candidate is { } x)
                {
                    extend++;
                    output.WriteLine($"EXTEND  {Label(device)}: {ext.Reason}\n  Extension {ext.ExtensionId}: {InWim(x.Path)} [{SafeText.Quote(x.ActualInstallSection)}] " +
                        $"{x.DriverVersion?.Date:yyyy-MM-dd} {Version(x.DriverVersion?.Version)}");
                }
                else
                {
                    undecided++;
                    output.WriteLine($"SKIP    {Label(device)}: extension {ext.ExtensionId}: {ext.Reason}");
                }
            }
            var decision = select(device, _ => true, cancellation);
            if (decision.Candidate is { } c)
            {
                install++;
                output.WriteLine($"INSTALL {Label(device)}: {decision.Reason}\n  WIM driver: {InWim(c.Path)} [{SafeText.Quote(c.ActualInstallSection)}] " +
                    $"{c.DriverVersion?.Date:yyyy-MM-dd} {Version(c.DriverVersion?.Version)}\n  Installed:  {(device.Unbound ? "none" : $"{SafeText.Path(device.Inf)} {SafeText.Path(device.Date)} {SafeText.Path(device.Version)}")}");
            }
            // Outranked is a decision to keep the installed driver, not a
            // failure to decide, so it must not count as undecided or set the
            // exit code.
            else if (decision.Reason is PerDeviceDriverSelection.NotNewer
                     or PerDeviceDriverSelection.Outranked)
                output.WriteLine($"KEEP    {Label(device)}: {decision.Reason} ({SafeText.Path(device.Inf)} {SafeText.Path(device.Date)} {SafeText.Path(device.Version)})");
            else if (decision.Reason != PerDeviceDriverSelection.NoCandidate)
            {
                undecided++;
                output.WriteLine($"SKIP    {Label(device)}: {decision.Reason}");
            }
        }
        output.WriteLine($"{devices} present devices: {install} would get a WIM driver, {extend} extension(s) Windows would apply, {undecided} decision(s) could not be made. Nothing was installed.");
        return undecided == 0 ? 0 : 1;
    }

    // Every device, before and after, and why: changed devices first, then by name.
    // Written to the log only: most devices have no driver in the WIM, and the
    // screen keeps to what happened (the driver report above).
    private static void WriteAllDevices(IReadOnlyList<DriverDetection.InstalledDevice> before, IReadOnlyList<DriverDetection.InstalledDevice>? after,
        Dictionary<string, string> names, Dictionary<string, string> reasons)
    {
        if (before.Count == 0) return;
        string all = before.Count == 1 ? "the device" : $"all {before.Count} devices";
        if (LogFile.Path is not { } log)
        {
            // A log asked for but not written (refused at the start, or stopped since) already has its warning.
            Console.WriteLine((Program.RequestedLog ?? Program.UnopenedLog) is not null
                ? $"  The log could not be written, so the before-and-after table of {all} was not kept."
                : Program.FromSettingsFile ? $@"  To keep a before-and-after table of {all}, add log = C:\Logs\wim.log (any file in a folder that exists) to the settings file's [defaults] section."
                : $@"  To keep a before-and-after table of {all}, add --log with a file in a folder that exists, such as --log C:\Logs\wim.log.");
            return;
        }
        Console.WriteLine($"  The before-and-after table of {all} is in the log: {SafeText.Path(log)}");
        static string Bound(DriverDetection.InstalledDevice? d) => d is null ? "(gone)" : d.Unbound ? "(none)" :
            $"{SafeText.Path(d.OriginalInf ?? d.Inf)} {SafeText.Path(d.Version)}";
        // ASCII "...", which every console shows; "…" can print as "." and make a cut version look real.
        static string Fit(string s, int w) => s.Length <= w ? s.PadRight(w) : s[..(w - 3)] + "...";
        // "name.inf 1.2.3.4": shorten the INF name, never the version.
        static string FitDriver(string s, int w)
        {
            int space = s.LastIndexOf(' ');
            if (s.Length <= w || space < 0 || s.Length - space + 4 > w) return Fit(s, w);
            return (s[..(w - (s.Length - space) - 3)] + "..." + s[space..]).PadRight(w);
        }
        var rows = before.Select(b =>
        {
            var a = after?.FirstOrDefault(x => string.Equals(x.InstanceId, b.InstanceId, StringComparison.OrdinalIgnoreCase));
            string was = Bound(b), now = after is null ? "(not captured)" : Bound(a);
            string why = reasons.TryGetValue(b.InstanceId, out var r) ? r : "Not evaluated.";
            return (Device: NameOf(names, b.InstanceId), Before: was,
                After: now != was ? now : why.Contains("Extension ", StringComparison.Ordinal) ? "same + extension" : "same", Why: why);
        }).OrderBy(r => r.After == "same").ThenBy(r => r.Device, StringComparer.OrdinalIgnoreCase).ToList();
        int dw = Math.Min(40, Math.Max(6, rows.Max(r => r.Device.Length)));
        int bw = Math.Min(32, Math.Max(6, rows.Max(r => r.Before.Length)));
        int aw = Math.Min(32, Math.Max(5, rows.Max(r => r.After.Length)));
        LogFile.Line($"All devices ({rows.Count})");
        LogFile.Line($"  {Fit("Device", dw)}  {Fit("Before", bw)}  {Fit("After", aw)}  Decision");
        string rule = $"  {new string('-', dw)}  {new string('-', bw)}  {new string('-', aw)}  {new string('-', 8)}";
        LogFile.Line(rule);
        foreach (var r in rows) LogFile.Line($"  {FitMiddle(r.Device, dw)}  {FitDriver(r.Before, bw)}  {FitDriver(r.After, aw)}  {r.Why}");
        LogFile.Line(rule);
        int changed = rows.Count(r => r.After != "same");
        LogFile.Line($"  {rows.Count} device{(rows.Count == 1 ? "" : "s")}: {changed} changed, {rows.Count - changed} unchanged");
    }

    internal static DirectDriverInstall.RunResult Run(string mount, CancellationToken cancellation,
        DirectDriverInstall.ICallJournal journal, Func<bool> mountAvailable, Dependencies? dependencies = null, InfCollectedIndex? collectedIndex = null)
    {
        int started = 0, returned = 0, succeeded = 0;
        bool restart = false, inFlight = false, uncertain = false, incomplete = false;
        bool modeSet = false, previous = false;
        Exception? failure = null;
        bool reported = false; // The driver report printed in full.
        var report = new List<(string Result, string Device, string Detail)>(); // What happened, device by device.
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var reasons = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // why, per device, for the full table
        IReadOnlyList<DriverDetection.InstalledDevice> before = Array.Empty<DriverDetection.InstalledDevice>();
        int failedCalls = 0;
        var kept = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var noDriver = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // The name Device Manager shows, falling back to the instance ID.
        // Rows keep instance IDs; names are looked up when the report prints, so one
        // device has one name (the final one, as in the device table), not whichever
        // name it had when its row was added.
        string Who(string instance) => instance;
        string Devices(List<string> instances) => string.Join("\n", instances);
        string Show(string ids)
        {
            string[] list = ids.Split('\n');
            string first = NameOf(names, list[0]);
            return list.Length == 1 ? first : $"{first} (+{list.Length - 1} more)";
        }
        var processed = new HashSet<string>(StringComparer.Ordinal);
        var attempted = new HashSet<string>(StringComparer.Ordinal);
        var failedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Packages Windows refused to stage; never offered again, for any device.
        // Staging (SetupCopyOEMInf) never sees the device, so a refusal is the
        // package's, whichever device or model line led to it.
        var refusedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Devices whose package Windows refused and that no later package replaced:
        // the operator asked for an install that Windows would not do, so the run fails.
        var refusedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool Allowed(InfIndex.ModelEntry model) => !refusedPackages.Contains(model.Path);
        var expected = new List<(string Instance, string? Published, InfIndex.ModelEntry Model)>();
        IReadOnlyList<DriverDetection.InstalledDevice>? after = null;
        Dependencies? api = dependencies;
        try
        {
            void Check()
            {
                cancellation.ThrowIfCancellationRequested();
                if (!mountAvailable()) throw new IOException("The mounted source is no longer available.");
            }
            Check();
            if (api is null)
            {
                var index = collectedIndex ?? throw new InvalidDataException("The pre-mount INF index is unavailable.");
                api = new(DriverDetection.CaptureInstalledDevices, Selector(index, cancellation),
                    DriverDetection.InstallSelectedDevice, CM_WaitNoPendingInstallEvents, SetupSetNonInteractiveMode,
                    ExtensionSelector(index, cancellation), DriverDetection.InstallExtension);
                foreach (var item in index.UnresolvedFiles)
                    Console.WriteLine($"Unparsed INF {SafeText.Path(item.ImagePath)}: {item.Reason} It blocks {(item.Ids is null ? "every device" : $"devices with any of its {item.Ids.Count} IDs")}.");
                foreach (var item in index.ScopedUnresolved)
                    Console.WriteLine($"Unparsed model in {SafeText.Path(item.Path)}: {item.Reason} It blocks devices with IDs {SafeText.Path(string.Join(", ", item.Ids))}.");
                foreach (var item in index.SkippedExtensions)
                    Console.WriteLine($"Skipped extension INF {SafeText.Path(item.Path)}: {item.Reason} It is not applied to any device.");
            }
            previous = api.SetNonInteractive(true);
            modeSet = true;
            IReadOnlyList<DriverDetection.InstalledDevice> Capture()
            {
                Check();
                var snapshot = api.Capture(cancellation);
                if (snapshot.GroupBy(x => x.InstanceId, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() != 1))
                    throw new InvalidDataException("The device snapshot contains duplicate instance IDs.");
                restart |= snapshot.Any(x => x.Restart);
                foreach (var d in snapshot) if (d.Name is { } name) names[d.InstanceId] = name;
                return snapshot;
            }
            before = Capture();
            after = before;
            bool finished = false;
            for (int round = 0; round < MaxRounds; round++)
            {
                Check();
                var pending = after.Where(device => !processed.Contains(DeviceState(device))).ToArray();
                if (pending.Length == 0) { finished = true; break; }
                bool called = false;
                foreach (var observed in pending)
                {
                    Check();
                    if (failedDevices.Contains(observed.InstanceId))
                    {
                        processed.Add(DeviceState(observed));
                        report.Add(("Skipped", Who(observed.InstanceId), "an earlier installation for it failed; no other driver is tried"));
                        incomplete = true;
                        continue;
                    }
                    var device = observed;
                    PerDeviceDriverSelection.Decision decision;
                    // A refused package is never offered again, so each pass back
                    // here bans one more path: bounded by the candidates.
                reselect:
                    decision = api.Select(device, Allowed, cancellation);
                    if (decision.Candidate is not null)
                    {
                        // Capture immediately before hand-off; reselect if relevant state changed.
                        var current = Capture().Where(x => string.Equals(x.InstanceId, device.InstanceId, StringComparison.OrdinalIgnoreCase)).ToArray();
                        if (current.Length != 1)
                        {
                            report.Add(("Skipped", Who(observed.InstanceId), "the device disappeared before installation"));
                            processed.Add(DeviceState(observed));
                            incomplete = true;
                            continue;
                        }
                        device = current[0];
                        decision = api.Select(device, Allowed, cancellation);
                    }
                    processed.Add(DeviceState(device));
                    // Keep the reason that led to an installation over a later "already current".
                    if (decision.Candidate is not null || !reasons.ContainsKey(device.InstanceId)) reasons[device.InstanceId] = decision.Reason;
                    // A device whose package Windows refused is neither driverless
                    // nor up to date, whatever is left to choose from.
                    bool wasRefused = refusedDevices.Contains(device.InstanceId);
                    if (wasRefused && decision.Candidate is null) reasons[device.InstanceId] = "Windows refused the selected package.";
                    if (decision.Candidate is null)
                    {
                        bool keeps = decision.Reason is PerDeviceDriverSelection.NotNewer or PerDeviceDriverSelection.Outranked;
                        if (decision.Reason == PerDeviceDriverSelection.NoCandidate && !wasRefused)
                        {
                            // Banned after Windows refused it for another device: the WIM does
                            // have a driver for this one.
                            if (refusedPackages.Count != 0 && api.Select(device, m => refusedPackages.Contains(m.Path), cancellation).Reason != PerDeviceDriverSelection.NoCandidate)
                                reasons[device.InstanceId] = "Windows refused this WIM's driver for another device, so it was not tried here.";
                            else noDriver.Add(device.InstanceId);
                        }
                        else if (keeps) { if (!wasRefused) kept.Add(device.InstanceId); }
                        // The WIM did have a driver: Windows refused it, and none is left to try.
                        else if (wasRefused && decision.Reason == PerDeviceDriverSelection.NoCandidate)
                            report.Add(("Unhandled", Who(device.InstanceId), "Windows refused this WIM's driver for it, and no other WIM driver is left to try."));
                        else report.Add(("Undecided", Who(device.InstanceId), decision.Reason));
                        // Outranked is a decision to keep the installed driver,
                        // exactly like NotNewer. Treating it as incomplete would fail a
                        // clean run wherever Windows' rank keeps a driver, for
                        // example on print queues.
                        if (decision.Reason is not (PerDeviceDriverSelection.NoCandidate or PerDeviceDriverSelection.NotNewer
                            or PerDeviceDriverSelection.Outranked)) incomplete = true;
                        continue;
                    }
                    // One hand-off per device and candidate, whatever its outcome:
                    // a returned call is never repeated because device state moved.
                    string attempt = device.InstanceId.ToUpperInvariant() + "\n" + CandidateState(decision.Candidate);
                    if (!attempted.Add(attempt))
                    {
                        report.Add(("Skipped", Who(device.InstanceId), "this driver was already handed to Windows for it; not repeated"));
                        incomplete = true;
                        continue;
                    }
                    int sequence = started + 1;
                    // No driver call has happened yet, but a failed write leaves the
                    // journal's own record uncertain, so the run reports unknown.
                    try
                    {
                    journal.WriteSelectedIntent(sequence, JsonSerializer.Serialize(new
                    {
                        device.InstanceId, InstalledInf = device.Inf, InstalledSection = device.Section, InstalledDate = device.Date,
                        InstalledVersion = device.Version, device.Unbound,
                        decision.Candidate.Path, decision.Candidate.InstallSection, decision.Candidate.ActualInstallSection,
                        decision.Candidate.HardwareId, decision.Candidate.DriverVersion
                    }));
                    }
                    catch { uncertain = true; throw; }
                    started = sequence;
                    inFlight = true;
                    after = null;
                    var outcome = api.Install(device.InstanceId, decision.Candidate);
                    inFlight = false;
                    called = true;
                    returned++;
                    // Record the outcome first: nothing below may leave a known
                    // outcome looking unknown in the journal.
                    uncertain |= outcome.StagingOutcomeUnknown || outcome.InstallationOutcomeUnknown;
                    restart |= outcome.Restart;
                    if (outcome.StagingOutcomeUnknown || outcome.InstallationOutcomeUnknown)
                        throw new IOException("The installation call did not return a known outcome; its intent remains open.");
                    try { journal.WriteSelectedCompletion(sequence, JsonSerializer.Serialize(outcome), outcome.JournalOutcome); } catch { uncertain = true; throw; }
                    // Windows refused the package before touching the device (a bad
                    // signature or catalog, typically). Windows' own installer would
                    // just use the next-ranked package, so this does too: the refused
                    // one is never offered again, and the device is selected afresh
                    // at once. If the device changed, something did happen, and no
                    // other driver is tried. Only Windows' verdict on the
                    // package counts: a read failing through the mount, or this
                    // program stopping before the call (error 0), says nothing about it.
                    bool refused = !outcome.Installed && !outcome.Staged && PackageVerdict(outcome.Error) &&
                        Capture().Where(x => string.Equals(x.InstanceId, device.InstanceId, StringComparison.OrdinalIgnoreCase))
                            .Select(DeviceState).SequenceEqual([DeviceState(device)]);
                    if (outcome.Installed) { succeeded++; refusedDevices.Remove(device.InstanceId); }
                    else if (refused) { refusedPackages.Add(decision.Candidate.Path); refusedDevices.Add(device.InstanceId); processed.Remove(DeviceState(device)); }
                    else { failedDevices.Add(device.InstanceId); incomplete = true; }
                    if (outcome.ErrorDetail is not null && !refused) incomplete = true;
                    if (outcome.Installed) expected.Add((device.InstanceId, outcome.PublishedInf, decision.Candidate));
                    if (outcome.Installed)
                        report.Add(("Installed", Who(device.InstanceId), Driver(decision.Candidate) + (outcome.Restart ? "; restart required" : "")));
                    else if (refused)
                        report.Add(("Refused", Who(device.InstanceId), $"{Driver(decision.Candidate)}: Windows refused it: {Why(outcome.ErrorDetail, outcome.Error)}; the next-ranked driver, if any, is tried"));
                    else
                    {
                        failedCalls++;
                        report.Add(("FAILED", Who(device.InstanceId), $"{Driver(decision.Candidate)}: {Why(outcome.ErrorDetail, outcome.Error)}"));
                    }
                    Check();
                    // Staging never touched the device (just checked), so choose
                    // again now: waiting a round per refusal could use up the round
                    // limit before an acceptable package is reached.
                    if (refused) goto reselect;
                }
                if (called)
                {
                    uint wait = api.Wait(SettleTimeoutMs);
                    if (wait != 0) throw new IOException($"Plug and Play did not settle (result {wait}).");
                    after = Capture();
                }
                // If there was no call, a fresh recheck may have observed a state that
                // differs from the batch snapshot. Capture again to evaluate it.
                else after = Capture();
                if (round == MaxRounds - 1 && after.Any(device => !processed.Contains(DeviceState(device))))
                    throw new IOException("The device discovery round limit was reached; results are incomplete.");
                if (after.All(device => processed.Contains(DeviceState(device)))) { finished = true; break; }
            }
            if (!finished) throw new IOException("The device discovery round limit was reached; results are incomplete.");
            if (refusedDevices.Count != 0) incomplete = true;

            // Extensions layer onto the function drivers now in place, so they go
            // last. One hand-off per distinct extension INF: Windows applies it to
            // every present device where it ranks best, so handing it over once per
            // device would only repeat the same call. Each hand-off is journaled
            // like any other driver call, in the same contiguous sequence.
            //
            // If Windows will not apply one, the next-ranked extension with the same
            // ExtensionId is handed over, as Windows' own installer would use it.
            // That is safe whatever went wrong: without a force flag Windows only
            // applies an extension where it ranks best, so it never downgrades. The
            // failure still fails the run: unlike staging a function driver,
            // nothing shows whether Windows refused the package or failed partway.
            if (api.SelectExtensions is not null && api.InstallExtension is not null)
            {
                var current = after ?? Capture();
                var handed = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // Extension INFs already given to Windows.
                bool NotHanded(InfIndex.ModelEntry model) => !handed.Contains(model.Path);
                HashSet<string>? retry = null; // Device and ExtensionId pairs to choose again; null on the first pass, which takes all.
                bool extensionCalled = false;
                for (int pass = 0; ; pass++)
                {
                    var wanted = new Dictionary<string, (InfIndex.ModelEntry Model, List<string> Devices)>(StringComparer.OrdinalIgnoreCase);
                    foreach (var device in current)
                        foreach (var choice in api.SelectExtensions(device, NotHanded, cancellation))
                        {
                            if (retry is not null && !retry.Contains(device.InstanceId.ToUpperInvariant() + "\n" + choice.ExtensionId.ToUpperInvariant())) continue;
                            if (choice.Candidate is null)
                            {
                                report.Add(("Undecided", Who(device.InstanceId), $"extension: {choice.Reason}"));
                                incomplete = true;
                                continue;
                            }
                            if (!wanted.TryGetValue(choice.Candidate.Path, out var entry))
                                wanted[choice.Candidate.Path] = entry = (choice.Candidate, new List<string>());
                            entry.Devices.Add(device.InstanceId);
                        }
                    if (wanted.Count == 0) break;
                    if (pass == MaxRounds) throw new IOException("The extension round limit was reached; results are incomplete.");
                    retry = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var pair in wanted)
                    {
                        Check();
                        var (model, devicesForExtension) = pair.Value;
                        int sequence = started + 1;
                        try
                        {
                            journal.WriteSelectedIntent(sequence, JsonSerializer.Serialize(new
                            {
                                Kind = "extension", model.Path, model.ExtensionId, model.InstallSection, model.ActualInstallSection,
                                model.DriverVersion, Devices = devicesForExtension
                            }));
                        }
                        catch { uncertain = true; throw; }
                        started = sequence;
                        inFlight = true;
                        after = null;
                        handed.Add(model.Path);
                        var outcome = api.InstallExtension(model);
                        inFlight = false;
                        extensionCalled = true;
                        returned++;
                        if (outcome.Installed) succeeded++;
                        else if (!outcome.NothingToChange) incomplete = true;
                        restart |= outcome.Restart;
                        try { journal.WriteSelectedCompletion(sequence, JsonSerializer.Serialize(outcome), outcome.JournalOutcome); } catch { uncertain = true; throw; }
                        if (outcome.Installed)
                        {
                            report.Add(("Extension", Devices(devicesForExtension), Driver(model) + " applied" + (outcome.Restart ? "; restart required" : "")));
                            // The device table must not call such a device unchanged or driverless.
                            foreach (string applied in devicesForExtension)
                            {
                                noDriver.Remove(applied);
                                reasons[applied] = reasons.TryGetValue(applied, out var was) && was != PerDeviceDriverSelection.NoCandidate
                                    ? $"{was} Extension {Driver(model)} applied." : $"Extension {Driver(model)} applied.";
                            }
                        }
                        else if (outcome.NothingToChange)
                            report.Add(("Extension", Devices(devicesForExtension), Driver(model) + ": Windows reported nothing to change"));
                        else
                        {
                            failedCalls++;
                            foreach (string device in devicesForExtension) retry.Add(device.ToUpperInvariant() + "\n" + model.ExtensionId!.ToUpperInvariant());
                            report.Add(("FAILED", Devices(devicesForExtension), $"extension {Driver(model)}: {Why(outcome.ErrorDetail, outcome.Error)}; the next-ranked extension, if any, is tried"));
                        }
                        Check();
                    }
                }
                if (extensionCalled)
                {
                    uint wait = api.Wait(SettleTimeoutMs);
                    if (wait != 0) throw new IOException($"Plug and Play did not settle after extensions (result {wait}).");
                }
                // Recapture either way, so the function-driver verification below
                // also proves the extensions left every function driver in place.
                after = Capture();
            }

            foreach (var item in expected)
            {
                var final = after?.SingleOrDefault(x => string.Equals(x.InstanceId, item.Instance, StringComparison.OrdinalIgnoreCase));
                var ver = item.Model.DriverVersion;
                bool versionKnown = PerDeviceDriverSelection.TryVersion(final?.Version, out ulong parsedVersion);
                bool verified = final is not null && final.CaptureError is null && !string.IsNullOrWhiteSpace(item.Published) &&
                    string.Equals(final.Inf, Path.GetFileName(item.Published), StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(final.Section) && !string.IsNullOrWhiteSpace(item.Model.ActualInstallSection) &&
                    string.Equals(final.Section, item.Model.ActualInstallSection, StringComparison.OrdinalIgnoreCase) &&
                    ver?.Date is not null && final.Date == ver.Date.Value.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) &&
                    versionKnown && ver.Version == parsedVersion;
                if (!verified)
                {
                    report.Add(("UNVERIFIED", Who(item.Instance), $"afterwards Windows did not report the expected driver ({SafeText.Path(Path.GetFileName(item.Published))}: its section, date and version)"));
                    incomplete = true;
                }
            }
            if (incomplete) throw new InvalidDataException("Not every device could be handled; the driver report lists each device's result.");
        }
        catch (Exception error) { failure = error; uncertain |= inFlight; }
        finally
        {
            if (modeSet)
                try { api!.SetNonInteractive(previous); }
                catch (Exception error) { failure = failure is null ? error : new AggregateException(failure, error); }
            try
            {
                Console.WriteLine();
                Console.WriteLine("Driver report");
                if (report.Count != 0)
                {
                    report = report.Select(r => (r.Result, Show(r.Device), r.Detail)).ToList();
                    int width = Math.Min(48, Math.Max("Device".Length, report.Max(r => r.Device.Length)));
                    static string Fit(string s, int w) => s.Length <= w ? s.PadRight(w) : s[..(w - 3)] + "...";
                    Console.WriteLine($"  {"Result",-11} {Fit("Device", width)}  Detail");
                    Console.WriteLine($"  {new string('-', 11)} {new string('-', width)}  {new string('-', 6)}");
                    foreach (var r in report) Console.WriteLine($"  {r.Result,-11} {FitMiddle(r.Device, width)}  {r.Detail}");
                    Console.WriteLine();
                }
                // A device installed this run is re-checked afterwards and found current; it is not "already" so.
                int upToDate = kept.Count(id => !expected.Any(e => string.Equals(e.Instance, id, StringComparison.OrdinalIgnoreCase)));
                // Calls and devices are counted separately: one device can take an extension too.
                int refusedCalls = report.Count(r => r.Result == "Refused");
                int unchanged = report.Count(r => r.Detail.EndsWith("Windows reported nothing to change", StringComparison.Ordinal));
                if (started == 0) Console.WriteLine("  Windows was not asked to install anything.");
                else Console.WriteLine($"  Windows was asked {started} time(s): {succeeded} succeeded, {failedCalls} failed, {refusedCalls} refused" +
                    $"{(unchanged > 0 ? $", {unchanged} had nothing to change" : "")}{(restart ? ".   RESTART REQUIRED" : ".")}");
                Console.WriteLine($"  Devices keeping their installed driver: {upToDate}   Devices with no driver in this WIM: {noDriver.Count}");
                if (uncertain) Console.WriteLine("  The outcome is UNKNOWN for at least one call: check Device Manager before running again.");
                if (failure is not null) Console.WriteLine($"  Problem: {SafeText.Message(failure.Message)}");
                WriteAllDevices(before, after, names, reasons);
                Console.WriteLine(); // Sets the report apart from what follows ("Unmounting...").
                reported = true;
            }
            catch (Exception error) { failure = failure is null ? error : new AggregateException(failure, error); }
        }
        return new(started, returned, succeeded, restart, uncertain, failure) { Reported = reported };
    }

    // Why Windows said no, in words for the commonest verdicts, with the code kept.
    private static string Why(string? detail, int error) => unchecked((uint)error) switch
    {
        0xE000022F => "the driver is not signed (0xE000022F)",
        0xE000024B => "its files do not match its signature (0xE000024B)",
        0x800B0109 => "it is signed by a certificate Windows does not trust (0x800B0109)",
        _ => detail is not null ? SafeText.Message(detail.TrimEnd('.')) : $"Windows error 0x{error:X8}",
    };

    // A device as a person knows it, with its ID for Device Manager or pnputil.
    private static string Label(DriverDetection.InstalledDevice device) => device.Name is { Length: > 0 } name
        ? $"{SafeText.Path(name)} ({SafeText.Path(device.InstanceId)})" : SafeText.Path(device.InstanceId);

    // A device's name, with its instance ID when another device has the same name,
    // so the one that failed can be found in Device Manager.
    private static string NameOf(IReadOnlyDictionary<string, string> names, string instance)
    {
        if (!names.TryGetValue(instance, out var name)) return SafeText.Path(instance);
        bool shared = names.Count(n => string.Equals(n.Value, name, StringComparison.OrdinalIgnoreCase)) > 1;
        return SafeText.Path(shared ? $"{name} ({instance})" : name);
    }

    // Shortened in the middle: the end of a device's instance ID is what tells
    // same-named devices apart.
    private static string FitMiddle(string s, int w)
    {
        if (s.Length <= w) return s.PadRight(w);
        int tail = w / 2 - 1;
        return s[..(w - 3 - tail)] + "..." + s[^tail..];
    }
}

