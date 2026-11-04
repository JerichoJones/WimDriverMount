using System.Text;

// Settings live in an INI file: the format Windows deployment people already
// read and write, and the one the INF files this tool parses are written in.
//
// A key is a command-line option without its leading dashes. The file is turned
// into the same option list the command line produces, so the command line
// stays the only place that knows what an option means and the two cannot
// drift apart. [defaults] applies to every mount; a mount's own key wins.
//
//   ; drivers for the VMware fleet
//   [defaults]
//   index = 1
//
//   [mount:vmware]
//   wim = \\server\images\vmware.wim
//   drive = V
//
//   [mount:dell]
//   wim = https://images.corp.local/dell.wim
//   drive = W
//   install-drivers = true
//   background = false
//
// Everything is checked before any worker starts, so a mistake on the last
// mount cannot leave the earlier ones running. This file checks only what is
// its own business — the shape of the file, known keys, and one drive letter
// per mount. Every rule about what an option means, and which options may be
// combined, comes from MountOptions, which each mount's option list is run
// through here. So a settings file cannot produce a mount the command line
// would then refuse, and the mistake is reported against its line number.
internal static class MountConfiguration
{
    internal sealed record Entry(string Label, IReadOnlyList<string> Arguments);
    private const int MaxCharacters = 1024 * 1024;

    // Options with no value. --keep-dokan is the default and is accepted so an
    // existing file can say so out loud.
    private static readonly string[] Flags =
        ["whatif", "install-drivers", "setup-log", "no-install-dokan", "keep-dokan",
         "remove-dokan", "preview-drivers", "background", "all-users", "evtlog"];

    // Options that take a value. The test-only options are deliberately absent,
    // and so is mount-config itself: a configuration cannot start another one.
    private static readonly string[] Valued =
        ["wim", "drive", "index", "get-dokan", "run", "run-args", "run-sha256",
         "wim-cert-sha256", "wim-sha256", "log"];

    // The file says what an elevated process should do, so TrustedFile
    // establishes that only administrators can change it before a word of it is
    // believed. See TrustedFile for why that matters.
    internal static IReadOnlyList<Entry> Read(string path)
    {
        using var stream = TrustedFile.OpenInstructions(path);
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), false);
        return Parse(reader);
    }

    internal static IReadOnlyList<Entry> Parse(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var text = new StringBuilder();
        char[] buffer = new char[4096];
        int read;
        while ((read = reader.Read(buffer, 0, buffer.Length)) != 0)
        {
            if (text.Length + read > MaxCharacters) throw new InvalidDataException("Configuration exceeds 1 MiB of text.");
            text.Append(buffer, 0, read);
        }
        string content = text.ToString();
        if (content.StartsWith('\uFEFF')) content = content[1..];

        var defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sections = new List<(string Label, int Line, Dictionary<string, string> Settings)>();
        Dictionary<string, string>? current = null;
        bool inDefaults = false, defaultsSeen = false;

        string[] lines = content.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            int number = i + 1;
            string line = lines[i];
            if (line.EndsWith('\r')) line = line[..^1];
            // A tab is a control character but indenting keys under a section
            // header is ordinary INI style, so refusing it reports the wrong
            // problem entirely.
            if (line.Any(c => char.IsControl(c) && c != '\t'))
                throw Error(number, "the line contains control characters");
            line = line.Trim();
            if (line.Length == 0 || line[0] == ';' || line[0] == '#') continue;

            if (line[0] == '[')
            {
                if (line[^1] != ']') throw Error(number, "a section header must end with ]");
                string name = line[1..^1].Trim();
                if (name.Equals("defaults", StringComparison.OrdinalIgnoreCase))
                {
                    if (defaultsSeen) throw Error(number, "[defaults] appears more than once");
                    if (sections.Count != 0) throw Error(number, "[defaults] must come before the mounts");
                    defaultsSeen = true;
                    inDefaults = true;
                    current = defaults;
                    continue;
                }
                string label = MountLabel(name, number);
                inDefaults = false;
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                // An unnamed mount is named by its position. The # cannot appear
                // in a name a file may write, so the made-up name can never
                // collide with a real one and refuse a legal file.
                sections.Add((label.Length == 0 ? $"mount #{sections.Count + 1}" : label, number, current));
                continue;
            }

            if (current is null) throw Error(number, "a setting must follow a [defaults] or [mount] section");
            int split = line.IndexOf('=');
            if (split <= 0) throw Error(number, "a setting must be written as key = value");
            string key = line[..split].Trim().ToLowerInvariant();
            string value = Value(line[(split + 1)..]);
            if (!Flags.Contains(key) && !Valued.Contains(key))
                throw Error(number, $"{SafeText.Quote(key)} is not a setting. The settings are: {string.Join(", ", Valued.Concat(Flags))}");
            if (inDefaults && key is "wim" or "drive")
                throw Error(number, $"{key} belongs to a single mount and cannot be a default");
            if (!inDefaults && key is "log" or "evtlog")
                throw Error(number, $"{key} applies to the whole run, so it goes in [defaults]");
            if (!current.TryAdd(key, value)) throw Error(number, $"{key} is set twice in the same section");
            if (Flags.Contains(key)) _ = Flag(value, number, key);
            else if (value.Length == 0) throw Error(number, $"{key} has no value");
            // get-dokan's value is optional on the command line, so one that reads as an
            // option would be taken as one: get-dokan = --all-users would open the drive.
            else if (key == "get-dokan" && value.StartsWith('-'))
                throw Error(number, "get-dokan takes tested, a path to a Dokan MSI, or an HTTPS URL");
        }

        if (sections.Count == 0) throw new InvalidDataException("Configuration must contain at least one [mount] section.");

        var entries = new List<Entry>();
        var drives = new HashSet<char>();
        var labels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (label, line, settings) in sections)
        {
            if (!labels.Add(label)) throw Error(line, $"{SafeText.Quote(label)} names more than one mount");
            var effective = new Dictionary<string, string>(defaults, StringComparer.OrdinalIgnoreCase);
            foreach (var pair in settings) effective[pair.Key] = pair.Value;
            entries.Add(Build(label, line, effective, drives));
        }
        return entries.AsReadOnly();
    }

    private static Entry Build(string label, int line, Dictionary<string, string> settings, HashSet<char> drives)
    {
        if (!settings.TryGetValue("wim", out string? wim)) throw Error(line, $"mount {SafeText.Quote(label)} has no wim setting");
        bool Set(string key) => settings.TryGetValue(key, out string? raw) && Flag(raw, line, key);
        if (settings.TryGetValue("drive", out string? drive))
        {
            // Parsed here only to catch one letter serving two mounts; the rule
            // about which letters are allowed belongs to MountOptions.
            char letter;
            try { letter = MountOptions.ParseDriveLetter(drive); }
            catch (ArgumentException ex) { throw Error(line, AsSetting(ex.Message)); }
            if (!drives.Add(letter)) throw Error(line, $"drive {letter}: is used by more than one mount");
        }
        // Keeping Dokan is already the default, so keep-dokan = false reads like
        // a way to remove it and does nothing at all. Say so instead.
        if (settings.ContainsKey("keep-dokan") && !Set("keep-dokan"))
            throw Error(line, "keep-dokan = false does nothing, because Dokan is kept by default; write remove-dokan = true to uninstall it after the run");
        if (Set("keep-dokan") && Set("remove-dokan"))
            throw Error(line, "keep-dokan and remove-dokan contradict each other");

        // A configuration is usually a set of drives to leave mounted, so a
        // mount runs in the background by default. A mount that installs
        // drivers or runs a program cannot: those need the foreground, and the
        // command line refuses the combination. Default those to the foreground
        // rather than emitting something certain to be rejected. They run in
        // turn, in file order.
        // A protected settings file protects itself, not the WIM it names: whoever
        // can change that WIM would otherwise choose what runs as administrator,
        // or which driver is installed, on every --mount-config. So such a mount
        // must pin the whole WIM. run-sha256 alone is not enough: Windows loads a
        // program's DLLs from its own folder first, and those are not checked.
        string? acts = settings.ContainsKey("run") ? "runs a program" : Set("install-drivers") ? "installs drivers" : null;
        if (acts is not null && !settings.ContainsKey("wim-sha256"))
            throw Error(line, $"mount {SafeText.Quote(label)} {acts}, so it needs wim-sha256 (the whole WIM's hash): " +
                "a settings file is trusted, but the WIM it names may not be. run-sha256 does not cover the DLLs beside a program");
        bool foreground = Set("install-drivers") || Set("preview-drivers") || settings.ContainsKey("run");
        bool background = settings.TryGetValue("background", out string? chosen)
            ? Flag(chosen, line, "background")
            : !foreground;
        // A plain mount in the foreground waits for Ctrl+C, so it would hold the
        // file open and never reach the mounts after it, with nothing saying so.
        if (!background && !foreground)
            throw Error(line, "background = false needs something to do in the foreground: " +
                "install-drivers, preview-drivers or run. A mount on its own would wait for " +
                "Ctrl+C and the later mounts would never start");

        var arguments = new List<string> { "--wim", wim };
        foreach (string key in Valued)
        {
            if (key == "wim" || !settings.TryGetValue(key, out string? raw)) continue;
            arguments.Add("--" + key);
            arguments.Add(raw);
        }
        foreach (string key in Flags)
        {
            // background is decided above. keep-dokan is the default, so there
            // is nothing to pass for it.
            if (key is "background" or "keep-dokan") continue;
            if (Set(key)) arguments.Add("--" + key);
        }
        if (background) arguments.Add("--background");

        // The command line owns every rule about what an option means and which
        // options may be combined, so the settings file is put through it here.
        // That is what stops a file from producing a mount the command line
        // would refuse, and it reports the mistake against its line rather than
        // when that mount runs, with the earlier mounts already up.
        try { _ = MountOptions.Parse([.. arguments], TextWriter.Null); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw Error(line, $"mount {SafeText.Quote(label)}: {AsSetting(ex.Message)}");
        }
        return new Entry(label, arguments.AsReadOnly());
    }

    // The command line's rules, in a settings file's words: "--drive" is "drive" there.
    // Only option names lose their dashes, so a path such as tools\--quiet.cmd is shown as it is.
    // An example value reads as the setting is written: "such as log = C:\Logs\wim.log".
    internal static string AsSetting(string message) => OptionName.Replace(ExampleValue.Replace(message, "such as $1 = "), "");

    private static readonly System.Text.RegularExpressions.Regex ExampleValue = new(
        @"such as --(" + string.Join("|", Valued.OrderByDescending(k => k.Length)) + @") ",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex OptionName = new(
        @"(?<![\w\\/-])--(?=(?:" + string.Join("|", Flags.Concat(Valued).Append("test-loopback-cert-sha256").OrderByDescending(k => k.Length)) + @")(?![\w-]))",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static string MountLabel(string name, int line)
    {
        if (name.Equals("mount", StringComparison.OrdinalIgnoreCase)) return "";
        if (!name.StartsWith("mount:", StringComparison.OrdinalIgnoreCase))
            throw Error(line, $"{SafeText.Quote(name)} is not a section; use [defaults], [mount] or [mount:name]");
        string label = name["mount:".Length..].Trim();
        if (label.Length == 0) throw Error(line, "a [mount:name] section needs a name");
        if (label.Length > 64 || !label.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ' '))
            throw Error(line, "a mount name may use up to 64 letters, digits, spaces, dots, dashes or underscores");
        return label;
    }

    // Surrounding double quotes are removed so a value can keep leading or
    // trailing spaces. Nothing inside them is an escape: a backslash is a
    // backslash, which is what a Windows path needs.
    //
    // Only a value that is wholly one quoted run is unwrapped. Stripping the
    // ends of anything that merely starts and finishes with a quote turns
    // "--out" "C:\Temp" into the single nonsense argument --out" "C:\Temp.
    private static string Value(string raw)
    {
        string text = raw.Trim();
        return text.Length >= 2 && text[0] == '"' && text[^1] == '"' && !text[1..^1].Contains('"')
            ? text[1..^1]
            : text;
    }

    private static bool Flag(string value, int line, string key) => value.Trim().ToLowerInvariant() switch
    {
        "true" or "yes" or "on" or "1" => true,
        "false" or "no" or "off" or "0" => false,
        _ => throw Error(line, $"{key} must be true or false")
    };

    // detail may be a sentence borrowed from MountOptions, which ends in a
    // period of its own.
    private static InvalidDataException Error(int line, string detail) =>
        new($"Line {line}: {detail.TrimEnd('.')}.");
}
