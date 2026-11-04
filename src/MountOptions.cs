using System.Runtime.InteropServices;

// Every rule about what options mean, and which of them may be combined, lives
// here and nowhere else.
//
// There are two ways into this program: the command line, and a settings file
// that is turned into a command line. If each had its own idea of the rules,
// the settings file could produce combinations the command line then refuses
// — a mount that fails only once the earlier mounts are already up. So both
// go through Parse, and the settings file is parsed for every mount before any
// worker starts.
internal sealed record MountOptions(
    string Wim, string? Letter, int Index, string? InstallerUrl, string? CertificateSha256, string? WimSha256,
    bool WhatIf, bool InstallDrivers, bool SetupLog, bool NoInstallDokan, bool KeepDokan,
    bool PreviewDrivers, bool Background, string? TestMount,
    string? RunPath, string? RunArgs, string? RunSha256,
    bool Web, Uri? WimUri, bool AllUsers = false)
{
    // notices carries the one message parsing produces. Pass TextWriter.Null to
    // check a command line without saying anything, as the settings-file
    // preflight does.
    internal static MountOptions Parse(string[] args, TextWriter notices)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(notices);
        string? path = null;
        string? letter = null;
        string? installerUrl = null; // null means the caller resolves the default.
        string? certificateSha256 = null;
        bool pinIsLoopbackTest = false;
        string? wimSha256 = null;
        int index = 1;
        bool whatIf = false;
        bool installDrivers = false;
        bool setupLog = false;
        bool noInstallDokan = false;
        bool keepDokan = true; // Removing Dokan needs a restart before the next run can reinstall it.
        bool previewDrivers = false;
        bool background = false;
        bool allUsers = false; // The drive is the mounting user's unless this says otherwise.
        string? testMount = null;
        string? runPath = null, runArgs = null, runSha256 = null;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            string key = args[i].ToLowerInvariant();
            if (key == "-whatif") key = "--whatif";
            if (!seen.Add(key))
                throw new ArgumentException($"{args[i]} is given more than once.");
            if (key == "--whatif") { whatIf = true; continue; }
            if (key == "--install-drivers") { installDrivers = true; continue; }
            if (key == "--setup-log") { setupLog = true; continue; }
            if (key == "--no-install-dokan") { noInstallDokan = true; continue; }
            if (key == "--keep-dokan") { keepDokan = true; continue; } // The default; kept for older scripts.
            if (key == "--remove-dokan")
            {
                keepDokan = false;
                notices.WriteLine("NOTE: --remove-dokan: after this run, Dokan is uninstalled if WIM Driver Mount installed it. Windows then usually needs a restart before Dokan can be installed again.");
                continue;
            }
            if (key == "--preview-drivers") { previewDrivers = true; continue; }
            if (key == "--background") { background = true; continue; }
            if (key == "--all-users") { allUsers = true; continue; }
            if (key == "--evtlog") continue; // Taken by Program; accepted here so a settings file may say evtlog = true.
            // Its value is optional: alone (or "tested", as a settings file says it) it means the
            // tested Dokan release for this PC; otherwise the file, share or HTTPS URL given.
            if (key == "--get-dokan")
            {
                string? source = i + 1 < args.Length && !args[i + 1].StartsWith('-') ? args[++i] : null;
                installerUrl = source is null || source.Equals("tested", StringComparison.OrdinalIgnoreCase)
                    ? DokanPackage.TestedUrl : DokanSource.ValidateUrl(source);
                continue;
            }
            if (key is not ("--wim" or "--index" or "--drive" or "--test-loopback-cert-sha256" or "--wim-cert-sha256" or "--wim-sha256" or "--test-mount" or "--run" or "--run-args" or "--run-sha256" or "--log"))
                throw new ArgumentException($"{args[i]} is not an option this program knows.");
            if (i + 1 >= args.Length)
                throw new ArgumentException(key switch
                {
                    "--wim" => @"--wim needs a value, such as --wim C:\Images\tools.wim.",
                    "--drive" => "--drive needs a value, such as --drive M:.",
                    "--index" => "--index needs a value, such as --index 1.",
                    "--run" => @"--run needs a value, such as --run Tools\setup.exe.",
                    _ => $"{args[i]} needs a value.",
                });
            string value = args[++i];
            switch (key)
            {
                case "--wim": path = value; break;
                case "--drive": letter = value; break;
                case "--test-loopback-cert-sha256":
                case "--wim-cert-sha256":
                    // One certificate pin. These are different keys, so the repeat
                    // check above does not catch both: the last would silently win
                    // and the loopback restriction would latch from the other, so
                    // "--wim-cert-sha256 A --test-loopback-cert-sha256 B" would pin B.
                    if (certificateSha256 is not null)
                        throw new ArgumentException("Give --wim-cert-sha256 or --test-loopback-cert-sha256, not both.");
                    certificateSha256 = value;
                    pinIsLoopbackTest = key == "--test-loopback-cert-sha256";
                    break;
                case "--wim-sha256": wimSha256 = value; break;
                case "--test-mount": testMount = value; break;
                case "--run": runPath = value; break;
                case "--run-args": runArgs = value; break;
                case "--run-sha256": runSha256 = value; break;
                case "--log":
                    // Taken by Program; checked here so a settings file's log = is a full path.
                    if (!Path.IsPathFullyQualified(value)) throw new ArgumentException(@"--log needs a full path, such as --log C:\Logs\wim.log.");
                    break;
                case "--index":
                    if (!int.TryParse(value, out index) || index < 1)
                        throw new ArgumentException("The image index must be a positive integer.");
                    break;
            }
        }

        bool web = Uri.TryCreate(path, UriKind.Absolute, out Uri? wimUri) && (wimUri.Scheme == Uri.UriSchemeHttps || wimUri.Scheme == Uri.UriSchemeHttp);
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException(@"Name the WIM to mount with --wim, such as --wim C:\Images\tools.wim.");
        if (!web && !Path.IsPathFullyQualified(path))
            throw new ArgumentException(@"Give the WIM's full path, such as C:\Images\tools.wim, or an HTTP or HTTPS URL.");
        if (web && (!string.IsNullOrEmpty(wimUri!.UserInfo) || !string.IsNullOrEmpty(wimUri.Query) || !string.IsNullOrEmpty(wimUri.Fragment)))
            throw new ArgumentException("The WIM URL must not contain credentials, a query, or a fragment.");
        if (web && string.IsNullOrWhiteSpace(wimUri!.Host))
            throw new ArgumentException("The WIM URL has no host, such as https://server/image.wim.");
        if (!web) ValidateWimPath(path);
        if (certificateSha256 is not null)
        {
            if (!web || wimUri!.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException("A certificate pin requires an HTTPS WIM URL; there is no certificate to pin otherwise.");
            if (pinIsLoopbackTest && !wimUri.IsLoopback)
                throw new ArgumentException("--test-loopback-cert-sha256 is for a loopback test only; use --wim-cert-sha256.");
            if (certificateSha256.Length != 64 || !certificateSha256.All(Uri.IsHexDigit))
                throw new ArgumentException("A certificate pin is the 64-digit SHA-256 of the server certificate.");
        }
        if (wimSha256 is not null && (wimSha256.Length != 64 || !wimSha256.All(Uri.IsHexDigit)))
            throw new ArgumentException("--wim-sha256 takes a 64-digit SHA-256 of the whole WIM.");
        // Plain HTTP authenticates neither the server nor the data, so nothing
        // establishes that these drivers are the ones the operator chose. The
        // way out is to prove the bytes instead.
        if (installDrivers && web && wimUri!.Scheme == Uri.UriSchemeHttp && wimSha256 is null)
            throw new ArgumentException("Installing drivers from a plain HTTP WIM needs --wim-sha256, or use HTTPS: " +
                "anyone in the path could otherwise choose which drivers are installed.");
        if (setupLog && !installDrivers) throw new ArgumentException("--setup-log requires --install-drivers.");
        // Under emulation Dokan would install a driver for Windows whose DLL this build cannot load.
        // Preview neither mounts nor uses Dokan, and ranks for Windows' own processor, so it may run.
        if (!previewDrivers && RuntimeInformation.ProcessArchitecture != RuntimeInformation.OSArchitecture)
            throw new InvalidOperationException("This x64 build cannot mount on an ARM64 PC; use the ARM64 build.");
        if (testMount is not null && (background || whatIf || installDrivers || previewDrivers))
            throw new ArgumentException("--test-mount cannot be combined with background, preview or driver modes.");
        if (background && (installDrivers || previewDrivers))
            throw new ArgumentException("Run driver operations separately from a background mount.");
        if (runArgs is not null && runPath is null) throw new ArgumentException("--run-args requires --run.");
        if (runSha256 is not null && runPath is null) throw new ArgumentException("--run-sha256 requires --run.");
        if (runSha256 is not null && (runSha256.Length != 64 || !runSha256.All(Uri.IsHexDigit)))
            throw new ArgumentException("--run-sha256 takes a 64-digit SHA-256 hash of the program to run.");
        if (runPath is not null && (background || whatIf || installDrivers || previewDrivers || testMount is not null))
            throw new ArgumentException("--run cannot be combined with background, preview, test or driver modes.");
        if (runPath is not null && (Path.IsPathRooted(runPath) || runPath.Contains(':')))
            throw new ArgumentException("--run takes a path relative to the WIM root, such as Tools\\setup.exe.");
        // Windows adds ".exe" to a program named without an extension (and drops a
        // trailing dot), so "Tools\setup" would start Tools\setup.exe -- not the
        // file --run-sha256 checked. Only names Windows starts as they are pass.
        if (runPath is not null && Path.GetExtension(runPath).ToLowerInvariant() is not (".exe" or ".com" or ".bat" or ".cmd"))
            throw new ArgumentException("--run must name a .exe, .com, .bat or .cmd file, such as Tools\\setup.exe.");
        // --run executes the WIM's own code with this program's administrator rights,
        // and plain HTTP neither authenticates the server nor protects the data, so
        // anyone in the path could choose what runs -- unless --wim-sha256 proves
        // every byte the mount serves.
        if (runPath is not null && web && wimUri!.Scheme == Uri.UriSchemeHttp && wimSha256 is null)
            throw new ArgumentException("--run from a plain HTTP WIM needs --wim-sha256, or use HTTPS, a network path or a local file.");
        if (previewDrivers && (installDrivers || whatIf))
            throw new ArgumentException("--preview-drivers is a preview; use it without --install-drivers or --whatif.");
        if (letter is not null) _ = ParseDriveLetter(letter);
        return new MountOptions(path, letter, index, installerUrl, certificateSha256, wimSha256, whatIf, installDrivers,
            setupLog, noInstallDokan, keepDokan, previewDrivers, background, testMount,
            runPath, runArgs, runSha256, web, wimUri, allUsers);
    }

    // A device path does not reach a file. Opening \\.\pipe\x hands an elevated
    // client connection to whoever is listening on it, which is enough for them
    // to impersonate this process, so the whole family is refused rather than
    // the program trying to work out what sits behind each one.
    private static void ValidateWimPath(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw new ArgumentException(@"--wim does not accept a device or extended path beginning \\?\ or \\.\.");
        // The pipe, IPC and reserved-device-name rules are DokanSource's, not a
        // copy of them: a copy can drift, for example by missing the superscript
        // forms of COM1 to COM3 that the Windows path parser also accepts.
        string root = Path.GetPathRoot(path) ?? throw new ArgumentException("--wim has no root.");
        DokanSource.ValidateFileComponents(path, root, "--wim");
    }

    internal static char ParseDriveLetter(string requested)
    {
        string value = requested.Trim().TrimEnd('\\');
        if (value.Length == 2 && value[1] == ':') value = value[..1];
        if (value.Length != 1 || !char.IsAsciiLetter(value[0]) || char.ToUpperInvariant(value[0]) < 'D')
            throw new ArgumentException("--drive must be a drive letter from D: to Z:, such as M:.");
        return char.ToUpperInvariant(value[0]);
    }
}
