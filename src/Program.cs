// WIM mount pattern adapted from DiscUtilsFs (MIT), copyright 2023 Olof Lagerkvist.
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using DiscUtils.MountDokan;
using DiscUtils.Wim;
using DokanNet;
using DokanNet.Logging;

internal static class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, char[] targetPath, int capacity);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetConsoleProcessList(uint[] processes, uint count);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr handle, uint mode);

    private static int Main(string[] args)
    {
        // First, so even the earliest background failure below is recorded. The
        // Windows event log is written only with --evtlog.
        bool isWorker = args.Length > 0 && args[0] == "--internal-worker";
        EventLog = Strip(ref args, "--evtlog");
        string? logPath = TakeValue(ref args, "--log");
        if (EventLog) WorkerDiagnostics.Sink = WimDriveEventLog.WriteDiagnostic;
        WorkerDiagnostics.FileSink = (stage, error) =>
        {
            LogFile.Line(stage switch
            {
                "worker" => "The background mount failed: ",
                "worker standard handles" => "The background mount could not start: ",
                "control request" => "A request to the background mount (a status check or an unmount) could not be completed. " +
                    "If it was an unmount, the drive may already be closing; run the same --unmount command again to finish or confirm it: ",
                "Dokan lifecycle" => "At the end of the mount, checking or removing Dokan failed: ",
                _ => "A step failed: ",
            } + SafeText.Message(error.Message));
            LogFile.Line("Details for support: " + WorkerDiagnostics.Describe(stage, error));
        };
        if (isWorker)
        {
            // Before the handles are dropped, so even that failure reaches the log.
            if (logPath is not null) StartLog(logPath, args);
            try { WorkerStandardHandles.DetachInherited(); }
            catch (Exception ex)
            {
                WorkerDiagnostics.Log("worker standard handles", ex);
                return 1; // No startup handshake or mount has been attempted.
            }
        }
        bool elevatedWindow = args.Length > 0 && args[0] == "--elevated-window";
        if (elevatedWindow) args = args[1..];
        // Started from a normal console: write into that console (the starter's),
        // not a second window, and do not wait for Enter.
        bool attached = false;
        if (elevatedWindow && args.Length >= 2 && args[0] == "--attach-console" && uint.TryParse(args[1], out uint caller))
        {
            args = args[2..];
            attached = sharedConsole = AttachToCaller(caller);
            headerShown = attached; // The starter already showed it, and the folder warning.
        }
        // --no-pause: close the elevated window when done, whatever the result; the
        // exit code says how it went. --from-menu (the right-click Unmount): no
        // window at all, and a message box only if something needs the user.
        noPause = Strip(ref args, "--no-pause");
        fromMenu = Strip(ref args, "--from-menu");
        StringWriter? captured = null;
        if (fromMenu)
        {
            headerShown = true;
            captured = new StringWriter();
            Console.SetOut(captured);
            Console.SetError(captured);
        }
        // The administrator copy names itself and what it runs: the starter may not have been able to log at all.
        if (!isWorker && logPath is not null) StartLog(logPath, args, elevatedWindow ? "Administrator copy: " + Started(args) : null);
        // Every line from here on also goes to the log, once one is open (a settings
        // file may open it later). Installed once: writers captured below stay valid.
        LogFile.FailureWriter = Console.Error;
        Console.SetOut(new LogFile.Tee(isWorker ? TextWriter.Null : Console.Out));
        Console.SetError(new LogFile.Tee(isWorker ? TextWriter.Null : Console.Error));
        if (elevatedWindow && (!OperatingSystem.IsWindows() || !IsAdministrator()))
        {
            Console.Error.WriteLine("WIM Driver Mount: Windows did not grant administrator rights. The operation was not started.");
            return Finish(1, captured);
        }
        if (OperatingSystem.IsWindows() && !attached && args.Length > 0 && args[0] is not ("--internal-worker" or "--help" or "-h" or "/?" or "--version") && IsAdministrator())
            TrustedFile.WarnIfProgramFolderOpen(Console.Error);
        DriverOperationRunner.State? last = null;
        int exitCode;
        try { exitCode = DriverOperationRunner.Run(state => RunMain(args, last = state), Console.Error, machineReadable: Console.IsErrorRedirected); }
        // The console is the user's: give it back with the code page it had.
        finally { if (attached && callerCodePage != 0) SetConsoleOutputCP(callerCodePage); }
        if (fromMenu) return Finish(exitCode, captured);
        if (elevatedWindow && !attached && !noPause && !Console.IsInputRedirected)
        {
            // The elevated window is separate from the caller's console; keep it
            // open so the result can be read before Windows closes it.
            Console.WriteLine(exitCode switch
            {
                0 => "\nFinished successfully.",
                3010 => "\nFinished. Restart Windows to complete it.",
                _ when last?.RunExitCode == exitCode => $"\nFinished. The program from the WIM exited with code {exitCode}.",
                _ => $"\nFinished with errors (exit code {exitCode}); see the messages above.",
            } + " Press Enter to close this window.");
            try { Console.ReadLine(); } catch (IOException) { }
        }
        return exitCode;
    }

    private static bool noPause, fromMenu, handedOff; // handedOff: the elevated copy reports, not this one.
    // Writing into the window the command was typed in, which unelevated programs share.
    private static bool sharedConsole;

    // The --log path asked for, as a full path. Passed on to the administrator copy and
    // the background mount even when this process could not open it (an admin-only folder).
    internal static string? RequestedLog;

    // A --log or log = this process could not open, for advice that names it.
    internal static string? UnopenedLog;

    // --evtlog: write the Windows Application event log (off by default).
    internal static bool EventLog;

    // Removes "--log <path>" wherever it is an option of its own; returns the path.
    private static string? TakeValue(ref string[] args, string option)
    {
        bool isValue = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (!isValue && string.Equals(args[i], option, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                string value = args[i + 1];
                args = [.. args[..i], .. args[(i + 2)..]];
                return value;
            }
            isValue = !isValue && TakesValue.Contains(args[i]);
        }
        return null;
    }

    // Opens the --log file. A relative path is taken from where the command was typed,
    // and a mapped drive becomes its share path, as --wim does (the elevated copy has
    // no mapped drives). `role` names this process in the log; null means the starter.
    private static void StartLog(string path, string[] args, string? role = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine(@"WARNING: --log needs a file path, such as --log C:\Logs\wim.log. Continuing without a log file.");
            return;
        }
        string? full = null;
        try
        {
            full = ElevationPaths.CallerPath(path);
            LogFile.Open(full);
            RequestedLog = full;
            UnopenedLog = null;
            int drive = Array.FindIndex(args, a => a == "--drive");
            LogFile.Line(role ?? (args.Length > 0 && args[0] == "--internal-worker" && drive >= 0 && drive + 1 < args.Length
                ? $"Background mount for {SafeText.Message(args[drive + 1])}: started."
                : Started(args)));
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or NotSupportedException)
        {
            // Unelevated, an administrators-only folder cannot be opened here, but the
            // administrator copy may still write it, so it is still passed on.
            bool admin = IsAdministrator();
            if (!admin && full is not null) RequestedLog = full;
            UnopenedLog = full ?? path;
            Console.Error.WriteLine($"WARNING: {SafeText.Message(ex.Message)} " + (!admin && full is not null
                ? "This program's lines are not logged; if administrator rights are requested, that copy tries the file again."
                : LogFile.Path is { } earlier ? $"The log continues in {SafeText.Path(earlier)}."
                : "Continuing without a log file."));
        }
    }

    // The settings log in the form the log is compared in, or itself if it has
    // none: StartLog then reports what is wrong with it, rather than this comparison.
    private static string ComparableLog(string path)
    {
        try { return LogFile.Normalize(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return path; }
    }

    private static string Started(string[] args) =>
        $"WIM Driver Mount {typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion} " +
        $"({RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}) started: {SafeText.Message(string.Join(' ', args))}";

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern uint GetConsoleOutputCP();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetConsoleOutputCP(uint codePage);
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    private static uint callerCodePage;
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetStdHandle(int handle, IntPtr value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    // Leaves this (hidden) console for the starter's. Nothing is read from it: an
    // unelevated program sharing that console could type into it. If attaching
    // fails, a console of our own is made, and the usual window and pause apply.
    private static bool AttachToCaller(uint processId)
    {
        FreeConsole();
        bool attached = AttachConsole(processId);
        if (attached) callerCodePage = GetConsoleOutputCP();
        else
        {
            // Started hidden, so a console of our own would be hidden too and its pause
            // would wait forever unseen: show it.
            AllocConsole();
            ShowWindow(GetConsoleWindow(), 1 /* SW_SHOWNORMAL */);
        }
        const uint ReadWrite = 0xC0000000, ShareReadWrite = 3, OpenExisting = 3;
        IntPtr output = CreateFileW("CONOUT$", ReadWrite, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        SetStdHandle(-11, output);
        SetStdHandle(-12, output);
        if (!attached) SetStdHandle(-10, CreateFileW("CONIN$", ReadWrite, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero));
        var utf8 = new System.Text.UTF8Encoding(false);
        Console.OutputEncoding = utf8;
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), utf8) { AutoFlush = true });
        Console.SetError(new StreamWriter(Console.OpenStandardError(), utf8) { AutoFlush = true });
        if (!attached) Console.SetIn(new StreamReader(Console.OpenStandardInput()));
        return attached;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb; public string? reserved, desktop, title;
        public int x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
        public short showWindow, reserved2; public IntPtr reserved3, stdInput, stdOutput, stdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr process, thread; public int processId, threadId; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, System.Text.StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(Microsoft.Win32.SafeHandles.SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(Microsoft.Win32.SafeHandles.SafeProcessHandle handle, out uint code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    // The --run program in a console of its own, made by this elevated process, so the
    // unelevated programs sharing the caller's window cannot type into it.
    // CreateProcess, not ShellExecute: that follows file associations HKCU can redirect.
    private static int RunInOwnConsole(string application, string arguments, string directory)
    {
        var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>() };
        const uint CreateNewConsole = 0x10;
        if (!CreateProcessW(application, new System.Text.StringBuilder($"\"{application}\" {arguments}"), IntPtr.Zero, IntPtr.Zero, false,
                CreateNewConsole, IntPtr.Zero, directory, ref startup, out ProcessInformation information))
        {
            int error = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(error, $"The program could not be started: {new System.ComponentModel.Win32Exception(error).Message}");
        }
        CloseHandle(information.thread);
        using var process = new Microsoft.Win32.SafeHandles.SafeProcessHandle(information.process, true);
        if (WaitForSingleObject(process, 0xFFFFFFFF) != 0 || !GetExitCodeProcess(process, out uint code))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "The program's exit code could not be read.");
        return (int)code;
    }

    // Removes a flag wherever it appears as an option of its own; true if it was there.
    // A value is left alone: "--run-args --no-pause" is the program's argument, not ours.
    private static bool Strip(ref string[] args, string flag)
    {
        var kept = new List<string>(args.Length);
        bool found = false, isValue = false;
        // --get-dokan is not in TakesValue: its value is optional, and a value it does take
        // never starts with "-", so it can never equal a flag stripped here.
        foreach (string arg in args)
        {
            if (!isValue && string.Equals(arg, flag, StringComparison.OrdinalIgnoreCase)) { found = true; continue; }
            kept.Add(arg);
            isValue = !isValue && TakesValue.Contains(arg); // The token after a value-taking option is its value.
        }
        args = [.. kept];
        return found;
    }

    private static readonly HashSet<string> TakesValue = new(StringComparer.OrdinalIgnoreCase)
    {
        "--wim", "--index", "--drive", "--test-loopback-cert-sha256", "--wim-cert-sha256",
        "--wim-sha256", "--test-mount", "--run", "--run-args", "--run-sha256", "--unmount", "--mount-config",
        "--protect-config", "--resume-worker-cleanup", "--inspect-driver-journal", "--inspect-legacy-driver-journal", "--log",
        "--capture-drivers", "--compression",
    };

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);

    // A right-click Unmount has no window: success is silent, and anything the
    // user must know (a failure, a restart) is shown in a message box.
    private static int Finish(int exitCode, StringWriter? captured)
    {
        if (captured is null || exitCode == 0 || handedOff) return exitCode;
        string[] lines = captured.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // From the last error line on, so the box starts at the start of a message.
        int start = Array.FindLastIndex(lines, l => l.StartsWith("WIM Driver Mount", StringComparison.Ordinal) && !l.Contains(" - mounts WIM images"));
        string text = string.Join(Environment.NewLine, (start >= 0 ? lines[start..] : lines).TakeLast(15));
        if (text.Length == 0) text = $"The operation did not finish (exit code {exitCode}).";
        const uint Error = 0x10, Information = 0x40, TopMost = 0x40000, Foreground = 0x10000;
        MessageBoxW(IntPtr.Zero, text, "WIM Driver Mount", (exitCode == 3010 ? Information : Error) | TopMost | Foreground);
        return exitCode;
    }

    private static int RunMain(string[] args, DriverOperationRunner.State state)
    {
        var watch = Stopwatch.StartNew();
        // A settings-file mount carries [defaults]' log = and evtlog =; --mount-config
        // applied them for the whole run already (the command line's are taken in Main).
        Strip(ref args, "--evtlog");
        TakeValue(ref args, "--log");
        // Help and version show the larger artwork: nothing else competes for the screen.
        // No arguments means help, from a prompt or a double-click.
        if (args.Length == 0 || (args.Length == 1 && (args[0] == "--help" || args[0] == "-h")))
        {
            Header(large: true);
            Usage();
            // Double-clicked: Windows made this console for us alone and closes it
            // the moment we exit, so the help would flash and vanish.
            if (args.Length == 0 && GetConsoleProcessList(new uint[2], 2) == 1 && !Console.IsInputRedirected)
            {
                Console.WriteLine("Press Enter to close this window.");
                try { Console.ReadLine(); } catch (IOException) { }
            }
            return 0;
        }
        if (args.Length == 1 && args[0] == "--version") { Header(large: true); return 0; }
        // One-step use: a WIM path alone (as when a WIM is dropped onto the program)
        // mounts it, installs the best driver for each device, and unmounts.
        if (args.Length == 1 && args[0] == "/?") { Header(large: true); Usage(); return 0; }
        if (args.Length == 1 && !args[0].StartsWith('-'))
        {
            bool url = Uri.TryCreate(args[0], UriKind.Absolute, out var oneStep) && (oneStep.Scheme == Uri.UriSchemeHttp || oneStep.Scheme == Uri.UriSchemeHttps);
            if (!url && !File.Exists(args[0]))
            {
                Console.Error.WriteLine($"WIM Driver Mount: {SafeText.Path(args[0])} was not found. Give the path of a WIM file, or an HTTP or HTTPS URL. For help, run: .\\WimDriverMount.exe --help");
                return 1;
            }
            args = ["--wim", url ? args[0] : Path.GetFullPath(args[0]), "--install-drivers"];
        }
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        {
            Console.Error.WriteLine("WIM Driver Mount requires 64-bit Windows.");
            return 1;
        }
        if (args.Length == 2 && args[0] == "--inspect-driver-journal")
            return DriverJournalInspectionCommand.Run(args[1], WorkerRecoveryStore.ReadDriverJournalOperation, Console.Out, Console.Error);
        if (args.Length == 2 && args[0] == "--inspect-legacy-driver-journal")
            return DriverJournalInspectionCommand.Run(args[1], WorkerRecoveryStore.ReadLegacyDriverJournalOperation, Console.Out, Console.Error);
        if (args.Length == 2 && args[0] == "--mount-config")
        {
            Header();
            try
            {
                string config = ElevationPaths.CallerPath(args[1]);
                // Elevate before reading. A settings file is required to be
                // writable by administrators only, and such a file usually has
                // no entry for the user at all, so a filtered token cannot even
                // open it: reading first would turn correct permissions into
                // "access denied" with no prompt ever shown.
                if (!IsAdministrator()) return RequestElevation(new[] { "--mount-config", config });
                // Read puts every mount through the real option rules, so by
                // here the whole file is known good and nothing has started.
                var entries = MountConfiguration.Read(config);
                fromSettingsFile = true;
                // log = and evtlog = may only be in [defaults], so every mount has the
                // same ones: apply them once, for the whole run.
                string[] first = [.. entries[0].Arguments];
                if (Strip(ref first, "--evtlog") && !EventLog) { EventLog = true; WorkerDiagnostics.Sink = WimDriveEventLog.WriteDiagnostic; }
                if (TakeValue(ref first, "--log") is { } settingsLog && ComparableLog(settingsLog) is var settingsFull &&
                    !string.Equals(settingsFull, RequestedLog is null ? null : LogFile.Normalize(RequestedLog), StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(settingsFull, LogFile.Path, StringComparison.OrdinalIgnoreCase))
                    StartLog(settingsLog, ["--mount-config", config], "Settings file run started: " + SafeText.Path(config));
                state.EventOperation = "configuration";
                // Each entry goes through the runner, as a single mount does, so
                // a driver install there gets its journal terminal, result and event.
                int? programExit = null; // The last row's --run program exit code, when that was its result.
                bool dokanRemoved = false; // Dokan was removed and Windows must restart before the next mount.
                return MountConfigurationCommand.Run(entries, entry => DriverOperationRunner.Run(row =>
                {
                    try { return RunMain(entry.Arguments.ToArray(), row); }
                    finally
                    {
                        state.SetupRestart |= row.SetupRestart;
                        programExit = row.RunExitCode;
                        dokanRemoved |= row.EventClosure?.Dokan == WorkerCompletionReceipt.DokanStatus.RestartRequired;
                    }
                }, Console.Error, machineReadable: Console.IsErrorRedirected), Console.Out, Console.Error, () =>
                    dokanRemoved ? "Dokan was removed (remove-dokan), and Windows must restart before it can be installed again. Restart Windows. " +
                        "To mount the rest, set remove-dokan only on the last mount in the settings file, then run the same --mount-config command again."
                    : DokanLifecycle.OwnershipUnconfirmed ? "An earlier mount in this run installed Dokan but could not confirm it. Run the same --mount-config command again."
                    : state.SetupRestart == DokanSetupRestart.None ? null
                    : "Dokan's installer says Windows must restart first. Restart Windows, then run the same --mount-config command again.",
                    () => programExit);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Mount configuration failed: " + SafeText.Message(ex.Message));
                if (ex is AdviceException advice) foreach (string line in advice.Lines) Console.Error.WriteLine(line);
                return 1;
            }
        }
        if (WorkerArguments.TryParse(args) is { } worker)
        {
            if (!IsAdministrator())
            {
                Console.Error.WriteLine("WIM Driver Mount: internal worker requires administrator rights.");
                return 1;
            }
            state.EventOperation = "worker";
            try
            {
                WorkerChild.RunAsync(worker.PipeName, worker.Wim, worker.Index, worker.Drive,
                    worker.ParentPid, worker.ParentCreated, worker.CertificateSha256, worker.SourceIdentity,
                    closure => state.EventClosure = closure, worker.WimSha256, worker.AllUsers, worker.SignedIn).GetAwaiter().GetResult();
                return state.EventClosure?.Dokan is WorkerCompletionReceipt.DokanStatus.Deferred or WorkerCompletionReceipt.DokanStatus.Failed or WorkerCompletionReceipt.DokanStatus.FailedRestart or WorkerCompletionReceipt.DokanStatus.FailedRestartInitiated ? 1 :
                    state.EventClosure?.Dokan == WorkerCompletionReceipt.DokanStatus.RestartRequired ? 3010 : 0;
            }
            catch (Exception ex)
            {
                WorkerDiagnostics.Log("worker", ex);
                return 1;
            }
        }
        if (args.Length == 2 && args[0] == "--unmount")
        {
            Header();
            string unmountLetter = args[1].TrimEnd(':', '\\').ToUpperInvariant();
            if (unmountLetter.Length != 1 || unmountLetter[0] is < 'D' or > 'Z')
            {
                Console.Error.WriteLine("WIM Driver Mount: specify a drive letter from D to Z.");
                return 1;
            }
            if (!IsAdministrator())
            {
                return RequestElevation(args);
            }
            state.EventOperation = "unmount";
            try { return WorkerUnmount.RunAsync(args[1], closure => state.EventClosure = closure).GetAwaiter().GetResult(); }
            catch (Exception ex) { Console.Error.WriteLine($"The unmount could not be confirmed: {SafeText.Message(ex.Message)}"); return 1; }
        }
        if (args.Length == 2 && args[0] == "--protect-config")
        {
            Header();
            // Resolved here, in the caller's own folder and drive mappings: the
            // elevated window starts in System32 and usually has neither.
            string target = ElevationPaths.CallerPath(args[1]);
            if (!IsAdministrator()) return RequestElevation(new[] { "--protect-config", target });
            try
            {
                TrustedFile.Protect(target, Console.Out);
                return 0;
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException
                or System.Security.AccessControl.PrivilegeNotHeldException)
            {
                Console.Error.WriteLine($"Could not protect the settings file: {SafeText.Message(ex.Message)}");
                return 1;
            }
        }
        if (args.Length == 2 && args[0] == "--resume-worker-cleanup")
        {
            Header();
            char drive;
            try { drive = MountOptions.ParseDriveLetter(args[1]); }
            catch (ArgumentException ex) { Console.Error.WriteLine(SafeText.Message(ex.Message)); return 1; }
            if (!IsAdministrator()) return RequestElevation(args);
            state.EventOperation = "unmount";
            return WorkerCleanupCommand.Run(drive, WorkerRecoveryStore.ResumeJournalCleanup, Console.Out, Console.Error, closure => state.EventClosure = closure);
        }
        if (args.Length >= 1 && args[0] is "--install" or "--uninstall")
        {
            Header();
            bool install = args[0] == "--install";
            bool force = install && Strip(ref args, "--force");
            if (args.Length > 2 || (args.Length == 2 && args[1].StartsWith('-')))
            {
                Console.Error.WriteLine($"WIM Driver Mount: use {args[0]}{(install ? " [<folder>] [--force]" : " [<folder>]")}. For help, run: .\\WimDriverMount.exe --help");
                return 1;
            }
            // Only the published single file is the whole program: any other build
            // would leave its DLLs behind, and under the dotnet host ProcessPath is dotnet.exe.
            // An assembly inside a single-file bundle has no location of its own.
#pragma warning disable IL3000
            if (install && (typeof(Program).Assembly.Location.Length != 0 ||
                !string.Equals(Path.GetFileName(Environment.ProcessPath), ProgramInstall.ProgramName, StringComparison.OrdinalIgnoreCase)))
#pragma warning restore IL3000
            {
                Console.Error.WriteLine($"WIM Driver Mount: only the published {ProgramInstall.ProgramName} (one file, as build.ps1 makes it) can install itself.");
                return 1;
            }
            string target = ElevationPaths.CallerPath(args.Length == 2 ? args[1] : ProgramInstall.DefaultFolder);
            string installed = Path.Combine(target, ProgramInstall.ProgramName);
            // The menu is machine-wide and every change to it is the elevated copy's:
            // installing is an administrator act for the whole computer. --uninstall
            // removes it after its checks and before any file: once the running program
            // is renamed, this process can no longer load the code that removes it.
            // An earlier version's per-user entry wins over the machine one where both exist, and
            // only that account can clear its own: the elevated copy may be another account.
            void RemoveUserEntry()
            {
                try { if (ExplorerMenu.RemoveUserEntry(installed) > 0) Console.WriteLine("Removed an earlier version's per-user File Explorer menu entry from this account."); }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    Console.Error.WriteLine($"WIM Driver Mount: an earlier version's per-user File Explorer menu entry could not be removed: {SafeText.Message(ex.Message)}");
                }
            }
            if (!IsAdministrator())
            {
                // Before an uninstall only while the machine entry is there, so a declined prompt leaves a menu.
                if (!install && ExplorerMenu.Registered(installed)) RemoveUserEntry();
                int elevated = RequestElevation(force ? [args[0], target, "--force"] : [args[0], target]);
                // After an uninstall too, unless this is the installed copy, renamed by now and
                // unable to load new code; its entry was cleared above while the machine one stood.
                if (elevated == 0 && (install || !string.Equals(Environment.ProcessPath, installed, StringComparison.OrdinalIgnoreCase))) RemoveUserEntry();
                return elevated;
            }
            int menuRemoved = -1;
            void RemoveMenu()
            {
                try { menuRemoved = ExplorerMenu.Unregister(installed); }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    menuRemoved = 1; // Part of it may be gone: put it back.
                    throw new IOException($"the File Explorer menu could not be removed ({SafeText.Message(ex.Message)}); no files were removed.");
                }
            }
            void RestoreMenu()
            {
                if (menuRemoved <= 0) return;
                if (File.Exists(installed))
                    try { ExplorerMenu.Register(installed); Console.Error.WriteLine("The File Explorer menu entry was put back."); return; }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }
                Console.Error.WriteLine("The File Explorer menu entry was removed. To bring it back, run --install from the copy you installed from.");
            }
            int result;
            try { result = install ? ProgramInstall.Install(target, force, Console.Out) : ProgramInstall.Uninstall(target, Console.Out, () => { RemoveMenu(); RemoveUserEntry(); DriveIcon.RemoveAllStale(); }); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or ArgumentException or NotSupportedException)
            {
                Console.Error.WriteLine($"WIM Driver Mount: {(install ? "install" : "uninstall")} failed: {SafeText.Message(ex.Message)}");
                RestoreMenu();
                return 1;
            }
            if (!install)
            {
                if (result != 0) RestoreMenu();
                else Console.WriteLine(menuRemoved > 0 ? "Removed \"Mount with WIM Driver Mount\" from the File Explorer menu."
                    : "The File Explorer menu had no Mount entry for this folder.");
                return result;
            }
            if (result != 0) return result;
            try
            {
                ExplorerMenu.Register(installed);
                Console.WriteLine("Right-clicking a .wim, .swm or .esd file in File Explorer now offers \"Mount with WIM Driver Mount\" to every account on this computer (Windows 11: Show more options).");
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                Console.Error.WriteLine($"WIM Driver Mount: the File Explorer menu could not be added: {SafeText.Message(ex.Message)}");
                return 1;
            }
            RemoveUserEntry();
            return 0;
        }
        if (args.Length >= 1 && args[0] == "--capture-drivers")
        {
            Header();
            string target;
            var compression = DriverCapture.Compression.Maximum;
            bool whatIf = false;
            try
            {
                if (args.Length < 2 || args[1].StartsWith('-'))
                    throw new ArgumentException(@"--capture-drivers needs the new WIM's path, such as --capture-drivers C:\Drivers\this-pc.wim.");
                // Resolved here, in the caller's folder and drive mappings, as --install does.
                target = ElevationPaths.CallerPath(args[1]);
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 2; i < args.Length; i++)
                {
                    string key = args[i].ToLowerInvariant() is "-whatif" ? "--whatif" : args[i].ToLowerInvariant();
                    if (!seen.Add(key)) throw new ArgumentException($"{args[i]} is given more than once.");
                    if (key == "--whatif") whatIf = true;
                    else if (key == "--compression" && i + 1 < args.Length) compression = DriverCapture.ParseCompression(args[++i]);
                    else throw new ArgumentException(key == "--compression" ? "--compression needs a value: none, fast or maximum."
                        : $"{args[i]} is not an option --capture-drivers takes. For help, run: .\\WimDriverMount.exe --help");
                }
                DriverCapture.ValidateTarget(target);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                Console.Error.WriteLine("WIM Driver Mount: " + SafeText.Message(ex.Message));
                return 1;
            }
            // The preview only reads, as --preview-drivers does; writing needs administrator rights.
            if (!whatIf && !IsAdministrator())
                return RequestElevation(["--capture-drivers", target, "--compression", compression.ToString().ToLowerInvariant()]);
            return DriverCapture.Run(target, compression, whatIf, Console.Out, Console.Error);
        }
        if (args.Length == 2 && args[0] == ExplorerMenu.MountFlag) return MountFromMenu(args[1], state);
        if ((args.Length == 1 || (args.Length == 3 && args[1] == "--get-dokan")) && args[0] == "--internal-dokan-setup")
        {
            try
            {
                if (!OperatingSystem.IsWindows() || !IsAdministrator())
                    throw new InvalidOperationException("Dokan setup requires administrator rights.");
                return DokanInstaller.InstallElevated(args.Length == 3 ? args[2] : DokanInstaller.DefaultInstallerSource);
            }
            catch (Exception ex) { Console.Error.WriteLine($"Dokan setup error: {SafeText.Message(ex.Message)}"); return 1; }
        }
        try
        {
            Header();
            if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
                throw new InvalidOperationException("WIM Driver Mount needs 64-bit Windows.");

            // Every option rule lives in MountOptions, so a settings file and a
            // command line cannot disagree about what is allowed.
            var notices = new StringWriter();
            var parsed = MountOptions.Parse(args, notices);
            Console.Write(AsTyped(notices.ToString()));
            string path = parsed.Wim;
            string? letter = parsed.Letter;
            string installerUrl = parsed.InstallerUrl ?? DokanInstaller.DefaultInstallerSource;
            string? testCertSha256 = parsed.CertificateSha256;
            string? wimSha256 = parsed.WimSha256;
            int index = parsed.Index;
            bool whatIf = parsed.WhatIf;
            bool installDrivers = parsed.InstallDrivers;
            bool setupLog = parsed.SetupLog;
            bool noInstallDokan = parsed.NoInstallDokan;
            bool keepDokan = parsed.KeepDokan;
            bool previewDrivers = parsed.PreviewDrivers;
            bool background = parsed.Background;
            string? testMount = parsed.TestMount;
            string? runPath = parsed.RunPath, runArgs = parsed.RunArgs, runSha256 = parsed.RunSha256;
            bool web = parsed.Web;
            Uri? wimUri = parsed.WimUri;
            if (!web)
            {
                // The elevated process usually lacks the caller's mapped drive letters: use the UNC path.
                string resolved = DokanInstaller.ResolveMappedSource(Path.GetFullPath(path));
                if (!string.Equals(resolved, path, StringComparison.Ordinal))
                {
                    args = (string[])args.Clone();
                    args[Array.FindIndex(args, a => a.Equals("--wim", StringComparison.OrdinalIgnoreCase)) + 1] = resolved;
                    path = resolved;
                }
            }
            // A Dokan installer on a mapped drive: the elevated window would not see
            // the drive. (A relative one is resolved beside this program, as documented.)
            int dokanAt = Array.FindIndex(args, a => a.Equals("--get-dokan", StringComparison.OrdinalIgnoreCase));
            if (dokanAt >= 0 && dokanAt + 1 < args.Length && Path.IsPathFullyQualified(args[dokanAt + 1]) &&
                DokanInstaller.ResolveMappedSource(args[dokanAt + 1]) is var dokanResolved && !string.Equals(dokanResolved, args[dokanAt + 1], StringComparison.Ordinal))
            {
                args = (string[])args.Clone();
                args[dokanAt + 1] = dokanResolved;
                installerUrl = dokanResolved;
            }
            // The preview reads the WIM and device inventory only; it needs no elevation or mount.
            if (!previewDrivers && !IsAdministrator()) return RequestElevation(args);
            if (!whatIf && !previewDrivers) state.EventOperation = installDrivers ? "driver" : background ? "background-start" : "mount";
            path = web ? wimUri!.AbsoluteUri : Path.GetFullPath(path);
            if (whatIf)
            {
                Console.WriteLine("WHATIF: Current process has administrator rights.");
            }
            char drive = SelectDrive(letter);
            string mount = $"{drive}:\\";
            Console.WriteLine($"WIM: {SafeText.Path(path)}\nImage index: {index}" + (previewDrivers ? "" : $"\nDrive: {mount}"));
            // The drive belongs to the account this elevated process runs as, which is
            // not the signed-in user when someone else's administrator password was typed.
            // A right-click Mount also lets in the account signed in here, the one that clicked.
            if (!previewDrivers)
                using (var mounter = System.Security.Principal.WindowsIdentity.GetCurrent())
                    Console.WriteLine(parsed.AllUsers
                        ? AsTyped("Access: every account on this computer (--all-users), with the WIM's own permissions.")
                        : $"Access: {SafeText.Path(mounter.Name)}{(fromMenu ? SignedInAlso(mounter) : "")}, SYSTEM and elevated administrators only. " +
                            (fromSettingsFile ? "Set all-users = true to let every account open it." : "Use --all-users to let every account open it."));
            if (web && wimUri!.Scheme == Uri.UriSchemeHttp) Console.Error.WriteLine("WARNING: HTTP does not protect or authenticate WIM data in transit.");
            if (web && background && !whatIf)
            {
                using var previewLifetime = new CancellationTokenSource();
                using var previewStream = new HttpsRangeStream(wimUri!, previewLifetime.Token, () => previewLifetime.Cancel(), testCertSha256);
                // Every part is checked here, so a missing or mismatched part is
                // reported before Dokan setup; the worker opens its own.
                var previewParts = SplitWim.OpenParts(previewStream, path, wimSha256 is not null, name =>
                    new HttpsRangeStream(new Uri(name), previewLifetime.Token, () => previewLifetime.Cancel(), testCertSha256));
                using var previewPartsLifetime = new SplitWim.Lease(previewParts);
                var previewWim = new WimFile(previewParts);
                if (index > previewWim.ImageCount) throw new ArgumentException(NoSuchImage(previewWim.ImageCount, index));
                using var previewImage = previewWim.GetImage(index - 1);
                _ = WorkerStartup.EncodeSourceIdentity(previewStream.Identity);
                using var lifecycle = DokanLifecycle.Acquire();
                DokanLifecycle.Prepare(keepDokan, () => DokanInstaller.EnsureInstalled(false, noInstallDokan, installerUrl,
                    result => state.SetupRestart |= result));
                using var remoteResult = WorkerStartup.StartAsync(path, index, drive, CancellationToken.None, testCertSha256, previewStream.Identity, wimSha256, parsed.AllUsers, fromMenu).GetAwaiter().GetResult();
                Console.WriteLine(remoteResult.Detail);
                if (remoteResult.Ready) Console.WriteLine($"READY {mount}");
                return remoteResult.Ready ? 0 : 1;
            }
            Console.WriteLine(whatIf ? $"WHATIF: Checking WIM access by opening read-only: {SafeText.Path(path)}" : "Opening WIM read-only...");

            // Do not allow a writer to change the backing archive while the mount is alive.
            using var sourceLifetime = new CancellationTokenSource();
            using Stream stream = web
                ? new HttpsRangeStream(wimUri!, sourceLifetime.Token, () => sourceLifetime.Cancel(), testCertSha256)
                : new ResilientFileSource(path, sourceLifetime.Token);
            // A split WIM's other parts are opened beside the first, in place.
            var parts = SplitWim.OpenParts(stream, path, wimSha256 is not null, name => web
                ? new HttpsRangeStream(new Uri(name), sourceLifetime.Token, () => sourceLifetime.Cancel(), testCertSha256)
                : new ResilientFileSource(name, sourceLifetime.Token));
            using var partsLifetime = new SplitWim.Lease(parts);
            // A background worker verifies its own stream before it mounts
            // (WorkerHost); checking here as well would read the whole WIM twice.
            var verified = wimSha256 is not null && !(background && !whatIf) ? WimSourceVerification.Require(stream, wimSha256, path, Console.Out, sourceLifetime.Cancel) : null;
            if (whatIf) Console.WriteLine("WHATIF: WIM access check passed; the file was opened read-only.");
            var wim = verified is not null ? new WimFile(verified) : new WimFile(parts);
            if (index > wim.ImageCount)
                throw new ArgumentException(NoSuchImage(wim.ImageCount, index));
            using var fs = wim.GetImage(index - 1);
            if (whatIf) Console.WriteLine($"WHATIF: WIM opened read-only; image {index} of {wim.ImageCount} metadata was read. Individual driver files have not been verified.");
            if (previewDrivers)
                return FilteredDriverInstall.Preview(InfCollectedIndex.Build(fs, mount, sourceLifetime.Token), Console.Out, sourceLifetime.Token);

            if (runPath is not null && runSha256 is not null)
            {
                // Windows reads the program again through the drive to start it, and
                // a web server or share could serve different bytes then. So it is read
                // and pinned before the drive exists -- and before Dokan setup or the
                // lifecycle lock, so a wrong hash changes nothing on this computer.
                string program = Path.GetFullPath(runPath, mount);
                if (!program.StartsWith(mount, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("--run must name a file inside the WIM.");
                byte[] pinned = fs.ReadAndPin("\\" + program[mount.Length..], 256 * 1024 * 1024);
                string actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pinned));
                if (!string.Equals(actual, runSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"The program does not match --run-sha256; nothing was installed, mounted or started. Found {actual}.");
                Console.WriteLine(AsTyped($"Program file matches --run-sha256 ({actual}). Files beside it are not checked."));
            }

            InfCollectedIndex? collectedIndex = null;
            if (installDrivers && !whatIf)
            {
                ConsoleCancelEventHandler collectHandler = (_, e) => { e.Cancel = true; sourceLifetime.Cancel(); };
                Console.CancelKeyPress += collectHandler;
                try { collectedIndex = InfCollectedIndex.Build(fs, mount, sourceLifetime.Token); }
                finally { Console.CancelKeyPress -= collectHandler; }
            }
            using var lifecycleLease = whatIf ? null : DokanLifecycle.Acquire();
            DokanInstaller.CheckResult dokanCheck = whatIf
                ? DokanInstaller.EnsureInstalled(true, noInstallDokan, installerUrl)
                : DokanLifecycle.Prepare(keepDokan, () => DokanInstaller.EnsureInstalled(false, noInstallDokan, installerUrl,
                    result => state.SetupRestart |= result));
            if (whatIf)
            {
                Console.WriteLine($"WHATIF: Would mount image {index} from {SafeText.Path(path)} read-only at {mount}.");
                if (installDrivers) Console.WriteLine("WHATIF: Would read the WIM's INFs once, choose the driver Windows would rank best for each present device, and ask Windows to install it only when it beats the installed driver. No drivers were installed.");
                if (setupLog) Console.WriteLine("WHATIF: SetupAPI log markers would be attempted during installation; no log was written.");
                Console.WriteLine($"Preview complete ({watch.Elapsed.TotalSeconds:0.0} s). Nothing was installed or mounted.");
                return dokanCheck.Ready ? 0 : 1;
            }
            if (background)
            {
                // The worker re-opens the path itself, so the hash has to travel
                // with it: verifying in this process proves nothing about what
                // the worker goes on to read, and a file on a share can change
                // between the two reads. The web branch above already passes it.
                using var result = WorkerStartup.StartAsync(path, index, drive, CancellationToken.None, wimSha256: wimSha256, allUsers: parsed.AllUsers, signedIn: fromMenu).GetAwaiter().GetResult();
                Console.WriteLine(result.Detail);
                if (result.Ready) Console.WriteLine($"READY {mount}");
                return result.Ready ? 0 : 1;
            }
            int mountResult = RunForegroundMount(fs, mount, drive, installDrivers, setupLog, testMount, runPath, runArgs, watch, sourceLifetime, state, lifecycleLease!, collectedIndex, parsed.AllUsers, !web && OnShare(path), out bool mountClosed);
            if (mountClosed)
            {
                var dokanStatus = DokanLifecycle.Finish();
                state.EventClosure = new(SplitWim.AnyWebPartFailed(parts) || verified?.Failed == true, dokanStatus);
                if (WorkerUnmount.DokanSentence(dokanStatus) is { } sentence) Console.WriteLine(sentence);
                else if (!keepDokan) Console.WriteLine(AsTyped("Dokan was not installed by WIM Driver Mount, so --remove-dokan left it in place."));
                if (WorkerUnmount.IsDokanFailure(dokanStatus)) { state.RunExitCode = null; return 1; }
                if (dokanStatus == WorkerCompletionReceipt.DokanStatus.RestartRequired && mountResult == 0) mountResult = 3010;
            }
            if (SplitWim.AnyWebPartFailed(parts))
                throw new IOException("The WIM source failed; the mount was stopped.");
            if (verified?.Failed == true) throw new IOException("The WIM changed after it was verified; the mount was stopped.");
            return mountResult;
        }
        catch (Exception ex)
        {
            state.RunExitCode = null; // A failure after the program ran is this run's result, not the program's code.
            // In a settings-file run, options are settings: "index", not "--index".
            string message = SafeText.Message(ex.Message);
            Console.Error.WriteLine($"WIM Driver Mount ERROR: {AsTyped(message)}");
            if (ex is ArgumentException && !fromSettingsFile) Console.Error.WriteLine(@"For help, run: .\WimDriverMount.exe --help");
            else Console.Error.WriteLine($"Stopped after {watch.Elapsed.TotalSeconds:0.0} s.");
            if (ex.InnerException is not null)
                Console.Error.WriteLine($"Cause: {SafeText.Message(ex.InnerException.Message)}");
            if (ex is DokanException dokanError)
            {
                Console.Error.WriteLine(dokanError.ErrorStatus is DokanStatus.MountPointError or DokanStatus.DriveLetterError
                    ? AsTyped("Dokan could not use that drive letter. Choose another letter, or leave --drive out to use the highest free one.")
                    : $"Dokan could not mount the drive (Dokan status {dokanError.ErrorStatus}, code 0x{dokanError.HResult:X8}).");
                if (dokanError.ErrorStatus == DokanStatus.VersionError)
                    Console.Error.WriteLine("The installed Dokan runtime or driver is incompatible with this mount.");
            }
            if (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
                Console.Error.WriteLine("Check that a compatible Dokan 2.x runtime and signed driver are installed.");
            return 1;
        }
    }


    // The right-click Mount: like Windows' Mount on an ISO, a background mount at
    // the highest free letter, then File Explorer on it. The image is chosen here,
    // unelevated, so the administrator prompt comes only once the user has
    // picked one; the elevated copy does the same --background mount a console would.
    // The letter is chosen here too, so the drive Explorer is opened on is the
    // one the elevated copy was told to use.
    private static int MountFromMenu(string wim, DriverOperationRunner.State state)
    {
        try
        {
            wim = ElevationPaths.CallerPath(wim);
            int index = 1;
            using (var first = new ResilientFileSource(wim, CancellationToken.None))
            {
                var parts = SplitWim.OpenParts(first, wim, false, name => new ResilientFileSource(name, CancellationToken.None));
                using var lease = new SplitWim.Lease(parts);
                var file = new WimFile(parts);
                if (file.ImageCount < 1) throw new InvalidDataException(NoSuchImage(file.ImageCount, 1));
                // A task dialog cannot scroll; past this many buttons it outgrows a screen.
                if (file.ImageCount > 16)
                    throw new NotSupportedException($"This WIM has {file.ImageCount} images, too many to list here. Mount it from a console with --wim and --index.");
                if (file.ImageCount > 1)
                {
                    if (ImageChoice.Ask(wim, file.ImageNames()) is not int chosen) { handedOff = true; return 0; }
                    index = chosen;
                }
            }
            char drive = SelectDrive(null);
            string[] mount = ["--wim", wim, "--index", index.ToString(System.Globalization.CultureInfo.InvariantCulture), "--drive", $"{drive}:", "--background"];
            int result = IsAdministrator() ? RunMain(mount, state) : RequestElevation(mount);
            if (result == 0)
            {
                // Explorer by its full path, from this process: the elevated copy
                // would hand it the administrator's rights.
                // The drive is mounted either way, so a failure here is reported, not returned.
                try
                {
                    using var explorer = Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
                        { UseShellExecute = false, ArgumentList = { $"{drive}:\\" } });
                }
                catch (System.ComponentModel.Win32Exception ex)
                {
                    MessageBoxW(IntPtr.Zero, $"Mounted at {drive}:, but File Explorer could not be opened on it: {SafeText.Message(ex.Message)}", "WIM Driver Mount", 0x40 | 0x40000);
                }
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidDataException or NotSupportedException or UnauthorizedAccessException
            or System.Xml.XmlException or System.ComponentModel.Win32Exception or EntryPointNotFoundException or InvalidOperationException)
        {
            Console.Error.WriteLine($"WIM Driver Mount could not mount {SafeText.Path(Path.GetFileName(wim))}: {SafeText.Message(ex.Message)}");
            return 1;
        }
    }

    // The caller owns the WIM stream and filesystem until the mount closes.
    private static int RunForegroundMount(WimFileSystem fs, string mount, char drive,
        bool installDrivers, bool setupLog, string? testMount, string? runPath, string? runArgs, Stopwatch watch, CancellationTokenSource cancellation,
        DriverOperationRunner.State state, DokanLifecycle.Lease lifecycleLease, InfCollectedIndex? collectedIndex, bool allUsers, bool shareSource, out bool mountClosed)
    {
        mountClosed = false;
        // While a --run program is open, Ctrl+C must not cut the WIM from under it:
        // a windowed program does not see Ctrl+C and would keep reading.
        string? running = null;
        ConsoleCancelEventHandler handler = (_, e) =>
        {
            e.Cancel = true;
            if (Volatile.Read(ref running) is { } name)
                Console.Error.WriteLine($"If {name} is still running, the drive stays mounted until it closes.");
            else cancellation.Cancel();
        };
        Console.CancelKeyPress += handler;
        Exception? operationError = null;
        try
        {
            int installResult = 0;
            int mountResult = RunMount(fs, mount, drive, watch, cancellation.Token, (mountedTarget, isMountRunning) =>
            {
                // A ready instance is now visible to later lifecycle checks.
                lifecycleLease.Dispose();
                if (testMount is not null)
                {
                    if (Path.IsPathRooted(testMount)) throw new ArgumentException("Test file must be relative to the WIM root.");
                    string file = Path.GetFullPath(testMount, mount);
                    if (!file.StartsWith(mount, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Test file must be inside the WIM.");
                    using var input = File.OpenRead(file);
                    string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input));
                    Console.WriteLine($"TEST: SHA-256 {hash} for {SafeText.Path(file)}.");
                    cancellation.Cancel();
                    return;
                }
                if (runPath is not null)
                {
                    // Run a program from the WIM; the mount stays up until it exits, and its
                    // exit code becomes this run's result.
                    string program = Path.GetFullPath(runPath, mount);
                    if (!program.StartsWith(mount, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("--run must name a file inside the WIM.");
                    if (!File.Exists(program)) throw new FileNotFoundException("The program was not found in the WIM: " + SafeText.Path(runPath));
                    // The drive must still be the mount this run created, as the driver path checks.
                    if (!isMountRunning() || !DriveTargetMatches(drive, mountedTarget))
                        throw new IOException($"The drive closed, or {drive}: no longer points at it, so the program was not started.");
                    // A script runs through cmd.exe named by full path, with /D so the
                    // user's own AutoRun setting does not run as administrator too.
                    // Windows drops a trailing dot or space from a path, so "setup.bat." is a script too.
                    bool script = Path.GetExtension(program.TrimEnd('.', ' ')).ToLowerInvariant() is ".bat" or ".cmd";
                    var start = script
                        ? new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                            $"/D /S /C \"\"{program}\"{(runArgs is null ? "" : " " + runArgs)}\"")
                        : new ProcessStartInfo(program) { Arguments = runArgs ?? "" };
                    start.UseShellExecute = false;
                    start.WorkingDirectory = Path.GetDirectoryName(program)!;
                    // The WIM's contents are not verified, so say plainly what is about to run.
                    Console.WriteLine($"Running {SafeText.Path(program)} from the mounted WIM, with administrator rights.");
                    if (sharedConsole) Console.WriteLine("It opens in a window of its own, so programs without administrator rights cannot type into it. That window closes when the program exits.");
                    Console.WriteLine("The WIM stays mounted until it exits.");
                    Volatile.Write(ref running, SafeText.Path(Path.GetFileName(program)));
                    try
                    {
                        // Ctrl+C before this point already stopped the WIM's reads.
                        if (cancellation.IsCancellationRequested) throw new OperationCanceledException("Stopped before the program started.");
                        int exitCode;
                        if (sharedConsole) exitCode = RunInOwnConsole(start.FileName, start.Arguments, start.WorkingDirectory);
                        else
                        {
                            using var child = Process.Start(start) ?? throw new InvalidOperationException("The program could not be started.");
                            child.WaitForExit();
                            exitCode = child.ExitCode;
                        }
                        installResult = exitCode;
                        state.RunExitCode = exitCode;
                        Console.WriteLine($"The program exited with code {exitCode}.");
                    }
                    finally { Volatile.Write(ref running, null); }
                    cancellation.Cancel();
                    return;
                }
                if (installDrivers)
                {
                    // The journal and source remain held until after mount cleanup.
                    var journal = WorkerRecoveryStore.CreateDriverJournal(continueAfterReturnedFailure: true);
                    try { state.AttachJournal(journal); }
                    catch { journal.Dispose(); throw; }
                    Console.WriteLine($"Driver journal operation ID: {journal.OperationId:D}");
                    Console.WriteLine("Windows may now install drivers on several devices. The WIM stays mounted until it finishes.");
                    DirectDriverInstall.RunResult Execute() => FilteredDriverInstall.Run(mount, cancellation.Token, journal,
                        () => isMountRunning() && DriveTargetMatches(drive, mountedTarget), collectedIndex: collectedIndex);
                    DirectDriverInstall.RunResult result;
                    if (setupLog)
                    {
                        Guid operation = Guid.NewGuid();
                        result = DirectDriverInstall.RunWithMarkers(Execute, () => SetupDeviceLog.MarkStart(operation),
                            code => SetupDeviceLog.MarkExit(operation, (uint)code));
                    }
                    else result = Execute();
                    state.Result = result;
                    installResult = result.ExitCode;
                    cancellation.Cancel();
                    return;
                }
                Console.WriteLine("Keep this process running. Press Ctrl+C to unmount.");
            }, allUsers: allUsers, signedIn: fromMenu, shareSource: shareSource);
            mountClosed = mountResult == 0;
            // The program's code is the result only when the mount itself succeeded.
            if (mountResult != 0) state.RunExitCode = null;
            return mountResult == 0 ? installResult : mountResult;
        }
        catch (Exception ex) { operationError = ex; throw; }
        finally
        {
            try { Console.CancelKeyPress -= handler; }
            catch (Exception ex)
            {
                throw operationError is null ? ex : new AggregateException("Mount and console handler cleanup failed.", operationError, ex);
            }
        }
    }

    // Called synchronously while the owner keeps the WIM and filesystem open.
    // The callback may report readiness but must not claim mount ownership.
    // The running-state delegate is valid only during the synchronous callback.
    // A WIM on a share, named by UNC path or through a mapped drive letter.
    internal static bool OnShare(string path) => path.StartsWith(@"\\", StringComparison.Ordinal) ||
        (Path.GetPathRoot(path) is { Length: > 0 } root && new DriveInfo(root).DriveType == DriveType.Network);

    internal static int RunMount(WimFileSystem fs, string mount, char drive, Stopwatch watch,
        CancellationToken cancellation, Action<string, Func<bool>> onReady, bool reportReady = true, bool allUsers = false, bool signedIn = false, bool unmountMenu = false, bool shareSource = false)
    {
        using var dokan = new Dokan(new NullLogger());
        int nativeVersion = dokan.Version;
        int driverVersion = dokan.DriverVersion;
        if (driverVersion == 0)
            throw new InvalidOperationException("Dokan driver is not available after the installation check.");
        Console.WriteLine($"Using Dokan {nativeVersion / 100}.{nativeVersion / 10 % 10}.{nativeVersion % 10}."); // Dokan reports 2.3.0 as 230

        using var operations = new WimDokanOperations(fs, DokanDiscUtilsOptions.ForceReadOnly | DokanDiscUtilsOptions.LeaveFSOpen);
        using (var mounter = System.Security.Principal.WindowsIdentity.GetCurrent())
        {
            var mountingUser = mounter.User ?? throw new InvalidOperationException("The mounting user's SID is unavailable.");
            // --all-users checks the signed-in account against the WIM's permissions like any other.
            if (allUsers) MountAccess.ApplyAllUsers(operations, mountingUser, fs);
            else MountAccess.Apply(operations, MountAccess.Owners(mountingUser, signedIn ? MountAccess.SignedInUser() : null));
        }
        var builder = new DokanInstanceBuilder(dokan);
        builder.ConfigureOptions(options =>
        {
            options.MountPoint = mount;
            // Alternate streams stay off: listing a file's streams crashes the worker in DokanNet 2.3.0.3
            // (dokan-dotnet issue #395, fixed on its main branch but in no release yet), so
            // a WIM's alternate data streams are not shown. Revisit with a fixed DokanNet.
            options.Options = DokanOptions.WriteProtection;
            options.SingleThread = !fs.IsThreadSafe;
            options.Version = 200;
            // Dokan gives up on a request after this and the volume can be lost,
            // so it must outlast the source retry window: our own per-read cap ends
            // a stalled read first, and the mount survives it.
            //
            // For a network source the longest a read can block is Windows'
            // decision, not ours, so take the larger of our own bound and what
            // the SMB client's session timeout allows. Measuring this rather
            // than assuming 60 seconds is the point: an administrator can raise
            // it, and against the 1000-second extended timeout a single blocked
            // read would outlast a fixed timeout.
            // Its notes concern a WIM on a share only, so they are shown only then.
            options.TimeOut = SmbTimeouts.DokanRequestTimeout(shareSource ? Console.Out : TextWriter.Null);
        });
        string? mountedTarget = null;
        bool removalAttempted = false;
        Exception? mountError = null;
        cancellation.ThrowIfCancellationRequested();
        // A background mount is ended with --unmount, so its drive gets the menu entry.
        using var driveIcon = DriveIcon.Set(drive, unmountMenu);
        var instance = builder.Build(operations);
        try
        {
            var deadline = Stopwatch.StartNew();
            while (!new DriveInfo(mount).IsReady)
            {
                if (cancellation.IsCancellationRequested) return 1;
                if (!instance.IsFileSystemRunning()) throw new IOException("The drive closed before it was ready.");
                if (deadline.Elapsed > TimeSpan.FromSeconds(30)) throw new TimeoutException("The mounted drive did not become ready within 30 seconds.");
                Thread.Sleep(100);
            }
            if (cancellation.IsCancellationRequested) return 1;
            if (!instance.IsFileSystemRunning()) throw new IOException("The drive closed before its letter could be checked.");
            string capturedTarget = ReadDriveTarget(drive);
            mountedTarget = capturedTarget;
            MountReadinessObservation.ConfirmAndAnnounce(cancellation, () => instance.IsFileSystemRunning(),
                () => DriveTargetMatches(drive, capturedTarget), () =>
                {
                    if (reportReady) Console.WriteLine($"READY {mount} (in {watch.Elapsed.TotalSeconds:0.0} s)");
                    onReady(capturedTarget, () => instance.IsFileSystemRunning());
                });
            while (!cancellation.IsCancellationRequested && instance.IsFileSystemRunning()) Thread.Sleep(200);
            if (!cancellation.IsCancellationRequested) throw new IOException("The filesystem closed unexpectedly.");
            Console.WriteLine("Unmounting...");
            if (!DriveTargetMatches(drive, mountedTarget))
                throw new IOException($"{drive}: no longer points at this mount, or cannot be checked, so it was not unmounted by letter. Dokan may still remove it when it closes.");
            MountCleanupAttempt.RequestAndWait(ref removalAttempted, () => dokan.RemoveMountPoint(mount), () =>
            {
                if (instance.WaitForFileSystemClosed(10000) != 0)
                    throw new IOException("The filesystem did not close within 10 seconds.");
            });
        }
        catch (Exception ex) { mountError = ex; throw; }
        finally
        {
            Exception? cleanupError = null;
            try
            {
                MountCleanupAttempt.Run(removalAttempted,
                    () => DriveTargetChangedOrUnknown(drive, mountedTarget, false),
                    instance.IsFileSystemRunning, () => dokan.RemoveMountPoint(mount),
                    () => Console.Error.WriteLine($"WARNING: {drive}: no longer points at this mount, or cannot be checked. Dokan may still remove it when it closes."));
            }
            catch (Exception ex) { cleanupError = cleanupError is null ? ex : new AggregateException("Handler removal and mount cleanup failed.", cleanupError, ex); }
            try { instance.Dispose(); }
            catch (Exception ex) { cleanupError = cleanupError is null ? ex : new AggregateException("Mount cleanup and disposal failed.", cleanupError, ex); }
            if (cleanupError is not null)
                throw mountError is null ? cleanupError : new AggregateException("Mount operation and cleanup failed.", mountError, cleanupError);
        }
        try
        {
            string remaining = ReadDriveTarget(drive);
            if (string.Equals(remaining, mountedTarget, StringComparison.OrdinalIgnoreCase))
                throw new IOException($"The unmount did not finish: {drive}: still points at the WIM.");
            Console.Error.WriteLine($"WARNING: {drive}: is in use again after the unmount, by something else or by this mount. Check it in File Explorer.");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 2) { }
        Console.WriteLine($"Unmounted after {watch.Elapsed.TotalSeconds:0.0} s.");
        return 0;
    }

    internal static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static char SelectDrive(string? requested)
    {
        if (requested is not null)
        {
            char selected = MountOptions.ParseDriveLetter(requested);
            if (selected < 'D' || IsAssigned(selected)) throw new IOException(selected < 'D' ? $"Drive {selected}: cannot be used; choose a letter from D to Z." : $"Drive {selected}: is already in use. Choose another letter, or leave --drive out to use the highest free one.");
            return selected;
        }
        for (char c = 'Z'; c >= 'D'; c--)
            if (!IsAssigned(c)) return c;
        throw new IOException("No drive letter from D: through Z: is available.");
    }

    private static bool IsAssigned(char letter)
    {
        var buffer = new char[32768];
        if (QueryDosDevice($"{letter}:", buffer, buffer.Length) != 0) return true;
        int error = Marshal.GetLastWin32Error();
        if (error == 2) return false; // ERROR_FILE_NOT_FOUND
        throw new System.ComponentModel.Win32Exception(error, $"Cannot check availability of {letter}:.");
    }

    private static string ReadDriveTarget(char letter)
    {
        var buffer = new char[32768];
        uint length = QueryDosDevice($"{letter}:", buffer, buffer.Length);
        if (length == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"Cannot inspect {letter}: mapping.");
        return new string(buffer, 0, checked((int)length));
    }

    internal static bool DriveTargetMatches(char letter, string? expected)
    {
        if (expected is null) return false;
        try { return string.Equals(ReadDriveTarget(letter), expected, StringComparison.OrdinalIgnoreCase); }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private static bool DriveTargetChangedOrUnknown(char letter, string? expected, bool absenceExpected)
    {
        if (expected is null) return true;
        try { return !string.Equals(ReadDriveTarget(letter), expected, StringComparison.OrdinalIgnoreCase); }
        catch (System.ComponentModel.Win32Exception ex) { return !(absenceExpected && ex.NativeErrorCode == 2); }
    }

    private static int RequestElevation(string[] args)
    {
        string? executable = Environment.ProcessPath;
        if (executable is null || !string.Equals(Path.GetFileName(executable), "WimDriverMount.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(executable)?.TrimEnd(Path.DirectorySeparatorChar), AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("WIM Driver Mount can ask for administrator rights only when the program file is named WimDriverMount.exe.");
            Console.Error.WriteLine("Rename it to WimDriverMount.exe, or run it from an administrator console.");
            return 1;
        }
        TrustedFile.WarnIfProgramFolderOpen(Console.Error);
        Console.WriteLine("WIM Driver Mount will request administrator rights. Approve the Windows prompt to continue.");
        try
        {
            var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas", WorkingDirectory = Environment.SystemDirectory };
            // Typed in a console a shell also uses: the elevated copy runs hidden and
            // writes here. Dropped onto the program or double-clicked, this console is
            // ours alone and closes when we exit, so it keeps its own window then.
            bool share = !fromMenu && GetConsoleProcessList(new uint[2], 2) > 1;
            if (fromMenu || share) start.WindowStyle = ProcessWindowStyle.Hidden;
            start.ArgumentList.Add("--elevated-window");
            if (share) { start.ArgumentList.Add("--attach-console"); start.ArgumentList.Add($"{Environment.ProcessId}"); }
            foreach (string arg in args) start.ArgumentList.Add(arg);
            if (noPause) start.ArgumentList.Add("--no-pause");
            if (RequestedLog is { } log) { start.ArgumentList.Add("--log"); start.ArgumentList.Add(log); }
            if (EventLog) start.ArgumentList.Add("--evtlog");
            if (fromMenu) start.ArgumentList.Add("--from-menu");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the elevated application.");
            if (!share && !fromMenu) Console.WriteLine("The work runs in its own administrator window.");
            // Ctrl+C reaches both copies; the elevated one acts on it (a foreground mount
            // unmounts), so this one keeps waiting for it rather than leaving first.
            Console.CancelKeyPress += (_, e) => e.Cancel = true;
            // The elevated process owns the operation; its exit code becomes this one's,
            // so a script started from a normal console sees the real result.
            handedOff = true;
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            // Saying no to the prompt is the user's own answer: no message box for it.
            if (ex is System.ComponentModel.Win32Exception { NativeErrorCode: 1223 })
            {
                handedOff = true;
                Console.Error.WriteLine("WIM Driver Mount: the administrator prompt was declined, so the operation did not run.");
                return 1;
            }
            Console.Error.WriteLine("WIM Driver Mount: administrator request failed: " + SafeText.Message(ex.Message));
            return 1;
        }
    }

    // Two sizes of the same artwork: the larger one where the screen is the only thing
    // being shown (help and version), the smaller where operation output needs the room.
    // Each is used only if the window can hold it; otherwise the next one down, then text.
    private static readonly (string Resource, int Width, int Height)[] Splashes =
    [
        ("WimDriverMount.SplashLarge", 77, 17),   // 13 rows by 75 columns, the name in block letters
        ("WimDriverMount.Splash", 69, 17),        // 13 rows by 67 columns
    ];

    private static string NoSuchImage(int count, int index) => count <= 0 ? "This WIM contains no images, so there is nothing to mount."
        : count == 1
        ? $"This WIM has 1 image, so --index {index} does not exist. Use --index 1, or leave --index out."
        : $"This WIM has {count} images, so --index {index} does not exist. Use a number from 1 to {count}.";

    private static bool headerShown, fromSettingsFile;

    // Named when another account's administrator password was typed: the signed-in
    // account that asked for the mount may open the drive too (MountAccess.SignedInUser).
    private static string SignedInAlso(WindowsIdentity mounter)
    {
        if (MountAccess.SignedInUser() is not { } user || user == mounter.User) return "";
        string name;
        try { name = user.Translate(typeof(NTAccount)).Value; }
        catch (Exception ex) when (ex is IdentityNotMappedException || ex.GetType() == typeof(SystemException)) { name = user.Value; }
        return $", {SafeText.Path(name)} (signed in here)";
    }

    // Option names as the user wrote them: "index" in a settings file, "--index" on the command line.
    private static string AsTyped(string text) => fromSettingsFile ? MountConfiguration.AsSetting(text) : text;
    internal static bool FromSettingsFile => fromSettingsFile;

    // Once per run: a settings file runs each mount through the same entry point.
    private static void Header(bool showSplash = true, bool large = false)
    {
        if (headerShown) return;
        headerShown = true;
        bool splashShown = false;
        if (showSplash && OperatingSystem.IsWindows() && !Console.IsOutputRedirected &&
            Environment.GetEnvironmentVariable("NO_COLOR") is null)
        {
            IntPtr output = GetStdHandle(-11);
            try
            {
                var choice = Splashes.Skip(large ? 0 : 1)
                    .FirstOrDefault(art => Console.WindowWidth >= art.Width && Console.WindowHeight >= art.Height);
                if (choice.Resource is not null && GetConsoleMode(output, out uint mode) &&
                    SetConsoleMode(output, mode | 0x0004))
                {
                    try
                    {
                        using Stream? resource = typeof(Program).Assembly.GetManifestResourceStream(choice.Resource);
                        if (resource is not null)
                        {
                            // The artwork contains glyphs outside Windows OEM code pages.
                            // Set the managed writer and attached console to UTF-8 together.
                            // Keep the caller's prior encoding after this optional splash.
                            var previousEncoding = Console.OutputEncoding;
                            try
                            {
                                Console.OutputEncoding = new System.Text.UTF8Encoding(false);
                                using var reader = new StreamReader(resource);
                                // Its own UTF-8 writer: Console.Out is the log's copy,
                                // which keeps its first encoding, and the artwork stays out of the log.
                                Console.Out.Flush();
                                var art = new StreamWriter(Console.OpenStandardOutput(), new System.Text.UTF8Encoding(false));
                                art.Write(reader.ReadToEnd());
                                art.Flush();
                                splashShown = true;
                            }
                            finally
                            {
                                try { Console.OutputEncoding = previousEncoding; }
                                catch (Exception ex) when (ex is IOException or System.Security.SecurityException)
                                { /* Optional artwork must not prevent the operation or text fallback. */ }
                            }
                        }
                    }
                    finally { SetConsoleMode(output, mode); }
                }
            }
            catch (Exception ex) when (ex is IOException or System.Security.SecurityException)
            { /* Keep the text header when the console or its encoding is unavailable. */ }
        }
        // The informational version carries the commit when the build stamped
        // one, so a binary in the field can be traced to its source.
        string version = typeof(Program).Assembly
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "unknown";
        // x64 and ARM64 builds of one commit share a version; say which this is.
        version += $" ({RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()})";
        if (splashShown)
        {
            // The artwork carries the name, so only the details follow it.
            Console.WriteLine($"  v{version} | Jericho Jones | MIT; notices in the licenses folder.");
            Console.WriteLine("  Operations request administrator rights when needed.\n");
            return;
        }
        Console.WriteLine($"WIM Driver Mount {version} - mounts WIM images as read-only drives\nOperations request administrator rights when needed.\nHelp, version, driver preview and journal inspection do not request administrator rights.\nAuthor: Jericho Jones\nLicense: MIT; third-party notices are in the licenses folder.\n");
    }

    private static void Usage() => Console.WriteLine("""
Every example runs from the program's folder and works as written in both
PowerShell and Command Prompt, once you replace anything in <...> with your own value.

One step: drop a WIM onto WimDriverMount.exe, or run
  .\WimDriverMount.exe <WIM path or URL>
It mounts the WIM, installs the driver Windows would rank best for each device
that needs one, and unmounts. No restart is automatic.

Mount a WIM as a drive (read-only):
  .\WimDriverMount.exe --wim C:\Images\tools.wim --drive M:
      Mounts it as M: until you press Ctrl+C in this window.
  .\WimDriverMount.exe --wim C:\Images\tools.wim --drive M: --background
      Mounts it as M: and returns; it stays mounted after this window closes.
  .\WimDriverMount.exe --unmount M:
      Unmounts a background mount. Right-clicking the drive in File Explorer offers
      the same as "Unmount with WIM Driver Mount" (Windows 11: Show more options).
  The WIM can also be a network path (\\server\share\tools.wim) or an HTTP or
  HTTPS URL. Leave out --drive to use the highest free letter, from Z: down. For a split WIM
  (.swm), give the first part; the others are read where they are, beside it.

Install drivers from a WIM:
  .\WimDriverMount.exe --wim C:\Images\drivers.wim --preview-drivers
      Shows, device by device, which driver it would pick and why. Changes nothing.
  .\WimDriverMount.exe --wim C:\Images\drivers.wim --install-drivers
      Installs a driver only where it beats the one Windows already has.

Capture this PC's drivers into a new WIM:
  .\WimDriverMount.exe --capture-drivers C:\Drivers\this-pc.wim
      Writes the third-party driver packages this PC's hardware uses into a new WIM:
      those of its devices (connected now or not), printers, scanners and print
      queues, and the sub-packages they install. Lists what it leaves out and why
      (devices an app made, drivers only a service uses). Then reads every file
      back to check it.
      --compression none, fast or maximum (default); --whatif lists the
      packages and checks the space without writing. Never changes an existing file.

Run a program from a WIM:
  .\WimDriverMount.exe --wim C:\Images\tools.wim --run Tools\setup.exe
      Mounts, runs the program, waits for it, unmounts, and returns its exit code.
  Add --run-sha256 <hash> to refuse a program that has been changed.

Install, with a right-click Mount in File Explorer:
  .\WimDriverMount.exe --install
      Copies the program to C:\Program Files\WimDriverMount, and adds "Mount with
      WIM Driver Mount" to the right-click menu of .wim, .swm and .esd files. That
      mounts the file at the highest free letter and opens it, like Mount on an ISO;
      each mount asks for administrator approval. --install <folder> installs
      elsewhere; --uninstall [<folder>] removes what --install added.

Run the same mounts every time:
  .\WimDriverMount.exe --protect-config C:\Config\mounts.ini
      Locks the settings file so only administrators can change it.
  .\WimDriverMount.exe --mount-config C:\Config\mounts.ini
      Runs the mounts in that file, in order.

If something went wrong:
  .\WimDriverMount.exe --unmount M:
      A background drive that won't go away.
  .\WimDriverMount.exe --resume-worker-cleanup M:
      When --unmount M: says to, or a new mount on M: says it already has a
      background mount record that --unmount M: does not clear.
  .\WimDriverMount.exe --inspect-driver-journal <ID>
      What an interrupted driver install recorded. The ID is printed when
      the install starts.

Windows asks for administrator approval when an operation needs it. From a console the
work then runs hidden, its output appears in this same window, and the command returns its
exit code. Dropped onto the program, it gets a window of its own that waits for Enter;
--no-pause closes it by itself. Run redirected commands from an administrator console.

Options:
  --index <number>       WIM image index, starting at 1 (default: 1).
  --drive <letter>       Drive letter, such as M: (default: an available letter).
  --background           Mount in the background; use --unmount to close it.
  --all-users            Let every account on this computer open the drive, each seeing
                         only what the WIM's own permissions allow. By default only you,
                         SYSTEM and elevated administrators can open it.
  --mount-config <path>  Run the mounts in an INI settings file, in order.
  --protect-config <path>
                         Make a settings file writable by administrators only,
                         with its folder, so --mount-config will accept it.
                         Shows the permissions before and after, and the file's
                         SHA-256 and contents to review. Refuses a file open for
                         writing elsewhere, a link, and shared folders (drive roots,
                         Windows, Program Files, profile folders, a folder with
                         subfolders): give the settings file a folder of its own.
  --install [<folder>]   Install to C:\Program Files\WimDriverMount, or <folder>, and add
                         the right-click Mount. A new folder is made administrator-
                         only; an existing one must already be, and is left as it is.
                         The same or a newer installed version is kept unless
                         --force is given.
  --uninstall [<folder>] Remove the files --install copied there, and the menu entry.
  --whatif               Preview without mounting or installing.
  --test-mount <path>    Mount, hash a relative file, and unmount for a basic test.
  --run <path>           Mount, run a program from the WIM (path relative to the WIM
                         root, such as Tools\setup.exe; a .exe, .com, .bat or .cmd),
                         wait for it to exit, unmount, and return its exit code.
  --run-args "<args>"    Command line passed to the --run program.
  --run-sha256 <hash>    Refuse to run the program unless its file matches this SHA-256
                         (up to 256 MB). Only that one file is checked; files beside it,
                         such as DLLs, are not. For a WIM you do not trust, use --wim-sha256.
  --install-drivers      For each present device, install the WIM driver Windows would
                         rank best (rank first, then date and version) when it beats
                         the installed one. A package Windows refuses to stage is
                         passed over for the next-ranked one.
  --setup-log            Request SetupAPI device-log markers for driver installation.
  --inspect-driver-journal <ID>  Show what a driver install recorded. Read-only.
  --inspect-legacy-driver-journal <ID>  The same, for a journal kept in ProgramData.
  --preview-drivers      Show the driver --install-drivers would choose for each device.
                         Reads the WIM only: no mount, Dokan, elevation or installation.
  --no-install-dokan     Do not install a missing Dokan prerequisite.
  --log <path>           Append this run's messages, with the time, to a text file in
                         an existing folder. A background mount keeps writing there,
                         with any failure. A --run program's own output is not included.
  --evtlog               Also write the Windows Application event log (off by default).
  --no-pause             When the work gets a window of its own (a dropped WIM), close
                         it when done instead of waiting for Enter.
  --remove-dokan         After this run, uninstall Dokan if this tool installed it.
                         Windows then usually needs a restart before Dokan can be installed again.
                         (By default Dokan stays installed for later runs.)
  --get-dokan [source]   Where to get Dokan when it is not installed. On its own:
                         download the release this program is tested with (Dokan
                         2.3.1), checked against its exact SHA-256 (in a settings
                         file: get-dokan = tested). With a source:
                         a Dokan MSI from a local file, a network path, or HTTPS (a
                         relative path is resolved beside this program).
                         Without it: the Dokan_x64.msi (Dokan_ARM64.msi on ARM64) beside
                         this program if present, else the latest official release.
  --wim-cert-sha256 <hash>  Only for your own HTTPS server with a self-signed
                         certificate, or to trust that one server and nothing in
                         between: accepts only the certificate with this SHA-256.
                         Checks who sends the file, not the file itself.
  --wim-sha256 <hash>    Require the whole WIM to hash to this SHA-256 before
                         mounting. Proves the bytes rather than the server, and
                         so works over plain HTTP -- but it reads the entire WIM
                         first, which for a large one is the download that
                         mounting it was meant to avoid. Not for a split WIM,
                         which is several files.

Driver modes cannot be combined with --background.
An INF that cannot be parsed blocks only devices whose IDs appear in it.
Windows enforces driver signatures. No restart is automatic.
Settings file: INI. Each [mount:<name>] section is one mount; [defaults] applies to
all. Keys are mount options without the dashes, such as wim = C:\Drivers\Lenovo.wim
and drive = M; commands such as unmount, and test-mount, are not keys. log and evtlog go only
in [defaults]. A mount that runs a program or installs drivers needs wim-sha256.
The settings file must be on an internal disk (not a share, USB or SD).
Missing Dokan is installed by default unless --no-install-dokan is supplied.
Journal inspection only reads. It cannot tell what Windows changed, and is no reason to retry.
--resume-worker-cleanup clears a leftover background-mount record; it does not unmount a drive.
A Dokan MSI is used only if Windows verifies its signature as LEOSAC's
(919 690 420 00014) and it is Dokan 2.3 or a later 2.x; do not put secrets in its URL.
Cleanup uses the drive letter. If another mount takes it during cleanup,
that mount may be affected. These checks do not prove drive ownership.
""");
}

// A path as the caller meant it: relative to the caller's folder, and through
// the caller's mapped drives. Elevated windows start in System32 and usually
// lack mapped drives, so a path is fixed before elevation, never after.
internal static class ElevationPaths
{
    internal static string CallerPath(string path) => DokanInstaller.ResolveMappedSource(Path.GetFullPath(path));
}
