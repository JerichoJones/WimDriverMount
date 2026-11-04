using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

// --log <path>: every line this run shows, timestamped, appended to one file. The
// window the user typed in, the hidden administrator copy and the background mount
// each append to it.
//
// Those last two run as administrator, and the file is somewhere the user (and so
// the unelevated half of the sign-in) can write. In a user-writable folder a
// junction can steer an elevated process into writing anywhere (see
// WorkerDiagnostics), so the file is opened without following a link at its own
// name, its real path is checked against the one asked for (a junction in any
// folder above changes it), and it is opened for appending only, so nothing in it
// can be overwritten.
internal static class LogFile
{
    private const uint AppendData = 0x0004, Synchronize = 0x00100000, ReadAttributes = 0x0080;
    private const uint ShareAll = 0x7, OpenReparsePoint = 0x00200000;
    private const uint AttributeDirectory = 0x10, AttributeReparsePoint = 0x400;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(SafeFileHandle file, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, [Out] char[] path, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetLongPathNameW(string shortPath, [Out] char[] longPath, uint length);
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicInfo { public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime; public uint FileAttributes; }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out BasicInfo info, int size);

    private static SafeFileHandle? file;
    private static readonly object Gate = new();

    internal static string? Path { get; private set; }

    // Opens (or creates) the log for appending. Throws IOException with a plain
    // reason when the path is not one it may safely write.
    internal static void Open(string path)
    {
        if (!System.IO.Path.IsPathFullyQualified(path))
            throw new IOException($"The log file must be a full path, such as C:\\Logs\\wim.log: {SafeText.Path(path)}");
        string full = Normalize(path);
        if (!System.IO.Path.IsPathFullyQualified(full) || full.StartsWith(@"\\?\", StringComparison.Ordinal) || full.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw new IOException($"The log file must be a full path on a drive or share, such as C:\\Logs\\wim.log: {SafeText.Path(path)}");
        // Windows drops a trailing dot or space from a name, and some names are devices,
        // so such a part names a different folder or file than the one written; refused.
        // A share's root comes without its closing backslash (\\server\share), a drive's with it (C:\).
        string root = System.IO.Path.GetPathRoot(full) ?? "";
        string rest = full[root.Length..];
        if (!root.EndsWith('\\') && rest.StartsWith('\\')) rest = rest[1..];
        foreach (string part in rest.Split('\\'))
            if (part.Length == 0 || part.EndsWith('.') || part.EndsWith(' ') || IsDeviceName(part))
                throw new IOException($"The log file path has a part Windows would read differently ({SafeText.Quote(part)}): {SafeText.Path(path)}. Use plain folder and file names.");
        string folder = System.IO.Path.GetDirectoryName(full) ?? throw new IOException($"The log file needs a folder: {SafeText.Path(full)}.");
        string name = System.IO.Path.GetFileName(full);
        if (name.Length == 0 || name.Contains(':'))
            throw new IOException($"The log file must be a plain file name in a folder: {SafeText.Path(full)}.");
        // Short names (C:\Users\USER~1) are expanded, so the real path below can match.
        // This reads each folder's own long name; it does not follow a junction.
        var longName = new char[32768];
        uint longLength = GetLongPathNameW(folder, longName, (uint)longName.Length);
        if (longLength > 0 && longLength < longName.Length) folder = new string(longName, 0, (int)longLength);
        // The folder first, without following a link, and checked to be where it says.
        using var directory = CreateFileW(folder, AddFile | Synchronize | ReadAttributes, ShareAll, IntPtr.Zero, OpenExisting,
            BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (directory.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            throw new IOException(error is 2 or 3
                ? $"The folder for the log file does not exist: {SafeText.Path(folder)}. Create it, or choose another folder."
                : $"The log file's folder cannot be opened: {SafeText.Path(folder)} ({new Win32Exception(error).Message.TrimEnd('.')}).");
        }
        if (Attributes(directory) is var folderAttributes && ((folderAttributes & AttributeReparsePoint) != 0 || (folderAttributes & AttributeDirectory) == 0) ||
            !string.Equals(FinalPath(directory).TrimEnd('\\'), folder.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new IOException($"The log file's folder is not reached by that exact path, so it was not used: {SafeText.Path(folder)}. " +
                @"A link, a junction or a SUBST drive letter leads there. Give the folder's real path, such as C:\Logs\wim.log or \\server\share\Logs\wim.log.");
        // Then the file, created inside that very folder object, so nothing can be
        // swapped in between; a link at the file's own name is opened, not followed.
        var handle = CreateIn(directory, name);
        try
        {
            if ((Attributes(handle) & (AttributeDirectory | AttributeReparsePoint)) != 0)
                throw new IOException($"The log file is a folder or a link, so it was not used: {SafeText.Path(full)}.");
        }
        catch { handle.Dispose(); throw; }
        lock (Gate)
        {
            file?.Dispose();
            file = handle;
            Path = full;
        }
    }

    private const uint AddFile = 0x0002, OpenExisting = 3, BackupSemantics = 0x02000000;

    private static bool IsDeviceName(string part)
    {
        string name = part.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            (name.Length == 4 && (name.StartsWith("COM", StringComparison.Ordinal) || name.StartsWith("LPT", StringComparison.Ordinal)) &&
             name[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }

    // The full path, with \\?\C:\Logs and \\?\UNC\server\share written as the
    // C:\Logs and \\server\share they name. Other \\?\ forms are left as they are.
    internal static string Normalize(string path)
    {
        string full = System.IO.Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + full[8..];
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal) && full.Length >= 7 && char.IsAsciiLetter(full[4]) && full[5] == ':' && full[6] == '\\') return full[4..];
        return full;
    }

    private static uint Attributes(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 0 /* FileBasicInfo */, out BasicInfo info, Marshal.SizeOf<BasicInfo>()))
            throw new IOException("The log file cannot be checked.");
        return info.FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public IntPtr Status, Information; }
    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock status,
        IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    // Opens or creates `name` relative to an already checked folder handle, for appending.
    private static SafeFileHandle CreateIn(SafeFileHandle directory, string name)
    {
        const uint OpenIf = 3, NonDirectory = 0x40, SynchronousIo = 0x20, OpenReparse = 0x00200000, CaseInsensitive = 0x40;
        IntPtr text = Marshal.StringToHGlobalUni(name);
        IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        bool added = false;
        try
        {
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = text }, unicode, false);
            directory.DangerousAddRef(ref added);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(), RootDirectory = directory.DangerousGetHandle(),
                ObjectName = unicode, Attributes = CaseInsensitive,
            };
            int status = NtCreateFile(out SafeFileHandle handle, AppendData | Synchronize | ReadAttributes, ref attributes, out _,
                IntPtr.Zero, 0x80 /* normal */, ShareAll, OpenIf, NonDirectory | SynchronousIo | OpenReparse, IntPtr.Zero, 0);
            if (status < 0)
            {
                handle.Dispose();
                throw new IOException($"The log file cannot be opened ({new Win32Exception((int)RtlNtStatusToDosError(status)).Message.TrimEnd('.')}).");
            }
            return handle;
        }
        finally
        {
            if (added) directory.DangerousRelease();
            Marshal.FreeHGlobal(unicode);
            Marshal.FreeHGlobal(text);
        }
    }

    private static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[32768];
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length) return string.Empty;
        string real = new(buffer, 0, (int)length);
        if (real.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + real[8..];
        return real.StartsWith(@"\\?\", StringComparison.Ordinal) ? real[4..] : real;
    }

    // One line, with the time and this process's ID (three processes may share the file).
    internal static void Line(string text)
    {
        lock (Gate)
        {
            if (file is null) return;
            byte[] bytes = Encoding.UTF8.GetBytes($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {text}\r\n");
            // An append-only handle: each write lands at the end, whole, whoever else writes.
            if (!WriteFile(file, bytes, bytes.Length, out _, IntPtr.Zero))
            {
                file.Dispose();
                file = null;
                string? stopped = Path;
                // No longer this program's log, so nothing says the log continues there.
                Path = null;
                // Said once, on the console itself, so the log is not taken for the whole run.
                try { FailureWriter?.WriteLine($"WARNING: The log file {SafeText.Path(stopped ?? "")} could not be written; this program's later lines are not in it."); }
                catch (IOException) { }
            }
        }
    }

    // The console's own error writer (not the copying one), for the warning above.
    internal static TextWriter? FailureWriter;

    // Wraps a console writer so every complete line also goes to the log.
    internal sealed class Tee(TextWriter inner) : TextWriter
    {
        private readonly StringBuilder pending = new();
        public override Encoding Encoding => inner.Encoding;

        public override void Write(char value)
        {
            inner.Write(value);
            Take(value);
        }

        public override void Write(string? value)
        {
            inner.Write(value);
            if (value is not null) foreach (char c in value) Take(c);
        }

        public override void WriteLine(string? value) { Write(value); Write(CoreNewLine); }

        public override void Flush() { inner.Flush(); }

        private void Take(char c)
        {
            lock (pending)
            {
                if (c == '\n') { Line(pending.ToString().TrimEnd('\r')); pending.Clear(); }
                else pending.Append(c);
            }
        }
    }
}
