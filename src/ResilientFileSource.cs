using System.ComponentModel;
using System.Runtime.InteropServices;
using DiscUtils.Wim;
using Microsoft.Win32.SafeHandles;

// A WIM on local disk, a mapped drive, or a UNC share, read so that a short
// interruption does not take the drive down with it.
//
// Local and remote files are treated differently on purpose.
//
// A local handle survives a disk hiccup, so it is held for the whole mount and
// never reopened. That is not only simpler: FileShare.Read denies writers for
// as long as the handle is open, so nobody can swap the file underneath a
// mounted drive. Reopening would trade that guarantee away for nothing.
//
// A share that drops is different. It leaves the handle permanently dead, so
// every later read fails even once the share returns, and reopening is the only
// way back. The price is that between the drop and the reopen the file is
// unprotected, so the reopened file has to be proved to be the same one:
// Windows' own volume serial and file ID, not its length and timestamp, which
// anyone who can write the file can set, and which a hostile server simply
// reports however it likes.
//
// Even this is not proof against an in-place edit of a file that keeps its
// identity. It establishes that this is the same file, not that its contents
// never changed.
//
// Unlike the web source, a source that stays unreachable past the retry window
// is not latched as failed. The one read fails, its caller sees an error, and
// the mount stays up; a later read can still succeed once the share returns.
//
// Read-only, single-version. The owner must serialize access.
internal sealed class ResilientFileSource : Stream, IWimSourceHealth
{

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public FileTime Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);

    private readonly string path;
    private readonly bool remote;
    private readonly long length;
    private readonly uint volume;
    private readonly ulong fileId;
    private readonly CancellationToken lifetime;
    private readonly TransientRetry retry;
    private FileStream? file;
    private long position;
    private bool disposed;
    // When the retry window was last spent without the source answering, or
    // null while it is answering. See Read for why this is remembered.
    private DateTime? unanswered;
    private readonly TimeSpan window;

    // testWindow exists so the outage regression can prove the per-request
    // behaviour in seconds instead of a minute per read. Production uses the
    // shared window.
    internal ResilientFileSource(string path, CancellationToken lifetime, TextWriter? report = null,
        TimeSpan? testWindow = null)
    {
        this.path = path ?? throw new ArgumentNullException(nameof(path));
        this.lifetime = lifetime;
        window = testWindow ?? TransientRetry.Window;
        retry = new TransientRetry(path, report, window);
        remote = path.StartsWith(@"\\", StringComparison.Ordinal);
        // Opening is not retried: at mount time the operator is present and a
        // clear immediate failure beats a minute of silence.
        file = Open();
        length = file.Length;
        (volume, fileId) = Identify(file);
    }

    public void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        lifetime.ThrowIfCancellationRequested();
    }

    private FileStream Open() =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.RandomAccess);

    // Windows' own identity for the open file. Opening follows links, so this
    // is the identity of the file actually read; a path redirected between a
    // drop and the reopen yields a different identity, which Handle refuses.
    private (uint Volume, ulong Id) Identify(FileStream open)
    {
        if (!GetFileInformationByHandle(open.SafeFileHandle, out FileInformation info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot establish the identity of {SafeText.Path(path)}.");
        return (info.Volume, ((ulong)info.IndexHigh << 32) | info.IndexLow);
    }

    private FileStream Handle()
    {
        if (file is not null) return file;
        FileStream reopened = Open();
        try
        {
            var (reopenedVolume, reopenedId) = Identify(reopened);
            // Serving blocks from two different WIMs would corrupt the mounted
            // view without any error at all, so a reconnected file must be the
            // same file and not merely one that looks like it.
            if (reopenedVolume != volume || reopenedId != fileId || reopened.Length != length)
                throw new InvalidDataException(
                    $"The WIM at {SafeText.Path(path)} is no longer the same file as the one that was mounted. " +
                    "The drive cannot keep serving it; unmount and mount again.");
        }
        catch { reopened.Dispose(); throw; }
        file = reopened;
        return file;
    }

    // Dropped after a read failure so the next attempt reopens and rechecks,
    // but only for a share, where the handle really is dead. A local handle is
    // kept: dropping it would give up the write protection it holds, and a
    // local read failure does not invalidate it anyway.
    //
    // The outage regression calls this to prove the reopen path, because a real
    // share dropping cannot be staged in a test.
    internal void Discard()
    {
        if (!remote) return;
        FileStream? dead = file;
        file = null;
        try { dead?.Dispose(); } catch (IOException) { } // A dead handle may also fail to close.
    }

    // A dropped share, a disk retrying, a server rebooting: all transient. A
    // file that has gone missing is included, because for a share that is what
    // a brief outage looks like, and the window bounds the wait either way.
    //
    // A changed WIM is raised as InvalidDataException, which derives from
    // SystemException rather than IOException, so it is excluded by not being
    // listed here and is never retried.
    //
    // An access denial is deliberately absent. Changing a share's permissions
    // while the drive is mounted is a decision, not a hiccup, and treating it
    // as one would make every later read wait out the whole window before failing —
    // so a directory listing would take minutes and pile up Dokan threads.
    private static bool Transient(Exception ex) => ex is IOException;

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (offset > buffer.Length - count) throw new ArgumentException("Invalid buffer range.");
        ObjectDisposedException.ThrowIf(disposed, this);
        if (count == 0 || position >= length) return 0;

        // One request from Windows becomes one read per compressed chunk of the
        // WIM, each landing here. Retrying every one of them for the full window
        // multiplies the wait by the number of chunks: a 64 KiB read of a
        // 32 KiB-chunk WIM on a share whose server is off would cost two reads of two
        // blocked attempts each, which outlasts the timeout Dokan gives the
        // whole request and loses the volume. So once the window has been spent
        // and nothing answered, later reads fail at once instead of each paying
        // it again. The first read to succeed clears it, which is the recovery
        // this class exists for.
        if (GivingUpRecently())
        {
            try { return ReadOnce(buffer, offset, count); }
            catch (Exception ex) when (Transient(ex))
            {
                Discard();
                throw new IOException(
                    $"The WIM source {SafeText.Path(path)} did not answer within " +
                    $"{window.TotalSeconds:0} seconds and is still not answering.", ex);
            }
        }

        int got = 0;
        try
        {
            retry.Run(() =>
            {
                got = 0;
                try { got = ReadOnce(buffer, offset, count); }
                catch { Discard(); throw; } // The next attempt reopens and rechecks.
            }, Transient, lifetime);
        }
        catch (Exception ex) when (Transient(ex))
        {
            unanswered = DateTime.UtcNow;
            throw;
        }
        unanswered = null;
        return got; // ReadOnce has already advanced the position.
    }

    private int ReadOnce(byte[] buffer, int offset, int count)
    {
        FileStream handle = Handle();
        handle.Position = position; // A reopened handle starts at zero.
        int read = handle.Read(buffer, offset, (int)Math.Min(count, length - position));
        position += read;
        return read;
    }

    // True while the source is known to be unreachable, so one outage is paid
    // for once per request rather than once per chunk.
    private bool GivingUpRecently() =>
        unanswered is DateTime when && DateTime.UtcNow - when < window;

    public override bool CanRead => !disposed;
    public override bool CanSeek => !disposed;
    public override bool CanWrite => false;
    public override long Length { get { ObjectDisposedException.ThrowIf(disposed, this); return length; } }

    public override long Position
    {
        get { ObjectDisposedException.ThrowIf(disposed, this); return position; }
        set => Seek(value, SeekOrigin.Begin);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        long target = checked((origin switch
        {
            SeekOrigin.Begin => 0,
            SeekOrigin.Current => position,
            SeekOrigin.End => length,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        }) + offset);
        if (target < 0) throw new IOException("Cannot seek before the start of the WIM.");
        position = target;
        return target;
    }

    public override void Flush() { ObjectDisposedException.ThrowIf(disposed, this); }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed)
        {
            FileStream? open = file;
            file = null;
            try { open?.Dispose(); } catch (IOException) { }
        }
        disposed = true;
        base.Dispose(disposing);
    }
}
