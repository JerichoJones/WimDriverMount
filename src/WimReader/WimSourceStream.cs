using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Streams;

namespace DiscUtils.Wim;

// Normalize uncompressed/empty EOF while keeping opened files tied to source health.
internal sealed class WimSourceStream(SparseStream inner, IWimSourceHealth? health) : SparseStream.ReadOnlySparseStream
{
    private readonly long declaredLength = inner.Length;
    private bool disposed;
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => inner.CanSeek;
    public override long Length => declaredLength;
    public override long Position { get => inner.Position; set { ThrowIfUnavailable(); inner.Position = value; } }
    public override IEnumerable<StreamExtent> Extents => inner.Extents;
    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return Read(buffer.AsSpan(offset, count));
    }
    public override int Read(Span<byte> buffer)
    {
        ThrowIfUnavailable();
        if (inner.Position >= declaredLength || buffer.IsEmpty) return 0;
        int requested = (int)Math.Min(buffer.Length, declaredLength - inner.Position);
        int read = inner.Read(buffer[..requested]);
        ThrowIfUnavailable();
        if (read == 0 && inner.Position < declaredLength) throw new EndOfStreamException("Uncompressed WIM resource ended before its declared length.");
        return read;
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfUnavailable();
        if (inner.Position >= declaredLength || buffer.IsEmpty) return 0;
        int requested = (int)Math.Min(buffer.Length, declaredLength - inner.Position);
        int read = await inner.ReadAsync(buffer[..requested], cancellationToken).ConfigureAwait(false);
        ThrowIfUnavailable();
        if (read == 0 && inner.Position < declaredLength) throw new EndOfStreamException("Uncompressed WIM resource ended before its declared length.");
        return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfUnavailable();
        long next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(inner.Position + offset),
            SeekOrigin.End => checked(declaredLength + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        if (next < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        Position = next;
        return next;
    }
    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        health?.ThrowIfUnavailable();
    }
    protected override void Dispose(bool disposing)
    {
        disposed = true;
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }
}
