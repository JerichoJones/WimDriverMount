// Solid ("packed") WIM resources, implemented from SOLID-RESOURCE-SPEC.md.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Streams;

namespace DiscUtils.Wim;

internal sealed class SolidResource
{
    internal const int MaxChunks = 1_000_000;
    // Each packed resource costs a seek and a header read before mounting -- over
    // HTTP a 1 MiB block each. Real ESDs have a few dozen.
    internal const int MaxPackedResources = 4096;
    private const long PackedMarker = 0x100000000L;

    // One decoded chunk for the whole process (spec section 4).
    private static readonly object CacheLock = new();
    private static SolidResource? _cachedResource;
    private static int _cachedChunk;
    private static byte[]? _cachedData;

    private readonly Stream _source;
    private readonly long _dataStart;
    private readonly int _chunkSize;
    private readonly long[] _chunkEnds; // end of each chunk's stored data, relative to _dataStart

    internal SolidResource(Stream source, long fileOffset, long packedLength)
    {
        _source = source;
        if (!source.CanSeek || fileOffset < 0 || packedLength < 16 || packedLength > source.Length ||
            fileOffset > source.Length - packedLength)
            throw new InvalidDataException("A solid resource lies outside the WIM.");

        Span<byte> header = stackalloc byte[16];
        ThrowIfUnavailable();
        source.Position = fileOffset;
        source.ReadExactly(header);
        ulong total = BinaryPrimitives.ReadUInt64LittleEndian(header);
        uint chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        uint method = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
        if (total > long.MaxValue) throw new InvalidDataException("A solid resource is too large.");
        if (chunkSize < 4096 || chunkSize > 64 * 1024 * 1024 || (chunkSize & (chunkSize - 1)) != 0)
            throw new InvalidDataException("A solid resource has an invalid chunk size.");
        if (method != 3) throw new InvalidDataException("A solid resource uses an unsupported compression method.");
        ulong count = total / chunkSize + (total % chunkSize == 0 ? 0UL : 1UL);
        if (count > MaxChunks) throw new InvalidDataException("A solid resource has too many chunks.");
        long tableEnd = 16 + (long)count * 4;
        if (tableEnd > packedLength) throw new InvalidDataException("A solid resource's chunk table does not fit.");

        Length = (long)total;
        ChunkCount = (int)count;
        _chunkSize = (int)chunkSize;
        _dataStart = fileOffset + tableEnd;
        _chunkEnds = new long[ChunkCount];
        byte[] table = new byte[ChunkCount * 4];
        ThrowIfUnavailable();
        source.ReadExactly(table);
        long end = 0, dataLength = packedLength - tableEnd;
        for (int i = 0; i < ChunkCount; i++)
        {
            uint stored = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(i * 4));
            if (stored < 1 || stored > ChunkLength(i)) throw new InvalidDataException("A solid resource has an invalid chunk size entry.");
            end = checked(end + stored);
            if (end > dataLength) throw new InvalidDataException("A solid resource's chunks run past its end.");
            _chunkEnds[i] = end;
        }
        if (end != dataLength) throw new InvalidDataException("A solid resource's chunks do not fill it exactly.");
    }

    internal long Length { get; }
    internal int ChunkCount { get; }

    internal void ThrowIfUnavailable() => (_source as IWimSourceHealth)?.ThrowIfUnavailable();

    internal int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > Length) throw new ArgumentOutOfRangeException(nameof(offset));
        int done = 0;
        while (done < destination.Length && offset < Length)
        {
            int chunk = (int)(offset / _chunkSize);
            int within = (int)(offset % _chunkSize);
            lock (CacheLock)
            {
                if (_cachedResource != this || _cachedChunk != chunk || _cachedData is null)
                {
                    _cachedResource = null;
                    _cachedData = Decode(chunk);
                    _cachedResource = this;
                    _cachedChunk = chunk;
                }
                ThrowIfUnavailable();
                int n = Math.Min(destination.Length - done, _cachedData.Length - within);
                _cachedData.AsSpan(within, n).CopyTo(destination[done..]);
                done += n;
                offset += n;
            }
        }
        return done;
    }

    private int ChunkLength(int chunk) => (int)Math.Min(_chunkSize, Length - (long)chunk * _chunkSize);

    private byte[] Decode(int chunk)
    {
        long start = chunk == 0 ? 0 : _chunkEnds[chunk - 1];
        byte[] input = new byte[_chunkEnds[chunk] - start];
        ThrowIfUnavailable();
        _source.Position = _dataStart + start;
        _source.ReadExactly(input);
        try { return NativeLzms.Decode(input, ChunkLength(chunk)); }
        catch (Win32Exception e) { throw new InvalidDataException("A solid resource chunk could not be decoded.", e); }
    }

    internal static void AssignSolidStreams(List<ResourceInfo> entries, Stream source)
    {
        long totalChunks = 0;
        int packedResources = 0;
        var resources = new List<SolidResource>();
        var starts = new List<long>();
        for (int runStart = 0; runStart < entries.Count;)
        {
            if ((entries[runStart].Header.Flags & ResourceFlags.Solid) == 0) { runStart++; continue; }
            int runEnd = runStart;
            while (runEnd < entries.Count && (entries[runEnd].Header.Flags & ResourceFlags.Solid) != 0) runEnd++;

            for (int i = runStart; i < runEnd; i++)
                if (entries[i].Header.OriginalSize is not (0 or PackedMarker))
                    throw new InvalidDataException("A solid resource entry is neither a packed resource nor a file.");

            resources.Clear();
            starts.Clear();
            long space = 0;
            for (int i = runStart; i < runEnd; i++)
            {
                var h = entries[i].Header;
                if (h.OriginalSize != PackedMarker) continue;
                if (++packedResources > MaxPackedResources) throw new InvalidDataException("The WIM has too many solid resources.");
                var resource = new SolidResource(source, h.FileOffset, h.CompressedSize);
                totalChunks += resource.ChunkCount;
                if (totalChunks > MaxChunks) throw new InvalidDataException("The WIM's solid resources have too many chunks in total.");
                resources.Add(resource);
                starts.Add(space);
                space = checked(space + resource.Length);
            }

            for (int i = runStart; i < runEnd; i++)
            {
                var h = entries[i].Header;
                if (h.OriginalSize != 0) continue;
                // Last resource starting at or before the offset; earlier empty resources share its start.
                int lo = 0, hi = starts.Count;
                while (lo < hi) { int mid = (lo + hi) / 2; if (starts[mid] <= h.FileOffset) lo = mid + 1; else hi = mid; }
                int r = lo - 1;
                if (h.FileOffset < 0 || r < 0 || h.FileOffset >= starts[r] + resources[r].Length)
                    throw new InvalidDataException("A file has no matching solid resource.");
                long within = h.FileOffset - starts[r];
                if (h.CompressedSize > resources[r].Length - within)
                    throw new InvalidDataException("A file exceeds its solid resource.");
                h.SolidResource = resources[r];
                h.SolidOffset = within;
                h.OriginalSize = h.CompressedSize;
            }
            runStart = runEnd;
        }
    }
}

internal sealed class SolidFileStream : SparseStream.ReadOnlySparseStream
{
    private readonly SolidResource _resource;
    private readonly long _start;
    private readonly long _length;
    private long _position;
    private bool _disposed;

    internal SolidFileStream(SolidResource resource, long start, long length)
    {
        if (start < 0 || length < 0 || start > resource.Length - length)
            throw new InvalidDataException("A file lies outside its solid resource.");
        _resource = resource;
        _start = start;
        _length = length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override long Length => _length;
    public override IEnumerable<StreamExtent> Extents => [new StreamExtent(0, _length)];

    public override long Position
    {
        get => _position;
        set
        {
            ThrowIfUnavailable();
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        ThrowIfUnavailable();
        if (_position >= _length || buffer.IsEmpty) return 0;
        int read = _resource.Read(_start + _position, buffer[..(int)Math.Min(buffer.Length, _length - _position)]);
        _position += read;
        return read;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
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
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        Position = next;
        return next;
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _resource.ThrowIfUnavailable();
    }

    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        base.Dispose(disposing);
    }
}
