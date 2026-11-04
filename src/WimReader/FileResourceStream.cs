//
// Copyright (c) 2008-2011, Kenneth Bell
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

using DiscUtils.Compression;
using DiscUtils.Streams;
using LTRData.Extensions.Buffers;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DiscUtils.Wim;

/// <summary>
/// Provides access to a (compressed) resource within the WIM file.
/// </summary>
/// <remarks>Stream access must be strictly sequential.</remarks>
internal class FileResourceStream : SparseStream.ReadOnlySparseStream
{
    private readonly Stream _baseStream;
    private readonly IWimSourceHealth? _sourceHealth;
    // Chunk lengths follow from adjacent offsets; one array per open, not two
    // (two arrays for a 1M-chunk table would pin 16 MB per open handle).
    private readonly long _lastChunkLength;
    private long ChunkLength(int chunk) => chunk == _chunkOffsets.Length - 1 ? _lastChunkLength : _chunkOffsets[chunk + 1] - _chunkOffsets[chunk];

    private readonly long[] _chunkOffsets;
    private readonly int _chunkSize;

    private int _currentChunk;
    private byte[]? _chunkBuffer;
    private ReadOnlyMemory<byte> _currentChunkData;
    private readonly ShortResourceHeader _header;
    private readonly IBlockDecompressor? _blockDecompressor;
    private readonly bool _isLzms;
    private readonly long _offsetDelta;

    private long _position;

    public FileResourceStream(Stream baseStream, ShortResourceHeader header, FileFlags fileFlags, int chunkSize, IWimSourceHealth? sourceHealth = null)
    {
        _baseStream = baseStream;
        _sourceHealth = sourceHealth;
        _header = header;
        _blockDecompressor = GetDecompressor(fileFlags);
        _isLzms = (fileFlags & FileFlags.LzmsCompression) != 0;
        _chunkSize = chunkSize;

        if (_chunkSize < 4096 || _chunkSize > 64 * 1024 * 1024 ||
            (_chunkSize & (_chunkSize - 1)) != 0 || header.OriginalSize <= 0)
            throw new InvalidDataException("Invalid compressed WIM resource dimensions.");
        int codecCount = ((fileFlags & FileFlags.XpressCompression) != 0 ? 1 : 0) +
            ((fileFlags & FileFlags.LzxCompression) != 0 ? 1 : 0) + (_isLzms ? 1 : 0);
        if (codecCount != 1) throw new InvalidDataException("Unsupported or ambiguous WIM compression flags.");
        // The LZX decoder below has a fixed 32 KB window, and Windows writes
        // LZX and XPRESS WIMs only in 32 KB chunks.
        if (!_isLzms && _chunkSize != 32 * 1024)
            throw new InvalidDataException("Unsupported chunk size for LZX or XPRESS WIM resources.");
        // Every open file keeps one decoded chunk, so the chunk size is memory
        // each handle pins in this elevated process. A real LZMS WIM uses 128 KB;
        // 64 MB chunks would let a crafted WIM pin 64 MB per open file. Solid blocks
        // use SolidResource's single shared cache instead.
        if (_isLzms && _chunkSize > 2 * 1024 * 1024)
            throw new InvalidDataException("Unsupported chunk size for LZMS WIM resources.");
        int offsetSize = header.OriginalSize > uint.MaxValue ? 8 : 4;
        long chunkCount = header.OriginalSize / _chunkSize + (header.OriginalSize % _chunkSize == 0 ? 0 : 1);
        if (chunkCount > 1_000_000 || (chunkCount - 1) * offsetSize > baseStream.Length)
            throw new InvalidDataException("Invalid or excessively large WIM chunk table.");
        var numChunks = (int)chunkCount;

        _chunkOffsets = new long[numChunks];
        Span<byte> buffer = stackalloc byte[8];
        for (var i = 1; i < numChunks; ++i)
        {
            _baseStream.ReadExactly(buffer[..offsetSize]);
            ulong rawOffset = offsetSize == 4 ? EndianUtilities.ToUInt32LittleEndian(buffer) : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(buffer);
            if (rawOffset > long.MaxValue) throw new InvalidDataException("WIM chunk offset is too large.");
            _chunkOffsets[i] = (long)rawOffset;
            long length = _chunkOffsets[i] - _chunkOffsets[i - 1];
            if (length <= 0 || length > _chunkSize ||
                _chunkOffsets[i] > baseStream.Length - (numChunks - 1L) * offsetSize)
                throw new InvalidDataException("Invalid compressed WIM chunk offset.");
        }

        _lastChunkLength = _baseStream.Length - _baseStream.Position - _chunkOffsets[numChunks - 1];
        if (_lastChunkLength <= 0 || _lastChunkLength > _chunkSize)
            throw new InvalidDataException("Invalid final compressed WIM chunk length.");
        _offsetDelta = _baseStream.Position;

        _currentChunk = -1;
    }

    private static IBlockDecompressor? GetDecompressor(FileFlags flags)
    {
        if ((flags & FileFlags.LzxCompression) != 0)
        {
            return new Lzx(windowBits: 15);
        }
        else if ((flags & FileFlags.XpressCompression) != 0)
        {
            return XpressHuffman.Default;
        }

        return null;
    }

    protected override void Dispose(bool disposing)
    {
        IsDisposed = true;

        if (disposing)
        {
            if (_blockDecompressor is IDisposable disposable)
            {
                disposable.Dispose();
            }

            if (_chunkBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(_chunkBuffer);
                _chunkBuffer = null;
            }
        }

        base.Dispose(disposing);
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override IEnumerable<StreamExtent> Extents
        => SingleValueEnumerable.Get(new StreamExtent(0, Length));

    public override long Length => _header.OriginalSize;

    public override long Position
    {
        get => _position;

        set { _sourceHealth?.ThrowIfUnavailable(); _position = value; }
    }

    public bool IsDisposed { get; private set; }

    public override int Read(byte[] buffer, int offset, int count)
    {
#if NET7_0_OR_GREATER
        ObjectDisposedException.ThrowIf(IsDisposed, this);
#else
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(FileResourceStream));
        }
#endif

        _sourceHealth?.ThrowIfUnavailable();
        if (_position >= Length)
        {
            return 0;
        }

        var maxToRead = (int)Math.Min(Length - _position, count);

        var totalRead = 0;

        while (totalRead < maxToRead)
        {
            var chunk = (int)(_position / _chunkSize);
            var chunkOffset = (int)(_position % _chunkSize);
            var numToRead = Math.Min(maxToRead - totalRead, _chunkSize - chunkOffset);

            if (numToRead == 0)
            {
                return totalRead;
            }

            if (_currentChunk != chunk || _currentChunkData.IsEmpty)
            {
                _currentChunk = -1;
                _currentChunkData = default;
                _chunkBuffer ??= ArrayPool<byte>.Shared.Rent(_chunkSize);
                _currentChunkData = new(_chunkBuffer, 0, DecompressChunk(chunk, _chunkBuffer));
                _currentChunk = chunk;
            }

            _sourceHealth?.ThrowIfUnavailable();
            _currentChunkData.Span.Slice(chunkOffset, numToRead).CopyTo(buffer.AsSpan(offset + totalRead, numToRead));

            _position += numToRead;
            totalRead += numToRead;
        }

        return totalRead;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
#if NET7_0_OR_GREATER
        ObjectDisposedException.ThrowIf(IsDisposed, this);
#else
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(FileResourceStream));
        }
#endif

        cancellationToken.ThrowIfCancellationRequested();
        _sourceHealth?.ThrowIfUnavailable();
        if (_position >= Length)
        {
            return 0;
        }

        var maxToRead = (int)Math.Min(Length - _position, buffer.Length);

        var totalRead = 0;

        while (totalRead < maxToRead)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var chunk = (int)(_position / _chunkSize);
            var chunkOffset = (int)(_position % _chunkSize);
            var numToRead = Math.Min(maxToRead - totalRead, _chunkSize - chunkOffset);

            if (numToRead == 0)
            {
                return totalRead;
            }

            if (_currentChunk != chunk || _currentChunkData.IsEmpty)
            {
                _currentChunk = -1;
                _currentChunkData = default;
                _chunkBuffer ??= ArrayPool<byte>.Shared.Rent(_chunkSize);
                _currentChunkData = new(_chunkBuffer, 0, await DecompressChunkAsync(chunk, _chunkBuffer, cancellationToken).ConfigureAwait(false));
                _currentChunk = chunk;
            }

            cancellationToken.ThrowIfCancellationRequested();
            _sourceHealth?.ThrowIfUnavailable();
            _currentChunkData.Slice(chunkOffset, numToRead).CopyTo(buffer.Slice(totalRead, numToRead));

            _position += numToRead;
            totalRead += numToRead;
        }

        return totalRead;
    }

    public override int Read(Span<byte> buffer)
    {
#if NET7_0_OR_GREATER
        ObjectDisposedException.ThrowIf(IsDisposed, this);
#else
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(FileResourceStream));
        }
#endif

        _sourceHealth?.ThrowIfUnavailable();
        if (_position >= Length)
        {
            return 0;
        }

        var maxToRead = (int)Math.Min(Length - _position, buffer.Length);

        var totalRead = 0;

        while (totalRead < maxToRead)
        {
            var chunk = (int)(_position / _chunkSize);
            var chunkOffset = (int)(_position % _chunkSize);
            var numToRead = Math.Min(maxToRead - totalRead, _chunkSize - chunkOffset);

            if (numToRead == 0)
            {
                return totalRead;
            }

            if (_currentChunk != chunk || _currentChunkData.IsEmpty)
            {
                _currentChunk = -1;
                _currentChunkData = default;
                _chunkBuffer ??= ArrayPool<byte>.Shared.Rent(_chunkSize);
                _currentChunkData = new(_chunkBuffer, 0, DecompressChunk(chunk, _chunkBuffer));
                _currentChunk = chunk;
            }

            _sourceHealth?.ThrowIfUnavailable();
            _currentChunkData.Span.Slice(chunkOffset, numToRead).CopyTo(buffer.Slice(totalRead, numToRead));

            _position += numToRead;
            totalRead += numToRead;
        }

        return totalRead;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    private int DecompressChunk(int chunk, Memory<byte> buffer)
    {
        var targetUncompressed = _chunkSize;
        if (chunk == _chunkOffsets.Length - 1)
        {
            targetUncompressed = (int)(Length - (long)chunk * _chunkSize);
        }

        var compressedSize = (int)ChunkLength(chunk);

        _baseStream.Position = _offsetDelta + _chunkOffsets[chunk];

        // A chunk that did not compress is stored as is.
        if (ChunkLength(chunk) == targetUncompressed)
        {
            _baseStream.ReadExactly(buffer.Span[..compressedSize]);
            return compressedSize;
        }

        var rawChunk = ArrayPool<byte>.Shared.Rent(compressedSize);
        try
        {
            _baseStream.ReadExactly(rawChunk.AsSpan(0, compressedSize));

            // LZX consumes 16-bit input words; a single byte cannot contain
            // even one complete word. Do not let the decoder pad a truncated
            // word into apparently successful output.
            if (_blockDecompressor is Lzx && compressedSize < 2)
                throw new InvalidDataException("Truncated LZX chunk input.");

            if (_isLzms)
            {
                var compressed = rawChunk.AsSpan(0, compressedSize).ToArray();
                NativeLzms.Decode(compressed, targetUncompressed).AsMemory().CopyTo(buffer);
                return targetUncompressed;
            }

            var bufferSpan = buffer.Span;

            bufferSpan.Clear();

            if (!_blockDecompressor!.TryDecompress(rawChunk.AsSpan(0, compressedSize), bufferSpan[..targetUncompressed], out var bytesWritten) || bytesWritten != targetUncompressed)
            {
                throw new IOException($"Failed to decompress chunk {chunk} in resource at location {_header.FileOffset}");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawChunk);
        }

        return targetUncompressed;
    }

    private async ValueTask<int> DecompressChunkAsync(int chunk, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var targetUncompressed = _chunkSize;
        if (chunk == _chunkOffsets.Length - 1)
        {
            targetUncompressed = (int)(Length - (long)chunk * _chunkSize);
        }

        var compressedSize = (int)ChunkLength(chunk);

        _baseStream.Position = _offsetDelta + _chunkOffsets[chunk];

        // A chunk that did not compress is stored as is.
        if (ChunkLength(chunk) == targetUncompressed)
        {
            await _baseStream.ReadExactlyAsync(buffer[..compressedSize], cancellationToken).ConfigureAwait(false);
            return compressedSize;
        }

        var rawChunk = ArrayPool<byte>.Shared.Rent(compressedSize);
        try
        {
            await _baseStream.ReadExactlyAsync(rawChunk.AsMemory(0, compressedSize), cancellationToken).ConfigureAwait(false);

            if (_blockDecompressor is Lzx && compressedSize < 2)
                throw new InvalidDataException("Truncated LZX chunk input.");

            if (_isLzms)
            {
                var compressed = rawChunk.AsSpan(0, compressedSize).ToArray();
                NativeLzms.Decode(compressed, targetUncompressed).AsMemory().CopyTo(buffer);
                return targetUncompressed;
            }

            if (!_blockDecompressor!.TryDecompress(rawChunk.AsSpan(0, compressedSize), buffer.Span[..targetUncompressed], out var bytesWritten) || bytesWritten != targetUncompressed)
            {
                throw new IOException($"Failed to decompress chunk {chunk} in resource at location {_header.FileOffset}");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawChunk);
        }

        return targetUncompressed;
    }
}
