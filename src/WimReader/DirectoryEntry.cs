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

using System;
using System.Collections.Immutable;
using System.IO;
using System.Text;
using DiscUtils.Internal;
using DiscUtils.Streams;
using LTRData.Extensions.Buffers;

namespace DiscUtils.Wim;

internal class DirectoryEntry
{
    private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);
    public FastDictionary<AlternateStreamEntry>? AlternateStreams;
    public FileAttributes Attributes;
    public long CreationTime;
    public string FileName = null!;
    public uint HardLink;
    public ImmutableArray<byte> Hash;
    public long LastAccessTime;
    public long LastWriteTime;
    public long Length;
    public uint ReparseTag;
    public uint SecurityId;
    public string? ShortName;
    public ushort StreamCount;
    public long SubdirOffset;

    public static DirectoryEntry? ReadFrom(DataReader reader, long metadataEnd, CancellationToken cancellation)
    {
        var startPos = reader.Position;

        cancellation.ThrowIfCancellationRequested();
        if (startPos < 0 || startPos > metadataEnd - 8) throw new InvalidDataException("Truncated WIM directory entry.");
        var length = reader.ReadInt64();
        if (length == 0)
        {
            return null;
        }

        if (length < 102 || length > 1024 * 1024 || length > metadataEnd - startPos)
            throw new InvalidDataException("Invalid WIM directory entry length.");
        long entryEnd = startPos + length;

        var result = new DirectoryEntry
        {
            Length = length,
            Attributes = (FileAttributes)reader.ReadUInt32(),
            SecurityId = reader.ReadUInt32(),
            SubdirOffset = reader.ReadInt64()
        };
        reader.Skip(16);
        result.CreationTime = reader.ReadInt64();
        result.LastAccessTime = reader.ReadInt64();
        result.LastWriteTime = reader.ReadInt64();

        var hash = reader.ReadBytes(20);

        if (!BufferUtilities.IsAllZeros(hash))
        {
            result.Hash = hash.ToImmutableArray();
        }

        reader.Skip(4);
        result.ReparseTag = reader.ReadUInt32();
        result.HardLink = reader.ReadUInt32();
        result.StreamCount = reader.ReadUInt16();
        int shortNameLength = reader.ReadUInt16();
        int fileNameLength = reader.ReadUInt16();

        if (result.StreamCount > 128 || (shortNameLength & 1) != 0 || (fileNameLength & 1) != 0 ||
            (long)shortNameLength + fileNameLength + 2 > entryEnd - reader.Position)
            throw new InvalidDataException("Invalid WIM directory names or stream count.");

        byte[] fileNameData = reader.ReadBytes(fileNameLength + 2);
        if (fileNameData.Length != fileNameLength + 2 || fileNameData[^1] != 0 || fileNameData[^2] != 0) throw new InvalidDataException("Invalid WIM file name.");
        result.FileName = StrictUnicode.GetString(fileNameData, 0, fileNameLength);

        if (shortNameLength > 0)
        {
            byte[] data = reader.ReadBytes(shortNameLength);
            if (data.Length != shortNameLength) throw new InvalidDataException("Invalid WIM short name.");
            result.ShortName = StrictUnicode.GetString(data);
        }
        else
        {
            result.ShortName = null;
        }

        static bool InvalidComponent(string? name) => name is not null &&
            (name is "." or ".." || name.IndexOfAny(new[] { '\\', '/', ':', '\0' }) >= 0 ||
             (name.Length > 0 && (name[^1] == '.' || name[^1] == ' ')));
        if (InvalidComponent(result.FileName) || InvalidComponent(result.ShortName))
            throw new InvalidDataException("A WIM directory entry contains an invalid path component.");

        if (entryEnd > reader.Position)
        {
            var toRead = (int)(entryEnd - reader.Position);
            reader.Skip(toRead);
        }

        if (result.StreamCount > 0)
        {
            result.AlternateStreams = new FastDictionary<AlternateStreamEntry>(StringComparer.OrdinalIgnoreCase, static entry => entry.Name);

            for (var i = 0; i < result.StreamCount; ++i)
            {
                cancellation.ThrowIfCancellationRequested();
                var stream = AlternateStreamEntry.ReadFrom(reader, metadataEnd);

                if (stream is not null)
                {
                    if (stream.Name == "" && i != 0)
                        throw new InvalidDataException("Unnamed WIM stream is not first.");
                    if (result.AlternateStreams.Contains(stream.Name))
                        throw new InvalidDataException("Duplicate WIM alternate stream name.");
                    result.AlternateStreams.Add(stream);

                    if (stream.Name == "" && !BufferUtilities.IsAllZeros(result.Hash.AsSpan()) &&
                        !result.Hash.AsSpan().SequenceEqual(stream.Hash.AsSpan()))
                        throw new InvalidDataException("Conflicting WIM file stream hashes.");

                    if (stream.Name == "" && BufferUtilities.IsAllZeros(result.Hash.AsSpan()))
                    {
                        result.Hash = stream.Hash;
                    }
                }
            }
        }

        return result;
    }

    public ImmutableArray<byte> GetStreamHash(string streamName)
    {
        if (string.IsNullOrEmpty(streamName))
        {
            if (!BufferUtilities.IsAllZeros(Hash.AsSpan()))
            {
                return Hash;
            }
        }

        if (AlternateStreams != null && AlternateStreams.TryGetValue(streamName, out var streamEntry))
        {
            return streamEntry.Hash;
        }

        return default;
    }
}
