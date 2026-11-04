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
using System.Collections.Generic;
using System.IO;
using DiscUtils.Core.WindowsSecurity.AccessControl;
using DiscUtils.Internal;
using DiscUtils.Streams;
using System.Linq;
using LTRData.Extensions.Split;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Collections.Immutable;
using System.Threading;

namespace DiscUtils.Wim;

/// <summary>
/// Provides access to the file system within a WIM file image.
/// </summary>
public class WimFileSystem : ReadOnlyDiscFileSystem, IWindowsFileSystem
{
    // Parsed folders, least recently used first, kept up to a total metadata size.
    // DiscUtils' ObjectCache keeps the 20 most recent alive whatever their size, so
    // a small crafted WIM of 20 large folders could pin gigabytes in the elevated
    // process. 64 MB is one folder at the per-folder limit, or many real ones.
    private const long DirectoryCacheBytes = 64L * 1024 * 1024;
    private readonly long _cacheLimit = DirectoryCacheBytes; // A field so a test can shrink it.
    // One folder's metadata. Half the cache, so a folder and the path above it
    // can be cached together (see GetEntry). Real images' largest folders
    // (WinSxS) are around 10 MB.
    private const long MaxDirectoryBytes = 32L * 1024 * 1024;
    private readonly Dictionary<long, LinkedListNode<(long Id, List<DirectoryEntry> Entries, long Bytes)>> _dirCache = new();
    private readonly LinkedList<(long Id, List<DirectoryEntry> Entries, long Bytes)> _dirOrder = new();
    private long _dirCacheBytes;
    private readonly Dictionary<long, long> _directoryByteSizes = new();
    private IReadOnlyList<CollectedInf>? _collectedInfs;
    private Dictionary<string, CollectedInf>? _collectedInfResources;
    // One file served from bytes already checked (--run-sha256), so a later read
    // -- Windows starting the program -- cannot get different bytes from the source.
    private sealed record PinnedContent(string Path, string Hash, byte[] Bytes);
    private volatile PinnedContent? _pinned;
    private sealed class MetadataBudget { public long Remaining = 64L * 1024 * 1024; }
    private WimFile _file;
    private SparseStream _metaDataStream;
    private long _rootDirPos;
    // Raw bytes, checked once on open; each caller gets a fresh descriptor. Kept
    // parsed, a table of tiny ACEs would become an object graph several times its size,
    // held for the whole mount.
    private List<byte[]> _securityDescriptors;

    internal WimFileSystem(WimFile file, SparseStream metaDataStream, string? volumeLabel, long totalBytes)
    {
        _file = file;
        _metaDataStream = metaDataStream;

        ReadSecurityDescriptors();

        VolumeLabel = volumeLabel;
        _totalBytes = totalBytes;
    }

    public override Stream RawStream => _file.FileStream;

    public override string? VolumeLabel { get; }

    /// <summary>
    /// Provides a friendly description of the file system type.
    /// </summary>
    public override string FriendlyName => "Microsoft WIM";

    /// <summary>
    /// Gets the security descriptor associated with the file or directory.
    /// </summary>
    /// <param name="path">The file or directory to inspect.</param>
    /// <returns>The security descriptor.</returns>
    public RawSecurityDescriptor? GetSecurity(string path)
    {
        var id = GetEntry(path)?.SecurityId
            ?? throw new FileNotFoundException("File or directory not found", path);

        // uint.MaxValue is the format's "no descriptor". An id past the end of the
        // table comes from a damaged or crafted image; it means the same thing,
        // and null is what the bridge turns into a clean "invalid parameter".
        // Throwing NotImplementedException, which the bridge does not catch,
        // would make simply viewing a file's permissions fail in a way Windows
        // cannot interpret.
        return id < (uint)_securityDescriptors.Count ? new RawSecurityDescriptor(_securityDescriptors[(int)id], 0) : null;
    }

    /// <summary>
    /// Sets the security descriptor associated with the file or directory.
    /// </summary>
    /// <param name="path">The file or directory to change.</param>
    /// <param name="securityDescriptor">The new security descriptor.</param>
    public void SetSecurity(string path, RawSecurityDescriptor securityDescriptor)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Gets the reparse point data associated with a file or directory.
    /// </summary>
    /// <param name="path">The file to query.</param>
    /// <returns>The reparse point information.</returns>
    public ReparsePoint GetReparsePoint(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        if ((dirEntry.Attributes & FileAttributes.ReparsePoint) == 0)
            throw new IOException("No reparse point");
        var hdr = _file.LocateResource(dirEntry.Hash)
            ?? throw new IOException("No reparse point");

        int size = ValidateReparseDataLength(hdr.OriginalSize);
        using var s = _file.OpenResourceStream(hdr);
        if (s.Length != size) throw new InvalidDataException("WIM reparse data length does not match its resource.");
        var buffer = s.ReadExactly(size);
        return new ReparsePoint((int)dirEntry.ReparseTag, buffer);
    }

    private static int ValidateReparseDataLength(long size)
    {
        // WIM stores the data after the common 8-byte Windows reparse header.
        if (size < 0 || size > 16 * 1024 - 8)
            throw new InvalidDataException("WIM reparse data exceeds the Windows buffer limit.");
        return (int)size;
    }

    /// <summary>
    /// Sets the reparse point data on a file or directory.
    /// </summary>
    /// <param name="path">The file to set the reparse point on.</param>
    /// <param name="reparsePoint">The new reparse point.</param>
    public void SetReparsePoint(string path, ReparsePoint reparsePoint)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Removes a reparse point from a file or directory, without deleting the file or directory.
    /// </summary>
    /// <param name="path">The path to the file or directory to remove the reparse point from.</param>
    public void RemoveReparsePoint(string path)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Gets the short name for a given path.
    /// </summary>
    /// <param name="path">The path to convert.</param>
    /// <returns>The short name.</returns>
    /// <remarks>
    /// This method only gets the short name for the final part of the path, to
    /// convert a complete path, call this method repeatedly, once for each path
    /// segment.  If there is no short name for the given path,<c>null</c> is
    /// returned.
    /// </remarks>
    public string? GetShortName(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        return dirEntry.ShortName;
    }

    /// <summary>
    /// Sets the short name for a given file or directory.
    /// </summary>
    /// <param name="path">The full path to the file or directory to change.</param>
    /// <param name="shortName">The shortName, which should not include a path.</param>
    public void SetShortName(string path, string shortName)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Gets the standard file information for a file.
    /// </summary>
    /// <param name="path">The full path to the file or directory to query.</param>
    /// <returns>The standard file information.</returns>
    public WindowsFileInformation GetFileStandardInformation(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        return new WindowsFileInformation
        {
            CreationTime = FileTime(dirEntry.CreationTime),
            LastAccessTime = FileTime(dirEntry.LastAccessTime),
            ChangeTime =
                FileTime(Math.Max(dirEntry.LastWriteTime,
                    Math.Max(dirEntry.CreationTime, dirEntry.LastAccessTime))),
            LastWriteTime = FileTime(dirEntry.LastWriteTime),
            FileAttributes = dirEntry.Attributes
        };
    }

    /// <summary>
    /// Sets the standard file information for a file.
    /// </summary>
    /// <param name="path">The full path to the file or directory to query.</param>
    /// <param name="info">The standard file information.</param>
    public void SetFileStandardInformation(string path, WindowsFileInformation info)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Gets the names of the alternate data streams for a file.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns>
    /// The list of alternate data streams (or empty, if none).  To access the contents
    /// of the alternate streams, use OpenFile(path + ":" + name, ...).
    /// </returns>
    public IEnumerable<string> GetAlternateDataStreams(string path)
        => GuardSourceHealth(EnumerateAlternateDataStreams(path));

    private IEnumerable<string> EnumerateAlternateDataStreams(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        if (dirEntry.AlternateStreams != null)
        {
            foreach (var altStream in dirEntry.AlternateStreams)
            {
                if (!string.IsNullOrEmpty(altStream.Name))
                {
                    yield return altStream.Name;
                }
            }
        }
    }

    /// <summary>
    /// Gets the file id for a given path.
    /// </summary>
    /// <param name="path">The path to get the id of.</param>
    /// <returns>The file id, or -1.</returns>
    /// <remarks>
    /// The returned file id uniquely identifies the file, and is shared by all hard
    /// links to the same file.  The value -1 indicates no unique identifier is
    /// available, and so it can be assumed the file has no hard links.
    /// </remarks>
    public long GetFileId(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        if (dirEntry.Hash.IsDefaultOrEmpty)
        {
            return -1;
        }

        return MemoryMarshal.Read<long>(dirEntry.Hash.AsSpan())
            ^ MemoryMarshal.Read<long>(dirEntry.Hash.AsSpan()[8..])
            ^ MemoryMarshal.Read<int>(dirEntry.Hash.AsSpan()[16..]);
    }

    /// <summary>
    /// Indicates whether the file is known by other names.
    /// </summary>
    /// <param name="path">The file to inspect.</param>
    /// <returns><c>true</c> if the file has other names, else <c>false</c>.</returns>
    public bool HasHardLinks(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("File or directory not found", path);

        return dirEntry.HardLink != 0u;
    }

    public int GetHardLinkCount(string path)
    {
        return HasHardLinks(path) ? 2 : 1;
    }

    /// <summary>
    /// Indicates if a directory exists.
    /// </summary>
    /// <param name="path">The path to test.</param>
    /// <returns>true if the directory exists.</returns>
    public override bool DirectoryExists(string path)
    {
        var dirEntry = GetEntry(path);
        return dirEntry != null && (dirEntry.Attributes & FileAttributes.Directory) != 0;
    }

    /// <summary>
    /// Indicates if a file exists.
    /// </summary>
    /// <param name="path">The path to test.</param>
    /// <returns>true if the file exists.</returns>
    public override bool FileExists(string path)
    {
        var dirEntry = GetEntry(path);
        return dirEntry != null && (dirEntry.Attributes & FileAttributes.Directory) == 0;
    }

    /// <summary>
    /// Gets the names of subdirectories in a specified directory matching a specified
    /// search pattern, using a value to determine whether to search subdirectories.
    /// </summary>
    /// <param name="path">The path to search.</param>
    /// <param name="searchPattern">The search string to match against.</param>
    /// <param name="searchOption">Indicates whether to search subdirectories.</param>
    /// <returns>Array of directories matching the search pattern.</returns>
    public override IEnumerable<string> GetDirectories(string path, string searchPattern, SearchOption searchOption)
    {
        var filter = WildcardMatcher(searchPattern);

        var dirs = DoSearch(path, filter, searchOption == SearchOption.AllDirectories, true, false);
        return GuardSourceHealth(dirs);
    }

    /// <summary>
    /// Gets the names of files in a specified directory matching a specified
    /// search pattern, using a value to determine whether to search subdirectories.
    /// </summary>
    /// <param name="path">The path to search.</param>
    /// <param name="searchPattern">The search string to match against.</param>
    /// <param name="searchOption">Indicates whether to search subdirectories.</param>
    /// <returns>Array of files matching the search pattern.</returns>
    public override IEnumerable<string> GetFiles(string path, string searchPattern, SearchOption searchOption)
    {
        var re = WildcardMatcher(searchPattern);

        var results = DoSearch(path, re, searchOption == SearchOption.AllDirectories, false, true);
        return GuardSourceHealth(results);
    }

    /// <summary>
    /// Gets the names of all files and subdirectories in a specified directory.
    /// </summary>
    /// <param name="path">The path to search.</param>
    /// <returns>Array of files and subdirectories matching the search pattern.</returns>
    public override IEnumerable<string> GetFileSystemEntries(string path)
    {
        var parentDirEntry = GetEntry(path)
            ?? throw new DirectoryNotFoundException($"The directory '{path}' does not exist");

        if (parentDirEntry.SubdirOffset == 0) return GuardSourceHealth(Array.Empty<string>());
        var parentDir = GetDirectory(parentDirEntry.SubdirOffset);

        return GuardSourceHealth(parentDir.Select(m => Utilities.CombinePaths(path, m.FileName)));
    }

    /// <summary>
    /// Gets the names of files and subdirectories in a specified directory matching a specified
    /// search pattern.
    /// </summary>
    /// <param name="path">The path to search.</param>
    /// <param name="searchPattern">The search string to match against.</param>
    /// <returns>Array of files and subdirectories matching the search pattern.</returns>
    public override IEnumerable<string> GetFileSystemEntries(string path, string searchPattern)
    {
        var filter = WildcardMatcher(searchPattern);

        var parentDirEntry = GetEntry(path)
            ?? throw new DirectoryNotFoundException($"The directory '{path}' does not exist");

        if (parentDirEntry.SubdirOffset == 0) return GuardSourceHealth(Array.Empty<string>());
        var parentDir = GetDirectory(parentDirEntry.SubdirOffset);

        var result = parentDir
            .Where(dirEntry => filter is null || filter(dirEntry.FileName))
            .Select(dirEntry => Utilities.CombinePaths(path, dirEntry.FileName));

        return GuardSourceHealth(result);
    }

    /// <summary>
    /// Gets the names of files and subdirectories in a specified directory matching a specified
    /// search pattern.
    /// </summary>
    /// <param name="path">The path to search.</param>
    /// <param name="searchPattern">The search string to match against.</param>
    /// <param name="searchOption">Indicates whether to search subdirectories.</param>
    /// <returns>Array of files and subdirectories matching the search pattern.</returns>
    public override IEnumerable<string> GetFileSystemEntries(string path, string searchPattern, SearchOption searchOption)
    {
        var re = WildcardMatcher(searchPattern);

        var results = DoSearch(path, re, searchOption == SearchOption.AllDirectories, true, true);
        return GuardSourceHealth(results);
    }

    // Reads a file's default stream whole, and from then on serves exactly those
    // bytes for it. The caller checks them; every later open, including through
    // the mounted drive, gets the same bytes whatever the source does. Paths
    // naming the same content (the WIM keys content by hash) share the pin.
    public byte[] ReadAndPin(string path, int maxBytes)
    {
        SplitFileName(path, out _, out string streamName);
        if (streamName.Length != 0) throw new ArgumentException("Only a file's default stream can be pinned.", nameof(path));
        using var stream = OpenFile(path, FileMode.Open, FileAccess.Read);
        if (stream.Length > maxBytes) throw new InvalidDataException($"The file is larger than {maxBytes / (1024 * 1024)} MB.");
        byte[] bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        _pinned = new PinnedContent(path, Convert.ToHexString(GetFileHash(path).AsSpan()), bytes);
        return bytes;
    }

    /// <summary>
    /// Opens the specified file.
    /// </summary>
    /// <param name="path">The full path of the file to open.</param>
    /// <param name="mode">The file mode for the created stream.</param>
    /// <param name="access">The access permissions for the created stream.</param>
    /// <returns>The new stream.</returns>
    public override SparseStream OpenFile(string path, FileMode mode, FileAccess access)
    {
        if (mode is not FileMode.Open and not FileMode.OpenOrCreate)
        {
            throw new NotSupportedException("No write support for WIM files");
        }

        if (access != FileAccess.Read)
        {
            throw new NotSupportedException("No write support for WIM files");
        }

        _file.Health?.ThrowIfUnavailable();
        SplitFileName(path, out _, out string streamName);
        var streamHash = GetFileHash(path);
        if (streamName.Length == 0 && _pinned is { } pinned &&
            (string.Equals(pinned.Path, path, StringComparison.OrdinalIgnoreCase) || pinned.Hash == Convert.ToHexString(streamHash.AsSpan())))
            return new WimSourceStream(SparseStream.FromStream(new MemoryStream(pinned.Bytes, false), Ownership.Dispose),
                _file.Health);
        if (streamName.Length == 0 && _collectedInfResources is not null &&
            _collectedInfResources.TryGetValue(Convert.ToHexString(streamHash.AsSpan()), out var cached))
            return new WimSourceStream(SparseStream.FromStream(cached.OpenRead(), Ownership.Dispose),
                _file.Health);
        var hdr = _file.LocateResource(streamHash);
        if (hdr == null)
        {
            if (BufferUtilities.IsAllZeros(streamHash.AsSpan()))
            {
                return new WimSourceStream(new ZeroStream(0), _file.Health);
            }

            throw new IOException("Unable to locate file contents");
        }

        return _file.OpenResourceStream(hdr);
    }

    /// <summary>
    /// Gets the attributes of a file or directory.
    /// </summary>
    /// <param name="path">The file or directory to inspect.</param>
    /// <returns>The attributes of the file or directory.</returns>
    public override FileAttributes GetAttributes(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("No such file or directory", path);

        return dirEntry.Attributes;
    }

    /// <summary>
    /// Gets the creation time (in UTC) of a file or directory.
    /// </summary>
    /// <param name="path">The path of the file or directory.</param>
    /// <returns>The creation time.</returns>
    public override DateTime GetCreationTimeUtc(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("No such file or directory", path);

        return FileTime(dirEntry.CreationTime);
    }

    /// <summary>
    /// Gets the last access time (in UTC) of a file or directory.
    /// </summary>
    /// <param name="path">The path of the file or directory.</param>
    /// <returns>The last access time.</returns>
    public override DateTime GetLastAccessTimeUtc(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("No such file or directory", path);

        return FileTime(dirEntry.LastAccessTime);
    }

    /// <summary>
    /// Gets the last modification time (in UTC) of a file or directory.
    /// </summary>
    /// <param name="path">The path of the file or directory.</param>
    /// <returns>The last write time.</returns>
    public override DateTime GetLastWriteTimeUtc(string path)
    {
        var dirEntry = GetEntry(path)
            ?? throw new FileNotFoundException("No such file or directory", path);

        return FileTime(dirEntry.LastWriteTime);
    }

    /// <summary>
    /// Gets the length of a file.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns>The length in bytes.</returns>
    public override long GetFileLength(string path)
    {
        var streamHash = GetFileHash(path);
        var hdr = _file.LocateResource(streamHash);
        if (hdr == null)
        {
            if (BufferUtilities.IsAllZeros(streamHash.AsSpan()))
            {
                return 0;
            }

            throw new IOException("Unable to locate file contents");
        }

        return CheckedLength(hdr) ?? throw new IOException("WIM file length does not match its stored resource.");
    }

    // The length the mounted drive reports to Windows, and nothing on the way
    // here bounds-checks it: a crafted record can declare any value, including a
    // negative one. Uncompressed, the stored bytes are the content, so the two
    // sizes must agree. Compressed, the declared size must fit the chunk table
    // FileResourceStream will demand when the file is opened. Solid sizes were
    // checked against their resource when the table was read. The reparse path
    // keeps its own, stricter check. Null means the record is damaged.
    private long? CheckedLength(ShortResourceHeader hdr)
    {
        long size = hdr.OriginalSize;
        if (size < 0) return null;
        if (hdr.SolidResource is not null) return size;
        if ((hdr.Flags & ResourceFlags.Compressed) == 0) return size == hdr.CompressedSize ? size : null;
        int chunkSize = _file.ChunkSize;
        if (chunkSize <= 0) return null;
        long chunks = size / chunkSize + (size % chunkSize == 0 ? 0 : 1);
        return chunks <= 1_000_000 && (chunks - 1) * (size > uint.MaxValue ? 8 : 4) <= hdr.CompressedSize ? size : null;
    }

    public override DiscFileSystemInfo GetFileSystemInfo(string path)
    {
        var dirEntry = GetEntry(path);
        if (dirEntry == null)
        {
            return new(this, path);
        }

        if (dirEntry.Attributes.HasFlag(FileAttributes.Directory))
        {
            return new CachedDiscDirectoryInfo(this, path, dirEntry.Attributes, FileTime(dirEntry.CreationTime),
                                            FileTime(dirEntry.LastAccessTime),
                                            FileTime(dirEntry.LastWriteTime));
        }

        // With no content resource the file is listed at size 0: either it is
        // genuinely empty (an all-zero hash), or the image is damaged and opening
        // it fails with "Unable to locate file contents" (OpenFile, GetFileLength).
        // That is how NTFS treats unreadable data -- listed, failing on open --
        // and it must not throw here: this runs inside a directory listing, and
        // one damaged file would make its whole folder unlistable. A size that
        // fails the length check is listed as 0 for the same reason. Dokan takes
        // listing sizes from here and GetFileInfo, not GetFileLength.
        var hdr = _file.LocateResource(GetFileHash(path));
        return new CachedDiscFileInfo(this, path, dirEntry.Attributes, FileTime(dirEntry.CreationTime),
                                            FileTime(dirEntry.LastAccessTime),
                                            FileTime(dirEntry.LastWriteTime), hdr is null ? 0 : CheckedLength(hdr) ?? 0);
    }

    public override DiscFileInfo GetFileInfo(string path)
    {
        var dirEntry = GetEntry(path);
        if (dirEntry == null || dirEntry.Attributes.HasFlag(FileAttributes.Directory))
        {
            return new(this, path);
        }

        var hdr = _file.LocateResource(GetFileHash(path));
        if (hdr == null)
        {
            return new(this, path);
        }

        return new CachedDiscFileInfo(this, path, dirEntry.Attributes, FileTime(dirEntry.CreationTime),
                                            FileTime(dirEntry.LastAccessTime),
                                            FileTime(dirEntry.LastWriteTime), CheckedLength(hdr) ?? 0);
    }

    public override DiscDirectoryInfo GetDirectoryInfo(string path)
    {
        var dirEntry = GetEntry(path);
        if (dirEntry == null || !dirEntry.Attributes.HasFlag(FileAttributes.Directory))
        {
            return new(this, path);
        }

        return new CachedDiscDirectoryInfo(this, path, dirEntry.Attributes, FileTime(dirEntry.CreationTime),
                                        FileTime(dirEntry.LastAccessTime),
                                        FileTime(dirEntry.LastWriteTime));
    }

    /// <summary>
    /// Gets the SHA-1 hash of a file's contents.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns>The 160-bit hash.</returns>
    /// <remarks>The WIM file format internally stores the SHA-1 hash of files.
    /// This method provides access to the stored hash.  Callers can use this
    /// value to compare against the actual hash of the byte stream to validate
    /// the integrity of the file contents.</remarks>
    public ImmutableArray<byte> GetFileHash(string path)
    {
        SplitFileName(path, out var filePart, out var altStreamPart);

        var dirEntry = GetEntry(filePart)
            ?? throw new FileNotFoundException("No such file or directory", path);

        if (dirEntry.Attributes.HasFlag(FileAttributes.Directory)
            && string.IsNullOrEmpty(altStreamPart))
        {
            throw new InvalidOperationException($"'{path}' is a directory");
        }

        return dirEntry.GetStreamHash(altStreamPart);
    }

    // The image's own total (its TOTALBYTES in the WIM's manifest), shown as the
    // drive's size, all of it used, as Windows shows a mounted ISO. A manifest
    // without one leaves the size unknown.
    private readonly long _totalBytes;

    /// <summary>
    /// Size of the Filesystem in bytes
    /// </summary>
    // Rounded up to 512 bytes, Dokan's default allocation unit (the mount sets no other):
    // Windows counts the drive in whole units and drops a partial last one, so 6,291,499
    // bytes showed as 6,291,456, less than the image holds.
    public override long Size => _totalBytes <= 0 ? throw new NotSupportedException("Filesystem size is not known")
        : _totalBytes > long.MaxValue - 511 ? _totalBytes : (_totalBytes + 511) & ~511L;

    /// <summary>
    /// Used space of the Filesystem in bytes
    /// </summary>
    public override long UsedSpace => Size;

    /// <summary>
    /// Available space of the Filesystem in bytes
    /// </summary>
    public override long AvailableSpace => _totalBytes > 0 ? 0 : throw new NotSupportedException("Filesystem size is not known");

    public override bool SupportsUsedAvailableSpace => _totalBytes > 0;

    /// <summary>
    /// Disposes of this instance.
    /// </summary>
    /// <param name="disposing"><c>true</c> if disposing, else <c>false</c>.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_metaDataStream != null)
            {
                _metaDataStream.Dispose();
                _metaDataStream = null!;
            }

            _file = null!;
            _collectedInfs = null;
            _collectedInfResources = null;
        }

        base.Dispose(disposing);
    }

    private static void SplitFileName(string path, out string filePart, out string altStreamPart)
    {
        var streamSepPos = path.IndexOf(':');

        if (streamSepPos >= 0)
        {
            filePart = path[..streamSepPos];
            altStreamPart = path[(streamSepPos + 1)..];
            // Win32 names the default data stream file::$DATA. Named data
            // streams remain distinct from the default stream and its cache.
            if (altStreamPart.Equals(":$DATA", StringComparison.OrdinalIgnoreCase)) altStreamPart = string.Empty;
            else if (altStreamPart.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase)) altStreamPart = altStreamPart[..^6];
        }
        else
        {
            filePart = path;
            altStreamPart = string.Empty;
        }
    }

    private IEnumerable<string> GuardSourceHealth(IEnumerable<string> entries)
    {
        _file.Health?.ThrowIfUnavailable();
        foreach (string entry in entries)
        {
            _file.Health?.ThrowIfUnavailable();
            yield return entry;
        }
        _file.Health?.ThrowIfUnavailable();
    }

    /// <summary>Immutable INF bytes and their original image path.</summary>
    public sealed class CollectedInf
    {
        private readonly byte[] _bytes;
        public string ImagePath { get; }
        public int Length => _bytes.Length;
        internal CollectedInf(string path, byte[] bytes) { ImagePath = path; _bytes = bytes; }
        public Stream OpenRead() => new MemoryStream(_bytes, 0, _bytes.Length, writable: false, publiclyVisible: false);
    }

    /// <summary>Walk the image once and read each unnamed INF resource once.</summary>
    // Kept in step with DokanSource.ValidateFileComponents, which this assembly cannot reference.
    private static bool IsDeviceName(string component)
    {
        string name = component.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            (name.Length == 4 && (name.StartsWith("COM", StringComparison.Ordinal) || name.StartsWith("LPT", StringComparison.Ordinal)) &&
             name[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }

    public IReadOnlyList<CollectedInf> CollectInfFiles(CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        _file.Health?.ThrowIfUnavailable();
        if (_collectedInfs is not null) return _collectedInfs;
        const int maxEntries = 1_000_000, maxDepth = 128, maxInfBytes = 32 * 1024 * 1024;
        const long maxContents = 256L * 1024 * 1024, maxPaths = 64L * 1024 * 1024;
        var budget = new MetadataBudget();
        var root = GetDirectory(0, 1, cancellation, budget);
        if (root.Count != 1 || root[0].FileName.Length != 0 ||
            (root[0].Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw new InvalidDataException("Invalid WIM root directory.");
        if (root[0].SubdirOffset == 0) return _collectedInfs = Array.Empty<CollectedInf>();
        var pending = new Stack<(long Id, string Path, int Depth)>();
        var visited = new HashSet<long> { root[0].SubdirOffset };
        var result = new List<CollectedInf>();
        var resources = new Dictionary<string, CollectedInf>(StringComparer.Ordinal);
        pending.Push((root[0].SubdirOffset, "", 0));
        long contents = 0, paths = 0;
        int entries = 0;
        static bool ValidName(string name) => name.Length > 0 && name is not ("." or "..") &&
            name.IndexOfAny(['\\', '/', ':', '\0']) < 0;
        static bool IsInfName(DirectoryEntry e) => e.FileName.EndsWith(".inf", StringComparison.OrdinalIgnoreCase) ||
            (e.ShortName?.EndsWith(".inf", StringComparison.OrdinalIgnoreCase) ?? false);
        while (pending.Count != 0)
        {
            cancellation.ThrowIfCancellationRequested();
            var dir = pending.Pop();
            var children = GetDirectory(dir.Id, maxEntries - entries, cancellation, budget);
            entries += children.Count;
            var aliases = new Dictionary<string, DirectoryEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in children)
            {
                cancellation.ThrowIfCancellationRequested();
                if (!ValidName(entry.FileName) || (!string.IsNullOrEmpty(entry.ShortName) && !ValidName(entry.ShortName)))
                    throw new InvalidDataException("Invalid WIM entry name; INF collection is incomplete.");
                foreach (string? name in new[] { entry.FileName, entry.ShortName })
                {
                    if (string.IsNullOrEmpty(name)) continue;
                    // Only collisions that could change which INF a mounted path names matter.
                    if (aliases.TryGetValue(name, out var other) && !ReferenceEquals(other, entry) &&
                        (((entry.Attributes | other.Attributes) & FileAttributes.Directory) != 0 || IsInfName(entry) || IsInfName(other)))
                        throw new InvalidDataException("Ambiguous WIM entry name; INF collection is incomplete.");
                    aliases[name] = entry;
                }
            }
            foreach (var entry in children)
            {
                cancellation.ThrowIfCancellationRequested();
                // Junctions and links are not followed. An INF that is itself a
                // reparse point cannot be collected, so coverage would be incomplete.
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    if (IsInfName(entry)) throw new InvalidDataException("WIM INF reparse point; INF collection is incomplete.");
                    continue;
                }
                string path = dir.Path + "\\" + entry.FileName;
                paths += 2L * path.Length + 64;
                if (path.Length > 32767 || paths > maxPaths) throw new InvalidDataException("WIM path limit exceeded; INF collection is incomplete.");
                if ((entry.Attributes & FileAttributes.Directory) != 0)
                {
                    if (entry.SubdirOffset == 0) continue;
                    if (dir.Depth >= maxDepth || !visited.Add(entry.SubdirOffset))
                        throw new InvalidDataException("WIM directory depth or identity invalid; INF collection is incomplete.");
                    pending.Push((entry.SubdirOffset, path, dir.Depth + 1));
                    continue;
                }
                if (entry.SubdirOffset != 0) throw new InvalidDataException("WIM file has a directory offset.");
                if (!entry.FileName.EndsWith(".inf", StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.IsNullOrEmpty(entry.ShortName) && entry.ShortName.EndsWith(".inf", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("An INF short name has a non-INF long name; collection is incomplete.");
                    continue;
                }
                // The INF is later handed to Windows by its mounted path, and on
                // some Windows versions a component named like a device (COM1.inf,
                // CON) opens the device, not the file. The same rule as --wim.
                if (path.Split('\\').Any(IsDeviceName))
                    throw new InvalidDataException("An INF path contains a reserved device name; INF collection is incomplete.");
                _file.Health?.ThrowIfUnavailable();
                var contentHash = entry.GetStreamHash(string.Empty);
                var hdr = _file.LocateResource(contentHash);
                if (hdr == null && !BufferUtilities.IsAllZeros(contentHash.AsSpan()))
                    throw new IOException("Unable to locate INF resource.");
                long size = hdr?.OriginalSize ?? 0;
                if (size < 0 || size > maxInfBytes || size > maxContents - contents)
                    throw new InvalidDataException("INF memory limit exceeded; collection is incomplete.");
                byte[] data = new byte[checked((int)size)];
                if (hdr != null)
                {
                    using var source = _file.OpenResourceStream(hdr);
                    int offset = 0;
                    while (offset < data.Length)
                    {
                        cancellation.ThrowIfCancellationRequested();
                        int read = source.Read(data, offset, Math.Min(65536, data.Length - offset));
                        if (read == 0) throw new EndOfStreamException("INF resource ended early.");
                        offset += read;
                    }
                }
                cancellation.ThrowIfCancellationRequested();
                _file.Health?.ThrowIfUnavailable();
                contents += size;
                var collected = new CollectedInf(path, data);
                result.Add(collected);
                resources.TryAdd(Convert.ToHexString(contentHash.AsSpan()), collected);
            }
        }
        cancellation.ThrowIfCancellationRequested();
        _file.Health?.ThrowIfUnavailable();
        _collectedInfResources = resources;
        return _collectedInfs = result.AsReadOnly();
    }

    /// <summary>The most entries one directory may have on the live drive. A real
    /// Windows image's largest folders (WinSxS) hold tens of thousands.</summary>
    public const int MaxDirectoryEntries = 200_000;

    private List<DirectoryEntry> GetDirectory(long id, int? maxEntries = null, CancellationToken cancellation = default, MetadataBudget? budget = null)
    {
        maxEntries ??= MaxDirectoryEntries;
        _file.Health?.ThrowIfUnavailable();
        List<DirectoryEntry>? dir = null;
        if (_dirCache.TryGetValue(id, out var cached))
        {
            _dirOrder.Remove(cached);
            _dirOrder.AddLast(cached);
            dir = cached.Value.Entries;
        }
        // Only a budgeted traversal (the pre-mount INF scan) needs a directory's
        // byte size, so only it records sizes. A directory first cached by an
        // ordinary read -- the root, at least -- has none, so read it again here.
        if (dir != null && budget is not null && !_directoryByteSizes.ContainsKey(id)) dir = null;

        if (dir == null)
        {
            _metaDataStream.Position = id == 0 ? _rootDirPos : id;
            var reader = new LittleEndianDataReader(_metaDataStream);

            dir = [];

            long start = reader.Position;
            long limit = Math.Min(MaxDirectoryBytes, budget?.Remaining ?? long.MaxValue);
            long end = start + Math.Min(limit, _metaDataStream.Length - start);
            var entry = DirectoryEntry.ReadFrom(reader, end, cancellation);

            while (entry != null)
            {
                cancellation.ThrowIfCancellationRequested();
                if (maxEntries.HasValue && dir.Count >= maxEntries.Value)
                    throw new InvalidDataException("WIM directory entry limit exceeded.");
                dir.Add(entry);
                if (reader.Position - start > MaxDirectoryBytes)
                    throw new InvalidDataException("WIM directory metadata byte limit exceeded.");
                entry = DirectoryEntry.ReadFrom(reader, end, cancellation);
            }

            // Recorded during a budgeted traversal only. Recording on every read
            // would fill this dictionary as Windows Search or Defender walks a large
            // image, and at 100,000 directories every new folder on the live drive
            // would fail. The cap still bounds the pre-mount scan, where failing is safe.
            if (budget is not null)
            {
                if (!_directoryByteSizes.ContainsKey(id) && _directoryByteSizes.Count >= 100_000)
                    throw new InvalidDataException("WIM directory bookkeeping limit exceeded.");
                _directoryByteSizes[id] = reader.Position - start;
            }
            if (_dirCache.Remove(id, out var replaced))
            {
                _dirOrder.Remove(replaced);
                _dirCacheBytes -= replaced.Value.Bytes;
            }
            long bytes = reader.Position - start;
            _dirCache[id] = _dirOrder.AddLast((id, dir, bytes));
            _dirCacheBytes += bytes;
            while (_dirCacheBytes > _cacheLimit && _dirOrder.First != _dirOrder.Last)
            {
                var oldest = _dirOrder.First!;
                _dirOrder.RemoveFirst();
                _dirCache.Remove(oldest.Value.Id);
                _dirCacheBytes -= oldest.Value.Bytes;
            }
        }

        if (maxEntries.HasValue && dir.Count > maxEntries.Value)
            throw new InvalidDataException("WIM directory entry limit exceeded.");
        if (budget is not null)
        {
            if (!_directoryByteSizes.TryGetValue(id, out long size) || size > budget.Remaining)
                throw new InvalidDataException("WIM traversal metadata byte limit exceeded.");
            budget.Remaining -= size;
        }
        return dir;
    }

    [MemberNotNull(nameof(_securityDescriptors))]
    private void ReadSecurityDescriptors()
    {
        var reader = new LittleEndianDataReader(_metaDataStream);

        var startPos = reader.Position;

        var totalLength = reader.ReadUInt32();
        var numEntries = reader.ReadUInt32();
        if (totalLength < 8 || totalLength > 16 * 1024 * 1024 || // real tables are hundreds of KB
            startPos > _metaDataStream.Length - totalLength ||
            numEntries > (totalLength - 8) / 8 || numEntries > 100_000)
            throw new InvalidDataException("Invalid WIM security descriptor table.");
        var sdLengths = new ulong[numEntries];

        for (uint i = 0; i < numEntries; ++i)
        {
            sdLengths[i] = reader.ReadUInt64();
        }

        _securityDescriptors = new List<byte[]>((int)numEntries);
        for (uint i = 0; i < numEntries; ++i)
        {
            if (sdLengths[i] > int.MaxValue || sdLengths[i] > (ulong)(startPos + totalLength - reader.Position))
                throw new InvalidDataException("Invalid WIM security descriptor length.");
            var descriptor = reader.ReadBytes((int)sdLengths[i]);
            if (descriptor.Length != (int)sdLengths[i]) throw new EndOfStreamException("Truncated WIM security descriptor.");
            _ = new RawSecurityDescriptor(descriptor, 0); // A malformed one still fails the open.
            _securityDescriptors.Add(descriptor);
        }

        if (reader.Position < startPos + totalLength)
        {
            reader.Skip((int)(startPos + totalLength - reader.Position));
        }

        _rootDirPos = MathUtilities.RoundUp(startPos + totalLength, 8);
    }

    // A time stored in the WIM, as Windows shows it. One a crafted image makes
    // impossible (negative, or past year 9999) reads as 1601-01-01 rather than
    // throwing: these run inside directory listings, where one bad entry would make
    // its whole folder unlistable.
    private static DateTime FileTime(long value) =>
        DateTime.FromFileTimeUtc(value is >= 0 and <= 0x24C85A5ED1C03FFF ? value : 0);

    // Null means "accept everything", which is what callers already test for.
    private static Func<string, bool>? WildcardMatcher(string? searchPattern) =>
        WildcardFilter.MatchesAll(searchPattern)
            ? null
            : name => WildcardFilter.Matches(name, searchPattern);

    private DirectoryEntry? GetEntry(string path)
    {
        // Windows asks about a named stream as "file:Stream", and the bridge does
        // exactly that for every stream it lists. No stored name may contain ':',
        // so without this a folder holding any named stream cannot be listed at
        // all: the lookup fails and the exception escapes the enumeration Dokan
        // is filling. Attributes and times of a stream are the host file's, which
        // is what NTFS reports. OpenFile and GetFileHash already split this way.
        SplitFileName(path, out path, out string stream);
        // A stream name belongs to the last path component only. SplitFileName
        // splits at the first ':', so a ':' earlier in the path would otherwise
        // be read as one, and "\Windows:x\System32" resolved to \Windows. No
        // stored name may contain ':', so such a path names nothing.
        if (stream.Contains('\\') || stream.Contains('/')) return null;

        if (path.EndsWithDirectorySeparator())
        {
            path = path[..^1];
        }

        if (!string.IsNullOrEmpty(path) && !path.StartsWithDirectorySeparator())
        {
            path = Path.DirectorySeparatorChar + path;
        }

        return GetEntry(path.AsMemory().TokenEnum('/', '\\').ToArray());
    }

    // Name lookup per cached directory, built on first use and dropped with the
    // directory. A linear scan per lookup would make listing an N-entry folder cost
    // N^2 (Explorer asks for each entry's details by name), so one large folder
    // in a hostile WIM could stall the single-threaded drive for minutes or hours.
    // First entry wins, by long or short name.
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<List<DirectoryEntry>, Dictionary<string, DirectoryEntry>> _dirIndex = new();

    private Dictionary<string, DirectoryEntry> Index(List<DirectoryEntry> dir) => _dirIndex.GetValue(dir, entries =>
    {
        var byName = new Dictionary<string, DirectoryEntry>(entries.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            byName.TryAdd(entry.FileName, entry);
            if (!string.IsNullOrEmpty(entry.ShortName)) byName.TryAdd(entry.ShortName, entry);
        }
        return byName;
    });

    private long CachedBytes(long id) => _dirCache.TryGetValue(id, out var node) ? node.Value.Bytes : 0;

    private DirectoryEntry? GetEntry(ReadOnlyMemory<char>[] path)
    {
        var currentDir = GetDirectory(0);
        long pathBytes = CachedBytes(0);
        DirectoryEntry? nextEntry = null;

        for (var i = 0; i < path.Length; ++i)
        {
            if (!Index(currentDir).TryGetValue(path[i].ToString(), out nextEntry))
            {
                return null;
            }

            // Only a folder on the way down is read. Reading the last one's own
            // contents would serve nothing, and make listing a folder of N subfolders
            // parse all N of them: a crafted WIM could stall the drive that way.
            if (i < path.Length - 1)
            {
                if (nextEntry.SubdirOffset == 0) return null;
                currentDir = GetDirectory(nextEntry.SubdirOffset);
                // The folders on one path must fit the cache together. Otherwise each
                // lookup evicts the folders the next one needs, and listing a folder
                // re-reads the whole path once per entry. Within the limit the path is
                // always the most recently used, so it stays cached.
                pathBytes += CachedBytes(nextEntry.SubdirOffset);
                if (pathBytes > _cacheLimit)
                    throw new InvalidDataException("The folders on this WIM path hold more metadata than the reader caches.");
            }
        }

        return nextEntry;
    }

    // Iterative, and each directory is visited once. A recursive walk with no
    // record of where it had been would let a crafted image whose folder points
    // back at an ancestor -- or one merely nested very deep -- recurse until the
    // stack overflowed, which .NET cannot catch: the elevated process would simply end.
    // CollectInfFiles already guards this way.
    private IEnumerable<string> DoSearch(string path, Func<string, bool>? filter, bool subFolders, bool dirs, bool files)
    {
        var parentDirEntry = GetEntry(path)
            ?? throw new DirectoryNotFoundException($"Directory '{path}' not found");

        var visited = new HashSet<long>();
        var pending = new Stack<(string Path, long Offset)>();
        if (parentDirEntry.SubdirOffset != 0) pending.Push((path, parentDirEntry.SubdirOffset));
        while (pending.Count > 0)
        {
            var (directory, offset) = pending.Pop();
            if (!visited.Add(offset)) continue;
            foreach (var de in GetDirectory(offset))
            {
                var isDir = (de.Attributes & FileAttributes.Directory) != 0;
                string full = Utilities.CombinePaths(directory, de.FileName);
                if (((isDir && dirs) || (!isDir && files)) && (filter is null || filter(de.FileName)))
                    yield return full;
                if (subFolders && isDir && de.SubdirOffset != 0)
                    pending.Push((full, de.SubdirOffset));
            }
        }
    }
}

