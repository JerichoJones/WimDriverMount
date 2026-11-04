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
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace DiscUtils.Wim;

/// <summary>
/// Provides access to the contents of WIM (Windows Imaging) files.
/// </summary>
public class WimFile
{
    private readonly FileHeader _fileHeader;
    private Dictionary<string, ResourceInfo> _resources;

    /// <summary>
    /// Initializes a new instance of the WimFile class.
    /// </summary>
    /// <param name="stream">A stream of the WIM file contents.</param>
    public WimFile(Stream stream) : this([stream]) { }

    /// <summary>
    /// Opens a WIM from all of its parts, in order: one stream for a normal WIM,
    /// or every .swm of a split WIM, first part first. Each part is read where it
    /// is; nothing is joined or copied. The caller owns and disposes the streams.
    /// </summary>
    public WimFile(IReadOnlyList<Stream> parts)
    {
        if (parts.Count is < 1 or > MaxParts) throw new ArgumentException($"A WIM has 1 to {MaxParts} parts.", nameof(parts));
        FileStream = parts[0];
        _parts = parts;

        _fileHeader = parts[0].ReadStruct<FileHeader>(512);

        if (!_fileHeader.IsValid())
        {
            throw new IOException("Not a valid WIM file");
        }

        // A single WIM's own part number is not checked: it is not
        // needed to read it.
        if (_fileHeader.TotalParts != parts.Count || (parts.Count > 1 && _fileHeader.PartNumber != 1))
        {
            throw new NotSupportedException(_fileHeader.PartNumber == 1
                ? $"This split WIM has {_fileHeader.TotalParts} parts, but {parts.Count} were given; every part is needed."
                : $"This file is part {_fileHeader.PartNumber} of a split WIM with {_fileHeader.TotalParts} parts. Open the first part; the others are found beside it.");
        }

        // Microsoft's WIM format: the first part holds the header and all
        // metadata; every part carries the same GUID, the part count, its own
        // part number and its own lookup table. A part from another split set,
        // a missing or reordered part, or a different compression is refused.
        _partHeaders = new FileHeader[parts.Count];
        _partHeaders[0] = _fileHeader;
        for (int i = 1; i < parts.Count; i++)
        {
            parts[i].Position = 0;
            var header = parts[i].ReadStruct<FileHeader>(512);
            const FileFlags Codec = FileFlags.Compression | FileFlags.XpressCompression | FileFlags.LzxCompression | FileFlags.LzmsCompression;
            if (!header.IsValid() || header.WimGuid != _fileHeader.WimGuid || header.TotalParts != _fileHeader.TotalParts ||
                header.PartNumber != i + 1 || (header.Flags & Codec) != (_fileHeader.Flags & Codec) ||
                header.CompressionSize != _fileHeader.CompressionSize)
                throw new InvalidDataException($"Split WIM part {i + 1} does not belong with part 1 (different set, order or compression).");
            _partHeaders[i] = header;
        }

        Health = parts.Count == 1 ? parts[0] as IWimSourceHealth : new PartsHealth(parts);
        ReadResourceTable();
    }

    /// <summary>The most parts a split WIM may have. DISM's smallest part is
    /// 1 MB, but a real split set is a handful of 4 GB or DVD-sized parts.</summary>
    public const int MaxParts = 100;

    private readonly IReadOnlyList<Stream> _parts;
    private readonly FileHeader[] _partHeaders;

    /// <summary>Reports a failed source, whichever part it was.</summary>
    internal IWimSourceHealth? Health { get; }

    private sealed class PartsHealth(IReadOnlyList<Stream> parts) : IWimSourceHealth
    {
        public void ThrowIfUnavailable()
        {
            foreach (var part in parts) (part as IWimSourceHealth)?.ThrowIfUnavailable();
        }
    }

    /// <summary>
    /// Gets the (zero-based) index of the bootable image.
    /// </summary>
    public int BootImage => (int)_fileHeader.BootIndex;

    /// <summary>
    /// Gets the version of the file format.
    /// </summary>
    public int FileFormatVersion => (int)_fileHeader.Version;

    /// <summary>
    /// Gets the identifying GUID for this WIM file.
    /// </summary>
    public Guid Guid => _fileHeader.WimGuid;

    /// <summary>
    /// Gets the number of disk images within this file.
    /// </summary>
    public int ImageCount => (int)_fileHeader.ImageCount;

    /// <summary>
    /// Gets the embedded manifest describing the file and the contained images.
    /// </summary>
    public string Manifest
    {
        get
        {
            // The declared size is attacker-chosen and compresses to almost
            // nothing; a real manifest is tens of kilobytes.
            using var stream = OpenResourceStream(_fileHeader.XmlDataHeader);
            if (stream.Length > MaxManifestBytes) throw new InvalidDataException("The WIM's XML manifest is too large.");
            using var reader = new StreamReader(stream, true);
            return reader.ReadToEnd();
        }
    }

    private const int MaxManifestBytes = 16 * 1024 * 1024;

    public Stream FileStream { get; }

    internal int ChunkSize => _fileHeader.CompressionSize;

    /// <summary>
    /// Gets a particular image within the file (zero-based index).
    /// </summary>
    /// <param name="index">The index of the image to retrieve.</param>
    /// <returns>The image as a file system.</returns>
    /// <remarks>The XML manifest file uses a one-based index, whereas this
    /// method is zero-based.</remarks>
    public WimFileSystem GetImage(int index)
        => TryGetImage(index, out var image)
        ? image :
        throw new ArgumentException($"No such image: {index}", nameof(index));

    /// <summary>
    /// Gets a particular image within the file (zero-based index).
    /// </summary>
    /// <param name="index">The index of the image to retrieve.</param>
    /// <param name="wimFileSystem">The image as a file system.</param>
    /// <returns>True if index was found in the image and a file system
    /// was returned in <paramref name="wimFileSystem"/>, otherwise false.</returns>
    /// <remarks>The XML manifest file uses a one-based index, whereas this
    /// method is zero-based.</remarks>
    public bool TryGetImage(int index, [NotNullWhen(true)] out WimFileSystem? wimFileSystem)
    {
        var metaDataFileInfo = LocateImage(index);

        if (metaDataFileInfo is null)
        {
            wimFileSystem = null;
            return false;
        }

        // A WIM manifest has no DTD; refusing one rules out entity expansion. The
        // name is read in one pass with no document tree: 16 MB of tiny elements
        // would otherwise become millions of objects.
        string? volumeLabel = null;
        long totalBytes = 0;
        bool totalSeen = false;
        string wanted = (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
        using (var xml = System.Xml.XmlReader.Create(new StringReader(Manifest),
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null }))
        {
            // WIM/IMAGE[@INDEX=n]/NAME and TOTALBYTES: depth 0, 1 and 2; the first of each wins.
            bool inImage = false;
            while ((volumeLabel is null || !totalSeen) && xml.Read())
            {
                if (xml.NodeType != System.Xml.XmlNodeType.Element) continue;
                if (xml.Depth == 0 && xml.Name != "WIM") break;
                if (xml.Depth == 1) inImage = xml.Name == "IMAGE" && xml.GetAttribute("INDEX") == wanted;
                else if (xml.Depth == 2 && inImage && xml.Name == "NAME" && volumeLabel is null) volumeLabel = TextOf(xml);
                else if (xml.Depth == 2 && inImage && xml.Name == "TOTALBYTES" && !totalSeen)
                {
                    totalSeen = true;
                    // A size the manifest gets wrong only mislabels the drive; a missing or odd one is left unknown.
                    if (!long.TryParse(TextOf(xml).Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out totalBytes)) totalBytes = 0;
                }
            }
            // Read to the end, so a damaged manifest is refused wherever the damage is.
            while (xml.Read()) { }
        }

        var metaDataStream = OpenResourceStream(metaDataFileInfo);

        wimFileSystem = new WimFileSystem(this, metaDataStream, volumeLabel, totalBytes);

        return true;
    }

    /// <summary>
    /// Each image's NAME from the XML manifest, by one-based index; null where an image has none.
    /// </summary>
    public IReadOnlyList<string?> ImageNames()
    {
        var names = new string?[Math.Max(ImageCount, 0)];
        using var xml = System.Xml.XmlReader.Create(new StringReader(Manifest),
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        int image = -1;
        while (xml.Read())
        {
            if (xml.NodeType != System.Xml.XmlNodeType.Element) continue;
            if (xml.Depth == 0 && xml.Name != "WIM") break;
            if (xml.Depth == 1)
                image = xml.Name == "IMAGE" && int.TryParse(xml.GetAttribute("INDEX"), System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out int index) && index >= 1 && index <= names.Length ? index - 1 : -1;
            else if (xml.Depth == 2 && image >= 0 && xml.Name == "NAME" && names[image] is null) names[image] = TextOf(xml);
        }
        return names;
    }

    // All text inside the current element, as XElement.Value gives it.
    private static string TextOf(System.Xml.XmlReader xml)
    {
        if (xml.IsEmptyElement) return string.Empty;
        var text = new StringBuilder();
        int depth = xml.Depth;
        while (xml.Read() && xml.Depth > depth)
            if (xml.NodeType is System.Xml.XmlNodeType.Text or System.Xml.XmlNodeType.CDATA or
                System.Xml.XmlNodeType.Whitespace or System.Xml.XmlNodeType.SignificantWhitespace)
                text.Append(xml.Value);
        return text.ToString();
    }

    internal ShortResourceHeader? LocateImage(int index)
    {
        var i = 0;

        using var s = OpenResourceStream(_fileHeader.OffsetTableHeader);
        long numRead = 0;
        Span<byte> resBuffer = stackalloc byte[ResourceInfo.Size];
        while (numRead < s.Length)
        {
            s.ReadExactly(resBuffer);
            numRead += ResourceInfo.Size;

            var info = new ResourceInfo();
            info.Read(resBuffer);

            if ((info.Header.Flags & ResourceFlags.MetaData) != 0)
            {
                if (i == index)
                {
                    return info.Header;
                }

                ++i;
            }
        }

        return null;
    }

    internal ShortResourceHeader? LocateResource(ImmutableArray<byte> hash)
    {
        if (hash.IsDefaultOrEmpty || BufferUtilities.IsAllZeros(hash.AsSpan()))
        {
            return null;
        }

        return _resources.TryGetValue(Convert.ToHexString(hash.AsSpan()), out var info) ? info.Header : null;
    }

    internal SparseStream OpenResourceStream(ShortResourceHeader hdr)
    {
        if (hdr.SolidResource is not null)
            return new SolidFileStream(hdr.SolidResource, hdr.SolidOffset, hdr.OriginalSize);

        // A resource is read from the part that holds it; headers that come from
        // the first part's own header (XML, lookup table, metadata) have none set.
        Stream source = hdr.Part ?? FileStream;
        long sourceLength = source.Length;
        if (hdr.FileOffset < 0 || hdr.CompressedSize < 0 || hdr.FileOffset > sourceLength ||
            hdr.CompressedSize > sourceLength - hdr.FileOffset)
            throw new IOException("WIM resource section is outside the source stream.");

        SparseStream fileSectionStream = new SubStream(source, Ownership.None, hdr.FileOffset,
            hdr.CompressedSize);

        if ((hdr.Flags & ResourceFlags.Compressed) == 0)
        {
            return new WimSourceStream(fileSectionStream, source as IWimSourceHealth);
        }

        return new FileResourceStream(fileSectionStream, hdr, _fileHeader.Flags,
            _fileHeader.CompressionSize, source as IWimSourceHealth);
    }

    [MemberNotNull(nameof(_resources))]
    private void ReadResourceTable()
    {
        _resources = [];
        var entries = new List<ResourceInfo>();
        Span<byte> resBuffer = stackalloc byte[ResourceInfo.Size];
        for (int part = 0; part < _parts.Count; part++)
        {
            var table = _partHeaders[part].OffsetTableHeader;
            if (part > 0) table.Part = _parts[part];
            using var s = OpenResourceStream(table);
            // s.Length is the table's DECLARED uncompressed size, so it is
            // attacker-chosen: a table of zeros compresses to almost nothing,
            // and each record costs a ResourceInfo, a hash array, a 40-char hex
            // string and a dictionary entry. At 5,000,000 that would be over a
            // gigabyte from a few hundred KB of input. A real install.wim has
            // well under 200,000 records, so 300,000 is still 50x headroom.
            // The cap is on all parts together, so splitting cannot multiply it.
            if (s.Length < 0 || s.Length % ResourceInfo.Size != 0 || entries.Count + s.Length / ResourceInfo.Size > 300_000)
                throw new InvalidDataException("Invalid or excessively large WIM resource table.");
            long numRead = 0;
            while (numRead < s.Length)
            {
                s.ReadExactly(resBuffer);
                numRead += ResourceInfo.Size;
                var info = new ResourceInfo();
                info.Read(resBuffer);
                if (_parts.Count > 1)
                {
                    // Each part's table lists only what that part holds.
                    if (info.PartNumber != part + 1)
                        throw new InvalidDataException($"Split WIM part {part + 1} lists a resource it says is in part {info.PartNumber}.");
                    if ((info.Header.Flags & ResourceFlags.Solid) != 0)
                        throw new NotSupportedException("A split WIM with solid (ESD) resources is not supported; DISM does not make one.");
                    info.Header.Part = _parts[part];
                }
                entries.Add(info);
            }
        }
        // Streams stored in solid resources (ESD, recovery compression); see
        // SOLID-RESOURCE-SPEC.md. Only a single-part WIM reaches here with any.
        SolidResource.AssignSolidStreams(entries, FileStream);
        foreach (var info in entries)
        {
            _resources.TryAdd(Convert.ToHexString(info.Hash.AsSpan()), info);
        }
    }
}
