# Solid WIM resources: implementation spec

Purpose: the clean-room specification for `SolidResource.cs`. The previous
implementation was derived from 7-Zip's LGPL `WimIn.cpp`. This document states
only facts about the on-disk format, the interface the rest of this reader
expects, and this project's own safety rules. It contains no code from that
implementation, and the new implementation is written from this document alone.

## 1. Where solid resources appear

A WIM's resource table is an array of 50-byte entries:

| Offset | Size | Field |
|---|---|---|
| 0 | 7 | Stored size (little-endian, 56 bits) |
| 7 | 1 | Resource flags |
| 8 | 8 | File offset (little-endian, signed) |
| 16 | 8 | Original size (little-endian, signed) |
| 24 | 2 | Part number |
| 26 | 4 | Reference count |
| 30 | 20 | SHA-1 of the stream's uncompressed content |

This reader already parses entries into `ResourceInfo` (`Header` is a
`ShortResourceHeader` with `CompressedSize`, `FileOffset`, `OriginalSize`,
`Flags`). Flag `0x10` (`ResourceFlags.Solid`) marks an entry as part of solid
("packed") storage, used by ESD files and `/Compress:recovery` WIMs.

Solid entries come in **runs**: maximal sequences of consecutive table entries
that all carry the solid flag. A table can hold several runs, separated by
non-solid entries. Each run is independent of the others.

Within a run, each entry is one of two kinds, told apart by its Original size
field:

- **Solid resource** (Original size field = `0x100000000`, exactly 2^32): a
  compressed container stored in the WIM. File offset = where it starts in the
  WIM file. Stored size = its total length in the WIM, header included.
- **Stream inside solid storage** (Original size field = `0`): one file's
  content. Here the fields are reused: File offset = where the stream starts
  within the run's *uncompressed space*, and Stored size = the stream's
  uncompressed length.
- Any other Original size value on a solid entry means the file is corrupt.

The run's **uncompressed space** is the uncompressed contents of the run's
solid resources laid end to end, in table order. Resource 0 occupies
`[0, len0)`, resource 1 occupies `[len0, len0 + len1)`, and so on. A stream's
File offset is a position in that space. This reader requires every stream to
lie entirely within one solid resource. A stream that starts in one and runs
into the next, or starts past the end, is corrupt.

## 2. A solid resource on disk

At its File offset, spanning exactly its Stored size:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Total uncompressed size `U` (little-endian, unsigned) |
| 8 | 4 | Chunk size `C` (little-endian) |
| 12 | 4 | Compression method (little-endian); `3` means LZMS |
| 16 | 4 × N | Stored size of each chunk, in order (little-endian u32) |
| 16 + 4N | rest | Chunk data, concatenated in order |

- `N` = the number of chunks = `ceil(U / C)`. If `U` is 0, N is 0.
- Chunk `i` uncompresses to `C` bytes, except the last, which uncompresses to
  whatever remains of `U`.
- A chunk whose stored size equals its uncompressed size is stored
  uncompressed. Otherwise it is raw LZMS data.
- The header, the chunk table and all chunk data together must equal the Stored
  size exactly: no gap, no trailing bytes.

Decoding LZMS: use the existing `NativeLzms.Decode(byte[] input, int outputSize)`
in this directory (Windows Compression API). It already returns the input
unchanged when `input.Length == outputSize`, so stored chunks need no special
case. It throws when the output length does not match.

## 3. Interface the rest of the reader uses

Keep these exactly. Other files and tests compile against them; one test
(`work/HttpWimRegression`) constructs the two classes through reflection by
these names and constructor shapes.

```text
namespace DiscUtils.Wim

internal sealed class SolidResource
    internal const int MaxChunks = 1_000_000;   // per resource, and the total across a WIM
    internal SolidResource(Stream source, long fileOffset, long packedLength)
    internal long Length { get; }               // U
    internal int ChunkCount { get; }            // N
    internal void ThrowIfUnavailable()          // forwards to (source as IWimSourceHealth)?.ThrowIfUnavailable()
    internal int Read(long offset, Span<byte> destination)
        // Copies uncompressed bytes from `offset`; returns how many (0 at or after Length).
        // offset < 0 or > Length -> ArgumentOutOfRangeException.

internal sealed class SolidFileStream : SparseStream.ReadOnlySparseStream   (DiscUtils.Streams)
    internal SolidFileStream(SolidResource resource, long start, long length)
        // A read-only, seekable view of [start, start + length) of the resource.
        // start < 0, length < 0, or past the resource end -> InvalidDataException.
```

`SolidFileStream` behaviour the tests check: `Position` and `Seek` check source
health *before* changing position, and leave the position unchanged when the
check throws. Reads at or past the end return 0, but still throw if the source
is unavailable. `CanSeek` is true. `Extents` is the one extent `[0, length)`.
`ReadAsync` completes synchronously (do not move reads to the thread pool).

The grouping in §1 also belongs in this file, as:

```text
internal static void AssignSolidStreams(List<ResourceInfo> entries, Stream source)
    // in SolidResource (static) -- called by WimFile.ReadResourceTable for the whole table.
    // For every stream entry inside solid storage it sets
    //   Header.SolidResource = the resource holding it
    //   Header.SolidOffset   = its offset within that resource's uncompressed data
    //   Header.OriginalSize  = Header.CompressedSize (its uncompressed length)
    // Non-solid entries are left untouched.
```

`ShortResourceHeader` already has the `SolidResource` and `SolidOffset` fields,
and `WimFile.OpenResourceStream` already returns
`new SolidFileStream(hdr.SolidResource, hdr.SolidOffset, hdr.OriginalSize)` when
`SolidResource` is set. Do not change those.

## 4. Safety rules (this project's own; all inputs are hostile)

The WIM may come from an arbitrary URL and is read by an elevated process.

- Validate the location before reading: `source.CanSeek`, File offset ≥ 0,
  Stored size ≥ 16, and the resource lies entirely within `source.Length`.
- Reject `U > long.MaxValue`, a chunk size that is not a power of two between
  4096 and 64 MiB inclusive, any method other than 3, `N > MaxChunks`, or a
  chunk table that would not fit inside the Stored size.
- Each chunk's stored size must be ≥ 1 and ≤ its uncompressed size, and the
  running end of chunk data must never pass the resource end. Use checked
  arithmetic wherever a sum could overflow.
- Across the whole table, the sum of all solid resources' `N` must not exceed
  `MaxChunks`. Entries may describe overlapping regions, so per-resource limits
  alone do not bound memory. Check after constructing each resource.
- Decoded data: hold **one** decoded chunk for the whole process, not one per
  resource or per stream, so memory stays at one chunk (≤ 64 MiB). Guard it with
  a lock so it stays correct even if two threads read at once. Re-read and
  decode only when a different resource or chunk is needed.
- Check `ThrowIfUnavailable()` before reading from the source and again before
  copying decoded bytes out, so a source that failed mid-read never yields data.
- Every malformed-input failure is an `InvalidDataException` (an unexpected end
  of source may stay `EndOfStreamException`). Never return garbage instead of
  failing.
- No recursion, no regex, no unbounded allocation driven by an input number
  without one of the limits above.

### Exact messages relied on

- `"A solid resource entry is neither a packed resource nor a file."`: a solid
  entry whose Original size is neither 0 nor 2^32. Check every entry of a run
  before acting on any of it.
- `"The WIM's solid resources have too many chunks in total."`: the
  whole-table chunk budget (test: `WimResourceRegression`).
- `"A file exceeds its solid resource."`: a stream starts inside a resource but
  runs past its end.
- `"A file has no matching solid resource."`: a stream starts outside every
  resource of its run.

## 5. Acceptance

- Every file of a solid WIM or ESD reads back byte for byte, at any position
  and at end of file, and each malformed case above fails with its message.
- `.\Run-Regressions.ps1` passes, notably `WimResourceRegression` and
  `HttpWimRegression` (solid EOF and source-failure behaviour).
- `SolidResource.cs` carries no 7-Zip attribution, because it is not derived
  from it.
