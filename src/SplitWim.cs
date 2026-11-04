using System.Buffers.Binary;
using DiscUtils.Wim;

// A split WIM (.swm) as DISM makes it with /Split-Image: X.swm, X2.swm ... XN.swm,
// side by side. The first part's header says how many there are. Every part is
// opened in place through the same kind of source as the first (local file, share
// or web server); nothing is joined, copied or downloaded whole.
internal static class SplitWim
{
    // The part count from the first file's header, or 1 for an ordinary WIM.
    // WimFile checks the header properly; this only decides what else to open.
    internal static int PartCount(Stream first)
    {
        Span<byte> header = stackalloc byte[44];
        first.Position = 0;
        first.ReadExactly(header);
        first.Position = 0;
        if (!header[..5].SequenceEqual("MSWIM"u8)) return 1;
        int part = BinaryPrimitives.ReadUInt16LittleEndian(header[40..]);
        int total = BinaryPrimitives.ReadUInt16LittleEndian(header[42..]);
        if (total is < 1 or > WimFile.MaxParts) throw new InvalidDataException(
            $"The WIM says it has {total} parts; at most {WimFile.MaxParts} are supported.");
        // Siblings are named from the first part (X.swm -> X2.swm); from part 2
        // they would be X22.swm, X23.swm... so stop here with the real reason.
        if (total > 1 && part != 1) throw new NotSupportedException(
            $"This file is part {part} of a split WIM with {total} parts. Open the first part; the others are found beside it.");
        return total;
    }

    // DISM's naming: part n of "X.swm" is "Xn.swm" in the same folder (or the same
    // place on the web server). Part 1 is the name given.
    internal static string PartName(string first, int part)
    {
        if (part == 1) return first;
        if (Uri.TryCreate(first, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            var builder = new UriBuilder(uri) { Path = Numbered(uri.AbsolutePath, part) };
            return builder.Uri.AbsoluteUri;
        }
        // A derived name gets the same checks as --wim itself: an extensionless
        // first part called COM or LPT would otherwise reach the COM2/LPT2 device.
        string local = Path.Combine(Path.GetDirectoryName(first) ?? "", Numbered(Path.GetFileName(first), part));
        DokanSource.ValidateFileComponents(local, Path.GetPathRoot(local) ?? throw new ArgumentException("Split WIM part has no root."), "--wim");
        return local;

        static string Numbered(string path, int n)
        {
            int slash = path.LastIndexOf('/') + 1;
            int dot = path.LastIndexOf('.');
            if (dot < slash) dot = path.Length;
            return path[..dot] + n + path[dot..];
        }
    }

    // All parts, first part first. The caller owns the first stream; the caller
    // also disposes the rest (every element after the first) when done.
    internal static List<Stream> OpenParts(Stream first, string firstName, bool wimSha256Given, Func<string, Stream> open)
    {
        int total = PartCount(first);
        var parts = new List<Stream> { first };
        if (total == 1) return parts;
        // --wim-sha256 is the hash of one file. Checking only the first part would
        // say nothing about the rest, so refuse rather than claim a check.
        if (wimSha256Given)
            throw new ArgumentException($"This WIM is split into {total} parts, and --wim-sha256 checks a single file. Leave it out to mount the parts where they are. " +
                "(A settings file needs --wim-sha256 to install drivers or run a program, so for that, first join the parts into one WIM, for example with DISM /Export-Image.)");
        Console.WriteLine($"Split WIM: {total} parts.");
        try
        {
            for (int n = 2; n <= total; n++)
            {
                string name = PartName(firstName, n);
                Console.WriteLine($"  Part {n}: {SafeText.Path(name)}");
                parts.Add(open(name));
            }
            return parts;
        }
        catch
        {
            Dispose(parts);
            throw;
        }
    }

    internal static void Dispose(List<Stream> parts)
    {
        for (int i = 1; i < parts.Count; i++) parts[i].Dispose();
    }

    internal sealed class Lease(List<Stream> parts) : IDisposable
    {
        public void Dispose() => SplitWim.Dispose(parts);
    }

    internal static bool AnyWebPartFailed(IEnumerable<Stream> parts) =>
        parts.Any(part => part is HttpsRangeStream remote && remote.HasFailed);
}
