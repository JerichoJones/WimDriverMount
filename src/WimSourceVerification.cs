using System.Security.Cryptography;
using DiscUtils.Wim;

// Proving the WIM is the exact file the operator meant, by its own bytes.
//
// The ETag the web source pins is chosen by the server, so it catches a
// legitimate server republishing the WIM and nothing else: a server that is not
// the one you meant reports whatever ETag it likes. A certificate pin answers
// that by authenticating the server; this answers it by authenticating the
// bytes, which is the only thing that holds over plain HTTP, where there is no
// server authentication at all.
//
// Hashing once is not enough: the mount reads the source again afterwards, and
// an HTTP server or a file on a share can then serve different bytes. So the
// whole-file hash is taken block by block, each block's own hash is kept, and
// every later read goes through Verified, which checks each block it serves.
//
// It is not free and must never be quiet about that: verifying means reading
// every byte before the drive appears, which for a large WIM over a slow link
// is the whole download the rest of this program exists to avoid.
internal static class WimSourceVerification
{
    internal const int Block = 1024 * 1024;

    // Returns the stream to mount from. The caller still owns and disposes source.
    internal static Verified Require(Stream source, string expected, string what, TextWriter output, Action? onFailure = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(output);
        if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
            throw new ArgumentException("The expected WIM hash must be 64 hexadecimal digits.", nameof(expected));
        if (!source.CanSeek) throw new ArgumentException("The WIM source cannot be reread for verification.", nameof(source));

        output.WriteLine($"Verifying {SafeText.Path(what)} against the given SHA-256. " +
            "This reads the whole WIM before mounting it.");
        long length = source.Length;
        long blocks = length / Block + (length % Block == 0 ? 0 : 1);
        // A server states the length before a byte is checked. 1 TiB, far above
        // any real WIM, keeps the block table at 32 MB instead of up to 2 GB.
        if (length < 0 || length > 1L << 40) throw new InvalidDataException("The WIM is too large to verify.");
        var hashes = new byte[checked((int)blocks * 32)];
        using var whole = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[Block];
        source.Position = 0;
        for (long i = 0; i < blocks; i++)
        {
            int count = (int)Math.Min(Block, length - i * Block);
            source.ReadExactly(buffer, 0, count);
            whole.AppendData(buffer, 0, count);
            SHA256.HashData(buffer.AsSpan(0, count), hashes.AsSpan(checked((int)i * 32), 32));
        }
        string actual = Convert.ToHexString(whole.GetHashAndReset());
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                $"The WIM does not match the given SHA-256. Expected {expected.ToUpperInvariant()}, " +
                $"read {actual}. Nothing has been mounted.");
        output.WriteLine($"WIM SHA-256 verified over {length:N0} bytes.");
        return new Verified(source, length, hashes, onFailure);
    }

    // Serves the source only in whole blocks that match the hashes taken while
    // verifying. A block that differs fails the read and every read after it.
    internal sealed class Verified(Stream source, long length, byte[] hashes, Action? onFailure = null) : Stream, IWimSourceHealth
    {
        private readonly byte[] cache = new byte[Block];
        private long cachedBlock = -1, position;
        internal bool Failed { get; private set; }

        public void ThrowIfUnavailable()
        {
            if (Failed) throw new IOException("The WIM changed after it was verified; the mount was stopped.");
            (source as IWimSourceHealth)?.ThrowIfUnavailable();
        }

        private void Fail()
        {
            Failed = true;
            onFailure?.Invoke(); // Stops the mount, as a failed web source does.
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            ThrowIfUnavailable();
            if (count == 0 || position >= length) return 0;
            long block = position / Block;
            int within = (int)(position % Block);
            int blockLength = (int)Math.Min(Block, length - block * Block);
            if (block != cachedBlock)
            {
                cachedBlock = -1;
                try
                {
                    source.Position = block * Block;
                    source.ReadExactly(cache, 0, blockLength);
                }
                // A share that comes back as a different or shorter file is the
                // same change as a block that no longer matches. An outage is an
                // IOException and stays retryable.
                catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
                {
                    Fail();
                    throw;
                }
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(cache.AsSpan(0, blockLength), hash);
                if (!CryptographicOperations.FixedTimeEquals(hash, hashes.AsSpan(checked((int)block * 32), 32)))
                {
                    Fail();
                    throw new InvalidDataException($"The WIM changed after it was verified (block at {block * Block:N0}); the mount was stopped.");
                }
                cachedBlock = block;
            }
            int take = Math.Min(count, blockLength - within);
            Buffer.BlockCopy(cache, within, buffer, offset, take);
            position += take;
            return take;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position
        {
            get => position;
            set { ArgumentOutOfRangeException.ThrowIfNegative(value); position = value; }
        }
        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => position + offset,
            SeekOrigin.End => length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
