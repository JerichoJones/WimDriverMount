using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using DiscUtils.Wim;

// A single-version, read-only HTTP or HTTPS source. The owner must serialize access.
internal sealed class HttpsRangeStream : Stream, IWimSourceHealth
{
    internal sealed record SourceIdentity(string Resource, long Length, string StrongETag);
    private const int BlockSize = 1024 * 1024;
    private static readonly TimeSpan OperationTimeout = TransientRetry.WebAttemptTimeout;
    // Instance values so the outage regression can prove the bound in seconds
    // rather than taking two and a half minutes to do it. Production always
    // uses the shared constants.
    private readonly TimeSpan maxReadTime;
    private readonly TimeSpan blockWindow;
    private readonly HttpClient client;
    private readonly TransientRetry retry;
    private readonly Uri uri;
    private readonly EntityTagHeaderValue validator;
    private readonly long length;
    private long position;
    private long cachedStart = -1;
    private byte[] cache = Array.Empty<byte>();
    private bool disposed;
    private volatile bool failed;
    private readonly CancellationToken lifetime;
    private readonly Action onFailure;
    internal bool HasFailed => failed;

    internal SourceIdentity Identity => new(uri.AbsoluteUri, length, validator.Tag);

    public void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (failed) throw new IOException("The web WIM stream has failed and cannot be reused.");
        lifetime.ThrowIfCancellationRequested();
    }

    internal HttpsRangeStream(Uri uri, CancellationToken lifetime, Action onFailure, string? certificateSha256 = null, SourceIdentity? expected = null,
        TimeSpan? testReadCeiling = null, TimeSpan? testBlockWindow = null)
    {
        if ((uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("The WIM URL must be HTTP or HTTPS without credentials, query, or fragment.");
        this.uri = uri;
        this.lifetime = lifetime;
        maxReadTime = testReadCeiling ?? TransientRetry.ReadCeiling;
        blockWindow = testBlockWindow ?? TransientRetry.Window;
        retry = new TransientRetry(uri.AbsoluteUri, null, blockWindow);
        this.onFailure = onFailure ?? throw new ArgumentNullException(nameof(onFailure));
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseDefaultCredentials = false
        };
        bool pinRefused = false, nameRefused = false; // Which part of the pinned check said no.
        if (certificateSha256 is not null)
        {
            // Whether the pin may name a loopback or any host is the command
            // line's rule, not this stream's: --test-loopback-cert-sha256 is
            // restricted there and --wim-cert-sha256 is not.
            if (uri.Scheme != Uri.UriSchemeHttps || certificateSha256.Length != 64 || !certificateSha256.All(Uri.IsHexDigit))
                throw new ArgumentException("A certificate pin is the 64-digit SHA-256 of an HTTPS server's certificate.");
            byte[] pin = Convert.FromHexString(certificateSha256);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
            {
                bool nameOk = certificate is not null && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                bool ok = nameOk && CryptographicOperations.FixedTimeEquals(SHA256.HashData(certificate!.RawData), pin);
                if (certificate is not null && !nameOk) nameRefused = true;
                else if (!ok) pinRefused = true;
                return ok;
            };
        }
        client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Range = new RangeHeaderValue(0, 0);
            if (expected is not null)
            {
                if (!string.Equals(expected.Resource, uri.AbsoluteUri, StringComparison.Ordinal) || expected.Length <= 0 ||
                    !EntityTagHeaderValue.TryParse(expected.StrongETag, out var expectedTag) ||
                    expectedTag is null || expectedTag.IsWeak || expectedTag.Tag == "*")
                    throw new ArgumentException("Invalid expected web WIM identity.", nameof(expected));
                request.Headers.IfMatch.Add(expectedTag);
            }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
            deadline.CancelAfter(OperationTimeout);
            using var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            var (serverLength, tag) = ValidateProbe(response);
            if (expected is not null && (expected.Length != serverLength ||
                !string.Equals(expected.StrongETag, tag.Tag, StringComparison.Ordinal)))
                throw new InvalidDataException("Web WIM identity differs from the expected version.");
            length = serverLength;
            validator = tag;
            byte[] first = ReadExactly(response.Content, 1, deadline.Token);
            cache = first;
            cachedStart = 0;
        }
        catch (OperationCanceledException) when (!lifetime.IsCancellationRequested)
        {
            client.Dispose();
            throw new TimeoutException("The WIM server did not answer in time. Check the network and the server.");
        }
        catch (HttpRequestException)
        {
            client.Dispose();
            throw new IOException(nameRefused
                ? "The WIM server's certificate is not for the name in the URL, so nothing was read from it. Use the name the certificate was issued for."
                : pinRefused
                ? "The WIM server's certificate does not match the certificate pin you gave, so nothing was read from it. If the server's certificate was replaced, give the new certificate's SHA-256."
                : "Could not connect to the WIM server. Check the address, the network and, for HTTPS, the server certificate.");
        }
        catch { client.Dispose(); throw; }
    }

    internal static (long Length, EntityTagHeaderValue Tag) ValidateProbe(HttpResponseMessage response)
    {
            var range = response.Content.Headers.ContentRange;
            var tag = response.Headers.ETag;
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new InvalidDataException($"The WIM server denied access (HTTP {(int)response.StatusCode}). WIM Driver Mount does not support server sign-in.");
            if (response.StatusCode == HttpStatusCode.PreconditionFailed)
                throw new InvalidDataException("The WIM server rejected the request conditions (HTTP 412). The WIM may have changed; do not reuse an earlier version identity.");
            if ((int)response.StatusCode is >= 300 and < 400)
                throw new InvalidDataException($"The WIM server returned HTTP {(int)response.StatusCode} instead of WIM data. Use a direct WIM URL; redirects are not supported.");
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone)
                throw new InvalidDataException($"The WIM server has no file at that URL (HTTP {(int)response.StatusCode}). Check the URL.");
            if (response.StatusCode != HttpStatusCode.PartialContent)
                throw new InvalidDataException($"The WIM server did not return a byte-range response (HTTP {(int)response.StatusCode}). Check the WIM URL and server byte-range support.");
            if (range?.Unit != "bytes" || range.From != 0 || range.To != 0 || !range.HasLength ||
                range.Length is null or <= 0 || response.Content.Headers.ContentLength != 1 || response.Content.Headers.ContentEncoding.Count != 0)
                throw new InvalidDataException("The WIM server returned an invalid byte-range response. Check its range and content-encoding settings.");
            if (tag is null || tag.IsWeak || tag.Tag == "*")
                throw new InvalidDataException("The WIM server did not provide a strong ETag. Configure a strong ETag for the WIM file.");
            return (range.Length.Value, tag);
    }

    public override bool CanRead => !disposed;
    public override bool CanSeek => !disposed;
    public override bool CanWrite => false;
    public override long Length { get { ObjectDisposedException.ThrowIf(disposed, this); return length; } }
    public override long Position { get { ObjectDisposedException.ThrowIf(disposed, this); return position; } set => Seek(value, SeekOrigin.Begin); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (offset > buffer.Length - count) throw new ArgumentException("Invalid buffer range.");
        ObjectDisposedException.ThrowIf(disposed, this);
        if (failed) throw new IOException("The web WIM stream has failed and cannot be reused.");
        int total = 0;
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        while (count > 0 && position < length)
        {
            if (position < cachedStart || position - cachedStart >= cache.Length)
            {
                // Per-block retries must not hold one read (and its Dokan thread) indefinitely.
                // The remaining budget is handed down, so the retrying inside a
                // block cannot outlive the read: checking only before each block
                // would let the last one start at the ceiling and then run a whole
                // fresh window past it, so a read could outlast Dokan's own
                // timeout and lose the volume.
                TimeSpan remaining = maxReadTime - elapsed.Elapsed;
                if (remaining <= TimeSpan.Zero) { Fail(); throw new TimeoutException("A web WIM read took too long; the source was stopped."); }
                // One block is retried for at most its own window, and the read
                // as a whole for at most its ceiling, whichever runs out first.
                TimeSpan budget = TimeSpan.FromTicks(Math.Min(blockWindow.Ticks, remaining.Ticks));
                try { FetchWithRetry(position, budget); }
                catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { throw; }
                catch { Fail(); throw; }
            }
            int start = checked((int)(position - cachedStart));
            int take = Math.Min(count, cache.Length - start);
            Buffer.BlockCopy(cache, start, buffer, offset, take);
            position += take;
            offset += take;
            count -= take;
            total += take;
        }
        return total;
    }

    private void Fail()
    {
        failed = true;
        cache = Array.Empty<byte>();
        onFailure();
    }

    // Each 1 MiB block gets its own deadline, so a large read on a slow link
    // does not time out as a whole, and its own retry window, so a server that
    // stops answering for a few seconds costs a pause and not the drive.
    // Transport errors are retried under the same If-Match validator; a changed
    // or non-conforming response is not.
    private void FetchWithRetry(long at, TimeSpan budget) => retry.Run(() =>
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        // An attempt already running is never cut short, so a read can exceed
        // its ceiling by at most one attempt. DokanRequestTimeout allows for it.
        deadline.CancelAfter(TimeSpan.FromTicks(Math.Min(OperationTimeout.Ticks, Math.Max(TimeSpan.FromSeconds(1).Ticks, budget.Ticks))));
        Fetch(at, deadline.Token);
    }, TransientWeb, lifetime, budget);

    // Connection refused, reset, a response cut short, an attempt that ran past
    // its deadline: all worth another try. A WIM that changed version, or a
    // server that will not honour byte ranges, is not — those are raised as
    // InvalidDataException, which derives from SystemException and not from
    // IOException, so it is already excluded by not being listed.
    private static bool TransientWeb(Exception ex) =>
        ex is HttpRequestException or OperationCanceledException or IOException;

    private void Fetch(long at, CancellationToken cancellation)
    {
        long start = at / BlockSize * BlockSize;
        int count = (int)Math.Min(BlockSize, length - start);
        long end = start + count - 1;
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Range = new RangeHeaderValue(start, end);
        request.Headers.IfMatch.Add(validator);
        using var response = client.Send(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
        // A server restarting, behind a gateway, or shedding load says so with
        // these, and it is worth waiting for. Any other refusal is treated as
        // settled, so a misconfigured server fails now instead of in a minute.
        if ((int)response.StatusCode is 408 or 429 or 502 or 503 or 504)
            throw new IOException($"The WIM server is temporarily unavailable (HTTP {(int)response.StatusCode}).");
        var range = response.Content.Headers.ContentRange;
        if (response.StatusCode != HttpStatusCode.PartialContent || range?.Unit != "bytes" ||
            range.From != start || range.To != end || range.Length != length ||
            response.Headers.ETag is null || response.Headers.ETag.IsWeak ||
            !string.Equals(response.Headers.ETag.Tag, validator.Tag, StringComparison.Ordinal) ||
            response.Content.Headers.ContentLength != count || response.Content.Headers.ContentEncoding.Count != 0)
            throw new InvalidDataException("Web WIM range or version changed, or the server did not honor the request.");
        byte[] next = ReadExactly(response.Content, count, cancellation);
        cache = next;
        cachedStart = start;
    }

    private static byte[] ReadExactly(HttpContent content, int count, CancellationToken cancellation)
    {
        using var input = content.ReadAsStream(cancellation);
        byte[] data = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = input.ReadAsync(data.AsMemory(read, count - read), cancellation).AsTask().GetAwaiter().GetResult();
            if (n == 0) throw new EndOfStreamException("WIM range ended early.");
            read += n;
        }
        return data;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (failed) throw new IOException("The web WIM stream has failed and cannot be reused.");
        long target = checked((origin switch { SeekOrigin.Begin => 0, SeekOrigin.Current => position, SeekOrigin.End => length, _ => throw new ArgumentOutOfRangeException(nameof(origin)) }) + offset);
        if (target < 0) throw new IOException("Cannot seek before the start of the WIM.");
        position = target;
        return target;
    }
    public override void Flush() { ObjectDisposedException.ThrowIf(disposed, this); }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing && !disposed) client.Dispose(); disposed = true; base.Dispose(disposing); }
}
