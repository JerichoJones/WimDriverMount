// Capability authentication for control requests, used by WorkerControl on every
// background mount. The shared secret travels over the verified startup exchange
// and is kept in the private recovery record, never in replaceable discovery data.
using System.Security.Cryptography;
using System.Text;

internal sealed class WorkerAuthorization : IDisposable
{
    internal enum Decision { Allowed, Denied, LimitReached }
    private const int MaxStatusRequests = 10_000, MaxUnmountRequests = 32;
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("WimDrive-control-request-v1\0");
    private readonly object sync = new();
    private readonly byte[] secret;
    private readonly string instance;
    private readonly HashSet<string> used = new(StringComparer.Ordinal);
    private bool disposed;
    private int statusRequests, unmountRequests;

    internal WorkerAuthorization(Guid instance, byte[] secret)
    {
        if (instance == Guid.Empty) throw new ArgumentException("Invalid worker instance.", nameof(instance));
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length != 32) throw new ArgumentException("Invalid control secret length.", nameof(secret));
        this.secret = (byte[])secret.Clone();
        this.instance = instance.ToString("N");
    }

    // Verify that the control server uses the prepared instance and capability.
    // The supplied buffer remains caller-owned and must be cleared by the caller.
    internal bool Matches(Guid expectedInstance, byte[] expectedSecret)
    {
        ArgumentNullException.ThrowIfNull(expectedSecret);
        lock (sync)
            return !disposed && expectedInstance.ToString("N") == instance && expectedSecret.Length == secret.Length &&
                CryptographicOperations.FixedTimeEquals(secret, expectedSecret);
    }

    // A client must protect the secret. It creates a fresh nonce per request,
    // keeps the exact request for verifying the signed response, and never
    // retries the same request after a timeout.
    internal static string CreateRequest(Guid instance, string operation, byte[] secret)
    {
        if (instance == Guid.Empty) throw new ArgumentException("Invalid worker instance.", nameof(instance));
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length != 32 || operation is not ("STATUS" or "UNMOUNT"))
            throw new ArgumentException("Invalid control request.");
        string prefix = instance.ToString("N") + "|" + operation + "|" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return prefix + "|" + Convert.ToBase64String(ComputeMac(secret, prefix));
    }

    // Check and consume the complete request before its operation has effects.
    // A valid request may still be relayed, and same-user secret theft or process
    // injection is outside this check. Separate limits reserve unmount capacity;
    // a full limit fails closed and requires manual investigation.
    internal Decision AuthorizeAndConsume(string request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Length > 256) return Decision.Denied;
        string[] fields = request.Split('|');
        if (fields.Length != 4 || fields[0] != instance || fields[1] is not ("STATUS" or "UNMOUNT")) return Decision.Denied;
        byte[] nonce, supplied;
        try { nonce = Convert.FromBase64String(fields[2]); supplied = Convert.FromBase64String(fields[3]); }
        catch (FormatException) { return Decision.Denied; }
        if (nonce.Length != 32 || supplied.Length != 32 || Convert.ToBase64String(nonce) != fields[2] ||
            Convert.ToBase64String(supplied) != fields[3]) return Decision.Denied;
        string prefix = fields[0] + "|" + fields[1] + "|" + fields[2];
        lock (sync)
        {
            if (disposed || used.Contains(fields[2])) return Decision.Denied;
            byte[] expected = ComputeMac(secret, prefix);
            if (!CryptographicOperations.FixedTimeEquals(expected, supplied)) return Decision.Denied;
            if (fields[1] == "STATUS" ? statusRequests >= MaxStatusRequests : unmountRequests >= MaxUnmountRequests)
                return Decision.LimitReached;
            used.Add(fields[2]);
            if (fields[1] == "STATUS") statusRequests++; else unmountRequests++;
            return Decision.Allowed;
        }
    }

    private static byte[] ComputeMac(byte[] secret, string prefix)
    {
        byte[] value = Encoding.ASCII.GetBytes(prefix);
        byte[] payload = new byte[Domain.Length + value.Length];
        Domain.CopyTo(payload, 0);
        value.CopyTo(payload, Domain.Length);
        return HMACSHA256.HashData(secret, payload);
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(secret);
            used.Clear();
        }
    }
}
