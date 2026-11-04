// Worker proof: signs control replies, completion receipts and the startup
// acknowledgement on every background mount. A public key is useful only if the client pins it from the verified startup
// exchange. Same-user process injection or private-key theft is not prevented.
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;

internal sealed class WorkerProof : IDisposable
{
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("WimDrive-worker-proof-v1\0");
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly ECDsa key;
    private readonly object sync = new();

    private WorkerProof(ECDsa key) => this.key = key;

    internal static WorkerProof Create() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    internal byte[] ExportPublicKey() { lock (sync) return key.ExportSubjectPublicKeyInfo(); }

    internal static bool IsValidPublicKey(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey.Length is < 64 or > 256) return false;
        try
        {
            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out int read);
            return read == publicKey.Length && verifier.KeySize == 256 &&
                verifier.ExportParameters(false).Curve.Oid.Value == "1.2.840.10045.3.1.7";
        }
        catch (CryptographicException) { return false; }
    }

    // The worker creates and retains this key.
    // The request must include the instance and exact operation. The response
    // must be the full response the client will use. Peer authorization and
    // secure channel binding are separate requirements.
    internal byte[] Sign(byte[] challenge, string request, string response)
    {
        byte[] payload = Payload(challenge, request, response);
        lock (sync) return key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    // expectedPublicKey is an independently pinned startup value, not a key
    // read solely from a replaceable discovery record or the current peer.
    internal static bool Verify(byte[] expectedPublicKey, byte[] challenge, string request, string response, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(expectedPublicKey);
        ArgumentNullException.ThrowIfNull(signature);
        if (expectedPublicKey.Length is < 64 or > 256 || signature.Length != 64) return false;
        byte[] payload = Payload(challenge, request, response);
        try
        {
            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(expectedPublicKey, out int read);
            if (read != expectedPublicKey.Length || verifier.KeySize != 256 ||
                verifier.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") return false;
            return verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
    }

    private static byte[] Payload(byte[] challenge, string request, string response)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        if (challenge.Length != 32) throw new ArgumentException("The challenge must contain 32 random bytes.", nameof(challenge));
        if (request.Length == 0 || request.Length > 1024 || response.Length == 0 || response.Length > 1024)
            throw new ArgumentException("Invalid request or response length.");
        byte[] requestBytes = Utf8.GetBytes(request);
        byte[] responseBytes = Utf8.GetBytes(response);
        if (requestBytes.Length > 2048 || responseBytes.Length > 2048)
            throw new ArgumentException("Request or response exceeds its byte limit.");
        byte[] payload = new byte[Domain.Length + challenge.Length + 8 + requestBytes.Length + responseBytes.Length];
        Domain.CopyTo(payload, 0);
        challenge.CopyTo(payload, Domain.Length);
        int offset = Domain.Length + challenge.Length;
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(offset, 4), requestBytes.Length);
        offset += 4;
        requestBytes.CopyTo(payload, offset);
        offset += requestBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(offset, 4), responseBytes.Length);
        offset += 4;
        responseBytes.CopyTo(payload, offset);
        return payload;
    }

    public void Dispose() { lock (sync) key.Dispose(); }
}
