// Bounded recovery data codec. This is not a record store or a trust anchor.
// The caller must protect, flush and verify storage before authorizing GO.
using System.Security.Cryptography;
using System.Text;

internal sealed class WorkerRecoveryRecord : IDisposable
{
    private const int MaxBytes = 4096;
    private const int MaxMappingBytes = 2048;
    private static readonly byte[] Magic = "WDR1"u8.ToArray();
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly byte[] publicKey;
    private readonly byte[] capability;
    private readonly object sync = new();
    private bool disposed;

    internal Guid Instance { get; }
    internal char Drive { get; }
    internal string PipeName { get; }
    internal uint ProcessId { get; }
    internal ulong CreationTime { get; }
    // Null means no readiness observation was saved. It does not mean no mount.
    internal string? ObservedMapping { get; }

    // The caller must generate capability using a cryptographic random generator
    // and keep both input arrays stable until this constructor returns.
    internal WorkerRecoveryRecord(Guid instance, char drive, string pipeName, uint processId,
        ulong creationTime, byte[] publicKey, byte[] capability, string? observedMapping)
    {
        ArgumentNullException.ThrowIfNull(pipeName);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(capability);
        const string prefix = "WimDrive-control-";
        if (instance == Guid.Empty || drive is < 'D' or > 'Z' || processId == 0 || creationTime == 0 ||
            !pipeName.StartsWith(prefix, StringComparison.Ordinal) ||
            pipeName.Length != prefix.Length + 32 ||
            !Guid.TryParseExact(pipeName[prefix.Length..], "N", out Guid pipeId) || pipeId == Guid.Empty ||
            !string.Equals(pipeName[prefix.Length..], pipeId.ToString("N"), StringComparison.Ordinal) ||
            capability.Length != 32 || !WorkerProof.IsValidPublicKey(publicKey) ||
            (observedMapping is not null && (observedMapping.Length == 0 || Utf8.GetByteCount(observedMapping) > MaxMappingBytes)))
            throw new ArgumentException("Invalid recovery record.");
        Instance = instance;
        Drive = drive;
        PipeName = pipeName;
        ProcessId = processId;
        CreationTime = creationTime;
        this.publicKey = (byte[])publicKey.Clone();
        this.capability = (byte[])capability.Clone();
        ObservedMapping = observedMapping;
    }

    // The caller owns returned buffers and must clear capability copies.
    internal byte[] CopyPublicKey() { lock (sync) { RequireOpen(); return (byte[])publicKey.Clone(); } }
    internal byte[] CopyCapability() { lock (sync) { RequireOpen(); return (byte[])capability.Clone(); } }

    // The returned plaintext includes the capability. The caller must clear it
    // and must not log it or place it in process arguments.
    internal byte[] Encode()
    {
        lock (sync)
        {
        RequireOpen();
        // Preallocate the maximum so the stream cannot abandon a smaller
        // backing array after the capability has been written.
        using var output = new MemoryStream(MaxBytes);
        try
        {
            using (var writer = new BinaryWriter(output, Utf8, leaveOpen: true))
            {
                writer.Write(Magic);
                writer.Write(Instance.ToByteArray());
                writer.Write((byte)Drive);
                writer.Write(ProcessId);
                writer.Write(CreationTime);
                WriteBytes(writer, Encoding.ASCII.GetBytes(PipeName));
                WriteBytes(writer, publicKey);
                writer.Write(capability);
                writer.Write(ObservedMapping is not null);
                if (ObservedMapping is not null) WriteBytes(writer, Utf8.GetBytes(ObservedMapping));
            }
            if (output.Length > MaxBytes) throw new InvalidDataException("Recovery record is too large.");
            return output.ToArray();
        }
        finally
        {
            // MemoryStream's backing array also contains the capability.
            if (output.TryGetBuffer(out ArraySegment<byte> buffer)) CryptographicOperations.ZeroMemory(buffer.AsSpan());
        }
        }
    }

    // Input is caller-owned plaintext, is not cleared here, and must be cleared
    // by the caller, who must keep it stable until decoding returns. Never log it
    // or place it in process arguments.
    internal static WorkerRecoveryRecord Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0 || data.Length > MaxBytes) throw new InvalidDataException("Invalid recovery record size.");
        byte[]? secret = null;
        try
        {
            using var input = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(input, Utf8, leaveOpen: false);
            if (!reader.ReadBytes(Magic.Length).AsSpan().SequenceEqual(Magic)) throw new InvalidDataException("Invalid recovery record version.");
            byte[] id = reader.ReadBytes(16);
            if (id.Length != 16) throw new EndOfStreamException();
            Guid instance = new(id);
            char drive = (char)reader.ReadByte();
            uint pid = reader.ReadUInt32();
            ulong creation = reader.ReadUInt64();
            byte[] nameBytes = ReadBytes(reader, 64);
            if (nameBytes.Any(b => b > 127)) throw new InvalidDataException("Invalid pipe name encoding.");
            string pipe = Encoding.ASCII.GetString(nameBytes);
            byte[] key = ReadBytes(reader, 256);
            secret = reader.ReadBytes(32);
            if (secret.Length != 32) throw new EndOfStreamException();
            byte flag = reader.ReadByte();
            if (flag > 1) throw new InvalidDataException("Invalid recovery state.");
            string? mapping = flag == 1 ? Utf8.GetString(ReadBytes(reader, MaxMappingBytes)) : null;
            if (input.Position != input.Length) throw new InvalidDataException("Trailing recovery data.");
            return new WorkerRecoveryRecord(instance, drive, pipe, pid, creation, key, secret, mapping);
        }
        finally { if (secret is not null) CryptographicOperations.ZeroMemory(secret); }
    }

    private static void WriteBytes(BinaryWriter writer, byte[] bytes)
    {
        if (bytes.Length > ushort.MaxValue) throw new InvalidDataException("Recovery field is too large.");
        writer.Write((ushort)bytes.Length);
        writer.Write(bytes);
    }

    private static byte[] ReadBytes(BinaryReader reader, int maximum)
    {
        int length = reader.ReadUInt16();
        if (length == 0 || length > maximum) throw new InvalidDataException("Invalid recovery field length.");
        byte[] value = reader.ReadBytes(length);
        if (value.Length != length) throw new EndOfStreamException();
        return value;
    }

    private void RequireOpen() { if (disposed) throw new ObjectDisposedException(nameof(WorkerRecoveryRecord)); }
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(capability);
        }
    }
}
