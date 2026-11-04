// Cleanup journal codec, written and read by WorkerRecoveryStore. Decoding this
// data does not prove exit: only the protected store and its publication ordering
// make it evidence that the application observed the original process exit.
using System.Buffers.Binary;
using System.Security.Cryptography;

internal static class WorkerCleanupJournal
{
    private static readonly byte[] Magic = "WDJ1"u8.ToArray();
    private const int HeaderLength = 6, ReceiptLength = 100, MaxRecord = 4096;
    internal const int MaximumLength = HeaderLength + MaxRecord + ReceiptLength;

    // Call while the prepared-file reservation and originally verified process
    // handle are retained. The caller must keep receipt stable throughout this
    // call, keep both handles through publication, and clear the returned bytes.
    // A receipt verifies the worker's claim, not the current drive mapping.
    internal static byte[] Create(WorkerRecoveryRecord prepared, byte[] receipt, WorkerProcessIdentity worker)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(worker);
        if (prepared.ObservedMapping is not null || receipt.Length != ReceiptLength ||
            worker.ProcessId != prepared.ProcessId || worker.CreationTime != prepared.CreationTime ||
            !WorkerCompletionReceipt.VerifyClosed(receipt, prepared) || !worker.HasConfirmedExit())
            throw new InvalidDataException("Cleanup evidence is not confirmed.");
        byte[] encoded = prepared.Encode();
        try
        {
            if (encoded.Length == 0 || encoded.Length > MaxRecord) throw new InvalidDataException("Invalid journal record size.");
            byte[] journal = new byte[HeaderLength + encoded.Length + ReceiptLength];
            Magic.CopyTo(journal, 0);
            BinaryPrimitives.WriteUInt16LittleEndian(journal.AsSpan(Magic.Length, 2), checked((ushort)encoded.Length));
            encoded.CopyTo(journal, HeaderLength);
            receipt.CopyTo(journal, HeaderLength + encoded.Length);
            return journal;
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    // Input contains the capability. The caller keeps it stable, clears it and
    // never logs it. Returned record is caller-owned and must be disposed.
    // Signature validation does not authenticate the stored exit observation.
    internal static WorkerRecoveryRecord Decode(byte[] journal, out WorkerCompletionReceipt.Closure closure)
    {
        closure = default;
        ArgumentNullException.ThrowIfNull(journal);
        if (journal.Length < HeaderLength + 1 + ReceiptLength || journal.Length > MaximumLength ||
            !journal.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw new InvalidDataException("Invalid cleanup journal.");
        int length = BinaryPrimitives.ReadUInt16LittleEndian(journal.AsSpan(Magic.Length, 2));
        if (length == 0 || length > MaxRecord || journal.Length != HeaderLength + length + ReceiptLength)
            throw new InvalidDataException("Invalid cleanup journal length.");
        byte[] encoded = journal.AsSpan(HeaderLength, length).ToArray();
        WorkerRecoveryRecord? record = null;
        try
        {
            record = WorkerRecoveryRecord.Decode(encoded);
            byte[] receipt = journal.AsSpan(HeaderLength + length, ReceiptLength).ToArray();
            if (!WorkerCompletionReceipt.TryVerifyClosed(receipt, record, out bool failed, out var dokan))
                throw new InvalidDataException("Cleanup journal receipt is invalid.");
            closure = new(failed, dokan);
            WorkerRecoveryRecord result = record;
            record = null;
            return result;
        }
        finally
        {
            record?.Dispose();
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

}
