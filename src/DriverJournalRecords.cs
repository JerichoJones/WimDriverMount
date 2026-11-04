using System.Buffers.Binary;

// Record codec and sequence inspection only. This does not authenticate records,
// persist them, establish an operation's identity, or prove cleanup.
internal static class DriverJournalRecords
{
    internal enum Kind : byte { Intent = 1, Completion = 2 }
    internal readonly record struct Record(Kind Type, int Sequence, bool Installed, int Error, bool Restart);
    internal readonly record struct Inspection(bool Valid, bool HasUnfinishedIntent, int CompletedCalls, bool RestartReported, bool OutcomeUnknown, bool RestartUnknown);
    private const int Length = 16;
    private const int MaxCalls = 100000;
    internal static byte[] FilteredMode => [0x57, 0x44, 0x4d, 0x31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // A terminal record is a claim by the writer, not proof of a complete or
    // authentic inventory. A recovery reader must validate the full inventory
    // and its storage identity before using it as an operation-wide result.
    internal enum Cleanup : byte { Unknown = 0, Confirmed = 1, Failed = 2 }
    internal readonly record struct Terminal(int CompletedCalls, int SuccessfulCalls,
        bool RestartReported, bool RestartUnknown, bool OutcomeUnknown, bool Failed, Cleanup CleanupStatus);

    internal static byte[] EncodeTerminal(Terminal record)
    {
        ValidateTerminal(record);
        var bytes = new byte[Length];
        "WDT1"u8.CopyTo(bytes);
        bytes[4] = (byte)((record.RestartReported ? 1 : 0) | (record.RestartUnknown ? 2 : 0) |
            (record.OutcomeUnknown ? 4 : 0) | (record.Failed ? 8 : 0));
        bytes[5] = (byte)record.CleanupStatus;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), record.CompletedCalls);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), record.SuccessfulCalls);
        return bytes;
    }

    internal static Terminal DecodeTerminal(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length || !bytes[..4].SequenceEqual("WDT1"u8) ||
            (bytes[4] & ~15) != 0 || bytes[6] != 0 || bytes[7] != 0)
            throw new InvalidDataException("Invalid driver journal terminal record.");
        var record = new Terminal(BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(8, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(12, 4)),
            (bytes[4] & 1) != 0, (bytes[4] & 2) != 0, (bytes[4] & 4) != 0,
            (bytes[4] & 8) != 0, (Cleanup)bytes[5]);
        ValidateTerminal(record);
        return record;
    }

    private static void ValidateTerminal(Terminal record)
    {
        if (record.CompletedCalls is < 0 or > MaxCalls || record.SuccessfulCalls < 0 ||
            record.SuccessfulCalls > record.CompletedCalls ||
            (record.OutcomeUnknown && !record.RestartUnknown) ||
            record.CleanupStatus is not (Cleanup.Unknown or Cleanup.Confirmed or Cleanup.Failed))
            throw new InvalidDataException("Invalid driver journal terminal record fields.");
    }

    internal static byte[] Encode(Record record)
    {
        Validate(record);
        var bytes = new byte[Length];
        "WDJ2"u8.CopyTo(bytes);
        bytes[4] = (byte)record.Type;
        bytes[5] = (byte)((record.Installed ? 1 : 0) | (record.Restart ? 2 : 0));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), record.Sequence);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), record.Error);
        return bytes;
    }

    internal static Record Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length || !bytes[..4].SequenceEqual("WDJ2"u8) || bytes[6] != 0 || bytes[7] != 0 || (bytes[5] & ~3) != 0)
            throw new InvalidDataException("Invalid driver journal record.");
        var record = new Record((Kind)bytes[4], BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(8, 4)),
            (bytes[5] & 1) != 0, BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(12, 4)), (bytes[5] & 2) != 0);
        Validate(record);
        return record;
    }

    private static void Validate(Record record)
    {
        if (record.Sequence is < 1 or > MaxCalls || record.Type is not (Kind.Intent or Kind.Completion) ||
            (record.Type == Kind.Intent && (record.Installed || record.Error != 0 || record.Restart)) ||
            (record.Type == Kind.Completion && record.Installed && record.Error != 0))
            throw new InvalidDataException("Invalid driver journal record fields.");
    }

    // Input is not required to be ordered. Any duplicate, gap or inconsistent
    // sequence makes the inspection invalid; the caller must report unknown.
    // This method does not accept or verify terminal records and cannot prove
    // operation completion.
    internal static Inspection Inspect(IEnumerable<byte[]> encoded, bool continueAfterReturnedFailure = false)
    {
        ArgumentNullException.ThrowIfNull(encoded);
        var records = new Dictionary<(int, Kind), Record>();
        bool restart = false, invalid = false;
        int count = 0;
        try
        {
            foreach (byte[] bytes in encoded)
            {
                if (++count > MaxCalls * 2) return new(false, true, 0, restart, true, true);
                if (bytes is null) { invalid = true; continue; }
                Record record;
                try { record = Decode(bytes); }
                catch (InvalidDataException) { invalid = true; continue; }
                if (record.Type == Kind.Completion) restart |= record.Restart;
                if (!records.TryAdd((record.Sequence, record.Type), record)) invalid = true;
            }
            if (invalid || records.Count == 0) return new(false, true, 0, restart, true, true);
            int last = records.Keys.Max(key => key.Item1);
            int completed = 0;
            bool unfinished = false;
            for (int i = 1; i <= last; i++)
            {
                bool intent = records.ContainsKey((i, Kind.Intent));
                bool completion = records.ContainsKey((i, Kind.Completion));
                if (!intent || (unfinished && (intent || completion))) return new(false, true, completed, restart, true, true);
                if (!completion) unfinished = true;
                else
                {
                    completed++;
                    Record result = records[(i, Kind.Completion)];
                    if (!continueAfterReturnedFailure && !result.Installed && result.Error != 259)
                    {
                        if (i != last) return new(false, true, completed, restart, true, true);
                    }
                }
            }
            // There is no verified terminal record or complete inventory yet.
            // Even a complete-looking sequence cannot establish the operation-wide outcome.
            return new(true, unfinished, completed, restart, true, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { return new(false, true, 0, restart, true, true); }
    }
}
