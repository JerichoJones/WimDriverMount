using System.Buffers.Binary;
using System.Text;

// Parser for the FILE_ID_BOTH_DIR_INFO entries returned in one Windows buffer.
// Entries are yielded as they are parsed so a later malformed entry does not
// hide evidence already observed by the caller.
internal static class DriverJournalDirectoryBuffer
{
    private const int HeaderLength = 104;
    internal readonly record struct Entry(string Name, uint Attributes, ulong FileId);

    internal static IEnumerable<Entry> Parse(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        int offset = 0;
        while (true)
        {
            if (offset < 0 || offset > buffer.Length - HeaderLength)
                throw new InvalidDataException("Invalid directory entry offset.");
            int next = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));
            uint nameLength = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 60, 4));
            uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 56, 4));
            ulong fileId = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset + 96, 8));
            int available = next == 0 ? buffer.Length - offset : next;
            if (next < 0 || (next != 0 && (next % 8 != 0 || next < HeaderLength || next > buffer.Length - offset)) ||
                nameLength == 0 || (nameLength & 1) != 0 || nameLength > available - HeaderLength)
                throw new InvalidDataException("Invalid directory entry length.");
            string name = new UnicodeEncoding(false, false, true).GetString(buffer, offset + HeaderLength, checked((int)nameLength));
            yield return new(name, attributes, fileId);
            if (next == 0) yield break;
            offset = checked(offset + next);
        }
    }
}
