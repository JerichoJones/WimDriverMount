using System.Text;

internal static class DeviceIdEncoding
{
    internal static string Decode(byte[] bytes)
    {
        try { return new UnicodeEncoding(false, false, true).GetString(bytes); }
        catch (DecoderFallbackException ex) { throw new InvalidDataException("Device ID property is not valid UTF-16.", ex); }
    }
}
