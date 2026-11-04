// Implements the documented identifier component only, not the full driver rank.
internal static class DriverIdentifierScore
{
    internal static int? Best(IReadOnlyList<string> deviceHardware, IReadOnlyList<string> deviceCompatible,
        string? infHardware, IReadOnlyList<string> infCompatible, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(deviceHardware);
        ArgumentNullException.ThrowIfNull(deviceCompatible);
        ArgumentNullException.ThrowIfNull(infCompatible);
        cancellation.ThrowIfCancellationRequested();
        if ((long)deviceHardware.Count + deviceCompatible.Count + infCompatible.Count > 100_000)
            throw new InvalidDataException("Identifier matching work limit exceeded; results are incomplete.");
        int? best = null;
        void Consider(int type, long position)
        {
            // Only the order matters to callers; clamp instead of failing the device.
            int value = type + (int)Math.Min(position, 0xfff);
            if (best is null || value < best) best = value;
        }
        static bool Equal(string? a, string? b) => !string.IsNullOrEmpty(a) && !string.IsNullOrEmpty(b) &&
            string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        var infPositions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int k = 0; k < infCompatible.Count; k++)
        {
            cancellation.ThrowIfCancellationRequested();
            if (!string.IsNullOrEmpty(infCompatible[k])) infPositions.TryAdd(infCompatible[k], k);
        }
        for (int j = 0; j < deviceHardware.Count; j++)
        {
            cancellation.ThrowIfCancellationRequested();
            if (Equal(deviceHardware[j], infHardware)) Consider(0, j);
            if (!string.IsNullOrEmpty(deviceHardware[j]) && infPositions.ContainsKey(deviceHardware[j])) Consider(0x1000, j);
        }
        for (int j = 0; j < deviceCompatible.Count; j++)
        {
            cancellation.ThrowIfCancellationRequested();
            if (Equal(deviceCompatible[j], infHardware)) Consider(0x2000, j);
            if (!string.IsNullOrEmpty(deviceCompatible[j]) && infPositions.TryGetValue(deviceCompatible[j], out int k))
                Consider(0x3000, j + (long)k * 0x100);
        }
        return best;
    }
}
