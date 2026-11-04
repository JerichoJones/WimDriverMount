namespace DiscUtils.Wim;

/// <summary>
/// Allows cached resource reads to detect a source that has already failed.
/// This does not poll the source for changes or stop a mounted filesystem.
/// </summary>
public interface IWimSourceHealth
{
    void ThrowIfUnavailable();
}
