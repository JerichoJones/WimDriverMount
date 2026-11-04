using Microsoft.Win32;

// How long Windows will let a read of a network file block before it gives up.
//
// This is not ours to choose. A share whose server goes silent — powered off,
// cable pulled, crashed without closing the connection — leaves the SMB client
// waiting for its own session timeout, and a synchronous file read cannot be
// cancelled while that happens. So the number deciding how long one read of a
// UNC WIM can take belongs to Windows, and the mount has to be arranged around
// it rather than assume it.
//
// SessionTimeout is 60 seconds by documented default. But
// ExtendedSessionTimeout can be 1000 seconds. Windows applies that to servers it
// has been told need longer, and against it a single blocked read would outlast
// Dokan's request timeout roughly fivefold and lose the volume. An administrator
// can raise SessTimeout directly too.
//
// Read from the registry rather than through the SMB management classes, which
// would mean taking a NuGet dependency to ask one question. Windows only writes
// these values when someone has changed them, so absent means the documented
// default is in force.
internal static class SmbTimeouts
{
    private const string Parameters = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private static readonly TimeSpan DefaultSession = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan DefaultExtendedSession = TimeSpan.FromSeconds(1000);

    internal readonly record struct Configuration(TimeSpan Session, TimeSpan ExtendedSession, bool Explicit);

    internal static Configuration Current()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(Parameters, writable: false);
            TimeSpan session = Seconds(key?.GetValue("SessTimeout"), DefaultSession);
            TimeSpan extended = Seconds(key?.GetValue("ExtendedSessTimeout"), DefaultExtendedSession);
            // A value present but equal to the default changes nothing worth reporting.
            bool set = session != DefaultSession || extended != DefaultExtendedSession;
            return new Configuration(session, extended, set);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Not knowing is reported by the caller, not guessed at.
            return new Configuration(DefaultSession, DefaultExtendedSession, false);
        }
    }

    private static TimeSpan Seconds(object? value, TimeSpan fallback)
    {
        if (value is not int seconds || seconds <= 0) return fallback;
        return TimeSpan.FromSeconds(seconds);
    }

    // What Dokan's per-request timeout has to beat for a UNC source: the worst
    // case is every attempt blocking for the whole session timeout. Below this,
    // Dokan abandons the request and the volume can be lost while Windows is
    // still waiting for the server.
    internal static TimeSpan RequiredRequestTimeout(Configuration smb) =>
        TimeSpan.FromTicks(smb.Session.Ticks * TransientRetry.MinimumAttempts);

    // Dokan must still be waiting when the slowest possible read finishes,
    // whether the limit is ours or Windows'.
    internal static TimeSpan DokanRequestTimeout(TextWriter output) => DokanRequestTimeout(output, Current());

    // The configuration is a parameter so the regression can drive the raised
    // and extended cases. They cannot be staged by changing this computer's SMB
    // settings, and an untested warning is one nobody has ever seen work.
    internal static TimeSpan DokanRequestTimeout(TextWriter output, Configuration smb)
    {
        ArgumentNullException.ThrowIfNull(output);
        TimeSpan needed = RequiredRequestTimeout(smb);
        TimeSpan chosen = needed > TransientRetry.DokanRequestTimeout
            ? needed + TimeSpan.FromSeconds(30)
            : TransientRetry.DokanRequestTimeout;
        if (smb.Explicit)
            output.WriteLine($"This computer's SMB session timeout was changed from the default: {smb.Session.TotalSeconds:0} s " +
                $"(extended {smb.ExtendedSession.TotalSeconds:0} s). The drive waits up to {chosen.TotalSeconds:0} s for each read to match.");
        // The extended timeout applies to servers Windows has been told need
        // longer. Allowing for it on every mount would make Dokan's own
        // protection useless, so say it plainly instead of silently absorbing it.
        if (smb.ExtendedSession > chosen)
            output.WriteLine($"Note: Windows can wait up to {smb.ExtendedSession.TotalSeconds:0} s for a server on its extended SMB session timeout list, " +
                $"longer than this drive waits ({chosen.TotalSeconds:0} s). If such a server stops answering, the drive may be lost. " +
                "Serving the WIM over HTTPS avoids this.");
        return chosen;
    }
}
