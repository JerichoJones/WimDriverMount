// A Windows Installer result is an observation, not proof that a reboot occurred.
[Flags]
internal enum DokanSetupRestart
{
    None = 0,
    Required = 1,
    Initiated = 2
}

internal sealed class DokanSetupRestartException : InvalidOperationException
{
    internal DokanSetupRestartException(DokanSetupRestart result)
        : base(result == DokanSetupRestart.Initiated
            ? "Dokan setup reported that it initiated a restart. The mount was not started; verify the computer state."
            : "Dokan setup reported that a restart is required. The mount was not started.")
    {
        Result = result;
    }

    internal DokanSetupRestart Result { get; }

    internal static DokanSetupRestart Observe(int exitCode, Action<DokanSetupRestart>? report)
    {
        DokanSetupRestart result = exitCode switch
        {
            3010 => DokanSetupRestart.Required,
            1641 => DokanSetupRestart.Initiated,
            _ => DokanSetupRestart.None
        };
        if (result != DokanSetupRestart.None) report?.Invoke(result);
        return result;
    }

    internal static void Check(int exitCode, Action<DokanSetupRestart>? report)
    {
        DokanSetupRestart result = Observe(exitCode, report);
        if (result == DokanSetupRestart.None) return;
        throw new DokanSetupRestartException(result);
    }
}
