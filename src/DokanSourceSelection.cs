internal static class DokanSourceSelection
{
    internal static string Default(string directory, string fallback, Func<string, bool> exists)
    {
        ArgumentNullException.ThrowIfNull(exists);
        string bundled = Path.Combine(directory, DokanPackage.MsiName);
        return exists(bundled) ? bundled : fallback;
    }
}
