// What counts as a usable Dokan installer source, and nothing else.
//
// This is split out from DokanInstaller so that deciding whether a value is
// acceptable does not drag in installing, downloading, or elevation. The option
// parser needs these checks, and a test needs to exercise them, without either
// one pulling in the whole installer.
internal static class DokanSource
{
    internal static string ValidateUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("A Dokan installer source is required.");
        if (value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                throw new ArgumentException("Dokan URL must be an HTTPS URL without credentials, query, or fragment.");
            return uri.AbsoluteUri;
        }
        if (value.Contains("://", StringComparison.Ordinal) || value.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            value.StartsWith(@"\\.\", StringComparison.Ordinal) || value.IndexOfAny(new[] { '\0', '*', '?' }) >= 0)
            throw new ArgumentException("Dokan source must be an HTTPS URL or a normal MSI file path.");
        string path = Path.GetFullPath(value, AppContext.BaseDirectory);
        string root = Path.GetPathRoot(path) ?? throw new ArgumentException("Dokan file path has no root.");
        ValidateFileComponents(path, root);
        if (!path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) || path[root.Length..].Contains(':'))
            throw new ArgumentException("Dokan file source must name an MSI without an alternate stream.");
        return path;
    }

    // Shared with --wim, which needs the same rules for the same reason: a path
    // that names a pipe or a console device does not name a file, and opening
    // one from an elevated process hands the listener something it should not
    // have. `what` only names the setting in the message, so each caller can
    // say what the operator actually typed.
    internal static void ValidateFileComponents(string path, string root, string what = "Dokan source")
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            string[] unc = path[2..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (unc.Length < 3 || unc[1].Equals("pipe", StringComparison.OrdinalIgnoreCase) ||
                unc[1].Equals("IPC$", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(
                    $@"{what} requires a file on a share, such as \\server\share\name, and cannot use a pipe or IPC share.");
        }
        foreach (string component in path[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            string name = component.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
            if (name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
                (name.Length == 4 && (name.StartsWith("COM", StringComparison.Ordinal) || name.StartsWith("LPT", StringComparison.Ordinal)) &&
                 (name[3] is >= '1' and <= '9' or '¹' or '²' or '³')))
                throw new ArgumentException($"{what} contains a reserved device name.");
        }
    }
}
