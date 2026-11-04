using System.Globalization;
using System.Text;

// Format untrusted values at the output boundary, never before comparison.
internal static class SafeText
{
    private const int MaxInputCharacters = 2048;

    // Normal Windows paths remain directly copyable. Exceptional paths use the
    // escaped representation and are explicitly marked as not directly copyable.
    internal static string Path(string? value)
    {
        if (value is null) return "<null>";
        if (value.Length > MaxInputCharacters) return "[escaped path; not directly copyable] " + Quote(value);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            int width = char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]) ? 2 : 1;
            UnicodeCategory category = char.GetUnicodeCategory(value, i);
            if (c == '"' || category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate)
                return "[escaped path; not directly copyable] " + Quote(value);
            i += width - 1;
        }
        return value;
    }

    // A message (ours or Windows'), shown as written: no added quotes, backslashes
    // left alone. Only characters that could change the console are escaped, as
    // an exception message can carry text from a WIM, a server or a settings file.
    internal static string Message(string? value) => value is null ? "<null>" : Escape(value, quoted: false);

    // A path inside a command the user is told to run, so the line still works
    // when pasted into PowerShell or Command Prompt.
    // Quoted unless it is only letters, digits and : \ . _ - (a space, &, comma or $ would break it).
    // $, a backtick and % still expand inside double quotes (PowerShell, cmd), and PowerShell
    // takes typographic quotes (U+2018 to U+201E) as quotes, so such a path is shown escaped.
    internal static string Argument(string? value)
    {
        string shown = Path(value);
        if (shown.StartsWith('[')) return shown;
        if (shown.Any(c => c is '$' or '`' or '%' or (>= '‘' and <= '„')))
            return "[escaped path; not directly copyable] " + Quote(value);
        return shown.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is ':' or '\\' or '.' or '_' or '-')) ? "\"" + shown + "\"" : shown;
    }

    internal static string Quote(string? value) => value is null ? "<null>" : Escape(value, quoted: true);

    private static string Escape(string value, bool quoted)
    {
        var output = new StringBuilder(Math.Min(value.Length, MaxInputCharacters) + 16);
        if (quoted) output.Append('"');
        int i = 0;
        while (i < value.Length && i < MaxInputCharacters)
        {
            char c = value[i];
            int width = char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]) ? 2 : 1;
            if (i + width > MaxInputCharacters) break;
            UnicodeCategory category = char.GetUnicodeCategory(value, i);
            if (quoted && (c == '\\' || c == '"')) { output.Append('\\').Append(c); }
            else if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate)
            {
                for (int j = 0; j < width; j++) output.Append("\\u").Append(((int)value[i + j]).ToString("X4", CultureInfo.InvariantCulture));
            }
            else output.Append(value, i, width);
            i += width;
        }
        if (quoted) output.Append('"');
        if (i < value.Length) output.Append(" [truncated]");
        return output.ToString();
    }
}
