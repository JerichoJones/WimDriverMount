namespace DiscUtils.Wim;

// Matches a Win32 search wildcard against a name without building a regex.
//
// Both the pattern and the names come from whatever process is listing the
// mounted drive. DiscUtils' own Utilities.ConvertWildcardsToRegEx compiles a
// Regex with no match timeout and keeps it forever in a static unbounded
// dictionary, so any unprivileged caller could hand the elevated process a
// pattern like "*a*a*a...*b" via FindFirstFileW and wedge the single-threaded
// mount on catastrophic backtracking, or grow its memory without bound by
// cycling distinct patterns. This matcher cannot backtrack exponentially,
// caches nothing, and does not recurse.
public static class WildcardFilter
{
    // A search pattern is a single path component, which Windows caps at 255
    // characters. Not exponential is not the same as bounded: the scan below is
    // O(name x pattern), and a long-path FindFirstFileW can send a pattern tens
    // of thousands of characters long, so an unprivileged caller could still
    // spend seconds of the single-threaded mount's time per listing. Past the
    // cap nothing a caller sends can match a real name, so it matches nothing,
    // and the work per name stays under 255 x the name's length.
    internal const int MaxPatternLength = 255;

    // FindFirstFile sends "?" as the DOS wildcard '>', some dots as '"' and a
    // '*' before a dot as '<' ("*.cat" arrives as "<.cat", "*." as "<"; seen in
    // the VM, 2026-11-04). The Dokan adapter turns '<' into '*', so the drive
    // (WimDokanOperations) matches '<' patterns here before the adapter sees them.
    // Those patterns go to .NET's NTFS matcher, which is exact but costs far
    // more per step than the scan below: uncapped, '*' x254 + "z" took 1.3 s
    // per 20,000-entry listing, and any local user may list the drive with
    // --all-users. So a DOS pattern longer than 64 characters finds nothing
    // (e.g. "name.*" for a name of 63 or more characters). At 64 the worst
    // measured was about 0.4 s per 20,000-entry listing of short names, and about
    // 1.2 s with 255-character names (red team 7; the person mounting chooses the
    // names, so not a lever for others); '*'/'?' patterns take the scan, about
    // 0.01-0.09 s.
    internal const int MaxDosPatternLength = 64;

    // Null, empty, "*" and "*.*" accept everything. DiscUtils' own
    // GetDirectories(path) and GetFiles(path) pass "*.*" meaning "all", and
    // FindFirstFile turns "*.*" into "*" before a drive sees it.
    internal static bool MatchesAll(string? pattern) =>
        string.IsNullOrEmpty(pattern) || pattern is "*" or "*.*";

    // Callers pass the real name: "audio" must find a folder named audio
    // (PowerShell's Get-ChildItem -Recurse -Force searches for every folder
    // that way). A '\' never appears in a name, so a pattern with one matches
    // nothing, as on NTFS (.NET's matcher would read it as an escape).
    public static bool Matches(string name, string? pattern)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (MatchesAll(pattern)) return true;
        if (pattern!.Length > MaxPatternLength || pattern.Contains('\\')) return false;
        if (pattern.AsSpan().IndexOfAny('<', '>', '"') >= 0)
            return pattern.Length <= MaxDosPatternLength
                && System.IO.Enumeration.FileSystemName.MatchesWin32Expression(pattern, name, ignoreCase: true);

        ReadOnlySpan<char> text = name, glob = pattern;
        // Greedy scan with a single remembered '*' position: worst case is
        // O(name * pattern), never exponential.
        int at = 0, part = 0, starPart = -1, starAt = 0;
        while (at < text.Length)
        {
            if (part < glob.Length && (glob[part] == '?' || Same(glob[part], text[at])))
            {
                at++;
                part++;
            }
            else if (part < glob.Length && glob[part] == '*')
            {
                starPart = part++;
                starAt = at;
            }
            else if (starPart >= 0)
            {
                part = starPart + 1;
                at = ++starAt;
            }
            else
            {
                return false;
            }
        }
        while (part < glob.Length && glob[part] == '*') part++;
        return part == glob.Length;
    }

    private static bool Same(char a, char b) =>
        a == b || char.ToUpperInvariant(a) == char.ToUpperInvariant(b);
}
