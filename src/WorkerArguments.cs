using System.Text.Json;

// The command line the parent hands its own executable when it starts a worker.
//
// It is parsed by key, with every required key demanded and anything unexpected
// refused, so the shape is stated once and adding an option costs a line. A
// positional test — a chain of length comparisons and index equalities — would
// be unreadable, would accept an optional value only when a different optional
// value happened to be present too, and would grow another nested case with
// every option.
//
// This is an internal interface between two copies of the same program, not a
// public one, and it is still validated strictly: a worker runs elevated and
// holds a mount, so a malformed or padded argument list is refused rather than
// interpreted generously.
internal sealed record WorkerArguments(
    string PipeName, string Wim, int Index, char Drive, uint ParentPid, ulong ParentCreated,
    string? CertificateSha256, string? WimSha256, HttpsRangeStream.SourceIdentity? SourceIdentity, bool AllUsers = false, bool SignedIn = false)
{
    private const int MaxIdentityLength = 2732;

    private static readonly string[] Required =
        ["--startup-pipe", "--wim", "--index", "--drive", "--parent-pid", "--parent-created"];

    // The parent only ever passes the pin as --wim-cert-sha256: the command line
    // has already folded --test-loopback-cert-sha256 into it and applied the
    // loopback rule (MountOptions), so the worker accepts the one key it is sent.
    private static readonly string[] Optional =
        ["--source-identity", "--wim-cert-sha256", "--wim-sha256", "--all-users", "--signed-in-user"];

    // Returns null when this is not a worker command line at all, so the caller
    // can go on to consider the others. Throws only when it is one and is wrong.
    internal static WorkerArguments? TryParse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length == 0 || args[0] != "--internal-worker") return null;

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; i += 2)
        {
            string key = args[i];
            if (!Required.Contains(key) && !Optional.Contains(key))
                throw new ArgumentException("Unexpected worker argument.");
            if (i + 1 >= args.Length) throw new ArgumentException("Worker argument has no value.");
            if (!values.TryAdd(key, args[i + 1])) throw new ArgumentException("Repeated worker argument.");
        }
        foreach (string key in Required)
            if (!values.ContainsKey(key)) throw new ArgumentException("Missing worker argument.");

        if (!int.TryParse(values["--index"], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out int index) || index < 1)
            throw new ArgumentException("Invalid worker image index.");
        if (values["--drive"].Length != 1) throw new ArgumentException("Invalid worker drive letter.");
        if (!uint.TryParse(values["--parent-pid"], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out uint parentPid))
            throw new ArgumentException("Invalid worker parent process id.");
        if (!ulong.TryParse(values["--parent-created"], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out ulong parentCreated))
            throw new ArgumentException("Invalid worker parent creation time.");

        HttpsRangeStream.SourceIdentity? identity = null;
        if (values.TryGetValue("--source-identity", out string? encoded))
        {
            if (encoded.Length > MaxIdentityLength) throw new ArgumentException("Source identity is too long.");
            identity = JsonSerializer.Deserialize<HttpsRangeStream.SourceIdentity>(Convert.FromBase64String(encoded))
                ?? throw new InvalidDataException("Missing source identity.");
        }

        string? pin = values.TryGetValue("--wim-cert-sha256", out string? real) ? real : null;
        if (pin is not null && !IsSha256(pin)) throw new ArgumentException("Invalid certificate hash.");
        string? wimHash = values.TryGetValue("--wim-sha256", out string? wim) ? wim : null;
        if (wimHash is not null && !IsSha256(wimHash)) throw new ArgumentException("Invalid WIM hash.");
        bool allUsers = values.TryGetValue("--all-users", out string? all) && (all == "1" ? true : throw new ArgumentException("Invalid all-users value."));
        bool signedIn = values.TryGetValue("--signed-in-user", out string? mine) && (mine == "1" ? true : throw new ArgumentException("Invalid signed-in-user value."));

        return new WorkerArguments(values["--startup-pipe"], values["--wim"], index, values["--drive"][0],
            parentPid, parentCreated, pin, wimHash, identity, allUsers, signedIn);
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);
}
