using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

// How this process signs in to an HTTPS WIM server: Windows sign-in, a bearer
// token read from a file, a client certificate, or a certificate with one of the
// other two. Each process builds its own from the options: a background worker
// is given the token file's path, never the token, and reads the file itself.
internal sealed partial class WimSignIn : IDisposable
{
    private const int MaxTokenBytes = 8 * 1024;
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    internal bool WindowsSignIn { get; }
    internal string? TokenFile { get; }
    internal string? Thumbprint { get; }
    private readonly string? token;
    private readonly X509Certificate2? certificate;
    private readonly bool machineStore;

    private WimSignIn(bool windowsSignIn, string? tokenFile, string? token, string? thumbprint, X509Certificate2? certificate, bool machineStore)
    {
        WindowsSignIn = windowsSignIn;
        TokenFile = tokenFile;
        this.token = token;
        Thumbprint = thumbprint;
        this.certificate = certificate;
        this.machineStore = machineStore;
    }

    // Null when no sign-in was asked for. The option rules (HTTPS only, not
    // Windows sign-in with a token) are MountOptions'; this reads and checks
    // what they name.
    internal static WimSignIn? Open(bool windowsSignIn, string? tokenFile, string? thumbprint)
    {
        if (!windowsSignIn && tokenFile is null && thumbprint is null) return null;
        string? token = tokenFile is null ? null : ReadToken(tokenFile);
        X509Certificate2? certificate = null;
        bool machine = false;
        if (thumbprint is not null) (certificate, machine) = FindCertificate(thumbprint);
        return new WimSignIn(windowsSignIn, tokenFile, token, thumbprint, certificate, machine);
    }

    internal bool HasCertificate => certificate is not null;

    // Called before the client's first request.
    internal void Apply(Uri uri, HttpClientHandler handler, HttpClient client)
    {
        // Only Negotiate (Kerberos, else NTLM) and plain NTLM (Jericho, 2026-11-05:
        // NTLM-only servers such as IIS set that way), and only for this origin:
        // Basic and Digest are never answered, so the password is never sent in a
        // form the server can read. Credentials go only after the server asks.
        if (WindowsSignIn)
        {
            var origin = new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
            handler.Credentials = new CredentialCache
            {
                { origin, "Negotiate", CredentialCache.DefaultNetworkCredentials },
                { origin, "NTLM", CredentialCache.DefaultNetworkCredentials },
            };
        }
        if (certificate is not null)
        {
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(certificate);
        }
        if (token is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    // What the operator is told before the first request. The account matters:
    // the elevated process may be another administrator's, whose Windows sign-in
    // and certificate store are the ones used.
    internal IEnumerable<string> Describe(string host)
    {
        if (WindowsSignIn)
            using (var self = WindowsIdentity.GetCurrent())
                yield return $"Signing in to {SafeText.Path(host)} as {SafeText.Path(self.Name)} (Windows sign-in).";
        if (TokenFile is not null) yield return $"Signing in to {SafeText.Path(host)} with the token in {SafeText.Path(TokenFile)}.";
        if (certificate is not null)
            yield return $"Signing in to {SafeText.Path(host)} with client certificate {Thumbprint} ({SafeText.Path(certificate.Subject)}), " +
                $"from the {(machineStore ? "computer" : "current user")} store.";
    }

    // RFC 6750's token form.
    internal static bool IsBearerToken(string value) => TokenForm().IsMatch(value);

    [GeneratedRegex(@"\A[A-Za-z0-9\-._~+/]+=*\z")]
    private static partial Regex TokenForm();

    private static string ReadToken(string path)
    {
        using FileStream file = TrustedFile.OpenInstructions(path, "token file");
        // Any program running as an ordinary account could otherwise read the
        // token silently. The owner and who may change it are already checked.
        if (TrustedFile.WhoElseCanRead(file.GetAccessControl()) is { } who)
            throw new AdviceException(
                $"{SafeText.Path(path)} can be read by {who}. A sign-in token must be readable only by administrators. Run:",
                $"  .\\WimDriverMount.exe --protect-config {SafeText.Argument(path)}");
        byte[] bytes = new byte[MaxTokenBytes + 1];
        int read = 0, n;
        while (read < bytes.Length && (n = file.Read(bytes, read, bytes.Length - read)) > 0) read += n;
        string? text = ParseToken(bytes.AsSpan(0, read));
        Array.Clear(bytes);
        // The content is never quoted: a near-miss is most of the secret.
        return text ?? throw new InvalidDataException($"{SafeText.Path(path)} does not hold one bearer token (letters, digits and - . _ ~ + / =).");
    }

    // One token in UTF-8, at most 8 KiB, blank space around it ignored; else null.
    internal static string? ParseToken(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxTokenBytes) return null;
        try
        {
            string text = new UTF8Encoding(false, true).GetString(data).TrimStart('\uFEFF').Trim();
            return IsBearerToken(text) ? text : null;
        }
        catch (DecoderFallbackException) { return null; }
    }

    private static (X509Certificate2, bool Machine) FindCertificate(string thumbprint)
    {
        string why = "not found";
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            using var store = new X509Store(StoreName.My, location);
            try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
            catch (System.Security.Cryptography.CryptographicException) { continue; }
            foreach (X509Certificate2 candidate in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false))
            {
                DateTime now = DateTime.Now;
                var usages = candidate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()?.EnhancedKeyUsages;
                string? problem = !candidate.HasPrivateKey ? "no private key"
                    : !KeyReadable(candidate) ? "this account cannot use its private key"
                    : now > candidate.NotAfter ? "expired"
                    : now < candidate.NotBefore ? "not valid yet"
                    : usages is not null && !usages.Cast<System.Security.Cryptography.Oid>().Any(u => u.Value == ClientAuthentication) ? "not for client sign-in"
                    : null;
                if (problem is null) return (candidate, location == StoreLocation.LocalMachine);
                why = problem;
                candidate.Dispose();
            }
        }
        throw new InvalidOperationException($"No usable client certificate {thumbprint}: {why}.");
    }

    // A computer-store key is often for administrators only; an unelevated
    // preview would otherwise fail the handshake with a misleading hint.
    private static bool KeyReadable(X509Certificate2 certificate)
    {
        try
        {
            using IDisposable? key = (IDisposable?)certificate.GetRSAPrivateKey() ?? certificate.GetECDsaPrivateKey();
            return key is not null;
        }
        catch (System.Security.Cryptography.CryptographicException) { return false; }
    }

    public void Dispose() => certificate?.Dispose();
}
