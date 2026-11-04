using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

// What makes a Dokan installer acceptable. Dokan is a kernel-mode driver installed
// elevated through msiexec rather than SetupAPI, so trust rests where Windows puts it for
// drivers: on who signed it. Windows must accept the Authenticode signature, the signer
// must be Dokan's publisher by EXACT organisation and company registration number, and
// the package must declare Dokan's upgrade code and a version this build can use.
//
// Not pinned to one build's bytes, deliberately, except where the user asks for it:
// --get-dokan on its own pins the tested build (TestedSha256). Otherwise a pin would keep
// installing one Dokan forever, and for a kernel driver that means keeping its
// vulnerabilities once Dokan has fixed them. A hash published beside the download comes
// from the same place as the file, so it proves transport integrity -- already given by
// HTTPS, and by the signature -- not authenticity. Authenticity is the signature: passing
// this check needs LEOSAC's private EV signing key.
//
// IsDokanPublisher matches the publisher exactly. A substring check such as
// subject.Contains("O=LEOSAC") would match any organisation whose name merely begins
// with LEOSAC, so a lawfully registered "LEOSAC Holdings Ltd" with a bought code-signing
// certificate and Dokan's upgrade code copied into its own MSI would pass every check here.
internal static class DokanPackage
{
    // Each processor's package: its file name, and its upgrade code, the one identifier
    // that stays the same across Dokan versions (UpgradeCodeX64/UpgradeCodeARM64 in
    // dokany's dokan_wix/version.xml). Dokan's driver must match Windows and its DLL must
    // match this program, so MountOptions refuses a build that differs from Windows.
    internal static (string MsiName, string UpgradeCode) For(Architecture architecture) => architecture == Architecture.Arm64
        ? ("Dokan_ARM64.msi", "{BD055051-AFAD-497D-8297-C4389835870A}")
        : ("Dokan_x64.msi", "{31A8F445-2AC6-494B-819C-4F4E1B2AECF1}");
    internal static string MsiName => For(RuntimeInformation.OSArchitecture).MsiName;
    internal static string UpgradeCode => For(RuntimeInformation.OSArchitecture).UpgradeCode;
    // The organisation that signs the official releases, and its French company
    // registration number (SIREN/SIRET), both read off the EV certificate on a genuine
    // release. The number identifies the company itself and survives certificate renewal,
    // which a thumbprint would not.
    internal const string SignerOrganisation = "LEOSAC";
    internal const string SignerRegistration = "919 690 420 00014";
    // GitHub serves the newest release's asset from this address.
    internal static string LatestUrl => "https://github.com/dokan-dev/dokany/releases/latest/download/" + MsiName;

    // The release this program is tested with, for --get-dokan on its own: its address and
    // the exact SHA-256 of its installer for this PC (GitHub publishes the same digests on the release page).
    internal const string TestedVersion = "2.3.1";
    internal static string TestedUrl => "https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/" + MsiName;
    internal static string TestedSha256 => TestedSha256For(RuntimeInformation.OSArchitecture);
    internal static string TestedSha256For(Architecture architecture) => architecture == Architecture.Arm64
        ? "F812A5BF11C15BC3910A1F0F53830FF771CEB3C80458F10686B0F45B0DB91D2E"
        : "69FF8CB37BFEC3A75921C85FFD1C6370B50A9EC4ECEF2CF3A009D488DCBF5465";

    // The tested release is pinned by its exact bytes as well as by its signature; any
    // other source is left to the signature checks.
    internal static void RequirePinned(string url, Stream file)
    {
        if (!string.Equals(url, TestedUrl, StringComparison.OrdinalIgnoreCase)) return;
        string found = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(file));
        if (found != TestedSha256)
            throw new InvalidOperationException($"The downloaded Dokan {TestedVersion} installer is not the one this program was tested with, so nothing was installed. Its SHA-256 is {found}; expected {TestedSha256}.");
    }

    // Exactly one organisation and exactly one serial number, each equal to Dokan's
    // publisher's -- not a substring anywhere in the subject text. Multi-valued
    // components are refused outright: the real certificate has none.
    internal static bool IsDokanPublisher(X500DistinguishedName subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        string? organisation = null, registration = null;
        int organisations = 0, registrations = 0;
        foreach (var component in subject.EnumerateRelativeDistinguishedNames())
        {
            if (component.HasMultipleElements) return false;
            string? oid = component.GetSingleElementType().Value;
            if (oid == "2.5.4.10") { organisation = component.GetSingleElementValue(); organisations++; }
            else if (oid == "2.5.4.5") { registration = component.GetSingleElementValue(); registrations++; }
        }
        return organisations == 1 && registrations == 1 &&
            string.Equals(organisation, SignerOrganisation, StringComparison.Ordinal) &&
            string.Equals(registration, SignerRegistration, StringComparison.Ordinal);
    }
    // The application links DokanNet 2.3 and its driver interface; a different major
    // version is not assumed to be compatible.
    internal static readonly Version MinimumVersion = new(2, 3);

    internal readonly record struct Identity(string ProductCode, Version Version, string Name);

    // ---- Authenticode ----
    private static readonly Guid GenericVerify = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo { internal uint Size; internal IntPtr Path, Handle, KnownSubject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        internal uint Size; internal IntPtr PolicyCallbackData, SipClientData;
        internal uint UiChoice, RevocationChecks, UnionChoice; internal IntPtr Info;
        internal uint StateAction; internal IntPtr StateData, UrlReference; internal uint ProviderFlags, UiContext;
        internal IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);

    // Throws unless Windows trusts the file's signature and the signer is Dokan's
    // publisher. Revocation is not checked, so this works on an isolated computer.
    internal static void RequireTrusted(string path)
    {
        IntPtr file = Marshal.StringToHGlobalUni(path);
        IntPtr info = IntPtr.Zero;
        try
        {
            var fileInfo = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = file };
            info = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
            Marshal.StructureToPtr(fileInfo, info, false);
            var data = new TrustData
            {
                Size = (uint)Marshal.SizeOf<TrustData>(),
                UiChoice = 2,          // WTD_UI_NONE
                RevocationChecks = 0,  // WTD_REVOKE_NONE: no network needed
                UnionChoice = 1,       // WTD_CHOICE_FILE
                Info = info,
                StateAction = 1,       // WTD_STATEACTION_VERIFY
                ProviderFlags = 0x1000 // WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = GenericVerify;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.StateAction = 2;      // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            if (result != 0)
                throw new InvalidOperationException($"Windows did not accept the Dokan installer's signature (0x{result:X8}). It is not an official signed release, or it was altered.");
        }
        finally
        {
            if (info != IntPtr.Zero) Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(file);
        }
        // .NET has no replacement for reading an Authenticode signer (SYSLIB0057's
        // loaders take certificate files, not signed programs). Callers make sure
        // nobody else can change the file between the two reads: the installer holds
        // it open denying writes until install, and --install checks its own copy in
        // a folder only administrators can change.
#pragma warning disable SYSLIB0057
        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        if (!IsDokanPublisher(certificate.SubjectName))
            throw new InvalidOperationException($"The Dokan installer is signed by {SafeText.Quote(certificate.Subject)}, which is not {SignerOrganisation} ({SignerRegistration}); it was not installed.");
    }

    // ---- The package's own declared identity ----
    private const uint ReadOnly = 0, NoMoreItems = 259;
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out IntPtr database);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiDatabaseOpenViewW(IntPtr database, string query, out IntPtr view);
    [DllImport("msi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiViewExecute(IntPtr view, IntPtr record);
    [DllImport("msi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiRecordGetStringW(IntPtr record, uint field, char[] value, ref uint size);
    [DllImport("msi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiCloseHandle(IntPtr handle);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint MsiEnumRelatedProductsW(string upgradeCode, uint reserved, uint index, char[] productCode);

    private static string Property(IntPtr database, string name)
    {
        // The name is a fixed internal string, never caller input.
        if (MsiDatabaseOpenViewW(database, $"SELECT `Value` FROM `Property` WHERE `Property`='{name}'", out IntPtr view) != 0)
            throw new InvalidDataException($"Cannot read {name} from the Dokan installer.");
        try
        {
            if (MsiViewExecute(view, IntPtr.Zero) != 0 || MsiViewFetch(view, out IntPtr record) != 0 || record == IntPtr.Zero)
                throw new InvalidDataException($"The Dokan installer declares no {name}.");
            try
            {
                var buffer = new char[256];
                uint size = (uint)buffer.Length;
                if (MsiRecordGetStringW(record, 1, buffer, ref size) != 0) throw new InvalidDataException($"Cannot read {name}.");
                return new string(buffer, 0, (int)size);
            }
            finally { MsiCloseHandle(record); }
        }
        finally { MsiCloseHandle(view); }
    }

    // Reads what the package says it is, without installing it.
    // architecture: this PC's unless a test names another.
    internal static Identity ReadIdentity(string path, Architecture? architecture = null)
    {
        if (MsiOpenDatabaseW(path, (IntPtr)ReadOnly, out IntPtr database) != 0)
            throw new InvalidDataException("The Dokan installer is not a readable Windows Installer package.");
        try
        {
            string upgrade = Property(database, "UpgradeCode");
            if (!string.Equals(upgrade, architecture is { } a ? For(a).UpgradeCode : UpgradeCode, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"The installer's upgrade code {SafeText.Quote(upgrade)} is not Dokan's; it was not installed.");
            string product = Property(database, "ProductCode");
            string name = Property(database, "ProductName");
            if (!Version.TryParse(Property(database, "ProductVersion"), out Version? version))
                throw new InvalidDataException("The Dokan installer declares no usable version.");
            if (version.Major != MinimumVersion.Major || version < MinimumVersion)
                throw new InvalidDataException($"This build needs Dokan {MinimumVersion.Major}.{MinimumVersion.Minor} or a later {MinimumVersion.Major}.x; the installer is {version}.");
            return new(product, version, name);
        }
        finally { MsiCloseHandle(database); }
    }

    // The product code of an installed Dokan, found through the upgrade code, so a
    // version installed by this tool can be removed without knowing it in advance.
    internal static string? InstalledProductCode()
    {
        var buffer = new char[39];
        for (uint index = 0; ; index++)
        {
            uint result = MsiEnumRelatedProductsW(UpgradeCode, 0, index, buffer);
            if (result == NoMoreItems) return null;
            if (result != 0) throw new InvalidDataException($"Cannot enumerate installed Dokan products (error {result}).");
            string product = new string(buffer).TrimEnd('\0');
            if (product.Length != 0) return product;
        }
    }
}
