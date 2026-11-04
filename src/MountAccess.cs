using System.Security.AccessControl;
using System.Security.Principal;
using DiscUtils.MountDokan;
using DokanNet;

// Who may open files on the mounted drive. Dokan publishes the drive letter to
// every session, and the bridge would otherwise apply the WIM's own ACLs, which
// typically let any local user read everything. The mount belongs to the user
// who made it: that user (elevated or not), for a right-click Mount the account
// signed in to the session it was made in (see SignedInUser), SYSTEM (Plug and
// Play and the driver installer read from the drive as SYSTEM) and elevated
// administrators may open files; everyone else is refused. Descriptors shown to callers say the same.
internal static class MountAccess
{
    internal static void Apply(DokanDiscUtils operations, SecurityIdentifier[] owners)
    {
        string allow = "(A;OICI;0x1200a9;;;SY)(A;OICI;0x1200a9;;;BA)" + string.Concat(owners.Select(o => $"(A;OICI;0x1200a9;;;{o.Value})"));
        var file = new FileSecurity();
        file.SetSecurityDescriptorSddlForm("O:BAG:BAD:P" + allow.Replace("OICI", ""));
        var directory = new DirectorySecurity();
        directory.SetSecurityDescriptorSddlForm("O:BAG:BAD:P" + allow);
        operations.ForcedFileSecurity = file;
        operations.DirectorySecurity = directory;
        operations.AccessCheck += (_, e) =>
        {
            bool allowed = false; // A requester we cannot identify is not let in.
            if (e.RequestorToken is { IsInvalid: false } token)
            {
                try
                {
                    using var identity = new WindowsIdentity(token.DangerousGetHandle());
                    allowed = Allowed(identity.User, new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), owners);
                }
                catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.SecurityException or ObjectDisposedException) { }
            }
            if (!allowed) e.Status = NtStatus.AccessDenied;
        };
    }

    // --all-users: every account may open the drive, but only what the WIM's own
    // permissions let it read. The bridge only displays those permissions and
    // Dokan does not enforce them, so without this every account could read
    // every file -- a captured SAM hive, another user's profile. The mounting
    // user, SYSTEM and elevated administrators keep full access, as without
    // --all-users. A file with no stored permissions (a WIM captured without
    // ACLs) is open to all, as a null access list is in Windows.
    internal static void ApplyAllUsers(DokanDiscUtils operations, SecurityIdentifier owner, DiscUtils.Wim.WimFileSystem image)
    {
        operations.AccessCheck += (_, e) =>
        {
            bool allowed = false;
            if (e.RequestorToken is { IsInvalid: false } token)
            {
                try
                {
                    using var identity = new WindowsIdentity(token.DangerousGetHandle());
                    allowed = Allowed(identity.User, new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), [owner]) ||
                        WimPermitsRead(identity, image, e.Path, e.IsDirectory);
                }
                catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.SecurityException or ObjectDisposedException or IOException) { }
            }
            if (!allowed) e.Status = NtStatus.AccessDenied;
        };
    }

    private const uint FileGenericRead = 0x120089;
    private static readonly uint[] FileMapping = [0x120089, 0x120116, 0x1200A0, 0x1F01FF];

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool DuplicateToken(IntPtr token, int level, out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle duplicate);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool AccessCheck(byte[] descriptor, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token, uint desired,
        uint[] mapping, byte[] privileges, ref uint privilegesLength, out uint granted,
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)] out bool status);

    // Windows' own access check of the requester against the WIM's stored
    // permissions, for read access (the drive is read-only).
    internal static bool WimPermitsRead(WindowsIdentity requester, DiscUtils.Wim.WimFileSystem image, string path, bool directory)
    {
        RawSecurityDescriptor stored;
        try
        {
            // The reader's descriptor type is DiscUtils' own; the binary form is shared.
            var wim = image.GetSecurity(path);
            if (wim is null) return true;
            byte[] raw = new byte[wim.BinaryLength];
            wim.GetBinaryForm(raw, 0);
            stored = new RawSecurityDescriptor(raw, 0);
        }
        catch (FileNotFoundException) { return true; } // Nothing to protect; the bridge reports not-found.
        if (stored.DiscretionaryAcl is null) return true;
        // AccessCheck needs an owner and group; only the access list decides a read.
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var descriptor = new RawSecurityDescriptor(stored.ControlFlags & ~ControlFlags.SelfRelative,
            stored.Owner ?? administrators, stored.Group ?? administrators, null, stored.DiscretionaryAcl);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        if (!DuplicateToken(requester.AccessToken.DangerousGetHandle(), 1 /* SecurityIdentification */, out var imitation))
            throw new System.ComponentModel.Win32Exception();
        using (imitation)
        {
            byte[] privileges = new byte[256];
            uint length = (uint)privileges.Length;
            if (!AccessCheck(bytes, imitation, FileGenericRead, FileMapping, privileges, ref length, out _, out bool granted))
                throw new System.ComponentModel.Win32Exception();
            return granted;
        }
    }

    // Administrator means the role is enabled in the requester's token: a
    // filtered token's deny-only Administrators group does not count.
    internal static bool Allowed(SecurityIdentifier? requester, bool enabledAdministrator, SecurityIdentifier[] owners) =>
        requester is not null && (owners.Contains(requester) || requester.IsWellKnown(WellKnownSidType.LocalSystemSid) || enabledAdministrator);

    // Who owns a drive: the mounting account, plus the signed-in one when it differs.
    internal static SecurityIdentifier[] Owners(SecurityIdentifier mounting, SecurityIdentifier? signedIn) =>
        signedIn is null || signedIn.Equals(mounting) ? [mounting] : [mounting, signedIn];

    // The account signed in to this process's session: the one whose desktop showed
    // the administrator prompt, so the one who clicked Mount when someone else's
    // administrator password was typed. Windows reports it, not the unelevated
    // caller, so a caller cannot name a different account to let in. Null when the
    // session has no signed-in user (a service or SSH) or the name has no SID.
    // shortcut: the name is resolved now, so an account renamed since sign-in and its
    // name given to another resolves to that other; reading the SID itself needs SYSTEM.
    internal static SecurityIdentifier? SignedInUser()
    {
        string? user = SessionText(5 /* WTSUserName */), domain = SessionText(7 /* WTSDomainName */);
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(domain)) return null; // A bare name could match another domain's account.
        try { return (SecurityIdentifier)new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)); }
        catch (Exception ex) when (ex is IdentityNotMappedException || ex.GetType() == typeof(SystemException)) { return null; } // Translate reports a Win32 failure as a plain SystemException.
    }

    private static string? SessionText(int kind)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, -1 /* this session */, kind, out IntPtr buffer, out _)) return null;
        try { return System.Runtime.InteropServices.Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    [System.Runtime.InteropServices.DllImport("wtsapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int kind, out IntPtr buffer, out int bytes);

    [System.Runtime.InteropServices.DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
