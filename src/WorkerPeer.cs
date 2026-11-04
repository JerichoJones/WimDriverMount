// Control peers must have the same Windows user SID and elevated tokens.
// Separate authenticated logons of that account are allowed; logon LUID is
// not a mount identity. Caller still verifies capability and worker identity.
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal static class WorkerPeer
{
    private const int TokenElevation = 20;

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr information, int informationLength, out int returnLength);

    // The server must come from WorkerPipe.CreateServer, which rejects remote
    // clients and grants access to the current user. Call only after a complete
    // client frame has arrived, because Windows impersonates the last pipe writer.
    // The handle can be shared; this does not authenticate every frame byte.
    // Check each request and close the connection if this check fails. The caller
    // must also verify process/endpoint identity and must not enter impersonated.
    internal static void RequireSameUserAndElevation(NamedPipeServerStream server)
    {
        ArgumentNullException.ThrowIfNull(server);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!server.IsConnected) throw new InvalidOperationException("Pipe is not connected.");
        using WindowsIdentity? ambient = WindowsIdentity.GetCurrent(true);
        if (ambient is not null) throw new InvalidOperationException("Peer checks require a non-impersonated caller.");
        using WindowsIdentity owner = WindowsIdentity.GetCurrent();
        SecurityIdentifier ownerSid = owner.User ?? throw new InvalidOperationException("Current user SID is unavailable.");
        bool ownerElevated = ReadElevation(owner.AccessToken);
        // A client whose identity cannot be read is refused like one that does not
        // match. A client connecting at Anonymous level makes reading it throw
        // SecurityException; if that escaped the control loop, the worker would
        // unmount -- any unelevated process of the user could end the mount.
        try
        {
            server.RunAsClient(() =>
            {
                using WindowsIdentity peer = WindowsIdentity.GetCurrent(true)
                    ?? throw new InvalidOperationException("Cannot read the impersonated client identity.");
                RequireMatchingIdentity(ownerSid, ownerElevated, peer.User, ReadElevation(peer.AccessToken));
            });
        }
        catch (UnauthorizedAccessException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new UnauthorizedAccessException("The pipe client's identity could not be checked.", ex);
        }
    }

    // Authentication LUID is intentionally absent: a new authenticated logon
    // must still supply this worker's HMAC capability and verify its identity.
    internal static void RequireMatchingIdentity(SecurityIdentifier ownerSid, bool ownerElevated,
        SecurityIdentifier? peerSid, bool peerElevated)
    {
        ArgumentNullException.ThrowIfNull(ownerSid);
        if (peerSid is null || !ownerSid.Equals(peerSid) || !ownerElevated || !peerElevated)
            throw new UnauthorizedAccessException("Pipe client must be elevated and have the worker's user SID.");
    }

    internal static bool ReadElevation(SafeAccessTokenHandle token)
    {
        // TOKEN_ELEVATION is one DWORD. Native Windows can return
        // ERROR_BAD_LENGTH for a null size probe; query the fixed layout once.
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            if (!GetTokenInformation(token, TokenElevation, buffer, sizeof(int), out int returned))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read token elevation.");
            if (returned != sizeof(int)) throw new InvalidDataException("Invalid token elevation length.");
            int value = Marshal.ReadInt32(buffer);
            if (value is not (0 or 1)) throw new InvalidDataException("Invalid token elevation value.");
            return value == 1;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}
