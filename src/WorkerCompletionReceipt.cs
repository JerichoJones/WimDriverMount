// Signed completion receipt: WorkerHost writes it when the mount closes and
// --unmount verifies it (WorkerRecoveryStore). A signature cannot prove that a dishonest or compromised
// worker actually performed cleanup.
using System.Globalization;
using System.Security.Cryptography;

internal static class WorkerCompletionReceipt
{
    internal enum DokanStatus { None, Kept, Removed, RestartRequired, Deferred, Failed, FailedRestart, FailedRestartInitiated }
    internal readonly record struct Closure(bool SourceFailed, DokanStatus Dokan);
    private static readonly byte[] Magic = "WDC1"u8.ToArray();
    private static readonly byte[] FailedMagic = "WDF1"u8.ToArray();
    private const int ChallengeLength = 32, SignatureLength = 64;
    private const int ReceiptLength = 4 + ChallengeLength + SignatureLength;

    // Only call after the mount, filesystem and WIM stream have all closed
    // successfully. Never create a CLOSED receipt for timeout or uncertainty.
    // Serialize this call with all other use and disposal of the proof key.
    internal static byte[] CreateClosed(WorkerProof proof, Guid instance, char drive, uint pid, ulong creation, bool sourceFailed = false,
        DokanStatus dokan = DokanStatus.None)
    {
        ArgumentNullException.ThrowIfNull(proof);
        string request = Request(instance, drive, pid, creation);
        byte[] challenge = RandomNumberGenerator.GetBytes(ChallengeLength);
        string response = Response(sourceFailed, dokan);
        byte[] signature = proof.Sign(challenge, request, response);
        if (signature.Length != SignatureLength) throw new CryptographicException("Invalid receipt signature size.");
        byte[] receipt = new byte[ReceiptLength];
        if (dokan == DokanStatus.None) (sourceFailed ? FailedMagic : Magic).CopyTo(receipt, 0);
        else { receipt[0] = (byte)'W'; receipt[1] = (byte)'X'; receipt[2] = (byte)Code(dokan); receipt[3] = (byte)(sourceFailed ? '1' : '0'); }
        challenge.CopyTo(receipt, Magic.Length);
        signature.CopyTo(receipt, Magic.Length + ChallengeLength);
        return receipt;
    }

    // The prepared record must be obtained under the retained reservation and
    // its key must originate from the checked startup exchange. A replaceable
    // record is not an independent anchor against a hostile same-user process.
    // A receipt is a past cleanup claim, not proof of the current drive mapping.
    // The caller must keep the receipt stable for the duration of this call.
    internal static bool VerifyClosed(byte[] receipt, WorkerRecoveryRecord prepared)
        => TryVerifyClosed(receipt, prepared, out _);

    internal static bool TryVerifyClosed(byte[] receipt, WorkerRecoveryRecord prepared, out bool sourceFailed)
        => TryVerifyClosed(receipt, prepared, out sourceFailed, out _);

    internal static bool TryVerifyClosed(byte[] receipt, WorkerRecoveryRecord prepared, out bool sourceFailed, out DokanStatus dokan)
    {
        sourceFailed = false;
        dokan = DokanStatus.None;
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(prepared);
        if (prepared.ObservedMapping is not null || receipt.Length != ReceiptLength) return false;
        bool failed = receipt.AsSpan(0, Magic.Length).SequenceEqual(FailedMagic);
        DokanStatus status = DokanStatus.None;
        if (!failed && !receipt.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            if (receipt[0] != 'W' || receipt[1] != 'X' || receipt[3] is not ((byte)'0' or (byte)'1')) return false;
            status = (char)receipt[2] switch { 'K' => DokanStatus.Kept, 'R' => DokanStatus.Removed, 'T' => DokanStatus.RestartRequired, 'D' => DokanStatus.Deferred, 'F' => DokanStatus.Failed, 'X' => DokanStatus.FailedRestart, 'I' => DokanStatus.FailedRestartInitiated, _ => DokanStatus.None };
            if (status == DokanStatus.None) return false;
            failed = receipt[3] == '1';
        }
        byte[] challenge = receipt.AsSpan(Magic.Length, ChallengeLength).ToArray();
        byte[] signature = receipt.AsSpan(Magic.Length + ChallengeLength, SignatureLength).ToArray();
        byte[] key = prepared.CopyPublicKey();
        if (!WorkerProof.Verify(key, challenge, Request(prepared.Instance, prepared.Drive,
            prepared.ProcessId, prepared.CreationTime), Response(failed, status), signature)) return false;
        sourceFailed = failed;
        dokan = status;
        return true;
    }

    internal static string Response(bool sourceFailed, DokanStatus dokan) => dokan == DokanStatus.None
        ? sourceFailed ? "CLOSED_SOURCE_FAILED" : "CLOSED"
        : $"CLOSED_DOKAN_{Code(dokan)}{(sourceFailed ? '1' : '0')}";

    internal static bool TryParseResponse(string response, out bool sourceFailed, out DokanStatus dokan)
    {
        foreach (DokanStatus status in Enum.GetValues<DokanStatus>())
            foreach (bool failed in new[] { false, true })
                if (string.Equals(response, Response(failed, status), StringComparison.Ordinal))
                { sourceFailed = failed; dokan = status; return true; }
        sourceFailed = false; dokan = DokanStatus.None; return false;
    }

    private static char Code(DokanStatus value) => value switch
    {
        DokanStatus.Kept => 'K', DokanStatus.Removed => 'R', DokanStatus.RestartRequired => 'T',
        DokanStatus.Deferred => 'D', DokanStatus.Failed => 'F', DokanStatus.FailedRestart => 'X', DokanStatus.FailedRestartInitiated => 'I', _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    private static string Request(Guid instance, char drive, uint pid, ulong creation)
    {
        if (instance == Guid.Empty || drive is < 'D' or > 'Z' || pid == 0 || creation == 0)
            throw new ArgumentException("Invalid receipt identity.");
        return "WimDrive-completion-v1|" + instance.ToString("N") + "|" + drive + "|" +
            pid.ToString(CultureInfo.InvariantCulture) + "|" + creation.ToString(CultureInfo.InvariantCulture);
    }
}
