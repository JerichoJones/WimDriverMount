// The background worker's control client. WorkerUnmount calls UnmountAsync and
// WorkerStartup calls VerifyStartupEndpointAsync.
// Identity and capability must come from independently trusted startup data.
using System.IO.Pipes;
using System.Security.Cryptography;

internal static class WorkerControlClient
{
    internal enum Outcome { Closed, ClosedSourceFailed, Failed, Limit, Unknown, Unavailable }
    internal sealed record Result(Outcome Outcome, string Detail, WorkerCompletionReceipt.DokanStatus Dokan = WorkerCompletionReceipt.DokanStatus.None);

    // Verify the actual control endpoint while the starter still holds the
    // child's process identity and the startup capability. STARTING is valid
    // here: the mount callback has not yet completed the startup exchange.
    internal static async Task VerifyStartupEndpointAsync(string pipeName, Guid instance,
        WorkerProcessIdentity identity, byte[] pinnedPublicKey, byte[] capability,
        CancellationToken cancellation, bool requireRunning = false)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(pinnedPublicKey);
        ArgumentNullException.ThrowIfNull(capability);
        if (instance == Guid.Empty || capability.Length != 32 || !WorkerProof.IsValidPublicKey(pinnedPublicKey))
            throw new ArgumentException("Invalid worker startup identity.");
        do
        {
            string status = await ExchangeAsync(pipeName, instance, "STATUS", identity, pinnedPublicKey,
                capability, () => { }, cancellation).ConfigureAwait(false);
            // RUNNING is always acceptable. STARTING is acceptable at startup, and
            // otherwise means "not yet": poll. Accepting only STARTING at startup
            // would report a worker that had already reached RUNNING as a failed start.
            if (status == "RUNNING" || (!requireRunning && status == "STARTING")) return;
            if (status != "STARTING") throw new InvalidDataException("Worker control endpoint is not in the expected state.");
            await Task.Delay(100, cancellation).ConfigureAwait(false);
        } while (true);
    }

    // The caller owns and retains identity through this call and any exit check;
    // it must not dispose the handle concurrently. Protect and clear its secret.
    // A lost or unverifiable response after a request starts is always unknown.
    internal static async Task<Result> UnmountAsync(string pipeName, Guid instance, uint pid, ulong creation,
        WorkerProcessIdentity identity, byte[] pinnedPublicKey, byte[] capability, CancellationToken cancellation,
        Func<Task>? beforeAcknowledgement = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(pinnedPublicKey);
        ArgumentNullException.ThrowIfNull(capability);
        if (instance == Guid.Empty || identity.ProcessId != pid || identity.CreationTime != creation ||
            capability.Length != 32 || !WorkerProof.IsValidPublicKey(pinnedPublicKey))
            throw new ArgumentException("Invalid trusted worker capability.");
        byte[] secret = (byte[])capability.Clone();
        byte[] key = (byte[])pinnedPublicKey.Clone();
        bool unmountMayHaveBeenSent = false;
        string? authenticatedFailure = null;
        // The status check answers at once; the unmount reply comes only after the
        // worker's cleanup, which can take minutes. One shared 30-second deadline
        // would give up on the second long before the worker answers it.
        using var statusDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        statusDeadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var unmountDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        unmountDeadline.CancelAfter(WorkerControl.CompletionWait + TimeSpan.FromSeconds(30));
        try
        {
            // Authenticate a status response before requesting any stop. A
            // second connection still requires the same held process and key.
            // Every value a genuine worker can sign here is acceptable -- including
            // LIMIT, which must not consume the separately reserved unmount
            // capacity -- and anything else fails the signature check before it
            // arrives, so the response itself is not inspected.
            _ = await ExchangeAsync(pipeName, instance, "STATUS", identity, key, secret,
                () => { }, statusDeadline.Token).ConfigureAwait(false);
            string result = await ExchangeAsync(pipeName, instance, "UNMOUNT", identity, key, secret,
                () => unmountMayHaveBeenSent = true, unmountDeadline.Token,
                response => { if (response is "FAILED" or "LIMIT") authenticatedFailure = response; }, beforeAcknowledgement).ConfigureAwait(false);
            if (WorkerCompletionReceipt.TryParseResponse(result, out bool sourceFailed, out var dokan))
                return new Result(sourceFailed ? Outcome.ClosedSourceFailed : Outcome.Closed,
                    sourceFailed ? "Worker reported completed cleanup after the WIM source failed or changed." : "Worker reported completed cleanup.", dokan);
            return result switch
            {
                "FAILED" => new Result(Outcome.Failed, "The background mount could not unmount the drive. If it was started with --log or --evtlog, the reason is in that log."),
                "LIMIT" => new Result(Outcome.Limit, "The background mount refused: it has already handled as many requests as it allows. Restart Windows, then run the same --unmount command again."),
                _ => new Result(Outcome.Unknown, "The background mount did not confirm the unmount; checking whether it closed.")
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Once authenticated, a negative response must not be converted to
            // an unknown outcome just because the acknowledgement failed.
            if (authenticatedFailure == "FAILED") return new Result(Outcome.Failed, "The background mount could not unmount the drive. If it was started with --log or --evtlog, the reason is in that log.");
            if (authenticatedFailure == "LIMIT") return new Result(Outcome.Limit, "The background mount refused: it has already handled as many requests as it allows. Restart Windows, then run the same --unmount command again.");
            return new Result(unmountMayHaveBeenSent ? Outcome.Unknown : Outcome.Unavailable,
                "The background mount could not be reached; checking whether it closed.");
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static async Task<string> ExchangeAsync(string pipeName, Guid instance, string operation,
        WorkerProcessIdentity identity, byte[] key, byte[] secret, Action beforeWrite, CancellationToken cancellation,
        Action<string>? onAuthenticatedResponse = null, Func<Task>? beforeAcknowledgement = null)
    {
        await using NamedPipeClientStream pipe = WorkerPipe.CreateClient(pipeName);
        // Connecting is quick or blocked; only the reply may take minutes. A pipe
        // held by another process costs 30 seconds, then --unmount falls back to
        // the stop signal, instead of the whole unmount reply deadline.
        using (var connectDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
        {
            connectDeadline.CancelAfter(TimeSpan.FromSeconds(30));
            await pipe.ConnectAsync(connectDeadline.Token).ConfigureAwait(false);
        }
        identity.RequirePipeServer(pipe);
        string request = WorkerAuthorization.CreateRequest(instance, operation, secret);
        string[] requestFields = request.Split('|');
        byte[] challenge = Convert.FromBase64String(requestFields[2]);
        beforeWrite(); // A failed or partial write may still have reached the worker.
        await WorkerPipe.WriteAsync(pipe, request, cancellation).ConfigureAwait(false);
        string frame = await WorkerPipe.ReadAsync(pipe, cancellation).ConfigureAwait(false);
        identity.RequirePipeServer(pipe);
        string[] fields = frame.Split('|');
        if (fields.Length != 2 || fields[0].Length == 0 || fields[0].Length > 32)
            throw new InvalidDataException("Invalid worker response.");
        byte[] signature = Convert.FromBase64String(fields[1]);
        if (Convert.ToBase64String(signature) != fields[1] || !WorkerProof.Verify(key, challenge, request, fields[0], signature))
            throw new InvalidDataException("Worker response could not be authenticated.");
        onAuthenticatedResponse?.Invoke(fields[0]);
        if (beforeAcknowledgement is not null) await beforeAcknowledgement().ConfigureAwait(false);
        await WorkerPipe.WriteAsync(pipe, "RECEIVED", cancellation).ConfigureAwait(false);
        return fields[0];
    }
}
