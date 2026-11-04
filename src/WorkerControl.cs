// The background worker's control server: STATUS and UNMOUNT, each authenticated
// by HMAC with a single-use nonce and answered with a signed response.
// WorkerChild builds it and WorkerHost.RunAsync runs it for every background mount.
// The caller owns the mount, proof key, completion signal and lifetime.
using System.IO.Pipes;
using System.ComponentModel;
using System.Text;

internal static class WorkerControl
{
    // How long the worker waits for cleanup before answering UNMOUNT. Removing an
    // owned Dokan installation can wait up to five minutes for the lifecycle lock
    // (DokanLifecycle) and then run msiexec to the end, so this matches the seven
    // minutes WorkerUnmount already allows for the worker to exit. A wait such as
    // 15 seconds would make the signed reply to --remove-dokan nearly always
    // UNKNOWN, so the confirmed path would never run. WorkerControlClient waits
    // this long plus margin.
    internal static readonly TimeSpan CompletionWait = TimeSpan.FromMinutes(7);

    // A successful completion must be supplied only after mount removal,
    // filesystem closure and disposal. Timeout means the result is unknown.
    // Keep the server and key alive until RunAsync has returned. Start processing
    // before the mount starts, once the capability is established. Requests are serialized. The shared secret
    // must come from a trusted startup exchange. This authenticates request
    // bytes, but a valid request can still be relayed. SID/elevation and last-writer
    // checks alone are insufficient. Cancellation callbacks must be nonblocking;
    // the I/O and completion deadlines cannot bound synchronous callbacks. A
    // same-user client can repeatedly occupy the only pipe instance.
    internal static async Task RunAsync(NamedPipeServerStream server, Guid instance, WorkerProof proof,
        CancellationTokenSource mountStop, Task<string> completion,
        WorkerAuthorization authorization, Func<bool> isReady, CancellationToken lifetime)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(mountStop);
        ArgumentNullException.ThrowIfNull(completion);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(isReady);
        if (instance == Guid.Empty) throw new ArgumentException("Invalid worker instance.", nameof(instance));
        string instanceText = instance.ToString("N");
        int droppedConnections = 0;
        while (!lifetime.IsCancellationRequested)
        {
            try { await server.WaitForConnectionAsync(lifetime).ConfigureAwait(false); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                if (lifetime.IsCancellationRequested) return;
                // A same-user process that connects and leaves before the first
                // wait makes it fail with ERROR_NO_DATA. Clear it and listen again,
                // a few times; a pipe that keeps failing is a real fault.
                if (ex is IOException && ++droppedConnections <= 3) { WorkerPipe.Reset(server); continue; }
                throw;
            }
            droppedConnections = 0;
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                string request = await WorkerPipe.ReadAsync(server, deadline.Token).ConfigureAwait(false);
                WorkerPeer.RequireSameUserAndElevation(server);
                string[] fields = request.Split('|');
                if (fields.Length != 4 || fields[0] != instanceText || fields[1] is not ("STATUS" or "UNMOUNT"))
                    throw new InvalidDataException("Invalid worker control request.");
                byte[] challenge = Convert.FromBase64String(fields[2]);
                if (challenge.Length != 32 || Convert.ToBase64String(challenge) != fields[2])
                    throw new InvalidDataException("Invalid control challenge.");
                var decision = authorization.AuthorizeAndConsume(request);
                if (decision == WorkerAuthorization.Decision.Denied) throw new UnauthorizedAccessException("Control request was not authorized.");
                string response;
                if (decision == WorkerAuthorization.Decision.LimitReached) response = "LIMIT";
                else if (fields[1] == "STATUS")
                    response = completion.IsCompleted ? "CLOSED_OR_FAILED" : mountStop.IsCancellationRequested ? "STOPPING" : isReady() ? "RUNNING" : "STARTING";
                else
                {
                    mountStop.Cancel();
                    try { response = await completion.WaitAsync(CompletionWait, lifetime).ConfigureAwait(false); }
                    catch (TimeoutException) { response = "UNKNOWN"; }
                    catch (Exception) when (!lifetime.IsCancellationRequested) { response = "UNKNOWN"; }
                }
                byte[] signature = proof.Sign(challenge, request, response);
                string frame = response + "|" + Convert.ToBase64String(signature);
                using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
                writeDeadline.CancelAfter(TimeSpan.FromSeconds(5));
                await WorkerPipe.WriteAsync(server, frame, writeDeadline.Token).ConfigureAwait(false);
                // The client has consumed the response before disconnect can
                // discard unread pipe bytes. An absent reply times out.
                if (await WorkerPipe.ReadAsync(server, writeDeadline.Token).ConfigureAwait(false) != "RECEIVED")
                    throw new InvalidDataException("Invalid control receipt.");
                // Once the client has read the confirmed close, no further
                // control connection is needed; let the worker exit promptly.
                if (fields[1] == "UNMOUNT" && WorkerCompletionReceipt.TryParseResponse(response, out _, out _)) return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or FormatException or OperationCanceledException or DecoderFallbackException or Win32Exception)
            {
                // Check inside one handler: cancellation can race exception filtering.
                if (lifetime.IsCancellationRequested && (ex is IOException or OperationCanceledException)) return;
                // A malformed, unauthorized, timed-out or disconnected client
                // receives no success. Drop the connection, including any partial frame.
                WorkerDiagnostics.Log("control request", ex);
            }
            finally
            {
                try { if (server.IsConnected) server.Disconnect(); }
                catch (Exception ex) when (ex is IOException or OperationCanceledException)
                {
                    if (!lifetime.IsCancellationRequested) throw;
                }
            }
        }
    }
}
