// The bridge between the mount lifecycle and the control server, run for every
// background mount by WorkerChild.
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using DiscUtils.Wim;

internal static class WorkerHost
{
    // activate must publish only tentative readiness until its trusted startup
    // exchange is acknowledged; it must honor cancellation and not own the
    // server, proof, authorization, or mount resources. It must not claim mount
    // ownership. Activation runs synchronously on the mount thread: if it does
    // not honor cancellation, startup and cleanup can block and remain unknown.
    internal static async Task RunAsync(string wimPath, int imageIndex, char drive,
        NamedPipeServerStream server, Guid instance, WorkerProof proof, WorkerAuthorization authorization,
        WorkerRecoveryRecord prepared, Task authorizedGo, Action<string, CancellationToken> activate, CancellationToken lifetime, string? certificateSha256 = null, HttpsRangeStream.SourceIdentity? sourceIdentity = null,
        Action<WorkerCompletionReceipt.Closure>? onClosure = null, string? wimSha256 = null, WaitHandle? stopSignal = null, bool allUsers = false, bool signedIn = false)
    {
        bool web = Uri.TryCreate(wimPath, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
        if ((!web && !Path.IsPathFullyQualified(wimPath)) || imageIndex < 1 || drive is < 'D' or > 'Z')
            throw new ArgumentException("Invalid worker mount arguments.");
        if (web != (sourceIdentity is not null)) throw new ArgumentException("Web WIM worker requires a source identity.");
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(authorizedGo);
        ArgumentNullException.ThrowIfNull(activate);
        using Process selfProcess = Process.GetCurrentProcess();
        using WorkerProcessIdentity self = WorkerProcessIdentity.CaptureChild(selfProcess);
        if (prepared.ObservedMapping is not null || prepared.Instance != instance || prepared.Drive != drive ||
            prepared.ProcessId != self.ProcessId || prepared.CreationTime != self.CreationTime ||
            !CryptographicOperations.FixedTimeEquals(prepared.CopyPublicKey(), proof.ExportPublicKey()))
            throw new InvalidDataException("Prepared recovery identity does not match the worker.");
        byte[] capability = prepared.CopyCapability();
        try
        {
            if (!authorization.Matches(instance, capability))
                throw new InvalidDataException("Prepared recovery capability does not match the control server.");
        }
        finally { CryptographicOperations.ZeroMemory(capability); }
        // While this worker serves the drive its recovery directory cannot be
        // renamed away, so --unmount can always find the records.
        using IDisposable recoveryPin = WorkerRecoveryStore.PinRecoveryDirectory();
        using var stop = new CancellationTokenSource();
        // A startup or lifetime cancellation requests cleanup but must not
        // stop control while a native mount or disposal remains blocked.
        using var controlLifetime = new CancellationTokenSource();
        using var registration = lifetime.Register(() => stop.Cancel());
        // The stop signal ends the mount exactly as UNMOUNT does: the same stop,
        // the same cleanup, the same signed closed receipt (see WorkerStopSignal).
        RegisteredWaitHandle? signalWait = stopSignal is null ? null
            : ThreadPool.RegisterWaitForSingleObject(stopSignal, (_, _) => stop.Cancel(), null, Timeout.Infinite, true);
        var completion = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int ready = 0;
        Exception? mountFailure = null;
        async Task RunControlGuarded()
        {
            try { await WorkerControl.RunAsync(server, instance, proof, stop, completion.Task, authorization,
                () => Volatile.Read(ref ready) != 0, controlLifetime.Token).ConfigureAwait(false); }
            finally { if (!controlLifetime.IsCancellationRequested) stop.Cancel(); }
        }
        Task control = RunControlGuarded();
        try
        {
            // The caller completes this gate only after it has authenticated GO.
            // Stop before GO must not open the WIM or create a mount.
            await authorizedGo.WaitAsync(stop.Token).ConfigureAwait(false);
            stop.Token.ThrowIfCancellationRequested();
            var result = await Task.Run(() =>
            {
                stop.Token.ThrowIfCancellationRequested();
                using Stream stream = web
                    ? new HttpsRangeStream(uri!, stop.Token, () => stop.Cancel(), certificateSha256, sourceIdentity)
                    : new ResilientFileSource(wimPath, stop.Token);
                // Verified here, in the process that will serve the drive, and
                // against its own stream. Checking in the parent would prove
                // nothing about what this one goes on to read.
                // A split WIM's other parts, opened in place. The first part keeps
                // the identity the parent saw; each later part is pinned when this
                // process first opens it, and WimFile binds every part to the first
                // by the set's GUID, part count and part number.
                string firstName = web ? uri!.AbsoluteUri : wimPath;
                var parts = SplitWim.OpenParts(stream, firstName, wimSha256 is not null, name => web
                    ? new HttpsRangeStream(new Uri(name), stop.Token, () => stop.Cancel(), certificateSha256)
                    : new ResilientFileSource(name, stop.Token));
                using var partsLifetime = new SplitWim.Lease(parts);
                var verified = wimSha256 is null ? null : WimSourceVerification.Require(stream, wimSha256, wimPath, Console.Out, stop.Cancel);
                stop.Token.ThrowIfCancellationRequested();
                var wim = verified is not null ? new WimFile(verified) : new WimFile(parts);
                if (imageIndex > wim.ImageCount) throw new ArgumentOutOfRangeException(nameof(imageIndex));
                using var fs = wim.GetImage(imageIndex - 1);
                int mountResult = Program.RunMount(fs, $"{drive}:\\", drive, Stopwatch.StartNew(), stop.Token, (target, isRunning) =>
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime, stop.Token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(20));
                    MountReadinessObservation.ActivateAndAnnounce(deadline.Token,
                        () => activate(target, deadline.Token), isRunning,
                        () => Program.DriveTargetMatches(drive, target),
                        () => Volatile.Write(ref ready, 1));
                }, reportReady: false, allUsers: allUsers, signedIn: signedIn, unmountMenu: true, shareSource: !web && Program.OnShare(wimPath));
                return (MountResult: mountResult, SourceFailed: SplitWim.AnyWebPartFailed(parts) || verified?.Failed == true);
            }, CancellationToken.None).ConfigureAwait(false);
            if (result.MountResult != 0 || control.IsCompleted || lifetime.IsCancellationRequested)
                throw new IOException("Worker mount or control did not finish normally.");
            // The task has returned only after its mount, image and stream
            // scopes completed. Publish before reporting CLOSED to a client.
            var dokan = DokanLifecycle.Finish();
            WorkerCompletionPublication.Publish(new(result.SourceFailed, dokan), onClosure,
                () =>
                {
                    byte[] receipt = WorkerCompletionReceipt.CreateClosed(proof, instance, drive, self.ProcessId, self.CreationTime, result.SourceFailed, dokan);
                    WorkerRecoveryStore.WriteClosedReceipt(prepared, receipt);
                }, () => completion.TrySetResult(WorkerCompletionReceipt.Response(result.SourceFailed, dokan)));
            if (result.SourceFailed) mountFailure = new IOException("The WIM source failed or changed after verification; the mount was stopped.");
        }
        catch (Exception ex)
        {
            mountFailure = ex;
            completion.TrySetResult("UNKNOWN");
        }
        finally
        {
            signalWait?.Unregister(null);
            // Wait for the unmount response and client receipt. If no client
            // is waiting, stop the control endpoint after the bounded grace.
            await Task.WhenAny(control, Task.Delay(TimeSpan.FromSeconds(20))).ConfigureAwait(false);
            controlLifetime.Cancel();
            try { await control.ConfigureAwait(false); }
            catch (OperationCanceledException) when (controlLifetime.IsCancellationRequested) { }
            catch (Exception ex) { mountFailure = mountFailure is null ? ex : new AggregateException("Mount and control failed.", mountFailure, ex); }
        }
        if (mountFailure is not null) throw mountFailure;
    }
}
