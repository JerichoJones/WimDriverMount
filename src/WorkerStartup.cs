// Background startup handshake.
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

internal static class WorkerStartup
{
    // After GO may have been sent, the caller owns both retained objects and
    // must keep them through verified cleanup. Disposing early loses that proof.
    internal sealed class Result : IDisposable
    {
        internal bool Ready { get; private set; }
        internal int ProcessId { get; }
        internal string Detail { get; private set; }
        internal WorkerProcessIdentity? RetainedIdentity { get; }
        internal WorkerRecoveryStore.PreparedReservation? RetainedReservation { get; }
        internal Result(bool ready, int processId, string detail, WorkerProcessIdentity? retainedIdentity = null,
            WorkerRecoveryStore.PreparedReservation? retainedReservation = null)
        { Ready = ready; ProcessId = processId; Detail = detail; RetainedIdentity = retainedIdentity; RetainedReservation = retainedReservation; }
        internal void SetDetail(string detail) => Detail = detail;
        internal void SetReady() { Ready = true; Detail = "Mounted in the background."; }
        internal void NoteTeardownFailure(char drive) { Ready = false; Detail = Unconfirmed(drive); }
        public void Dispose()
        {
            try { RetainedReservation?.Dispose(); }
            finally { RetainedIdentity?.Dispose(); }
        }
    }
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static string EncodeSourceIdentity(HttpsRangeStream.SourceIdentity identity)
    {
        byte[] encoded = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(identity);
        if (encoded.Length > 2048) throw new ArgumentException("Web source identity is too long for background startup.");
        return Convert.ToBase64String(encoded);
    }

    private static string Unconfirmed(char drive) =>
        $"The background mount on {drive}: did not confirm that it started.\n" +
        $"To clear it, whether or not {drive}: appeared, run: .\\WimDriverMount.exe --unmount {drive}:\n" +
        (LogFile.Path is { } log
            ? $"If the background mount got far enough to say why, the reason is in {SafeText.Path(log)}."
            : Program.UnopenedLog is { } unopened
            ? $"The log file {SafeText.Path(unopened)} could not be opened (see the warning above), so the reason may not be in it. " +
              (Program.FromSettingsFile ? "Fix that log path, or run the mount again without background = true." : "Fix that log path, or run the mount again without --background.")
            : Program.RequestedLog is { } stopped
            ? $"If the background mount got far enough to say why, the reason may be in {SafeText.Path(stopped)}; this program stopped writing to it (see the warning above), but the background mount writes on its own."
            : Program.FromSettingsFile ? @"To see why, add log = C:\Logs\wim.log (any file in a folder that exists) to the settings file's [defaults] section and run it again."
            : @"To see why, run the mount again with --log C:\Logs\wim.log added (any file in a folder that exists; the background mount writes its reason there), or without --background.");

    internal static async Task<Result> StartAsync(string wim, int index, char drive, CancellationToken cancellation, string? certificateSha256 = null, HttpsRangeStream.SourceIdentity? sourceIdentity = null, string? wimSha256 = null, bool allUsers = false, bool signedIn = false)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        bool web = Uri.TryCreate(wim, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
        if ((!web && !Path.IsPathFullyQualified(wim)) || index < 1 || drive is < 'D' or > 'Z')
            throw new ArgumentException("Invalid background mount arguments.");
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Application executable is unavailable.");
        if (!string.Equals(Path.GetFileNameWithoutExtension(executable), "WimDriverMount", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("A background mount needs the program file to be named WimDriverMount.exe. Rename it, then run this again.");
        cancellation.ThrowIfCancellationRequested();
        WorkerUnmount.ClearEnded(drive);
        string pipeName = "WimDrive-start-" + Guid.NewGuid().ToString("N");
        var arguments = new List<string>();
        using Process current = Process.GetCurrentProcess();
        using WorkerProcessIdentity parentIdentity = WorkerProcessIdentity.CaptureChild(current);
        foreach (string argument in new[] { "--internal-worker", "--startup-pipe", pipeName, "--wim", wim, "--index", index.ToString(System.Globalization.CultureInfo.InvariantCulture), "--drive", drive.ToString(), "--parent-pid", parentIdentity.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), "--parent-created", parentIdentity.CreationTime.ToString(System.Globalization.CultureInfo.InvariantCulture) })
            arguments.Add(argument);
        if (sourceIdentity is not null)
        {
            arguments.Add("--source-identity");
            arguments.Add(EncodeSourceIdentity(sourceIdentity));
        }
        if (certificateSha256 is not null) { arguments.Add("--wim-cert-sha256"); arguments.Add(certificateSha256); }
        if (wimSha256 is not null) { arguments.Add("--wim-sha256"); arguments.Add(wimSha256); }
        if (allUsers) { arguments.Add("--all-users"); arguments.Add("1"); }
        if (signedIn) { arguments.Add("--signed-in-user"); arguments.Add("1"); }
        // The background mount writes to the same --log file, and the event log only with --evtlog.
        if (Program.RequestedLog is { } log) { arguments.Add("--log"); arguments.Add(log); }
        if (Program.EventLog) arguments.Add("--evtlog");
        NamedPipeServerStream server = WorkerPipe.CreateServer(pipeName);
        Process child;
        try { child = WorkerProcessLaunch.Start(executable, arguments); }
        catch { try { await server.DisposeAsync().ConfigureAwait(false); } catch (Exception) { } throw; }
        int pid = 0;
        bool goMayHaveBeenSent = false;
        CancellationTokenSource? timeout = null;
        byte[]? capability = null;
        WorkerProcessIdentity? identity = null;
        WorkerRecoveryStore.PreparedReservation? reservation = null;
        Result? outcome = null;
        try
        {
            pid = child.Id;
            timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            // Synchronous record storage is not bounded by this I/O deadline.
            timeout.CancelAfter(TimeSpan.FromSeconds(90));
            identity = WorkerProcessIdentity.CaptureChild(child);
            // Pipe names can be listed, so another process of the same user may
            // connect first -- and may already have gone, which makes the wait
            // fail with ERROR_NO_DATA. Turn it away and wait again for the child,
            // within the same deadline.
            while (true)
            {
                Task connection = server.WaitForConnectionAsync(timeout.Token);
                Task exit = child.WaitForExitAsync(timeout.Token);
                if (await Task.WhenAny(connection, exit).ConfigureAwait(false) == exit)
                    throw new IOException("The background process ended before it could start the mount.");
                try { await connection.ConfigureAwait(false); identity.RequirePipeClient(server); break; }
                catch (Exception ex) when (ex is InvalidDataException || (ex is IOException && !timeout.IsCancellationRequested))
                {
                    WorkerPipe.Reset(server);
                }
            }
            string preparedFrame = await ReadChecked(server, identity, timeout.Token).ConfigureAwait(false);
            string[] fields = preparedFrame.Split('|');
            if (fields.Length != 5 || fields[0] != "PREPARED" || fields[2] != drive.ToString() ||
                !Guid.TryParseExact(fields[1], "N", out Guid instance) || instance == Guid.Empty || fields[1] != instance.ToString("N"))
                throw new InvalidDataException("Invalid prepared startup response.");
            byte[] key = DecodeCanonical(fields[4]);
            if (!WorkerProof.IsValidPublicKey(key)) throw new InvalidDataException("Invalid worker public key.");
            capability = RandomNumberGenerator.GetBytes(32);
            using var prepared = new WorkerRecoveryRecord(instance, drive, fields[3], identity.ProcessId,
                identity.CreationTime, key, capability, observedMapping: null);
            WorkerRecoveryStore.WritePrepared(prepared);
            reservation = WorkerRecoveryStore.ReserveExpectedPrepared(prepared);

            // The framed API uses strings, so the capability's encoded form can
            // remain in managed memory. Never log it or pass it as an argument.
            await WriteChecked(server, identity, "CAP|" + Convert.ToBase64String(capability), timeout.Token).ConfigureAwait(false);
            string armed = await ReadChecked(server, identity, timeout.Token).ConfigureAwait(false);
            if (armed != "ARMED|" + fields[1]) throw new InvalidDataException("Worker did not confirm its control setup.");
            string goBody = "GO|" + fields[1];
            string goFrame = goBody + "|" + Mac(capability, goBody);
            // Allocate the result before GO so even an allocation failure
            // afterward can return the retained recovery handles.
            outcome = new Result(false, pid, Unconfirmed(drive), identity, reservation);
            goMayHaveBeenSent = true;
            await WriteChecked(server, identity, goFrame, timeout.Token).ConfigureAwait(false);

            string[] ready = (await ReadChecked(server, identity, timeout.Token).ConfigureAwait(false)).Split('|');
            if (ready.Length != 3 || ready[0] != "READY" || ready[1] != fields[1])
                throw new InvalidDataException("Invalid readiness response.");
            byte[] mappingBytes = DecodeCanonical(ready[2]);
            if (mappingBytes.Length is < 1 or > 2048) throw new InvalidDataException("Invalid observed mapping size.");
            string mapping = Utf8.GetString(mappingBytes);
            using var observed = new WorkerRecoveryRecord(instance, drive, fields[3], identity.ProcessId,
                identity.CreationTime, key, capability, mapping);
            reservation.WriteReady(observed);
            // This checks the actual endpoint, the retained child process and
            // a signed response before any startup acknowledgment is sent.
            await WorkerControlClient.VerifyStartupEndpointAsync(fields[3], instance, identity, key, capability,
                timeout.Token).ConfigureAwait(false);
            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            // ACK permits the worker to continue. If its response is lost,
            // the outcome is unknown and the saved record remains available.
            string ackBody = "PREACK|" + fields[1] + "|" + Convert.ToBase64String(challenge) + "|" + Convert.ToBase64String(SHA256.HashData(mappingBytes));
            string ack = ackBody + "|" + Mac(capability, ackBody);
            await WriteChecked(server, identity, ack, timeout.Token).ConfigureAwait(false);
            string[] response = (await ReadChecked(server, identity, timeout.Token).ConfigureAwait(false)).Split('|');
            if (response.Length != 2 || response[0] != "PREACKED" ||
                !WorkerProof.Verify(key, challenge, ack, "PREACKED", DecodeCanonical(response[1])))
                throw new InvalidDataException("Worker acknowledgement could not be verified.");
            await WorkerControlClient.VerifyStartupEndpointAsync(fields[3], instance, identity, key, capability,
                timeout.Token, requireRunning: true).ConfigureAwait(false);
            outcome.SetReady();
            return outcome;
        }
        catch (Exception) when (goMayHaveBeenSent && outcome is not null)
        {
            outcome.SetDetail(Unconfirmed(drive));
            return outcome;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return outcome = new Result(false, pid, goMayHaveBeenSent
                ? Unconfirmed(drive)
                : $"The background mount on {drive}: did not start, so nothing was mounted.\nReason: {SafeText.Message(ex.Message)}",
                goMayHaveBeenSent ? identity : null, goMayHaveBeenSent ? reservation : null);
        }
        finally
        {
            try { timeout?.Cancel(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
            try { timeout?.Dispose(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
            if (capability is not null) CryptographicOperations.ZeroMemory(capability);
            try { await server.DisposeAsync().ConfigureAwait(false); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
            try { child.Dispose(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
            if (!goMayHaveBeenSent || outcome is null)
            {
                if (!goMayHaveBeenSent && reservation is not null)
                    try { reservation.RemoveBeforeGo(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
                try { reservation?.Dispose(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
                try { identity?.Dispose(); } catch (Exception) { outcome?.NoteTeardownFailure(drive); }
            }
        }
    }

    // Same-user injection, shared handles and relay are not prevented by these
    // checks. Reject partial frames and verify the held child around each frame.
    private static async Task<string> ReadChecked(NamedPipeServerStream pipe, WorkerProcessIdentity child, CancellationToken cancellation)
    {
        child.RequirePipeClient(pipe);
        string frame = await WorkerPipe.ReadAsync(pipe, cancellation).ConfigureAwait(false);
        WorkerPeer.RequireSameUserAndElevation(pipe);
        child.RequirePipeClient(pipe);
        return frame;
    }

    private static async Task WriteChecked(NamedPipeServerStream pipe, WorkerProcessIdentity child, string frame, CancellationToken cancellation)
    {
        child.RequirePipeClient(pipe);
        await WorkerPipe.WriteAsync(pipe, frame, cancellation).ConfigureAwait(false);
        child.RequirePipeClient(pipe);
    }

    private static byte[] DecodeCanonical(string value)
    {
        byte[] bytes = Convert.FromBase64String(value);
        if (Convert.ToBase64String(bytes) != value) throw new InvalidDataException("Noncanonical startup encoding.");
        return bytes;
    }

    // A keyed GO/PREACK binds each operation to the instance and exact frame.
    internal static string Mac(byte[] capability, string body)
    {
        byte[] data = Utf8.GetBytes("WimDrive-start-v1|" + body);
        return Convert.ToBase64String(HMACSHA256.HashData(capability, data));
    }
}
