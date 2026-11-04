// Background worker. The parent passes no capability on the command line.
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

internal static class WorkerChild
{
    internal static async Task RunAsync(string startupPipe, string wim, int index, char drive,
        uint parentPid, ulong parentCreation, string? certificateSha256, HttpsRangeStream.SourceIdentity? sourceIdentity,
        Action<WorkerCompletionReceipt.Closure>? onClosure = null, string? wimSha256 = null, bool allUsers = false, bool signedIn = false)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        using var parent = WorkerProcessIdentity.Open(parentPid, parentCreation);
        await using var startup = WorkerPipe.CreateClient(startupPipe);
        await startup.ConnectAsync(deadline.Token).ConfigureAwait(false);
        parent.RequirePipeServer(startup);
        using var selfProcess = Process.GetCurrentProcess();
        using var self = WorkerProcessIdentity.CaptureChild(selfProcess);
        using var proof = WorkerProof.Create();
        Guid instance = Guid.NewGuid();
        string id = instance.ToString("N");
        string controlName = "WimDrive-control-" + Guid.NewGuid().ToString("N");
        using var control = WorkerPipe.CreateServer(controlName);
        // Before anything is reported, so the unmount path that cannot be
        // blocked exists for the worker's whole life.
        using var stopSignal = WorkerStopSignal.Create(instance);
        byte[] key = proof.ExportPublicKey();
        await Write(startup, parent, $"PREPARED|{id}|{drive}|{controlName}|{Convert.ToBase64String(key)}", deadline.Token).ConfigureAwait(false);
        string[] cap = (await Read(startup, parent, deadline.Token).ConfigureAwait(false)).Split('|');
        if (cap.Length != 2 || cap[0] != "CAP") throw new InvalidDataException("Invalid startup capability.");
        byte[] secret = Decode(cap[1], 32);
        try
        {
            using var prepared = new WorkerRecoveryRecord(instance, drive, controlName, self.ProcessId, self.CreationTime, key, secret, null);
            using var authorization = new WorkerAuthorization(instance, secret);
            using var lifetime = new CancellationTokenSource();
            var go = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task host = WorkerHost.RunAsync(wim, index, drive, control, instance, proof, authorization, prepared, go.Task,
                (mapping, cancellation) => Activate(startup, parent, id, mapping, secret, proof, cancellation), lifetime.Token, certificateSha256, sourceIdentity, onClosure, wimSha256, stopSignal, allUsers, signedIn);
            try
            {
                await Write(startup, parent, "ARMED|" + id, deadline.Token).ConfigureAwait(false);
                string frame = await Read(startup, parent, deadline.Token).ConfigureAwait(false);
                RequireMac(frame, "GO|" + id, secret);
                go.TrySetResult();
                await host.ConfigureAwait(false);
            }
            catch
            {
                lifetime.Cancel();
                go.TrySetCanceled();
                try { await host.ConfigureAwait(false); } catch { }
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static void Activate(NamedPipeClientStream startup, WorkerProcessIdentity parent, string id,
        string mapping, byte[] secret, WorkerProof proof, CancellationToken cancellation)
    {
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(mapping);
        if (bytes.Length is < 1 or > 2048) throw new InvalidDataException("Invalid drive mapping.");
        Write(startup, parent, "READY|" + id + "|" + Convert.ToBase64String(bytes), cancellation).GetAwaiter().GetResult();
        string frame = Read(startup, parent, cancellation).GetAwaiter().GetResult();
        string[] fields = frame.Split('|');
        if (fields.Length != 5 || fields[0] != "PREACK" || fields[1] != id) throw new InvalidDataException("Invalid startup acknowledgement.");
        byte[] challenge = Decode(fields[2], 32);
        byte[] digest = Decode(fields[3], 32);
        if (!CryptographicOperations.FixedTimeEquals(digest, SHA256.HashData(bytes))) throw new InvalidDataException("Drive mapping changed in startup exchange.");
        RequireMac(frame, string.Join('|', fields.Take(4)), secret);
        byte[] signature = proof.Sign(challenge, frame, "PREACKED");
        // Do not require the starter to remain alive after it receives the
        // acknowledgement. The starter confirms RUNNING on the control pipe.
        parent.RequirePipeServer(startup);
        WorkerPipe.WriteAsync(startup, "PREACKED|" + Convert.ToBase64String(signature), cancellation).GetAwaiter().GetResult();
    }

    private static async Task<string> Read(NamedPipeClientStream pipe, WorkerProcessIdentity parent, CancellationToken cancellation)
    {
        parent.RequirePipeServer(pipe);
        string value = await WorkerPipe.ReadAsync(pipe, cancellation).ConfigureAwait(false);
        parent.RequirePipeServer(pipe);
        return value;
    }
    private static async Task Write(NamedPipeClientStream pipe, WorkerProcessIdentity parent, string value, CancellationToken cancellation)
    {
        parent.RequirePipeServer(pipe);
        await WorkerPipe.WriteAsync(pipe, value, cancellation).ConfigureAwait(false);
        parent.RequirePipeServer(pipe);
    }
    private static byte[] Decode(string value, int size)
    {
        byte[] bytes = Convert.FromBase64String(value);
        if (bytes.Length != size || Convert.ToBase64String(bytes) != value) throw new InvalidDataException("Invalid startup encoding.");
        return bytes;
    }
    private static void RequireMac(string frame, string body, byte[] secret)
    {
        string prefix = body + "|";
        if (!frame.StartsWith(prefix, StringComparison.Ordinal)) throw new InvalidDataException("Invalid startup frame.");
        byte[] mac = Decode(frame[prefix.Length..], 32);
        if (!CryptographicOperations.FixedTimeEquals(mac, Convert.FromBase64String(WorkerStartup.Mac(secret, body))))
            throw new UnauthorizedAccessException("Startup authentication failed.");
    }
}
