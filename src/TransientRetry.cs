using System.Diagnostics;

// A WIM source can stop answering for a while without the drive being lost: a
// network hiccup, a web server restarting, a file share reconnecting, a disk
// retrying a bad sector. A read that fails once is retried for a window rather
// than failing the operation immediately.
//
// The window is bounded on purpose. A source that is genuinely gone must fail
// rather than hang the drive forever, because every blocked read also blocks a
// Dokan thread and whatever program is waiting on it.
//
// These values are related, and the relation is what keeps the drive alive.
// SourceOutageRegression asserts it, because a comment saying so cannot catch
// arithmetic that does not hold.
//
//   Window        how long one failing source operation keeps being retried.
//   WebAttemptTimeout   deadline for a single web request.
//   ReadCeiling   cap on one read, which may need several blocks and so several
//                 windows. A read is allowed to overshoot it by at most one
//                 attempt, because an attempt already in flight is not cut off.
//   DokanRequestTimeout   when Dokan gives up on a request and the volume can
//                 be lost. Must exceed ReadCeiling + WebAttemptTimeout, so our
//                 own cap always ends a slow read first.
//
// Known limit: the ceiling is per stream read, and one Dokan request can make
// several reads, so a web server failing slowly on several blocks can still
// outlast Dokan. A per-request clock is not used: Dokan resets its own timeout
// during long directory listings, so such a clock would end a healthy slow
// listing and the mount.
//
// A read of a local or UNC file is bounded differently, and not by this code: a
// synchronous file read cannot be cancelled, so each attempt takes as long as
// Windows takes to give up — for a share that is SessTimeout, 60 seconds by
// default. What is bounded here is the number of attempts. If an administrator
// raises SessTimeout well above the default, DokanRequestTimeout has to rise
// with it; MinimumAttempts times SessTimeout is the figure to beat.
internal sealed class TransientRetry
{
    internal static readonly TimeSpan Window = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan WebAttemptTimeout = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan ReadCeiling = TimeSpan.FromSeconds(150);
    internal static readonly TimeSpan DokanRequestTimeout = ReadCeiling + WebAttemptTimeout + TimeSpan.FromSeconds(45);
    // An attempt that fails slowly must not use up the right to try again. A
    // share whose server is switched off blocks for the whole of SessTimeout
    // and only then throws, and reopening the handle is the one thing that
    // could recover it, so it always gets at least one more go.
    internal const int MinimumAttempts = 2;
    private static readonly TimeSpan FirstDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan LongestDelay = TimeSpan.FromSeconds(2);

    private readonly string source;
    private readonly TextWriter report;
    private readonly TimeSpan window;
    private bool reported;

    internal TransientRetry(string source, TextWriter? report = null, TimeSpan? window = null)
    {
        this.source = source;
        this.report = report ?? Console.Error;
        this.window = window ?? Window;
        if (this.window < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));
    }

    // Runs attempt, retrying while transient says the failure may pass and
    // either the budget has room for another wait or the minimum number of
    // attempts has not been reached. The last failure is rethrown, so the
    // caller still sees the real cause rather than a retry wrapper.
    //
    // budget overrides the instance window for this call. A read spanning
    // several blocks passes what is left of its own ceiling, so the retrying
    // cannot outlive the read that asked for it.
    internal void Run(Action attempt, Func<Exception, bool> transient, CancellationToken cancellation,
        TimeSpan? budget = null)
    {
        TimeSpan limit = budget ?? window;
        var elapsed = Stopwatch.StartNew();
        var delay = FirstDelay;
        try
        {
            for (int attempts = 1; ; attempts++)
            {
                cancellation.ThrowIfCancellationRequested();
                try
                {
                    attempt();
                    Recovered();
                    return;
                }
                catch (Exception ex) when (transient(ex) && !cancellation.IsCancellationRequested &&
                    (attempts < MinimumAttempts || elapsed.Elapsed + delay < limit))
                {
                    Retrying(ex, limit);
                    cancellation.WaitHandle.WaitOne(delay);
                    cancellation.ThrowIfCancellationRequested();
                    delay = TimeSpan.FromTicks(Math.Min(LongestDelay.Ticks, delay.Ticks * 2));
                }
            }
        }
        catch (Exception ex)
        {
            // A deliberate unmount is not an outage and says nothing. Neither
            // is a prompt answer that was simply wrong — a changed WIM, say —
            // which would otherwise be reported as a source that went quiet.
            if (ex is not OperationCanceledException && transient(ex)) GaveUp(limit);
            throw;
        }
    }

    // One line per outage, not per attempt, so a flapping link does not bury
    // everything else the run prints. The source is quoted like any other
    // untrusted text: a share or file name may carry formatting characters that
    // would otherwise rewrite the operator's console line.
    // limit, not the instance window: a read near its ceiling may be handed a
    // budget of a second or two, and saying "60 seconds" there is a lie the
    // operator would time us against.
    private void Retrying(Exception ex, TimeSpan limit)
    {
        if (reported) return;
        reported = true;
        report.WriteLine($"The WIM source stopped answering: {SafeText.Path(source)}");
        report.WriteLine($"  Reason: {SafeText.Message(ex.Message.TrimEnd('.'))}.");
        report.WriteLine($"  Retrying for up to {limit.TotalSeconds:0} seconds. The drive stays mounted.");
    }

    private void Recovered()
    {
        if (!reported) return;
        reported = false;
        report.WriteLine($"The WIM source is answering again: {SafeText.Path(source)}. The drive was not lost.");
    }

    // Without this, an outage lasting several windows would announce itself once and
    // then go quiet, so a five-minute outage would read as a single 60-second one.
    // Clearing the flag also lets the next outage announce itself.
    private void GaveUp(TimeSpan limit)
    {
        if (!reported) return;
        reported = false;
        report.WriteLine($"The WIM source did not answer within {limit.TotalSeconds:0} seconds: {SafeText.Path(source)}");
        report.WriteLine("  This read failed, so a program reading the drive may report an error.");
    }
}
