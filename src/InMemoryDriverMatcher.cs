// Candidate discovery and identifier scores only. Platform and full rank are separate.
internal sealed class InMemoryDriverMatcher
{
    internal sealed record Match(InfIndex.ModelEntry Model, int IdentifierScore);
    private readonly IReadOnlyList<InfIndex.ModelEntry> models;
    private readonly Dictionary<string, List<int>> byId = new(StringComparer.OrdinalIgnoreCase);
    private const long MaxLookupBytes = 128L * 1024 * 1024;
    private const long MaxCandidateBytes = 64L * 1024 * 1024;
    internal InMemoryDriverMatcher(IReadOnlyList<InfIndex.ModelEntry> source, CancellationToken cancellation)
    {
        models = source ?? throw new ArgumentNullException(nameof(source));
        cancellation.ThrowIfCancellationRequested();
        long associations = 0, estimatedBytes = 0;
        for (int i = 0; i < models.Count; i++)
        {
            cancellation.ThrowIfCancellationRequested();
            var model = models[i];
            if (!model.PlatformApplicable) continue;
            var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void Add(string id)
            {
                if (string.IsNullOrEmpty(id) || !unique.Add(id)) return;
                if (++associations > 2_000_000) throw new InvalidDataException("Model lookup limit exceeded; results are incomplete.");
                if (!byId.TryGetValue(id, out var hits))
                {
                    estimatedBytes += 2L * id.Length + 160;
                    byId.Add(id, hits = new List<int>());
                }
                estimatedBytes += 16;
                if (estimatedBytes > MaxLookupBytes) throw new InvalidDataException("Model lookup memory limit exceeded; results are incomplete.");
                hits.Add(i);
            }
            Add(model.HardwareId);
            foreach (var id in model.CompatibleIds) { cancellation.ThrowIfCancellationRequested(); Add(id); }
        }
    }
    internal IReadOnlyList<Match> Find(IReadOnlyList<string> hardware, IReadOnlyList<string> compatible, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(hardware);
        ArgumentNullException.ThrowIfNull(compatible);
        cancellation.ThrowIfCancellationRequested();
        if ((long)hardware.Count + compatible.Count > 100_000) throw new InvalidDataException("Device ID limit exceeded; results are incomplete.");
        var candidates = new HashSet<int>();
        long work = 0;
        foreach (string id in hardware.Concat(compatible))
        {
            cancellation.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(id) || !byId.TryGetValue(id, out var hits)) continue;
            foreach (int i in hits)
            {
                if (++work > 2_000_000) throw new InvalidDataException("Candidate lookup limit exceeded; results are incomplete.");
                if (candidates.Add(i) && (long)candidates.Count * 128 > MaxCandidateBytes) throw new InvalidDataException("Candidate memory limit exceeded; results are incomplete.");
            }
        }
        var matches = new List<Match>();
        foreach (int i in candidates.Order())
        {
            cancellation.ThrowIfCancellationRequested();
            var model = models[i];
            long scoringWork = (long)hardware.Count + compatible.Count + model.CompatibleIds.Count;
            work += scoringWork;
            if (work > 2_000_000) throw new InvalidDataException("Candidate scoring limit exceeded; results are incomplete.");
            int? score = DriverIdentifierScore.Best(hardware, compatible, model.HardwareId, model.CompatibleIds, cancellation);
            if (score is not null) matches.Add(new(model, score.Value));
        }
        return matches.AsReadOnly();
    }
}
