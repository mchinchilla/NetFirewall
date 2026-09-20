using System.Collections.Concurrent;

namespace NetFirewall.Services.Diagnostics;

/// <summary>Singleton. Slot counts are deliberately small: one doctor, a couple of pings, a few route lookups.</summary>
public sealed class DiagnosticGate : IDiagnosticGate
{
    private static readonly IReadOnlyDictionary<string, int> Capacity = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        [DiagFamilies.Doctor]    = 1,
        [DiagFamilies.Ping]      = 2,
        [DiagFamilies.Route]     = 4,
        [DiagFamilies.Conntrack] = 2,
        [DiagFamilies.Journal]   = 1,
        [DiagFamilies.Probe]     = 1,
        [DiagFamilies.Iface]     = 4,
    };

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new(StringComparer.Ordinal);

    public IDisposable? TryEnter(string family)
    {
        var gate = _gates.GetOrAdd(family, f => new SemaphoreSlim(Capacity.GetValueOrDefault(f, 1)));
        return gate.Wait(0) ? new Lease(gate) : null;
    }

    private sealed class Lease(SemaphoreSlim gate) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
                gate.Release();
        }
    }
}
