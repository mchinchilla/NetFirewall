using System.Buffers;
using System.Net;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Benchmarks;

/// <summary>
/// Raw packet → real <see cref="DhcpWorker"/> parse/dispatch → a DI scope per packet (as in
/// production) → the REAL <see cref="DhcpServerService"/> (subnet selection, class match, address
/// choice, option building incl. DNS / NTP / domain search / classless routes, serialization) →
/// send seam. Only the database-backed services are replaced, by fakes that hand back
/// pre-completed tasks so they add no noise. Unlike <see cref="ProcessSinglePacketBenchmarks"/>,
/// which mocks the whole service, this measures what a lease actually costs on the CPU.
/// </summary>
[MemoryDiagnoser]
public class FullPipelineBenchmarks
{
    private RecordingWorker _worker = null!;
    private byte[] _packet = null!;
    private static readonly IPEndPoint Client = new(IPAddress.Any, 68);

    [Params("Discover", "Request")]
    public string MessageType { get; set; } = "Discover";

    [GlobalSetup]
    public async Task Setup()
    {
        var type = MessageType == "Request" ? DhcpMessageType.Request : DhcpMessageType.Discover;
        _packet = BuildPacket(type);

        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IDhcpSubnetService>(new FakeSubnets());
        services.AddSingleton<IDhcpLeasesService>(new FakeLeases());
        services.AddSingleton<IOptions<DhcpConfig>>(Options.Create(new DhcpConfig()));
        services.AddScoped<IDhcpServerService, DhcpServerService>();
        var sp = services.BuildServiceProvider();
        _worker = new RecordingWorker(sp.GetRequiredService<IServiceScopeFactory>());

        // Sanity: the pipeline must actually answer, or we'd be timing an early return.
        await ProcessPacket();
        if (_worker.LastLength < 300)
            throw new InvalidOperationException($"No DHCP reply was produced (len {_worker.LastLength}).");
    }

    /// <summary>
    /// Rent → process → dispose, exactly as the receive loop does. No [IterationSetup]: it forces
    /// ONE invocation per iteration, which makes the time pure noise and hides allocations
    /// (the "Allocated: -" it printed was "not measurable", not zero).
    /// </summary>
    [Benchmark]
    public async Task ProcessPacket()
    {
        var rented = ArrayPool<byte>.Shared.Rent(_packet.Length);
        _packet.CopyTo(rented, 0);
        var ctx = new DhcpPacketContext(rented, _packet.Length, Client, "eth1", ArrayPool<byte>.Shared);
        try { await _worker.ProcessSinglePacketAsync(ctx, CancellationToken.None); }
        finally { ctx.Dispose(); }
    }

    /// <summary>A Windows-style client: client-id, hostname, PRL asking for the usual 12 options.</summary>
    private static byte[] BuildPacket(DhcpMessageType type)
    {
        var p = new List<byte>(new byte[236]);
        p[0] = 1; p[1] = 1; p[2] = 6;
        p[4] = 0x39; p[5] = 0x03; p[6] = 0xF3; p[7] = 0x26;
        p[10] = 0x80;                                           // broadcast flag
        byte[] mac = [0x00, 0x0C, 0x29, 0x3E, 0x5C, 0x1A];
        for (var i = 0; i < 6; i++) p[28 + i] = mac[i];
        p.AddRange([99, 130, 83, 99]);
        p.AddRange([53, 1, (byte)type]);
        p.AddRange([61, 7, 1, .. mac]);
        if (type == DhcpMessageType.Request)
        {
            p.AddRange([50, 4, 192, 168, 50, 120]);              // requested IP
            p.AddRange([54, 4, 192, 168, 50, 1]);                // server identifier
        }
        p.AddRange([12, 9, .. "DESKTOP-7"u8.ToArray()]);
        p.AddRange([60, 8, .. "MSFT 5.0"u8.ToArray()]);
        p.AddRange([55, 12, 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121]);
        p.Add(255);
        while (p.Count < 300) p.Add(0);
        return p.ToArray();
    }

    private sealed class RecordingWorker(IServiceScopeFactory scopes)
        : DhcpWorker(NullLogger<DhcpWorker>.Instance, scopes, new ConfigurationBuilder().Build())
    {
        public int LastLength;

        internal override ValueTask<int> SendResponseAsync(
            ReadOnlyMemory<byte> response, IPEndPoint destination, string? interfaceName, CancellationToken ct)
        {
            LastLength = response.Length;
            return ValueTask.FromResult(response.Length);
        }
    }

    // ── fakes: the DB-backed side, answering from memory with cached completed tasks ──

    private sealed class FakeSubnets : IDhcpSubnetService
    {
        private static readonly DhcpSubnet Lan = new()
        {
            Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
            SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("192.168.50.1"),
            Broadcast = IPAddress.Parse("192.168.50.255"), DomainName = "home.lan",
            DnsServers = [IPAddress.Parse("192.168.50.1"), IPAddress.Parse("1.1.1.1")],
            NtpServers = [IPAddress.Parse("192.168.50.1")],
            DefaultLeaseTime = 86400, MaxLeaseTime = 604800, InterfaceMtu = 1500,
            DomainSearchList = "home.lan,corp.example.com",
            StaticRoutesJson = """[{"network":"10.20.0.0/16","gateway":"192.168.50.254"}]""",
        };
        private static readonly Task<DhcpSubnet?> SubnetTask = Task.FromResult<DhcpSubnet?>(Lan);
        private static readonly Task<DhcpClass?> NoClass = Task.FromResult<DhcpClass?>(null);
        private static readonly Task<(IPAddress? Ip, DhcpPool? Pool)> Free =
            Task.FromResult<(IPAddress?, DhcpPool?)>((IPAddress.Parse("192.168.50.120"), null));

        public Task<DhcpSubnet?> FindSubnetForRequestAsync(DhcpRequest request, CancellationToken cancellationToken = default) => SubnetTask;
        public Task<DhcpSubnet?> FindSubnetByNetworkAsync(IPAddress ipAddress, CancellationToken cancellationToken = default) => SubnetTask;
        public Task<DhcpSubnet?> FindSubnetByInterfaceAsync(string interfaceName, CancellationToken cancellationToken = default) => SubnetTask;
        public Task<(IPAddress? Ip, DhcpPool? Pool)> FindAvailableIpInSubnetAsync(DhcpSubnet subnet, string macAddress, DhcpRequest request, CancellationToken cancellationToken = default) => Free;
        public Task<DhcpClass?> MatchClientClassAsync(DhcpRequest request, CancellationToken cancellationToken = default) => NoClass;
        private static readonly Task<RequestedIpVerdict> AllowedVerdict = Task.FromResult(RequestedIpVerdict.Allowed);
        public Task<RequestedIpVerdict> CheckRequestedIpAsync(DhcpSubnet subnet, string macAddress, IPAddress ip, CancellationToken cancellationToken = default) => AllowedVerdict;
        public Task<IReadOnlyList<DhcpSubnet>> GetAllSubnetsAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DhcpSubnet>>([Lan]);
        public Task<IReadOnlyList<FwInterface>> GetEnabledInterfacesAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<FwInterface>>([]);
        public Task<DhcpSubnet?> GetSubnetWithPoolsAsync(Guid subnetId, CancellationToken cancellationToken = default) => SubnetTask;
        public Task<IReadOnlyList<DhcpPool>> GetPoolsForSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DhcpPool>>([]);
        public Task<IReadOnlyList<DhcpExclusion>> GetExclusionsForSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DhcpExclusion>>([]);
        public Task<DhcpSubnet> CreateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DhcpSubnet> UpdateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<bool> DeleteSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DhcpPool> CreatePoolAsync(DhcpPool pool, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<bool> DeletePoolAsync(Guid poolId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public void InvalidateCache() { }
    }

    private sealed class FakeLeases : IDhcpLeasesService
    {
        private static readonly Task<bool> Yes = Task.FromResult(true);
        private static readonly Task<IPAddress?> Assigned = Task.FromResult<IPAddress?>(IPAddress.Parse("192.168.50.120"));
        private static readonly Task<DdnsUpdateResult?> NoDdns = Task.FromResult<DdnsUpdateResult?>(null);

        public Task<IPAddress?> OfferLeaseAsync(string macAddress, IPAddress? rangeStart, IPAddress rangeEnd) => Assigned;
        public Task AssignLeaseAsync(string macAddress, IPAddress ipAddress, int leaseTime, string? hostname = null) => Task.CompletedTask;
        public Task<DdnsUpdateResult?> AssignLeaseWithDdnsAsync(string macAddress, IPAddress ipAddress, int leaseTime, string? hostname, Guid? subnetId, CancellationToken cancellationToken = default) => NoDdns;
        public Task<bool> CanAssignIpAsync(string macAddress, IPAddress ipAddress) => Yes;
        public Task ReleaseLeaseAsync(string macAddress) => Task.CompletedTask;
        public Task<DdnsUpdateResult?> ReleaseLeaseWithDdnsAsync(string macAddress, Guid? subnetId, CancellationToken cancellationToken = default) => NoDdns;
        public Task MarkIpAsDeclinedAsync(IPAddress ipAddress) => Task.CompletedTask;
        public bool IsIpDeclined(IPAddress ipAddress) => false;
        public Task<IPAddress?> GetAssignedIpAsync(string macAddress) => Assigned;
        public Task<(DhcpLease? Lease, string? Fqdn)> GetLeaseWithFqdnAsync(string macAddress, CancellationToken cancellationToken = default) => Task.FromResult<(DhcpLease?, string?)>((null, null));
        public Task<int> BulkImportReservationsAsync(IEnumerable<DhcpMacReservation> reservations, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> BulkImportLeasesAsync(IEnumerable<DhcpLease> leases, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> CleanupExpiredLeasesAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
        public Task<IReadOnlyList<DhcpLease>> GetAllActiveLeasesAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DhcpLease>>([]);
        public Task<IReadOnlyList<DhcpMacReservation>> GetAllReservationsAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<DhcpMacReservation>>([]);
    }
}
