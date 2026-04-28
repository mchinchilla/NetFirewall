using System.Buffers;
using System.Net;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Benchmarks;

/// <summary>
/// Validates the per-packet allocation budget claims in
/// <c>docs/PerformanceAnalysis.md</c> against the real
/// <see cref="DhcpWorker.ProcessSinglePacketAsync"/> code path. The
/// <see cref="IDhcpServerService"/> is mocked so the benchmark measures only
/// the worker's parse + dispatch + send loop — no DB, no socket, no scoped DI
/// per call beyond what production already pays.
///
/// <para>Run from repo root:</para>
/// <code>
/// dotnet run -c Release --project NetFirewall.Benchmarks -- --filter '*'
/// </code>
///
/// <para>Two variants live here:</para>
/// <list type="bullet">
///   <item><b>EmptyResponse</b> — service returns <see cref="DhcpResponseBuffer.Empty"/>;
///     no send path. Isolates the parse + dispatch cost.</item>
///   <item><b>NonEmptyResponse</b> — service returns a small Ack packet that
///     drives <c>SendResponseAsync</c> through the (mocked) send path. Adds
///     the response-message-type counter increments.</item>
/// </list>
/// </summary>
[MemoryDiagnoser] // gen0/1/2 + total bytes per op — required to validate alloc budget
public class ProcessSinglePacketBenchmarks
{
    private RecordingDhcpWorker _worker = null!;
    private DhcpPacketContext _ctx;
    private byte[] _packetTemplate = null!;
    private static readonly IPEndPoint AnyEndPoint = new(IPAddress.Loopback, 68);

    [Params("Discover", "Request")]
    public string MessageType { get; set; } = "Discover";

    [Params(true, false)]
    public bool ServiceReturnsResponse { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var type = MessageType == "Request" ? DhcpMessageType.Request : DhcpMessageType.Discover;
        _packetTemplate = BuildValidRequest(type);

        var service = new Mock<IDhcpServerService>(MockBehavior.Strict);
        if (ServiceReturnsResponse)
        {
            // Build a small Ack response (260 bytes — typical real response size).
            var resp = new byte[260];
            resp[236] = 99; resp[237] = 130; resp[238] = 83; resp[239] = 99;
            resp[240] = 53; resp[241] = 1; resp[242] = (byte)DhcpMessageType.Ack;
            resp[243] = 0xFF;
            // pool=null so the service buffer doesn't get returned to a pool
            // we don't own — would crash ArrayPool.Shared.
            var buffer = new DhcpResponseBuffer(resp, resp.Length, pool: null);
            service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>())).ReturnsAsync(buffer);
        }
        else
        {
            service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>())).ReturnsAsync(DhcpResponseBuffer.Empty);
        }

        var sp = new ServiceCollection().AddScoped(_ => service.Object).BuildServiceProvider();
        _worker = new RecordingDhcpWorker(sp.GetRequiredService<IServiceScopeFactory>());
    }

    [IterationSetup]
    public void IterationSetup()
    {
        // Fresh packet context per iteration — the worker disposes it (returns
        // the buffer to the pool), so we must re-rent each time.
        var pool = ArrayPool<byte>.Shared;
        var rented = pool.Rent(_packetTemplate.Length);
        Array.Copy(_packetTemplate, rented, _packetTemplate.Length);
        _ctx = new DhcpPacketContext(rented, _packetTemplate.Length, AnyEndPoint, "eth0", pool);
    }

    [Benchmark]
    public async Task ProcessSinglePacket()
    {
        await _worker.ProcessSinglePacketAsync(_ctx, CancellationToken.None);
    }

    private static byte[] BuildValidRequest(DhcpMessageType type)
    {
        var pkt = new byte[576];
        pkt[0] = 1;
        pkt[1] = 1; pkt[2] = 6;
        pkt[4] = 0xDE; pkt[5] = 0xAD; pkt[6] = 0xBE; pkt[7] = 0xEF;
        pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC;
        pkt[31] = 0x11; pkt[32] = 0x22; pkt[33] = 0x01;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
        pkt[240] = 53; pkt[241] = 1; pkt[242] = (byte)type;
        pkt[243] = 0xFF;
        return pkt;
    }

    /// <summary>Captures sends without touching a socket — same pattern as
    /// the test seam in DhcpWorkerProcessPacketTests.</summary>
    private sealed class RecordingDhcpWorker : DhcpWorker
    {
        public RecordingDhcpWorker(IServiceScopeFactory scopeFactory)
            : base(NullLogger<DhcpWorker>.Instance, scopeFactory, new ConfigurationBuilder().Build())
        {
        }

        internal override ValueTask<int> SendResponseAsync(
            ReadOnlyMemory<byte> response, IPEndPoint destination,
            string? interfaceName, CancellationToken cancellationToken)
        {
            // No-op; we want to measure the worker's pre-send work, not the
            // socket. ToArray would itself allocate and pollute the numbers.
            return ValueTask.FromResult(response.Length);
        }
    }
}
