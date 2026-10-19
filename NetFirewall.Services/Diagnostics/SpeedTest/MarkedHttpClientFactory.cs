using System.Net;
using System.Net.Sockets;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <summary>
/// HTTP clients whose sockets carry an fwmark, so the kernel's policy rules pin
/// every connection to one WAN — the same steering <c>ping -m</c> uses.
/// Binding to the interface instead (<c>curl --interface</c>, SO_BINDTODEVICE)
/// is ignored by policy routing, exactly like <c>ping -I</c>.
/// </summary>
public interface IMarkedHttpClientFactory
{
    /// <summary>
    /// A client for one test. HTTP/1.1 only, so N parallel requests are N TCP
    /// connections (HTTP/2 would multiplex them onto one). Every connection is
    /// refused unless the resolved address is public. The caller disposes it.
    /// </summary>
    HttpClient Create(long fwmark);
}

/// <inheritdoc />
public sealed class MarkedHttpClientFactory : IMarkedHttpClientFactory
{
    // <asm-generic/socket.h>
    private const int SolSocket = 1;
    private const int SoMark = 36;

    private readonly IDiagnosticInputValidator _validator;

    public MarkedHttpClientFactory(IDiagnosticInputValidator validator) => _validator = validator;

    public HttpClient Create(long fwmark)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
            AutomaticDecompression = DecompressionMethods.None,   // count wire bytes, not inflated ones
            ConnectTimeout = TimeSpan.FromSeconds(5),
            MaxConnectionsPerServer = int.MaxValue,
            UseProxy = false,
            UseCookies = false,
            // Redirect hops go through here too, so a redirect to a private address is refused as well.
            ConnectCallback = (ctx, ct) => ConnectAsync(ctx.DnsEndPoint, fwmark, ct),
        };

        var client = new HttpClient(handler, disposeHandler: true)
        {
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Timeout = Timeout.InfiniteTimeSpan,   // the test's own deadline cancels it
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NetFirewall-SpeedTest/1.0");
        return client;
    }

    private async ValueTask<Stream> ConnectAsync(DnsEndPoint endpoint, long fwmark, CancellationToken ct)
    {
        // IPv4 only: the per-WAN policy tables are IPv4.
        var addresses = IPAddress.TryParse(endpoint.Host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(endpoint.Host, AddressFamily.InterNetwork, ct);

        var target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? throw new HttpRequestException($"{endpoint.Host} has no IPv4 address.");
        if (!_validator.IsPublicAddress(target))
            throw new HttpRequestException($"{endpoint.Host} resolves to {target}, which is not a public address.");

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            // SO_MARK needs CAP_NET_ADMIN, which the daemon holds. Off Linux (dev boxes)
            // there is no policy routing to steer, so the test runs unmarked.
            if (fwmark > 0 && OperatingSystem.IsLinux())
                socket.SetRawSocketOption(SolSocket, SoMark, BitConverter.GetBytes(unchecked((int)(uint)fwmark)));

            await socket.ConnectAsync(new IPEndPoint(target, endpoint.Port), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
