using System.Net.Http;
using System.Text;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Tests.Daemon;

/// <summary>
/// The daemon's <c>/v1/firewall/apply</c> answers a failed apply with the
/// normal <c>ServiceResponse</c> envelope but HTTP 500. The client used to
/// short-circuit on any non-2xx and replace the body with "Daemon returned
/// HTTP 500", so the operator never saw nft's actual complaint.
/// </summary>
public class DaemonClientEnvelopeTests
{
    private static HttpResponseMessage Resp(HttpStatusCode code, string body, string mediaType = "application/json") =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, mediaType) };

    [Fact]
    public async Task NonSuccessStatus_WithEnvelopeBody_KeepsTheDaemonsMessage()
    {
        using var resp = Resp(HttpStatusCode.InternalServerError,
            """{"success":false,"message":"nft: Interface does not exist (oif wg0)","data":null}""");

        var env = await DaemonClient.ReadEnvelopeAsync<object>(resp, CancellationToken.None);

        Assert.False(env.Success);
        Assert.Equal("nft: Interface does not exist (oif wg0)", env.Message);
    }

    [Fact]
    public async Task NonSuccessStatus_WithSuccessTrueBody_IsStillAFailure()
    {
        using var resp = Resp(HttpStatusCode.InternalServerError,
            """{"success":true,"message":"looks fine","data":null}""");

        var env = await DaemonClient.ReadEnvelopeAsync<object>(resp, CancellationToken.None);

        Assert.False(env.Success);
        Assert.Equal("looks fine", env.Message);
    }

    [Fact]
    public async Task NonSuccessStatus_WithNonJsonBody_FallsBackToStatusText()
    {
        using var resp = Resp(HttpStatusCode.BadGateway, "<html>nginx</html>", "text/html");

        var env = await DaemonClient.ReadEnvelopeAsync<object>(resp, CancellationToken.None);

        Assert.False(env.Success);
        Assert.StartsWith("Daemon returned HTTP 502", env.Message);
    }

    [Fact]
    public async Task NonSuccessStatus_WithProblemDetails_FallsBackToStatusText()
    {
        // ProblemDetails deserializes into an envelope with no Message — an
        // empty explanation must not replace the status text.
        using var resp = Resp(HttpStatusCode.InternalServerError,
            """{"type":"about:blank","title":"boom","status":500}""", "application/problem+json");

        var env = await DaemonClient.ReadEnvelopeAsync<object>(resp, CancellationToken.None);

        Assert.False(env.Success);
        Assert.StartsWith("Daemon returned HTTP 500", env.Message);
    }

    [Fact]
    public async Task SuccessStatus_WithEnvelope_ReturnsItVerbatim()
    {
        using var resp = Resp(HttpStatusCode.OK, """{"success":true,"message":"Applied.","data":null}""");

        var env = await DaemonClient.ReadEnvelopeAsync<object>(resp, CancellationToken.None);

        Assert.True(env.Success);
        Assert.Equal("Applied.", env.Message);
    }
}
