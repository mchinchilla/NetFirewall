using NetFirewall.Daemon.Endpoints;
using NetFirewall.Services.Daemon;
using Xunit;

namespace NetFirewall.Tests.Daemon;

/// <summary>
/// /v1/crypto/* runs without a user session (TOTP enrollment and the login's TOTP step happen
/// before one exists), so the caller gate is the only gate: the TOTP cipher is served only when
/// PeerCredentialMiddleware actually filters peers.
/// </summary>
public class CryptoEndpointGateTests
{
    [Fact]
    public void NoAllowList_IsRefused() =>
        Assert.False(CryptoEndpoints.IsPeerGated(new DaemonOptions()));

    [Fact]
    public void EmptyAllowList_IsRefused() =>
        Assert.False(CryptoEndpoints.IsPeerGated(new DaemonOptions { AcceptedPeerUids = [] }));

    [Fact]
    public void AcceptedPeerUids_Gates() =>
        Assert.True(CryptoEndpoints.IsPeerGated(new DaemonOptions { AcceptedPeerUids = [999, 0] }));

    [Fact]
    public void LegacyExpectedPeerUid_Gates() =>
        Assert.True(CryptoEndpoints.IsPeerGated(new DaemonOptions { ExpectedPeerUid = 999 }));
}
