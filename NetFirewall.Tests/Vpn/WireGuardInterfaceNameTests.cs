using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Controllers;
using NetFirewall.Web.Models.Vpn;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Pins the interface-name immutability contract: the name keys the on-disk
/// config, the policy-routing table, and the live interface, so a rename —
/// UI accident or tampered POST — must never reach the database. Two doors
/// are guarded: the Web's server Save (ignores posted names on update) and
/// the importer (refuses a .conf whose name differs from the managed one).
/// </summary>
public sealed class WireGuardInterfaceNameTests
{
    // ── Web Save: posted rename is ignored on update ──

    [Fact]
    public async Task Save_ExistingServer_IgnoresPostedRename()
    {
        var existing = new WgServer
        {
            Id = Guid.NewGuid(), Name = "wg0", Mode = "server",
            PrivateKey = "PRIV", PublicKey = "PUB",
            ListenPort = 51820, AddressCidr = "10.10.0.1/24", Enabled = true,
        };

        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.GetServerAsync(It.IsAny<CancellationToken>())).ReturnsAsync(existing);
        wg.Setup(x => x.GetPeersAsync(existing.Id, It.IsAny<CancellationToken>()))
          .ReturnsAsync(Array.Empty<WgPeer>());
        wg.Setup(x => x.SaveServerAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((WgServer s, CancellationToken _) => s);

        var controller = new WireGuardController(
            wg.Object, new Mock<IVpnRoutingService>().Object,
            new Mock<IWireGuardTeardownService>().Object, new Mock<IDaemonClient>().Object,
            NullLogger<WireGuardController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        // Enabled=false skips the routing-scaffold side effect — this test is
        // only about the name.
        var form = new WgServerFormViewModel
        {
            Id = existing.Id, Name = "wg9", ListenPort = 51820,
            AddressCidr = "10.10.0.1/24", Enabled = false,
        };

        await controller.Save(form, CancellationToken.None);

        wg.Verify(x => x.SaveServerAsync(
            It.Is<WgServer>(s => s.Name == "wg0"), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Importer: a conf under a different name is refused, not half-imported ──

    [Fact]
    public async Task Import_DifferentInterfaceName_WhenServerExists_Throws()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wgimport-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "wg1.conf"),
                "[Interface]\nPrivateKey = PRIV\nAddress = 10.0.0.2/32\n");

            var wg = new Mock<IWireGuardService>();
            wg.Setup(x => x.GetServerAsync(It.IsAny<CancellationToken>()))
              .ReturnsAsync(new WgServer { Id = Guid.NewGuid(), Name = "wg0" });

            var importer = new WireGuardImporter(
                wg.Object,
                new Mock<IWireGuardApplyService>().Object,
                NpgsqlDataSource.Create("Host=localhost;Username=unused"),
                NullLogger<WireGuardImporter>.Instance,
                Options.Create(new WireGuardApplyOptions { ConfigDir = dir }));

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => importer.ImportAsync("wg1", CancellationToken.None));
            Assert.Contains("wg0", ex.Message);

            // Nothing was written: no server upsert, no peer churn.
            wg.Verify(x => x.SaveServerAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()), Times.Never);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
