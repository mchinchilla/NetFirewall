using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Web.Controllers;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// The audit-log table query used to bind a parameter named <c>action</c>,
/// which MVC fills with the method name ("Table"). Search then ran
/// <c>WHERE action = 'Table'</c> and the page always looked empty even
/// though <c>fw_audit_log</c> had rows (the table chips still listed names).
/// </summary>
public class FwAuditLogControllerTests
{
    [Fact]
    public async Task Table_EmptyOp_DoesNotFilterByTheMvcActionName()
    {
        var firewall = new Mock<IFirewallService>();
        firewall.Setup(f => f.SearchAuditLogsAsync(
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<DateTime?>(),
                It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<FwAuditLog>());

        var c = new FwAuditLogController(firewall.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        await c.Table(table: null, op: null, since: "24h", page: 1, CancellationToken.None);

        firewall.Verify(f => f.SearchAuditLogsAsync(
            null,
            null,
            It.IsAny<DateTime?>(),
            50,
            0,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Table_OpInsert_FiltersByInsert()
    {
        var firewall = new Mock<IFirewallService>();
        firewall.Setup(f => f.SearchAuditLogsAsync(
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<DateTime?>(),
                It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<FwAuditLog>());

        var c = new FwAuditLogController(firewall.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        await c.Table(table: "fw_filter_rules", op: "INSERT", since: "", page: 1, CancellationToken.None);

        firewall.Verify(f => f.SearchAuditLogsAsync(
            "fw_filter_rules",
            "INSERT",
            null,
            50,
            0,
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
