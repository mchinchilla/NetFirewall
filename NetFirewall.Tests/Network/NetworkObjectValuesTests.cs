using NetFirewall.Models.Network;
using NetFirewall.Web.Models.Network;
using Xunit;

namespace NetFirewall.Tests.Network;

public class NetworkObjectValuesTests
{
    [Theory]
    [InlineData("192.168.99.20, 192.168.99.21", 2)]
    [InlineData("192.168.99.20\n192.168.99.21;192.168.99.22", 3)]
    [InlineData("192.168.99.20/32", 1)]
    public void Split_AcceptsCommaNewlineSemicolon(string raw, int count)
    {
        Assert.Equal(count, NetworkObjectValues.Split(raw).Length);
    }

    [Fact]
    public void HostForm_AllowsMultipleIpv4Addresses()
    {
        var form = new NetworkObjectFormViewModel
        {
            Name = "DIEGO_DEVICES",
            Type = NetworkObjectTypes.Host,
            Value = "192.168.99.20\n192.168.99.21"
        };
        var results = form.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(form)).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void HostForm_RejectsGarbageInList()
    {
        var form = new NetworkObjectFormViewModel
        {
            Name = "DIEGO_DEVICES",
            Type = NetworkObjectTypes.Host,
            Value = "192.168.99.20, not-an-ip"
        };
        var results = form.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(form)).ToList();
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(form.Value)));
    }
}
