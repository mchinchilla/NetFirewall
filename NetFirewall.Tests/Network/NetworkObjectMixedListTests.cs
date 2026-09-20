using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Services.Settings;
using NetFirewall.Web.Filters;
using NetFirewall.Web.Models.Network;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// A list object must be able to hold hosts and ranges together — that is what a
/// rule like "the PBX plus a few phones" needs. The resolver always allowed it;
/// the form did not, and rejected the save with a message that named no field.
/// </summary>
public class NetworkObjectMixedListTests
{
    private static IReadOnlyList<string> Errors(NetworkObjectFormViewModel form)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(form, new ValidationContext(form), results, validateAllProperties: true);
        return results.SelectMany(r => r.ErrorMessage is null ? [] : new[] { r.ErrorMessage }).ToList();
    }

    private static NetworkObjectFormViewModel Host(string value) =>
        new() { Name = "PBX_WAN2", Type = NetworkObjectTypes.Host, Value = value };

    [Fact]
    public void HostObject_AcceptsHostsAndRangesInTheSameValue()
    {
        var form = Host("""
            192.168.99.145/32,
            192.168.99.60-192.168.99.79,
            192.168.99.8/32,
            192.168.99.101/32
            """);

        Assert.Empty(Errors(form));
    }

    [Theory]
    [InlineData("192.168.99.8")]                          // bare
    [InlineData("192.168.99.8/32")]                       // explicit /32
    [InlineData("192.168.99.60-192.168.99.79")]           // range
    [InlineData("192.168.99.8, 10.0.0.1-10.0.0.9")]       // mixed
    public void HostObject_Accepts(string value) => Assert.Empty(Errors(Host(value)));

    [Theory]
    [InlineData("192.168.99.60-79")]        // shorthand nft does not understand
    [InlineData("192.168.99.0/24")]         // a network belongs in a network object
    [InlineData("192.168.99.60-")]
    [InlineData("-192.168.99.79")]
    [InlineData("potato")]
    public void HostObject_StillRejectsWhatNftWouldChokeOn(string value)
    {
        var errors = Errors(Host(value));
        Assert.NotEmpty(errors);
        // The message must quote the offending token, not just say "invalid".
        Assert.Contains(errors, e => e.Contains(value.Trim(), StringComparison.Ordinal));
    }

    [Fact]
    public void RangeObject_StillTakesExactlyOneRange()
    {
        // Unlike the list type, `range` is not split — two of them in one value
        // would reach nft as a single bad token.
        var form = new NetworkObjectFormViewModel
        {
            Name = "TWO", Type = NetworkObjectTypes.Range,
            Value = "10.0.0.1-10.0.0.5, 10.0.0.20-10.0.0.25",
        };
        Assert.NotEmpty(Errors(form));
    }

    [Theory]
    [InlineData("10.0.0.1-10.0.0.9", true)]
    [InlineData("10.0.0.1 - 10.0.0.9", true)]
    [InlineData("10.0.0.1-9", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("10.0.0.1-", false)]
    [InlineData("-10.0.0.9", false)]
    [InlineData("", false)]
    public void IsIpv4Range(string token, bool expected) =>
        Assert.Equal(expected, NetworkObjectValues.IsIpv4Range(token));

    [Fact]
    public async Task Resolver_ExpandsTheMixedListToTheTokensNftExpects()
    {
        var objects = new Mock<INetworkObjectService>();
        var mixed = new NetworkObject
        {
            Id = Guid.NewGuid(), Name = "PBX_WAN2", Type = NetworkObjectTypes.Host,
            Value = "192.168.99.145/32, 192.168.99.60-192.168.99.79, 192.168.99.8, 192.168.99.101",
        };
        objects.Setup(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>())).ReturnsAsync(new[] { mixed });

        var resolver = new NetworkObjectResolver(objects.Object, new Mock<IAppSettingsService>().Object,
            NullLogger<NetworkObjectResolver>.Instance);

        var resolved = await resolver.ResolveAsync(["PBX_WAN2"]);

        Assert.Equal(
            ["192.168.99.145/32", "192.168.99.60-192.168.99.79", "192.168.99.8/32", "192.168.99.101/32"],
            resolved);
    }

    [Fact]
    public void TypeLabels_SayWhatTheTypeActuallyHolds()
    {
        // "host" read as one machine, which is why nobody tried a list in it.
        Assert.Contains("ranges", NetworkObjectTypes.DisplayName(NetworkObjectTypes.Host), StringComparison.OrdinalIgnoreCase);
        Assert.All(NetworkObjectTypes.All, t => Assert.False(string.IsNullOrWhiteSpace(NetworkObjectTypes.DisplayName(t))));
    }

    [Theory]
    [InlineData("192.168.99.8", true)]
    [InlineData("192.168.99.8/32", true)]
    [InlineData("9", false)]            // IPAddress.TryParse says 0.0.0.9 — a typo, not a host
    [InlineData("10.0.1", false)]       // classful shorthand for 10.0.0.1
    [InlineData("192.168.99.8/24", false)]
    public void IsIpv4Host_RequiresAFullDottedQuad(string token, bool expected) =>
        Assert.Equal(expected, NetworkObjectValues.IsIpv4Host(token));

    [Theory]
    [InlineData("Value", "Value")]
    [InlineData("ConfigText", "Config Text")]
    [InlineData("Lans[0].EnableDhcp", "Enable Dhcp")]
    [InlineData("", "")]
    public void ValidationToast_NamesTheFieldTheWayTheLabelDoes(string key, string expected) =>
        Assert.Equal(expected, ValidationToServiceResponseFilter.FieldLabel(key));
}
