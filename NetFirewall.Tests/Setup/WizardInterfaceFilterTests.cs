using NetFirewall.Services.Setup;
using Xunit;

namespace NetFirewall.Tests.Setup;

/// <summary>Step 1 lists real NICs only: service-owned links and the kernel's fallback tunnel devices are hidden.</summary>
public class WizardInterfaceFilterTests
{
    [Theory]
    [InlineData("gre0")] [InlineData("gretap0")] [InlineData("erspan0")] [InlineData("sit0")]
    [InlineData("ip_vti0")] [InlineData("ip6_vti0")] [InlineData("ip6tnl0")] [InlineData("ip6gre0")]
    [InlineData("tunl0")] [InlineData("wg0")] [InlineData("docker0")] [InlineData("veth12ab")]
    public void KernelAndServiceDevices_AreHidden(string name) =>
        Assert.True(SetupWizardService.IsServiceManagedInterface(name));

    [Theory]
    [InlineData("eth0")] [InlineData("ens192")] [InlineData("enp3s0")]
    [InlineData("gre1")]   // a tunnel the operator created is real and stays listed
    public void RealInterfaces_AreListed(string name) =>
        Assert.False(SetupWizardService.IsServiceManagedInterface(name));
}
