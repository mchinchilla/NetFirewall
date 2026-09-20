namespace NetFirewall.Services.Network;

/// <summary>Linux implementation of <see cref="INetworkLinkProbe"/> over <c>/sys/class/net/&lt;iface&gt;</c>.</summary>
public sealed class SysfsNetworkLinkProbe : INetworkLinkProbe
{
    private const string NetClassPath = "/sys/class/net";

    public bool Exists(string interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName)
            || interfaceName.Contains('/')
            || interfaceName.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        // No sysfs (macOS dev box, tests) → unknown → let the caller probe.
        if (!OperatingSystem.IsLinux()) return true;

        return Directory.Exists(Path.Combine(NetClassPath, interfaceName));
    }
}
