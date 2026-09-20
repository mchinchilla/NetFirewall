namespace NetFirewall.Services.Network;

/// <summary>
/// Answers "does this network interface exist right now?" without spawning a
/// process. Lets pollers skip <c>wg show</c> / <c>ip link</c> on a tunnel the
/// operator has intentionally stopped, instead of logging an exec failure on
/// every status poll.
/// </summary>
public interface INetworkLinkProbe
{
    /// <summary>
    /// True when <paramref name="interfaceName"/> is present in the kernel.
    /// On platforms without sysfs this returns <c>true</c> ("unknown") so the
    /// caller falls back to probing the tool directly.
    /// </summary>
    bool Exists(string interfaceName);
}
