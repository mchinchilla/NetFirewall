namespace NetFirewall.Services.Firewall;

/// <summary>
/// Applies the generated <c>tc</c> (Linux traffic control) HTB hierarchy
/// to the running kernel. Sister of <see cref="INftApplyService"/> for QoS —
/// nftables doesn't shape traffic on its own, you need iproute2's tc.
/// </summary>
public interface ITcApplyService
{
    /// <summary>
    /// Generates the script via <see cref="IFirewallService.GenerateTcScriptAsync"/>,
    /// writes it to a temp file, and runs it with <c>bash</c>. Returns the
    /// reused <see cref="NftApplyResult"/> so callers can treat both apply
    /// flows uniformly.
    /// </summary>
    Task<NftApplyResult> ApplyAsync(CancellationToken ct = default);
}
