using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

/// <summary>Outcome of a WireGuard bring-up: the wg apply itself plus the tunnel's route re-apply.</summary>
public sealed class WireGuardBringUpResult
{
    public required NftApplyResult Apply { get; init; }

    /// <summary>Null when the link never came up — routing was not attempted.</summary>
    public PolicyRoutingApplyResult? Routing { get; init; }

    public bool Success => Apply.Success && (Routing is null || Routing.Success);

    public int RoutesReapplied =>
        Routing?.Steps.Count(s => s.Phase == "ip-route" && s.Executed && s.Success) ?? 0;

    /// <summary>One-line operator message for the toast and the apply history.</summary>
    public string Describe(string interfaceName)
    {
        if (!Apply.Success)
            return Apply.Error ?? "wg apply failed";

        if (Routing is null || Routing.Success)
        {
            var n = RoutesReapplied;
            var routes = n == 0
                ? $"no policy routes ride on {interfaceName}"
                : $"{n} policy route{(n == 1 ? "" : "s")} re-applied";
            return $"WireGuard {interfaceName} applied (exit {Apply.ExitCode}); {routes}.";
        }

        return $"WireGuard {interfaceName} is up, but re-applying its policy routes failed: {Routing.Error}. " +
               "Run Firewall → Apply → Policy routing.";
    }

    /// <summary>The wg output followed by the routing commands, for the detail pane.</summary>
    public string? CombinedOutput
    {
        get
        {
            if (Routing is null || Routing.Steps.Count == 0) return Apply.Output;
            var lines = Routing.Steps.Select(s =>
                s.Executed && !s.Success ? $"{s.Command}  # FAILED: {s.Detail}" : s.Command);
            return $"{Apply.Output}\n# policy routes for the tunnel\n{string.Join('\n', lines)}".Trim();
        }
    }
}
