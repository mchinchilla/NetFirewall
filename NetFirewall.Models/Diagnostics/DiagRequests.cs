namespace NetFirewall.Models.Diagnostics;

// Request shapes shared by the Web (form → JSON) and the daemon (JSON → tool).
// Every field is re-validated on both sides by IDiagnosticInputValidator; the
// records themselves carry no validation so they stay trivially serialisable.

/// <summary>Ping a target, optionally steering the probe through a policy-routing mark or an interface.</summary>
public sealed record PingRequest(
    string Target,
    string? Interface = null,
    string? Fwmark = null,
    int Count = 3,
    int TimeoutSec = 2);

public sealed record TracerouteRequest(
    string Target,
    string? Interface = null,
    string? Fwmark = null,
    int MaxHops = 20,
    int TimeoutSec = 2);

/// <summary><c>ip route get &lt;target&gt; [from &lt;from&gt; iif &lt;iif&gt;] [mark &lt;fwmark&gt;]</c> — "which way would this packet go?"</summary>
public sealed record RouteGetRequest(
    string Target,
    string? Fwmark = null,
    string? From = null,
    string? Iif = null);

public sealed record ConntrackLookupRequest(
    string? Src = null,
    string? Dst = null,
    string? Proto = null,
    int? Port = null,
    int Limit = 200);

/// <summary>Kernel-log drops. <see cref="Filter"/> ∈ drops | martians | wg | all.</summary>
public sealed record DropLogRequest(
    string? Interface = null,
    int SinceMinutes = 60,
    int Lines = 500,
    string Filter = "drops");

public sealed record VpnDoctorRequest(bool IncludeJournal = true);

/// <summary><see cref="Mode"/> ∈ mark | bind | both — how to steer the probe pings.</summary>
public sealed record VpnProbeRequest(string? Target = null, string Mode = "both");

/// <summary>A wg-quick client config pasted by the operator. Private/preshared keys are stripped before it leaves the browser's request handler.</summary>
public sealed record VpnCompareRequest(string ConfigText);
