namespace NetFirewall.Services.Diagnostics.Capture;

/// <summary>Why the daemon can or cannot open a capture socket.</summary>
public enum CaptureCapability
{
    /// <summary>The probe could not run (not Linux, or an error we do not recognise).</summary>
    Unknown,
    /// <summary>socket(AF_PACKET, SOCK_RAW) succeeded — capture sockets are allowed here.</summary>
    Available,
    /// <summary>EAFNOSUPPORT: the address family is filtered away, which on a systemd unit means RestrictAddressFamilies.</summary>
    BlockedBySandbox,
    /// <summary>EACCES/EPERM: the family is allowed but the process lacks CAP_NET_RAW.</summary>
    PermissionDenied,
}

public sealed record CapturePreflight(CaptureCapability Status, string Detail);

/// <summary>
/// Answers "may this process capture at all?" without tcpdump.
///
/// tcpdump's own answer is libpcap's <c>Packet capture is not supported on that
/// device</c>, which names the device and so sends the operator to look at the
/// NIC. On an appliance the cause is nearly always the opposite end: the unit's
/// sandbox refused socket(AF_PACKET). Opening that socket directly is the same
/// first call libpcap makes, and its errno separates the two for certain instead
/// of guessing from the wording.
/// </summary>
public interface ICaptureCapabilityProbe
{
    CapturePreflight Probe();
}
