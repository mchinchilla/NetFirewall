using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Diagnostics.Capture;

/// <inheritdoc />
public sealed class AfPacketCapabilityProbe : ICaptureCapabilityProbe
{
    private readonly ILogger<AfPacketCapabilityProbe> _logger;

    public AfPacketCapabilityProbe(ILogger<AfPacketCapabilityProbe> logger) => _logger = logger;

    public CapturePreflight Probe()
    {
        if (!OperatingSystem.IsLinux())
            return new CapturePreflight(CaptureCapability.Unknown, "Capture sockets are a Linux concept.");

        try
        {
            // AddressFamily.Packet maps to AF_PACKET. The protocol does not matter for
            // this question: we only want to know whether the socket call is permitted,
            // and the socket is closed immediately.
            using var probe = new Socket(AddressFamily.Packet, SocketType.Raw, ProtocolType.Raw);
            return new CapturePreflight(CaptureCapability.Available, "socket(AF_PACKET, SOCK_RAW) succeeded.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressFamilyNotSupported)
        {
            return new CapturePreflight(CaptureCapability.BlockedBySandbox,
                "socket(AF_PACKET, SOCK_RAW) returned EAFNOSUPPORT.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AccessDenied or SocketError.ProtocolNotSupported)
        {
            return new CapturePreflight(CaptureCapability.PermissionDenied,
                $"socket(AF_PACKET, SOCK_RAW) was refused ({ex.SocketErrorCode}).");
        }
        catch (Exception ex)
        {
            // Never let the probe decide anything on its own — it only sharpens a message.
            _logger.LogDebug(ex, "AF_PACKET probe could not classify the failure");
            return new CapturePreflight(CaptureCapability.Unknown, ex.Message);
        }
    }
}
