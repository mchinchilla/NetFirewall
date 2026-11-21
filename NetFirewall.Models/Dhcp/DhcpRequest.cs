using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpRequest
{
    // Fixed Fields from DHCP Header
    public byte Op { get; set; }
    public byte HType { get; set; }
    public byte HLen { get; set; }
    public byte Hops { get; set; }
    public byte[] Xid { get; set; }
    public ushort Secs { get; set; }
    public ushort Flags { get; set; }
    public IPAddress CiAddr { get; set; } = IPAddress.Any;
    public IPAddress YiAddr { get; set; } = IPAddress.Any;
    public IPAddress SiAddr { get; set; } = IPAddress.Any;
    public IPAddress GiAddr { get; set; } = IPAddress.Any;
    public string ClientMac { get; set; } = string.Empty;
    public byte[] ChAddr { get; set; } = Array.Empty<byte>();
    public string? SName { get; set; }
    public string? File { get; set; }

    // DHCP Options — null means "the client did not send this option".
    // The distinction matters: a REQUEST without option 50 (renewal) must NOT
    // look like a request for 0.0.0.0, and an absent hostname must NOT look
    // like an empty one to class matchers / DDNS.
    public DhcpMessageType MessageType { get; set; }
    public IPAddress? RequestedIp { get; set; }
    public byte[]? ClientIdentifier { get; set; }
    public string? Hostname { get; set; }
    public byte[]? ParameterRequestList { get; set; }
    /// <summary>Option 93 — PXE client architecture (RFC 4578).</summary>
    public ushort? ClientArchitecture { get; set; }
    /// <summary>Option 77 — first user class ("iPXE" for iPXE).</summary>
    public string? UserClass { get; set; }
    /// <summary>Option 97 — PXE client UUID, echoed in replies.</summary>
    public byte[]? ClientMachineId { get; set; }
    /// <summary>Option 82 exactly as the relay sent it — echoed verbatim in every reply (RFC 3046 §2.2).</summary>
    public byte[]? RelayAgentInformation { get; set; }
    /// <summary>
    /// False when option 82 came from a source the trusted-relay list doesn't vouch for
    /// (<see cref="DhcpRelayPolicy"/>): still echoed, but never used for class or pool matching.
    /// </summary>
    public bool RelayAgentInfoTrusted { get; set; } = true;
    public string? VendorClassIdentifier { get; set; }
    /// <summary>Option 54 — which server a REQUEST is addressed to. A server
    /// whose identifier doesn't match must stay silent (RFC 2131 §4.3.2).</summary>
    public IPAddress? ServerIdentifier { get; set; }
    public int LeaseTime { get; set; }
    /// <summary>Option 57 — the largest DHCP datagram the client accepts (RFC 2132 §9.10). Null = 576.</summary>
    public ushort? MaxMessageSize { get; set; }

    public bool IsBootp { get; set; }
    public bool IsPxeRequest { get; set; }
    /// <summary>UEFI HTTP boot client: option 60 starts with "HTTPClient" (UEFI spec, HTTP Boot).</summary>
    public bool IsHttpBoot { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; } = new(IPAddress.Any, 0);

    /// <summary>
    /// The network interface name on which this request was received.
    /// Used for multi-interface DHCP server to select the correct subnet.
    /// </summary>
    public string? SourceInterfaceName { get; set; }

    public DhcpRequest()
    {
        Xid = new byte[ 4 ];
        ChAddr = new byte[ 16 ];
    }
}