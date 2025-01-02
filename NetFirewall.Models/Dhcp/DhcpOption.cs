using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpOption
{
    public byte Code { get; set; }
    public byte[] Data { get; set; }
}

public enum DhcpOptionCode : byte
{
    SubnetMask = 1,
    Router = 3,
    DNS = 6,
    BootFileName = 67,
    ServerName = 66,
    PxeClientArchType = 93,
    PxeClientNetworkInterface = 94,
    PxeDiscoveryControl = 97,
    YiAddr = 50, // Your (client) IP Address
}

public static class DhcpOptionExtensions
{
    public static DhcpOption CreateOption( DhcpOptionCode code, byte[] data )
    {
        return new DhcpOption { Code = (byte)code, Data = data };
    }

    public static DhcpOption CreateOption( DhcpOptionCode code, string data )
    {
        return new DhcpOption { Code = (byte)code, Data = System.Text.Encoding.ASCII.GetBytes( data ) };
    }
}