namespace NetFirewall.Models.Dhcp;

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