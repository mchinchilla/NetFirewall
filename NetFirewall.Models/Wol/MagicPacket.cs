namespace NetFirewall.Models.Wol;

/// <summary>
/// The Wake-on-LAN "magic packet" payload: six <c>0xFF</c> bytes followed by the
/// target MAC repeated sixteen times (102 bytes). A sleeping NIC scans every
/// frame it sees for this pattern, whatever the protocol around it — the UDP
/// datagram is only the envelope that gets it onto the wire as a broadcast.
/// </summary>
public static class MagicPacket
{
    public const int Length = 6 + 16 * 6;

    public static byte[] Build(ReadOnlySpan<byte> mac)
    {
        if (mac.Length != 6) throw new ArgumentException("A MAC address is six bytes.", nameof(mac));

        var packet = new byte[Length];
        packet.AsSpan(0, 6).Fill(0xFF);
        for (var i = 0; i < 16; i++)
            mac.CopyTo(packet.AsSpan(6 + i * 6, 6));
        return packet;
    }
}
