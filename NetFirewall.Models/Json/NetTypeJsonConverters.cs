using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetFirewall.Models.Json;

/// <summary>
/// System.Text.Json cannot serialize <see cref="IPAddress"/> out of the box:
/// its <c>ScopeId</c> getter throws for IPv4 addresses, so any envelope that
/// carries one (DhcpMacReservation, DhcpPool, DhcpSubnet, FwPortForward,
/// FailoverPeer, …) 500s AFTER the DB write succeeds. Register these on the
/// host's JsonOptions so entities round-trip as plain strings.
/// </summary>
public sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.Null ? null : IPAddress.Parse(reader.GetString()!);

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString());
}

/// <summary>
/// Writes MACs in the canonical colon form (<c>00:0C:29:71:5E:67</c>) instead
/// of <see cref="PhysicalAddress.ToString"/>'s bare hex; reads either form.
/// </summary>
public sealed class PhysicalAddressJsonConverter : JsonConverter<PhysicalAddress>
{
    public override PhysicalAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.Null
            ? null
            : PhysicalAddress.Parse(reader.GetString()!.Replace(":", "-").ToUpperInvariant());

    public override void Write(Utf8JsonWriter writer, PhysicalAddress value, JsonSerializerOptions options) =>
        writer.WriteStringValue(string.Join(":", value.GetAddressBytes().Select(b => b.ToString("X2"))));
}
