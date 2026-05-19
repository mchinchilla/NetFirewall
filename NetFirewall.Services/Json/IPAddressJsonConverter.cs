using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetFirewall.Services.Json;

/// <summary>
/// System.Text.Json has no built-in converter for <see cref="IPAddress"/>:
/// the default reflection-based serializer emits an empty object, which then
/// round-trips back as null on the client. That breaks any DTO carrying an
/// IPAddress field (e.g. <c>TopTalkerHost.SrcIp</c>) — the daemon endpoint
/// silently returns useless data and the dashboard panel renders empty.
/// This converter writes/reads the address as its canonical string form.
/// </summary>
public sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;
        var s = reader.GetString();
        return string.IsNullOrEmpty(s) ? null : IPAddress.Parse(s);
    }

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString());
}
