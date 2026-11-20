namespace NetFirewall.Models.Dhcp;

/// <summary>
/// PXE / iPXE client recognition (RFC 4578, PXE 2.1). Pure — no IO.
/// Architecture comes from option 93; older ROMs only put it in option 60 as
/// "PXEClient:Arch:00007:UNDI:003016", so that is parsed as a fallback (the old code's
/// Contains("00007") also matched the UNDI field).
/// </summary>
public static class PxeBoot
{
    // RFC 4578 §2.1 / IANA "Processor Architecture Types".
    public const ushort BiosX86 = 0;
    public const ushort EfiIa32 = 6;
    public const ushort EfiX64Bc = 7;
    public const ushort EfiX64 = 9;
    public const ushort EfiArm32 = 10;
    public const ushort EfiArm64 = 11;
    public const ushort HttpX86 = 15;
    public const ushort HttpX64 = 16;
    public const ushort HttpArm32 = 18;
    public const ushort HttpArm64 = 19;

    /// <summary>Client architecture: option 93, else "Arch:NNNNN" in option 60, else null.</summary>
    public static ushort? Architecture(DhcpRequest request)
    {
        if (request.ClientArchitecture is { } arch) return arch;
        var vci = request.VendorClassIdentifier;
        if (vci is null) return null;
        var i = vci.IndexOf("Arch:", StringComparison.Ordinal);
        if (i < 0 || i + 10 > vci.Length) return null;
        return ushort.TryParse(vci.AsSpan(i + 5, 5), out var parsed) ? parsed : null;
    }

    public static bool IsUefi(ushort arch) => arch is EfiIa32 or EfiX64Bc or EfiX64 or EfiArm32 or EfiArm64
        or HttpX86 or HttpX64 or HttpArm32 or HttpArm64;

    public static bool IsArm(ushort arch) => arch is EfiArm32 or EfiArm64 or HttpArm32 or HttpArm64;

    /// <summary>iPXE identifies itself with user class (option 77) "iPXE".</summary>
    public static bool IsIpxe(DhcpRequest request) =>
        string.Equals(request.UserClass, "iPXE", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Option 77 per RFC 3004 is a list of length-prefixed classes, but most firmware (iPXE among
    /// them) sends the bare string. Accept both; return the first class.
    /// </summary>
    public static string? ParseUserClass(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return null;
        var body = data[0] > 0 && data[0] == data.Length - 1 ? data[1..] : data;
        return global::System.Text.Encoding.ASCII.GetString(body);
    }

    /// <summary>
    /// The boot file for this client. Priority: class override, iPXE (breaks the chainload loop),
    /// then by architecture — UEFI clients get the UEFI file, everything else the BIOS file.
    /// </summary>
    public static string? BootFile(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        if (clientClass?.BootFilename is { } fromClass) return fromClass;
        if (subnet is null) return request.File;
        if (IsIpxe(request) && !string.IsNullOrEmpty(subnet.BootFilenameIpxe)) return subnet.BootFilenameIpxe;
        if (request.IsPxeRequest && Architecture(request) is { } arch && IsUefi(arch)
            && !string.IsNullOrEmpty(subnet.BootFilenameUefi))
            return subnet.BootFilenameUefi;
        return subnet.BootFilename ?? request.File;
    }

    /// <summary>
    /// Option 43 for PXE clients: PXE_DISCOVERY_CONTROL (sub-option 6) = 8, "boot from the file
    /// in the offer, no boot-server discovery" — what dnsmasq/ISC send for plain TFTP boot.
    /// </summary>
    public static ReadOnlySpan<byte> VendorOptions => [6, 1, 8, 255];

    /// <summary>Option 60 in replies to PXE clients — PXE 2.1 ROMs ignore offers without it.</summary>
    public static ReadOnlySpan<byte> PxeClientClass => "PXEClient"u8;
}
