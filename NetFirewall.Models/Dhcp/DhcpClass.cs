using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// DHCP client classification for conditional configuration.
/// Similar to ISC-DHCP classes/subclasses.
/// </summary>
[Map("dhcp_classes")]
public class DhcpClass
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Type of match: vendor_class, user_class, mac_prefix, hardware_type, option
    /// </summary>
    [Map("match_type")]
    public string MatchType { get; set; } = string.Empty;

    /// <summary>
    /// Value to match against (e.g., "PXEClient", "00:11:22")
    /// </summary>
    [Map("match_value")]
    public string MatchValue { get; set; } = string.Empty;

    /// <summary>
    /// Override options for clients matching this class (JSON)
    /// </summary>
    [Map("options")]
    public string? Options { get; set; }

    /// <summary>
    /// Override TFTP/next-server for this class
    /// </summary>
    [Map("next_server")]
    public IPAddress? NextServer { get; set; }

    /// <summary>
    /// Override boot filename for this class
    /// </summary>
    [Map("boot_filename")]
    public string? BootFilename { get; set; }

    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Match types for client classification
/// </summary>
public static class DhcpClassMatchTypes
{
    public const string VendorClass = "vendor_class";       // Option 60 - Vendor Class Identifier
    public const string UserClass = "user_class";           // Option 77 - User Class
    public const string MacPrefix = "mac_prefix";           // First N bytes of MAC
    public const string HardwareType = "hardware_type";     // Ethernet, Token Ring, etc.
    public const string ClientId = "client_id";             // Option 61 - Client Identifier
    public const string Hostname = "hostname";              // Option 12 - Hostname
    public const string Option = "option";                  // Any DHCP option
    public const string RelayAgent = "relay_agent";         // Option 82 - Relay Agent Info
}

/// <summary>
/// Common vendor class identifiers for PXE detection
/// </summary>
public static class PxeVendorClasses
{
    public const string PxeClientLegacy = "PXEClient:Arch:00000";      // BIOS x86
    public const string PxeClientUefi32 = "PXEClient:Arch:00006";      // UEFI x86
    public const string PxeClientUefi64 = "PXEClient:Arch:00007";      // UEFI x64
    public const string PxeClientUefiHttp = "PXEClient:Arch:00016";    // UEFI HTTP
    public const string PxeClientArm32 = "PXEClient:Arch:00002";       // ARM 32-bit
    public const string PxeClientArm64 = "PXEClient:Arch:00011";       // ARM 64-bit
    public const string iPxe = "iPXE";                                  // iPXE client
}

/// <summary>
/// Client architecture types for PXE (Option 93)
/// </summary>
public enum PxeClientArchitecture : ushort
{
    IntelX86Bios = 0,
    Nec_PC98 = 1,
    IA64 = 2,
    DecAlpha = 3,
    ArcX86 = 4,
    IntelLeanClient = 5,
    UEFI_x86 = 6,
    UEFI_x64 = 7,
    EfiXscale = 8,
    EbcBc = 9,
    Arm32Uefi = 10,
    Arm64Uefi = 11,
    PowerPCOpenFirmware = 12,
    PowerPCSoftFloat = 13,
    PowerPCHardFloat = 14,
    UefiHttp = 15,
    UEFI_x86_Http = 16,
    UEFI_x64_Http = 17,
    UEFI_Arm32_Http = 18,
    UEFI_Arm64_Http = 19,
    UEFI_Riscv32 = 20,
    UEFI_Riscv64 = 21,
    UEFI_Riscv128 = 22,
    S390Basic = 23,
    S390Extended = 24,
    Mips32Uefi = 25,
    Mips64Uefi = 26,
    SunwayUefi = 27,
    LoongArch32Uefi = 28,
    LoongArch64Uefi = 29
}
