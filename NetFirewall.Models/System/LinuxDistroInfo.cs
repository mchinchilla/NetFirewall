namespace NetFirewall.Models.System;

public class LinuxDistroInfo
{
    public string Id { get; set; } = string.Empty;          // debian, ubuntu
    public string Name { get; set; } = string.Empty;        // Debian GNU/Linux, Ubuntu
    public string Version { get; set; } = string.Empty;     // 12, 24.04
    public string VersionCodename { get; set; } = string.Empty; // bookworm, noble
    public DistroFamily Family { get; set; } = DistroFamily.Unknown;
    public NetworkConfigMethod ConfigMethod { get; set; } = NetworkConfigMethod.Unknown;
}

public enum DistroFamily
{
    Unknown,
    Debian,
    RedHat,
    Arch,
    Alpine
}

public enum NetworkConfigMethod
{
    Unknown,
    Netplan,        // Ubuntu 18.04+ uses netplan with YAML files
    Interfaces      // Debian uses /etc/network/interfaces
}
