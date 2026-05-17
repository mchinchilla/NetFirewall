namespace NetFirewall.Models.System;

/// <summary>
/// Outcome of a network-interface redetect run. The daemon walks /sys/class/net,
/// reconciles each NIC against <c>fw_interfaces</c>, and reports counts so the
/// UI can show a meaningful toast instead of "Done.".
/// </summary>
public sealed class RedetectResult
{
    /// <summary>NICs new to fw_interfaces — inserted with detected values + suggested type/role.</summary>
    public int Added { get; set; }

    /// <summary>NICs already in fw_interfaces — IP/mask/gateway/MAC/MTU refreshed from OS,
    /// but role/type/description/addressing_mode are preserved (operator-edited).</summary>
    public int Updated { get; set; }

    /// <summary>fw_interfaces rows for NICs no longer present on the host (flagged, not deleted).</summary>
    public int Missing { get; set; }

    /// <summary>Names of NICs whose IP or gateway actually changed from what was in the DB.</summary>
    public List<string> Changed { get; set; } = new();
}
