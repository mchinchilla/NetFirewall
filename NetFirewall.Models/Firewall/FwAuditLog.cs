using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwAuditLog
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("table_name")]
    public string TableName { get; set; } = string.Empty;

    [Map("record_id")]
    public Guid RecordId { get; set; }

    [Map("action")]
    public string Action { get; set; } = string.Empty; // INSERT, UPDATE, DELETE

    [Map("old_values")]
    public string? OldValues { get; set; } // JSON

    [Map("new_values")]
    public string? NewValues { get; set; } // JSON

    [Map("user_id")]
    public string? UserId { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }
}
