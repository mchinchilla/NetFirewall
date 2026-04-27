using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Network;

namespace NetFirewall.Web.Models.Network;

public sealed class NetworkObjectFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, StringLength(80, MinimumLength = 2)]
    [RegularExpression(@"^[A-Za-z][A-Za-z0-9_\-]*$",
        ErrorMessage = "Name must start with a letter and contain only letters, digits, underscore, dash.")]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Type { get; set; } = NetworkObjectTypes.Host;

    /// <summary>Empty for groups; required otherwise.</summary>
    public string? Value { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    /// <summary>Group members — only meaningful when Type == "group".</summary>
    public List<Guid> MemberIds { get; set; } = new();

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!NetworkObjectTypes.IsValid(Type))
        {
            yield return new ValidationResult($"Invalid type. Must be one of: {string.Join(", ", NetworkObjectTypes.All)}.",
                new[] { nameof(Type) });
            yield break;
        }

        if (Type == NetworkObjectTypes.Group)
        {
            if (MemberIds.Count == 0)
                yield return new ValidationResult("A group needs at least one member.", new[] { nameof(MemberIds) });
        }
        else
        {
            if (string.IsNullOrWhiteSpace(Value))
            {
                yield return new ValidationResult($"Value is required for {Type} objects.", new[] { nameof(Value) });
                yield break;
            }

            var v = Value.Trim();
            switch (Type)
            {
                case NetworkObjectTypes.Host:
                    if (!System.Net.IPAddress.TryParse(v.Replace("/32", ""), out _))
                        yield return new ValidationResult("Host must be a valid IPv4 address.", new[] { nameof(Value) });
                    break;
                case NetworkObjectTypes.Network:
                    if (!v.Contains('/'))
                        yield return new ValidationResult("Network must be a CIDR (e.g. 10.0.0.0/24).", new[] { nameof(Value) });
                    break;
                case NetworkObjectTypes.Range:
                    var parts = v.Split('-', 2);
                    if (parts.Length != 2 ||
                        !System.Net.IPAddress.TryParse(parts[0].Trim(), out _) ||
                        !System.Net.IPAddress.TryParse(parts[1].Trim(), out _))
                        yield return new ValidationResult("Range must be 'start-end' IPs (e.g. 10.0.0.10-10.0.0.50).", new[] { nameof(Value) });
                    break;
            }
        }
    }
}
