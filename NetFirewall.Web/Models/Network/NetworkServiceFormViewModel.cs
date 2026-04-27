using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Network;

namespace NetFirewall.Web.Models.Network;

public sealed class NetworkServiceFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }
    public bool IsBuiltin { get; set; }      // read-only flag carried through

    [Required, StringLength(80, MinimumLength = 2)]
    [RegularExpression(@"^[A-Za-z][A-Za-z0-9_\-]*$",
        ErrorMessage = "Name must start with a letter and contain only letters, digits, underscore, dash.")]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Protocol { get; set; } = NetworkServiceProtocols.Tcp;

    [Range(0, 65535)]
    public int PortStart { get; set; }

    [Range(0, 65535)]
    public int? PortEnd { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(40)]
    public string? Category { get; set; }

    /// <summary>If non-empty this is a group; PortStart/End are ignored.</summary>
    public List<Guid> MemberIds { get; set; } = new();

    public bool IsGroup => MemberIds.Count > 0;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!NetworkServiceProtocols.IsValid(Protocol))
            yield return new ValidationResult($"Invalid protocol. Must be one of: {string.Join(", ", NetworkServiceProtocols.All)}.",
                new[] { nameof(Protocol) });

        if (!IsGroup)
        {
            if (PortEnd.HasValue && PortEnd.Value < PortStart)
                yield return new ValidationResult("port_end must be greater than or equal to port_start.",
                    new[] { nameof(PortEnd) });
        }
    }
}
