using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.RegularExpressions;

namespace NetFirewall.Web.Models.Network;

/// <summary>
/// Form input for creating / editing a static route. Validates CIDR notation
/// for the destination and IPv4 for the optional gateway. Cross-cutting
/// rules (must reference an existing iface) live in IValidatableObject.
/// </summary>
public sealed class StaticRouteFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required(ErrorMessage = "Pick the interface this route belongs to.")]
    public Guid InterfaceId { get; set; }

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
        ErrorMessage = "Destination must be IPv4 CIDR (e.g. 10.0.0.0/8 or 192.168.5.0/24).")]
    public string Destination { get; set; } = string.Empty;

    [IPv4(AllowEmpty = true)] public string? Gateway { get; set; }

    [Range(0, 1024, ErrorMessage = "Metric must be 0-1024.")]
    public int Metric { get; set; } = 100;

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        // CIDR sanity: parse network + prefix length manually.
        if (!string.IsNullOrEmpty(Destination))
        {
            var parts = Destination.Split('/');
            if (parts.Length == 2
                && IPAddress.TryParse(parts[0], out var ip)
                && int.TryParse(parts[1], out var prefix))
            {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    yield return new ValidationResult("Only IPv4 destinations are supported.", new[] { nameof(Destination) });
                else if (prefix is < 0 or > 32)
                    yield return new ValidationResult("CIDR prefix must be 0-32.", new[] { nameof(Destination) });
            }
            else
            {
                yield return new ValidationResult("Could not parse the destination CIDR.", new[] { nameof(Destination) });
            }
        }
    }
}
