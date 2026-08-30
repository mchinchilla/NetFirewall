namespace NetFirewall.Web.Models.Firewall;

/// <summary>
/// The nft line a rule form currently produces, rendered by the real generator
/// so it cannot drift from what an apply would write.
/// </summary>
public sealed class RulePreviewViewModel
{
    /// <summary>The rendered nft statement, already trimmed.</summary>
    public required string Line { get; init; }

    /// <summary>
    /// Why this rule would defeat the chain's default-deny policy, when it
    /// would. Same text the save path refuses with.
    /// </summary>
    public string? Bypass { get; init; }

    /// <summary>Set when the form is too incomplete to render anything useful.</summary>
    public string? Problem { get; init; }
}

/// <summary>
/// Model for the connection-state picker. The posted value stays a
/// comma-separated string so the server contract is unchanged — only the way
/// the operator produces it becomes a set of toggles instead of typed prose.
/// </summary>
public sealed class ConnStatePickerViewModel
{
    /// <summary>Form field name, e.g. <c>ConnectionStates</c>.</summary>
    public required string Name { get; init; }

    public string Label { get; init; } = "Connection states";

    /// <summary>Current value as stored: <c>"established, related"</c>.</summary>
    public string? Value { get; init; }
}
