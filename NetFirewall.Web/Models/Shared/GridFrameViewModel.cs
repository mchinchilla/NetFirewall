namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// Model of the <c>_Grid</c> partial: a NetOpenGrid document embedded in a same-origin
/// iframe (<c>/netgrid/{GridId}?embed=1</c>). The frame isolates the grid's own htmx 4 /
/// Alpine runtime from the host's; site.js (<c>NetFw.grids</c>) sizes it to its content,
/// syncs theme + mode into it, replays its row actions in the host and refreshes it when
/// one of <see cref="RefreshOn"/> fires on <c>body</c>.
/// </summary>
public sealed class GridFrameViewModel
{
    public required string GridId { get; init; }

    /// <summary>Accessible name of the frame.</summary>
    public required string Title { get; init; }

    /// <summary>Grid state used when the page URL carries none (filters, sort, group).</summary>
    public string? DefaultQuery { get; init; }

    /// <summary>HX-Trigger events (e.g. <c>refreshLeases</c>) after which the grid re-reads its rows.</summary>
    public IReadOnlyList<string> RefreshOn { get; init; } = [];

    /// <summary>Poll interval for live data (leases); 0 = only on <see cref="RefreshOn"/>.</summary>
    public int RefreshEverySeconds { get; init; }

    /// <summary>
    /// Forward the host page's query string to the grid (deep links like
    /// <c>/Dhcp/Leases?sort=expires:asc</c>). Off for pages whose own query means something else.
    /// </summary>
    public bool ForwardQuery { get; init; } = true;

    /// <summary>
    /// What the host does for each <c>AddBulkAction(name)</c> of the grid: the grid only
    /// raises <c>netgrid:bulk-action</c> with the selected keys; site.js confirms, POSTs and
    /// refreshes. Keyed by the bulk action name.
    /// </summary>
    public IReadOnlyDictionary<string, GridBulkActionHost> BulkActions { get; init; } =
        new Dictionary<string, GridBulkActionHost>();
}

/// <summary>
/// Host side of a grid bulk action. The selected row keys are posted form-encoded as
/// repeated <see cref="KeysField"/> values plus <see cref="Values"/>, through htmx (antiforgery,
/// elevation replay, HX-Trigger toast/refresh). <c>{count}</c> and <c>{s}</c> (plural) in the
/// confirm texts are filled in by the host.
/// </summary>
public sealed record GridBulkActionHost(string Url)
{
    public string KeysField { get; init; } = "ids";
    public IReadOnlyDictionary<string, string> Values { get; init; } = new Dictionary<string, string>();
    public string? ConfirmTitle { get; init; }
    public string? ConfirmMessage { get; init; }
    public string ConfirmLabel { get; init; } = "Confirm";
    public string ConfirmLevel { get; init; } = "default";
}

/// <summary>camelCase JSON for the data-* attributes site.js reads.</summary>
public static class GridFrameJson
{
    public static readonly System.Text.Json.JsonSerializerOptions Options = new(System.Text.Json.JsonSerializerDefaults.Web);
}
