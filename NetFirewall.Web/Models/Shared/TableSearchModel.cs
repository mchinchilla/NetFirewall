namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// Drives <c>_TableSearch.cshtml</c> — a reusable free-text filter input for
/// HTMX-backed list tables. The input binds to an Alpine variable in the
/// surrounding <c>x-data</c> scope and, on (debounced) input, fires a
/// <c>manual-refresh</c> event on the target table container so the server
/// re-renders the filtered partial. The filter value travels with the table's
/// <c>:hx-vals</c>, so it survives auto-refresh polling.
/// </summary>
public sealed class TableSearchModel
{
    /// <summary>The <c>id</c> of the HTMX table container to refresh on input.</summary>
    public required string TableId { get; init; }

    /// <summary>Placeholder text shown in the empty input.</summary>
    public string Placeholder { get; init; } = "Filter…";

    /// <summary>
    /// Name of the Alpine <c>x-data</c> variable this input is bound to. Must
    /// match the variable referenced in the table's <c>:hx-vals</c>. Defaults
    /// to <c>q</c>.
    /// </summary>
    public string Var { get; init; } = "q";

    /// <summary>Client-side max length guard (also enforced server-side).</summary>
    public int MaxLength { get; init; } = 64;

    /// <summary>
    /// When true, filtering happens entirely in the browser via
    /// <c>window.NetFw.filterTable</c> — hides non-matching <c>&lt;tbody&gt;</c>
    /// rows of the target table, no server round-trip. Use for list pages that
    /// render all rows and don't poll. When false (default), the input triggers
    /// a <c>manual-refresh</c> on the table container so the server re-renders a
    /// filtered partial (use for polling tables whose filter must ride on
    /// <c>:hx-vals</c>, e.g. DHCP leases).
    /// </summary>
    public bool ClientSide { get; init; }
}
