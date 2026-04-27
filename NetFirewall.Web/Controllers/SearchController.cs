using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Services.Search;

namespace NetFirewall.Web.Controllers;

[Authorize]
[Route("/Search")]
public sealed class SearchController : Controller
{
    private readonly ISearchService _search;

    public SearchController(ISearchService search) => _search = search;

    /// <summary>
    /// Dropdown results for the top-bar autocomplete. Returns a small
    /// rendered partial (HTMX swaps it into the dropdown container).
    /// </summary>
    [HttpGet("dropdown")]
    public async Task<IActionResult> Dropdown(string? q, CancellationToken ct)
    {
        var hits = await _search.SearchAsync(q, limit: 12, ct);
        ViewBag.Query = q;
        return PartialView("_SearchDropdown", hits);
    }
}
