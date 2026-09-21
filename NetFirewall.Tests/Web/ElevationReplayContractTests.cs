using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Web;

/// <summary>
/// The TOTP step-up answers a privileged request with 401 and replays it once the
/// code is verified. The 401 can only carry a URL and a verb, so replaying from
/// those alone posts an EMPTY BODY: the first "Start capture" after a step-up came
/// back "the Interface field is required", and clicking again worked because the
/// session was elevated by then.
///
/// The replay therefore has to go through the element that made the original
/// request, so htmx re-reads that form and honours its hx-target. There is no JS
/// test runner here (no npm, by project rule), so this pins the contract in source.
/// </summary>
public class ElevationReplayContractTests
{
    private static string WebRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "NetFirewall.Web");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate NetFirewall.Web from " + AppContext.BaseDirectory);
    }

    private static string SiteJs() => File.ReadAllText(Path.Combine(WebRoot(), "wwwroot", "js", "site.js"));

    [Fact]
    public void TheModalIsHandedTheElementThatMadeTheRequest()
    {
        var js = SiteJs();
        var listener = Regex.Match(js, @"showElevationModal""\s*,\s*\(event\)\s*=>\s*\{(?<body>.*?)\n\}\);", RegexOptions.Singleline);
        Assert.True(listener.Success, "The showElevationModal listener moved — update this lint with it.");

        Assert.Matches(@"elev\.request\([^)]*,[^)]*\)", listener.Groups["body"].Value);
    }

    [Fact]
    public void AGuardedLinkCanAskForElevationBeforeItNavigates()
    {
        var js = SiteJs();
        // A link leaves the page, so it cannot replay anything: it has to check first
        // and then navigate once the code is accepted.
        Assert.Matches(@"async navigate\(url\)", js);
        Assert.Matches(@"retry\?\.navigate", js);
    }

    [Fact]
    public void NoPlainLinkPointsAtAnActionThatNeedsElevation()
    {
        // Following such an href renders the step-up 401's JSON body in the tab. The
        // anchor must hand the click to the elevation store instead.
        var web = WebRoot();
        var routes = ElevatedGetRoutes(web);
        Assert.NotEmpty(routes);   // if this empties out, the lint has stopped looking

        var offenders = new List<string>();
        foreach (var view in Directory.EnumerateFiles(Path.Combine(web, "Views"), "*.cshtml", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(view);
            foreach (Match anchor in Regex.Matches(text, @"<a\b[^>]*>", RegexOptions.Singleline))
            {
                var href = Regex.Match(anchor.Value, @"href=""(?<h>[^""]+)""");
                if (!href.Success) continue;
                if (!routes.Any(r => r.IsMatch(href.Groups["h"].Value))) continue;
                if (anchor.Value.Contains("$store.elevation.navigate", StringComparison.Ordinal)) continue;

                offenders.Add($"{Path.GetRelativePath(web, view)} → {href.Groups["h"].Value}");
            }
        }

        Assert.True(offenders.Count == 0,
            "These links navigate straight into an action that requires a TOTP step-up; add "
            + "@click.prevent=\"$store.elevation.navigate($el.href)\":\n  " + string.Join("\n  ", offenders));
    }

    /// <summary>Route templates of every [HttpGet] action that also requires elevation.</summary>
    private static List<Regex> ElevatedGetRoutes(string web)
    {
        var routes = new List<Regex>();

        foreach (var file in Directory.EnumerateFiles(Path.Combine(web, "Controllers"), "*Controller.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            var prefix = Regex.Match(text, @"\[Route\(""(?<p>[^""]+)""\)\]").Groups["p"].Value.TrimEnd('/');

            // An action's attributes sit in one unbroken block above its signature.
            foreach (Match block in Regex.Matches(text, @"(?<attrs>(?:\s*\[[^\]]*\]\s*)+)public\s", RegexOptions.Singleline))
            {
                var attrs = block.Groups["attrs"].Value;
                if (!attrs.Contains("RequireElevated", StringComparison.Ordinal)) continue;

                var get = Regex.Match(attrs, @"\[HttpGet\(""(?<t>[^""]*)""\)\]");
                if (!get.Success) continue;

                var template = get.Groups["t"].Value;
                var path = template.StartsWith('~')
                    ? template.TrimStart('~')
                    : prefix + "/" + template.TrimStart('/');

                // {id:guid} and friends stand in for one path segment.
                var pattern = "^" + Regex.Escape(path).Replace(@"\{", "{").Replace(@"\}", "}");
                pattern = Regex.Replace(pattern, @"\{[^}]*\}", @"[^""/]+") + "$";
                routes.Add(new Regex(pattern, RegexOptions.IgnoreCase));
            }
        }

        return routes;
    }

    [Fact]
    public void TheReplayGoesThroughThatElement()
    {
        var js = SiteJs();
        var call = Regex.Match(js, @"htmx\.ajax\(verb,\s*retry\.url,(?<args>[^;]*)\);");
        Assert.True(call.Success, "The elevation replay moved — update this lint with it.");

        var args = call.Groups["args"].Value;
        Assert.Contains("source", args, StringComparison.Ordinal);
        // The old unconditional form is the bug: it sends no values and throws the
        // response away, so the panel never appears either.
        Assert.DoesNotMatch(@"^\s*\{\s*target:\s*""body""", args);
    }
}
