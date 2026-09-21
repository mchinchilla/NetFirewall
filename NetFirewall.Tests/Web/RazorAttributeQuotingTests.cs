using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Web;

/// <summary>
/// Razor writes an expression's value into the tag verbatim, so building an
/// attribute as a string has to include the quotes. <c>_JobPanel</c> emitted
/// <c>hx-trigger=every 2s</c>, which the HTML parser read as
/// <c>hx-trigger="every"</c> plus a boolean attribute named <c>2s</c>: htmx saw an
/// invalid trigger, never polled, and the job panel sat at "0 packets · 0s" until
/// the page was reloaded by hand.
///
/// It renders, it validates, and no test that checks behaviour can see it — only
/// reading the produced markup character by character shows the bug.
/// </summary>
public class RazorAttributeQuotingTests
{
    // A string literal that opens an htmx/Alpine/data attribute whose value is not
    // quoted. The negative lookahead spares the correct form, where the C# literal
    // continues with an escaped quote: "x-show=\"...\"".
    private static readonly Regex UnquotedAttribute = new(
        @"""(?<lit>(?:hx|x|data|aria)-[A-Za-z.-]+=(?![""'\\])[^""]*)""",
        RegexOptions.Compiled);

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

    [Fact]
    public void NoViewBuildsAnAttributeWithoutItsQuotes()
    {
        var web = WebRoot();
        var offenders = new List<string>();

        foreach (var view in Directory.EnumerateFiles(Path.Combine(web, "Views"), "*.cshtml", SearchOption.AllDirectories))
        {
            var lines = File.ReadAllLines(view);
            for (var i = 0; i < lines.Length; i++)
            {
                foreach (Match m in UnquotedAttribute.Matches(lines[i]))
                    offenders.Add($"{Path.GetRelativePath(web, view)}:{i + 1} → \"{m.Groups["lit"].Value}\"");
            }
        }

        Assert.True(offenders.Count == 0,
            "Attributes built in Razor code must carry their own quotes — the parser splits the value at "
            + "the first space otherwise:\n  " + string.Join("\n  ", offenders));
    }

    [Theory]
    [InlineData(@"@(poll ? ""hx-trigger=every 2s"" : """")", true)]
    [InlineData(@"@(poll ? ""hx-get=/Diagnostics/Jobs/"" + job.Id : """")", true)]
    [InlineData(@"$""hx-trigger=\""every 2s\""""", false)]
    [InlineData(@"""x-show=\""!$store.ui.sidebarCollapsed\"" x-transition.opacity""", false)]
    [InlineData(@"<div hx-trigger=""every 2s"">", false)]
    public void TheLintSeesTheBrokenFormAndNotTheGoodOne(string line, bool shouldFlag) =>
        Assert.Equal(shouldFlag, UnquotedAttribute.IsMatch(line));
}
