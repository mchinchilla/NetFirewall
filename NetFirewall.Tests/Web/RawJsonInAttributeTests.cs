using System.Text.RegularExpressions;
using Xunit;

namespace NetFirewall.Tests.Web;

/// <summary>
/// Lint over every view: no <c>@Html.Raw(...)</c> inside a DOUBLE-quoted Alpine/HTML attribute.
/// Raw JSON carries <c>"</c>, which ends the attribute mid-expression — the egress picker
/// rendered <c>x-data="wgEgressPicker(["</c> and died once one extra source existed. Let Razor
/// encode it (<c>&amp;quot;</c> decodes back inside the attribute).
/// </summary>
public sealed class RawJsonInAttributeTests
{
    private static readonly Regex RawInDoubleQuotedAttr =
        new(@"\s[:@\w.-]+=""[^""]*@Html\.Raw\(", RegexOptions.Compiled);

    private static string ViewsRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "NetFirewall.Web", "Views");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate NetFirewall.Web/Views from " + AppContext.BaseDirectory);
    }

    [Fact]
    public void NoView_PutsRawHtmlInsideADoubleQuotedAttribute()
    {
        var root = ViewsRoot();
        var offenders = Directory.EnumerateFiles(root, "*.cshtml", SearchOption.AllDirectories)
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, line, i)))
            .Where(x => RawInDoubleQuotedAttr.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(root, x.f)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();
        Assert.True(offenders.Count == 0, "Raw HTML inside a double-quoted attribute:\n" + string.Join('\n', offenders));
    }
}
