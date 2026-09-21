using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Web;

/// <summary>
/// Razor resolves a partial referenced BY NAME by looking in the current
/// controller's view folder and then in Views/Shared — and nowhere else. A
/// partial that lives in another controller's folder therefore compiles fine,
/// passes every unit test, and throws InvalidOperationException the first time
/// a page in a different folder renders it.
///
/// That is how <c>_ToolPageHeader</c> shipped in Views/Diagnostics and 500'd on
/// every Diagnostics page served by a different controller. This walks the
/// views and controllers and resolves each literal partial reference the way
/// Razor will at runtime.
/// </summary>
public class PartialViewResolutionTests
{
    // Html.Partial("x") / Html.PartialAsync("x") / await Html.PartialAsync("x", model)
    private static readonly Regex ViewReference =
        new(@"\bPartial(?:Async)?\(\s*""(?<name>[^""]+)""", RegexOptions.Compiled);

    // PartialView("x") / PartialView("x", model) from a controller
    private static readonly Regex ControllerReference =
        new(@"\bPartialView\(\s*""(?<name>[^""]+)""", RegexOptions.Compiled);

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

    /// <summary>Mirrors Razor's lookup: the owning folder, then Views/Shared. Absolute paths are taken literally.</summary>
    private static bool Resolves(string web, string name, string ownerFolder)
    {
        if (name.StartsWith('~') || name.StartsWith('/'))
        {
            var rooted = Path.Combine(web, name.TrimStart('~').TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
            return File.Exists(rooted);
        }

        var file = name.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase) ? name : name + ".cshtml";
        return File.Exists(Path.Combine(ownerFolder, file))
            || File.Exists(Path.Combine(web, "Views", "Shared", file));
    }

    [Fact]
    public void EveryPartialReferencedFromAViewResolves()
    {
        var web = WebRoot();
        var offenders = new List<string>();

        foreach (var view in Directory.EnumerateFiles(Path.Combine(web, "Views"), "*.cshtml", SearchOption.AllDirectories))
        {
            var owner = Path.GetDirectoryName(view)!;
            foreach (Match m in ViewReference.Matches(File.ReadAllText(view)))
            {
                var name = m.Groups["name"].Value;
                if (!Resolves(web, name, owner))
                    offenders.Add($"{Path.GetRelativePath(web, view)} → \"{name}\"");
            }
        }

        Assert.True(offenders.Count == 0,
            "Partials that Razor cannot resolve at runtime (move them to Views/Shared, or use a ~/Views/... path):\n  "
            + string.Join("\n  ", offenders));
    }

    [Fact]
    public void EveryPartialReturnedFromAControllerResolves()
    {
        var web = WebRoot();
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(Path.Combine(web, "Controllers"), "*Controller.cs", SearchOption.AllDirectories))
        {
            var controller = Path.GetFileNameWithoutExtension(file);
            var owner = Path.Combine(web, "Views", controller[..^"Controller".Length]);

            foreach (Match m in ControllerReference.Matches(File.ReadAllText(file)))
            {
                var name = m.Groups["name"].Value;
                if (!Resolves(web, name, owner))
                    offenders.Add($"{Path.GetRelativePath(web, file)} → \"{name}\" (looked in {Path.GetRelativePath(web, owner)} and Views/Shared)");
            }
        }

        Assert.True(offenders.Count == 0,
            "PartialView(...) names a partial Razor cannot resolve:\n  " + string.Join("\n  ", offenders));
    }
}
