using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Web;

/// <summary>
/// Guards the "unchecked checkbox never posts" trap across every Razor view.
///
/// Browsers (and HTMX's FormData) omit an unchecked checkbox from the request
/// entirely. MVC then leaves the bound property at the view model's default —
/// and every <c>Enabled</c> flag in this app defaults to <c>true</c> — so a
/// user unticking "Enabled" silently saved <c>true</c> (mangle rules, filter
/// rules, NAT, port forwards, DHCP pools, WireGuard peers, ...).
///
/// The contract, mirroring <c>Html.CheckBoxFor</c>: every <b>named</b>
/// boolean checkbox (<c>value="true"</c>) must be followed by a hidden input
/// with the same name and <c>value="false"</c>. MVC binds the first value, so
/// checked posts "true,false" → true and unchecked posts "false" → false.
///
/// Multi-value list checkboxes (day-of-week pickers, member ids, source lists)
/// carry a non-"true" value and are intentionally out of scope.
/// </summary>
public class CheckboxPostContractTests
{
    private static readonly Regex CheckboxTag = new(
        @"<input\b(?=[^>]*\btype=""checkbox"")(?=[^>]*\bvalue=""true"")[^>]*\bname=""(?<name>[^""]+)""[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

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
    public void SharedFormField_Checkbox_EmitsHiddenFalseFallback()
    {
        var src = File.ReadAllText(Path.Combine(ViewsRoot(), "Shared", "_FormField.cshtml"));

        var checkbox = src.IndexOf("type=\"checkbox\"", StringComparison.Ordinal);
        var hidden = src.IndexOf("<input type=\"hidden\" name=\"@Model.Name\" value=\"false\" />", StringComparison.Ordinal);

        Assert.True(checkbox >= 0, "_FormField no longer renders a checkbox branch?");
        Assert.True(hidden > checkbox,
            "_FormField's checkbox must be followed by <input type=\"hidden\" name=\"@Model.Name\" value=\"false\" /> " +
            "so an unchecked box still posts and the model binder does not keep the `= true` default.");
    }

    [Fact]
    public void EveryNamedBooleanCheckbox_HasHiddenFalseTwin()
    {
        var root = ViewsRoot();
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(root, "*.cshtml", SearchOption.AllDirectories))
        {
            if (file.EndsWith("_FormField.cshtml", StringComparison.Ordinal)) continue; // covered above
            var src = File.ReadAllText(file);

            foreach (Match m in CheckboxTag.Matches(src))
            {
                var name = m.Groups["name"].Value;
                var twin = new Regex(
                    @"<input\b(?=[^>]*\btype=""hidden"")(?=[^>]*\bname=""" + Regex.Escape(name) + @""")(?=[^>]*\bvalue=""false"")[^>]*>",
                    RegexOptions.IgnoreCase);
                if (!twin.IsMatch(src))
                    offenders.Add($"{Path.GetRelativePath(root, file)} → name=\"{name}\"");
            }
        }

        Assert.True(offenders.Count == 0,
            "Boolean checkboxes without a hidden value=\"false\" twin (unchecked state will never reach the server):\n  " +
            string.Join("\n  ", offenders));
    }
}
