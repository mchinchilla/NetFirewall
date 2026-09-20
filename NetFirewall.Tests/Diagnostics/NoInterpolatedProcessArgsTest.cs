using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// Shell-safety guard for the Diagnostics services: every process spawn must use
/// the argument-vector overload of <c>IProcessRunner.RunAsync</c>. A request
/// value interpolated into the string overload (<c>RunAsync("ping", $"…{target}")</c>)
/// would let a crafted target become extra arguments. Same source-lint style as
/// <c>CheckboxPostContractTests</c>.
/// </summary>
public class NoInterpolatedProcessArgsTest
{
    private static readonly Regex StringOverloadWithInterpolation =
        new(@"RunAsync\(\s*[^,\n]+,\s*\$""", RegexOptions.Compiled);

    private static readonly Regex StringOverloadWithConcat =
        new(@"RunAsync\(\s*[^,\n]+,\s*""[^""\n]*""\s*\+", RegexOptions.Compiled);

    private static string DiagnosticsRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "NetFirewall.Services", "Diagnostics");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate NetFirewall.Services/Diagnostics from " + AppContext.BaseDirectory);
    }

    [Fact]
    public void DiagnosticsServices_NeverInterpolateIntoTheStringOverload()
    {
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(DiagnosticsRoot(), "*.cs", SearchOption.AllDirectories))
        {
            var src = File.ReadAllText(file);
            if (StringOverloadWithInterpolation.IsMatch(src) || StringOverloadWithConcat.IsMatch(src))
                offenders.Add(Path.GetFileName(file));
        }

        Assert.True(offenders.Count == 0,
            "Process arguments built by string interpolation/concatenation in Services/Diagnostics — use the IReadOnlyList<string> overload:\n  "
            + string.Join("\n  ", offenders));
    }
}
