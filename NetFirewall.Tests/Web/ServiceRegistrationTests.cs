using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;

namespace NetFirewall.Tests.Web;

/// <summary>
/// A service the container cannot construct is invisible until an endpoint asks
/// for it. The daemon shipped <c>IVpnDoctorContextFactory</c> without
/// <c>IVpnRoutingService</c> (every VPN doctor run answered 500) and
/// <c>IRecoveryCodeService</c> without <c>IRecoveryCodeGenerator</c> (every TUI
/// login answered 500) — both compiled, both passed every test.
///
/// Both hosts now validate their container at startup, which catches this on the
/// appliance. This catches it at <c>dotnet test</c>, on a machine where nobody
/// runs the daemon: it reads the registration source, resolves each registered
/// implementation by reflection, and checks that every NetFirewall interface its
/// constructor asks for is registered in that same host.
/// </summary>
public class ServiceRegistrationTests
{
    private static readonly Assembly[] Assemblies =
    [
        typeof(NetFirewall.Services.Firewall.IFirewallService).Assembly,
        typeof(NetFirewall.Models.ServiceResponse<object>).Assembly,
    ];

    // AddScoped<IFoo, Foo>() / AddSingleton<Foo>() / AddHostedService<Worker>()
    private static readonly Regex Generic = new(
        @"\.Add(?:Singleton|Scoped|Transient|HostedService)<\s*(?<a>[A-Za-z0-9_.]+)\s*(?:,\s*(?<b>[A-Za-z0-9_.]+)\s*)?>",
        RegexOptions.Compiled);

    // AddScoped(typeof(IVpnDoctorCheck), checkType) and the `new[] { typeof(...) }` lists it loops over.
    private static readonly Regex TypeOf = new(@"\btypeof\(\s*(?<n>[A-Za-z0-9_.]+)\s*\)", RegexOptions.Compiled);

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "NetFirewall.Web"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate the repo root from " + AppContext.BaseDirectory);
    }

    /// <summary>A name written in Program.cs is either fully qualified or shortened by a using.</summary>
    private static Type? Resolve(string name)
    {
        var matches = Assemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => t.FullName == name || t.Name == name || (t.FullName?.EndsWith("." + name, StringComparison.Ordinal) ?? false))
            .Distinct()
            .ToList();
        return matches.Count == 1 ? matches[0] : null;   // ambiguous or unknown: not ours to judge
    }

    private static (HashSet<Type> Registered, List<Type> Implementations) Parse(params string[] files)
    {
        var registered = new HashSet<Type>();
        var impls = new List<Type>();

        foreach (var text in files.Select(File.ReadAllText))
        {
            foreach (Match m in Generic.Matches(text))
            {
                var a = Resolve(m.Groups["a"].Value);
                var b = m.Groups["b"].Success ? Resolve(m.Groups["b"].Value) : null;
                if (a is not null) registered.Add(a);
                var impl = b ?? a;
                if (impl is { IsClass: true, IsAbstract: false }) impls.Add(impl);
            }

            // typeof(IFoo) registers a service; typeof(FooCheck) is an implementation of one.
            foreach (Match m in TypeOf.Matches(text))
            {
                var t = Resolve(m.Groups["n"].Value);
                if (t is null) continue;
                if (t.IsInterface) registered.Add(t);
                else if (t is { IsClass: true, IsAbstract: false }) impls.Add(t);
            }
        }

        return (registered, impls.Distinct().ToList());
    }

    /// <summary>The constructor MS.DI would pick: the greediest public one.</summary>
    private static ConstructorInfo? Greediest(Type t) =>
        t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)
         .OrderByDescending(c => c.GetParameters().Length)
         .FirstOrDefault();

    private static bool IsOurs(Type t) =>
        t.Assembly == Assemblies[0] || t.Assembly == Assemblies[1];

    private static List<string> MissingDependencies(string host, params string[] files)
    {
        var (registered, impls) = Parse(files);
        var missing = new List<string>();

        foreach (var impl in impls)
        {
            var ctor = Greediest(impl);
            if (ctor is null) continue;

            foreach (var p in ctor.GetParameters())
            {
                var t = p.ParameterType;
                // IEnumerable<IFoo> is satisfied by zero registrations, but a doctor with
                // no checks is a bug too — so unwrap and demand at least one.
                if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IEnumerable<>))
                    t = t.GetGenericArguments()[0];

                if (!t.IsInterface || !IsOurs(t)) continue;      // framework, options, loggers, POCOs
                if (registered.Contains(t)) continue;

                missing.Add($"{host}: {impl.Name} needs {t.Name}, which {host} never registers");
            }
        }

        return missing;
    }

    [Fact]
    public void DaemonRegistersEveryDependencyItsOwnServicesAskFor()
    {
        var root = RepoRoot();
        var missing = MissingDependencies("the daemon", Path.Combine(root, "NetFirewall.Daemon", "Program.cs"));

        Assert.True(missing.Count == 0,
            "Unbuildable services — the host starts, then answers 500 on the first request that needs one:\n  "
            + string.Join("\n  ", missing));
    }

    [Fact]
    public void WebRegistersEveryDependencyItsOwnServicesAskFor()
    {
        var root = RepoRoot();
        var missing = MissingDependencies("the Web",
            Path.Combine(root, "NetFirewall.Web", "Program.cs"),
            Path.Combine(root, "NetFirewall.Web", "Daemon", "DaemonServiceCollectionExtensions.cs"));

        Assert.True(missing.Count == 0,
            "Unbuildable services — the host starts, then answers 500 on the first request that needs one:\n  "
            + string.Join("\n  ", missing));
    }

    [Fact]
    public void BothHostsValidateTheirContainerAtStartup()
    {
        // The belt to this test's braces: a registration added through an extension
        // method this test cannot read still fails loudly on the appliance.
        var root = RepoRoot();
        foreach (var program in new[] { "NetFirewall.Daemon", "NetFirewall.Web" }
                     .Select(p => Path.Combine(root, p, "Program.cs")))
        {
            var text = File.ReadAllText(program);
            Assert.True(text.Contains("ValidateOnBuild = true", StringComparison.Ordinal),
                $"{Path.GetRelativePath(root, program)} must keep ValidateOnBuild on so a broken container "
                + "fails at startup instead of on the first request.");
        }
    }
}
