using System.Text.RegularExpressions;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The Web's data grids (NetOpenGrid, <c>/netgrid/*</c>) are embedded in SAME-ORIGIN iframes.
/// An nginx site still sending <c>X-Frame-Options: DENY</c> (the pre-grid template) makes every
/// grid render as a blank frame. setup.sh only rewrites nginx on a fresh install or with
/// <c>--configure-nginx</c>, so an upgraded appliance keeps the old header until someone looks.
/// Pure file read of the NetFirewall nginx site(s); Skip when there is none.
/// </summary>
public sealed partial class NginxFramingCheck(params string[] directories) : ICheck
{
    private readonly string[] _directories = directories.Length > 0
        ? directories
        : ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"];

    public string Category => "Web";
    public string Name => "nginx allows same-origin grid frames";
    public IReadOnlyList<string> Services => ["web"];

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var sites = new List<string>();
        foreach (var dir in _directories)
        {
            if (!Directory.Exists(dir)) continue;
            sites.AddRange(Directory.EnumerateFiles(dir).Where(f => Path.GetFileName(f).Contains("netfirewall", StringComparison.OrdinalIgnoreCase)));
        }
        if (sites.Count == 0) return CheckResult.Skip("no NetFirewall nginx site found");

        foreach (var site in sites)
        {
            string text;
            try { text = await File.ReadAllTextAsync(site, ct); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }

            if (DenyHeader().IsMatch(text))
            {
                return CheckResult.Warn(
                    $"{site} sends X-Frame-Options DENY — the data grids will render blank",
                    remedy: "Re-render the site with ./setup.sh --configure-nginx, or change the header to "
                          + "add_header X-Frame-Options \"SAMEORIGIN\" always; (plus Content-Security-Policy \"frame-ancestors 'self'\") and run nginx -t && systemctl reload nginx.");
            }
        }
        return CheckResult.Pass($"no DENY frame policy in {sites.Count} site file(s)");
    }

    [GeneratedRegex(@"^\s*add_header\s+X-Frame-Options\s+""?DENY""?", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex DenyHeader();
}
