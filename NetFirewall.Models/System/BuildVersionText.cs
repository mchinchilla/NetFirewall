using System.Reflection;
using System.Text.RegularExpressions;

namespace NetFirewall.Models.System;

/// <summary>
/// What a binary says about its own build. <see cref="Version"/> is what
/// <c>deploy/build-bundle.sh</c> stamped from <c>git describe</c> (<c>0.6.1</c>,
/// <c>0.6.1-3-g97f88aa</c>, <c>97f88aa-dirty</c>); <see cref="Commit"/> is the short
/// SHA it was built from, when known.
/// </summary>
/// <param name="Version">Display version, no leading <c>v</c> and no <c>+sha</c> suffix.</param>
/// <param name="Commit">Short (7-char) commit SHA, or null when the build didn't record one.</param>
/// <param name="IsRelease">A plain <c>X.Y.Z</c>: built exactly from a release tag.</param>
/// <param name="IsDirty">Built from a tree with uncommitted changes.</param>
public sealed record BuildInfo(string Version, string? Commit, bool IsRelease, bool IsDirty);

/// <summary>
/// Turns <c>AssemblyInformationalVersion</c> into <see cref="BuildInfo"/>. The bundle
/// passes <c>InformationalVersion=&lt;git describe&gt;</c> and <c>SourceRevisionId=&lt;sha&gt;</c>,
/// so a release build carries <c>0.6.1+&lt;40-char sha&gt;</c>; a plain <c>dotnet build</c>
/// carries the SDK default <c>1.0.0+&lt;sha&gt;</c>. Pure: the Web footer, the login card, the
/// daemon's <c>/health</c> and the TUI all read the same answer.
/// </summary>
public static partial class BuildVersionText
{
    private const int ShortShaLength = 7;

    /// <summary>The display version — what <c>/health</c> reports and setup.sh compares to the bundle.</summary>
    public static string Of(Assembly assembly) => Info(assembly).Version;

    public static BuildInfo Info(Assembly assembly)
    {
        var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(info)
            ? Parse(assembly.GetName().Version?.ToString(3) ?? "0.0.0")
            : Parse(info);
    }

    public static BuildInfo Parse(string informational)
    {
        var text = informational.Trim();
        if (text.Length > 1 && (text[0] == 'v' || text[0] == 'V') && char.IsDigit(text[1]))
            text = text[1..];

        string? commit = null;
        var plus = text.IndexOf('+');
        if (plus >= 0)
        {
            commit = ShortSha(text[(plus + 1)..]);
            text = text[..plus];
        }

        // git describe past a tag: 0.6.1-3-g97f88aa(-dirty). No tag at all: 97f88aa(-dirty).
        var dirty = text.EndsWith("-dirty", StringComparison.Ordinal);
        commit ??= DescribeSha().Match(text) is { Success: true } m
            ? m.Groups["sha"].Value[..ShortShaLength]
            : null;

        return new BuildInfo(text, commit, ReleaseVersion().IsMatch(text), dirty);
    }

    private static string? ShortSha(string metadata) =>
        HexSha().IsMatch(metadata) ? metadata[..ShortShaLength].ToLowerInvariant() : null;

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ReleaseVersion();

    [GeneratedRegex(@"^[0-9a-fA-F]{7,40}$")]
    private static partial Regex HexSha();

    [GeneratedRegex(@"(?:^|-g)(?<sha>[0-9a-f]{7,40})(?:-dirty)?$")]
    private static partial Regex DescribeSha();
}
