using System.Reflection;

namespace NetFirewall.Models.System;

/// <summary>
/// The version an operator should see: the one <c>deploy/build-bundle.sh</c> stamps
/// into <c>AssemblyInformationalVersion</c> from <c>git describe</c> (<c>1.4.0</c>,
/// <c>1.4.0-3-g97f88aa</c>, <c>97f88aa-dirty</c>). A plain <c>dotnet build</c> carries
/// the SDK default <c>1.0.0+&lt;40-char sha&gt;</c>, shortened here to seven hex digits.
/// Pure: the Web footer, the daemon's <c>/health</c> and the TUI all print the same text.
/// </summary>
public static class BuildVersionText
{
    public static string Of(Assembly assembly)
    {
        var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(info)
            ? assembly.GetName().Version?.ToString(3) ?? "0.0.0"
            : Normalize(info);
    }

    /// <summary>Strips a leading <c>v</c> (views add their own) and shortens a SourceLink
    /// <c>+sha</c> suffix to seven characters.</summary>
    public static string Normalize(string informational)
    {
        var text = informational.Trim();
        if (text.Length > 1 && (text[0] == 'v' || text[0] == 'V') && char.IsDigit(text[1]))
            text = text[1..];

        var plus = text.IndexOf('+');
        if (plus >= 0 && text.Length - plus - 1 > 7)
            text = text[..(plus + 8)];

        return text;
    }
}
