using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using NetFirewall.Services.Monitoring.Host;

namespace NetFirewall.Web.Models.Monitoring;

/// <summary>One stacked series of the matrix: which sample value, in which theme token.</summary>
/// <param name="Token">A <c>--metric-*</c> custom property from site.css (never a raw palette name).</param>
public sealed record DotLayer(Func<HostSample, double> Value, string Token);

/// <summary>
/// The host monitor chart: one column of dots per slice of the window, filled
/// from the bottom up to the value and split between the stacked series (user
/// and system, read and write…). Light on purpose: the dots are not one rect
/// each, they're a mask. Every colour run is a single rect the mask cuts into
/// dots, so a chart is dozens of elements, not hundreds. Pure: no state, no IO.
/// </summary>
public static class DotMatrixSvg
{
    public const int Rows = 8;

    private const int Cell = 10;

    public static IHtmlContent Render(string id, IReadOnlyList<HostSample?> columns, IReadOnlyList<DotLayer> layers, double scale, string label)
    {
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(layers);

        var invariant = CultureInfo.InvariantCulture;
        var width = Math.Max(1, columns.Count) * Cell;
        var height = Rows * Cell;
        var mask = $"{id}-mask";
        var dots = $"{id}-dots";

        var svg = new StringBuilder(2048);
        svg.Append(invariant, $"<svg viewBox=\"0 0 {width} {height}\" class=\"block h-auto w-full\" role=\"img\" aria-label=\"{HtmlEncoder.Default.Encode(label)}\">");
        // Mask luminance, not a colour: white keeps a dot, black cuts it out.
        svg.Append(invariant, $"<defs><pattern id=\"{dots}\" width=\"{Cell}\" height=\"{Cell}\" patternUnits=\"userSpaceOnUse\"><rect x=\"1.5\" y=\"1.5\" width=\"7\" height=\"7\" rx=\"1.5\" fill=\"white\" /></pattern>");
        svg.Append(invariant, $"<mask id=\"{mask}\" maskUnits=\"userSpaceOnUse\" x=\"0\" y=\"0\" width=\"{width}\" height=\"{height}\"><rect width=\"{width}\" height=\"{height}\" fill=\"url(#{dots})\" /></mask></defs>");
        svg.Append(invariant, $"<g mask=\"url(#{mask})\"><rect width=\"{width}\" height=\"{height}\" style=\"fill:var(--metric-dot-empty)\" />");

        for (var c = 0; c < columns.Count; c++)
        {
            if (columns[c] is not { } sample) continue;

            foreach (var (from, to, token) in Segments(sample, layers, scale))
            {
                svg.Append(invariant, $"<rect x=\"{c * Cell}\" y=\"{(Rows - to) * Cell}\" width=\"{Cell}\" height=\"{(to - from) * Cell}\" style=\"fill:var({token})\" />");
            }
        }

        svg.Append("</g></svg>");
        return new HtmlString(svg.ToString());
    }

    /// <summary>
    /// The rows each series fills in one column, bottom up. Anything above zero
    /// shows at least one dot; anything past the scale stays on the top row.
    /// </summary>
    public static IEnumerable<(int From, int To, string Token)> Segments(HostSample sample, IReadOnlyList<DotLayer> layers, double scale)
    {
        ArgumentNullException.ThrowIfNull(layers);

        double[] values = [.. layers.Select(layer => Math.Max(0, layer.Value(sample)))];
        var total = values.Sum();
        if (total <= 0 || scale <= 0) yield break;

        var top = Math.Clamp((int)Math.Round(total / scale * Rows), 1, Rows);
        double cumulative = 0;
        var previous = 0;

        for (var i = 0; i < layers.Count; i++)
        {
            cumulative += values[i];
            var boundary = i == layers.Count - 1 ? top : Math.Clamp((int)Math.Round(cumulative / total * top), previous, top);
            if (boundary > previous)
            {
                yield return (previous, boundary, layers[i].Token);
                previous = boundary;
            }
        }
    }
}
