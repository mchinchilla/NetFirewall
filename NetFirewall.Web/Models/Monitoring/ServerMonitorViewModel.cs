using System.Globalization;
using Microsoft.AspNetCore.Html;
using NetFirewall.Models;
using NetFirewall.Services.Monitoring.Host;

namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// Monitoring → Server (full page) and the five-tile strip on the dashboard and
/// Monitoring overview. Both render from the same in-memory window; the strip is
/// just the narrow series with a one-line detail per tile.
/// </summary>
public sealed record ServerMonitorViewModel(ServiceResponse<HostMonitorView> Status, int WindowSeconds)
{
    /// <summary>
    /// Disk and network charts never stretch below this: an idle box's noise
    /// (a few KB/s) must not paint as a full column.
    /// </summary>
    public const double RateFloor = 64 * 1024;

    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public HostMonitorView? View => Status.Data;

    /// <summary>Every 2 s with one-second columns, every 5 s otherwise.</summary>
    public int RefreshSeconds => WindowSeconds <= HostWindows.Default ? 2 : 5;

    /// <summary>The window chips: seconds and label.</summary>
    public static IReadOnlyList<(int Seconds, string Label)> Windows { get; } =
        [(60, "1m"), (300, "5m"), (900, "15m"), (3600, "1h")];

    // Heroicons (outline, 24px) — same stroke set the rest of the UI uses.
    public const string IconCpu = "M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 0 0 2.25-2.25V6.75a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 6.75v10.5a2.25 2.25 0 0 0 2.25 2.25Zm.75-12h9v9h-9v-9Z";
    public const string IconMemory = "M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3V6.75a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3v4.5a3 3 0 0 1-3 3m-13.5 0a3 3 0 0 0-3 3v3a3 3 0 0 0 3 3h13.5a3 3 0 0 0 3-3v-3a3 3 0 0 0-3-3";
    public const string IconLoad = "M2.25 12h3.5l2.5-6.5 4.5 13 2.75-6.5h6.25";
    public const string IconDisk = "M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125";
    public const string IconNetwork = "M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418";
    public const string IconProcesses = "M8.25 6.75h12M8.25 12h12m-12 5.25h12M3.75 6.75h.007v.008H3.75V6.75Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0ZM3.75 12h.007v.008H3.75V12Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm-.375 5.25h.007v.008H3.75v-.008Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z";
    public const string IconFilesystems = "M21.75 17.25v-.228a4.5 4.5 0 0 0-.12-1.03l-2.268-9.64a3.375 3.375 0 0 0-3.285-2.602H7.923a3.375 3.375 0 0 0-3.285 2.602l-2.268 9.64a4.5 4.5 0 0 0-.12 1.03v.228m19.5 0a3 3 0 0 1-3 3H5.25a3 3 0 0 1-3-3m19.5 0a3 3 0 0 0-3-3H5.25a3 3 0 0 0-3 3m16.5 0h.008v.008h-.008v-.008Zm-3 0h.008v.008h-.008v-.008Z";

    /// <summary>
    /// The five metric cards over this window. <paramref name="strip"/> renders
    /// every chart on the narrow series (equal tiles) with distinct SVG ids so
    /// the strip and the full page can share one document.
    /// </summary>
    public IReadOnlyList<ServerMetricCard> Cards(bool strip = false)
    {
        if (View is not { Current: { } now } m) return [];

        var cores = Math.Max(1, m.Identity.Cores);
        var wide = strip ? m.Narrow : m.Wide;
        var prefix = strip ? "strip-" : "srv-";
        var diskScale = RateScale(m.Narrow, s => s.DiskBytesPerSecond);
        var netScale = RateScale(m.Narrow, s => s.NetworkBytesPerSecond);

        return
        [
            new("CPU", IconCpu, "--metric-cpu-system",
                $"{Pct(now.CpuBusy)} %",
                [
                    new($"user {Pct(now.CpuUser)}%", "--metric-cpu-user"),
                    new($"system {Pct(now.CpuSystem)}%", "--metric-cpu-system"),
                    new($"I/O wait {Pct(now.CpuIoWait)}%", "--metric-cpu-iowait"),
                ],
                $"system {Pct(now.CpuSystem)}%",
                DotMatrixSvg.Render(prefix + "cpu", wide,
                [
                    new(s => s.CpuSystem, "--metric-cpu-system"),
                    new(s => s.CpuUser, "--metric-cpu-user"),
                    new(s => s.CpuIoWait, "--metric-cpu-iowait"),
                ], 1, "CPU"),
                Caption: $"{cores} cores · system = packet forwarding + IRQ",
                Wide: true),

            new("Memory", IconMemory, "--metric-memory",
                $"{Percent(now.MemoryUsed, m.Identity.MemoryTotal)} %",
                [
                    new($"{Bytes(now.MemoryUsed)} of {Bytes(m.Identity.MemoryTotal)}", "--metric-memory"),
                    new($"cache {Bytes(now.MemoryCache)}"),
                    new($"swap {Bytes(now.SwapUsed)} of {Bytes(m.Identity.SwapTotal)}"),
                ],
                $"{Bytes(now.MemoryUsed)} of {Bytes(m.Identity.MemoryTotal)}",
                DotMatrixSvg.Render(prefix + "memory", wide,
                    [new(s => s.MemoryUsed, "--metric-memory")],
                    Math.Max(1, m.Identity.MemoryTotal), "Memory"),
                Caption: null,
                Wide: true),

            new("Load", IconLoad, "--metric-load",
                Load(now.Load1),
                [
                    new("1 min", "--metric-load"),
                    new($"5 min {Load(now.Load5)}"),
                    new($"15 min {Load(now.Load15)}"),
                ],
                $"5 min {Load(now.Load5)}",
                DotMatrixSvg.Render(prefix + "load", m.Narrow, [new(s => s.Load1, "--metric-load")], cores, "Load"),
                Caption: $"Top row: all {cores} cores busy",
                Wide: false),

            new("Disk", IconDisk, "--metric-disk-read",
                Rate(now.DiskBytesPerSecond),
                [
                    new($"{Rate(now.DiskReadBytesPerSecond)} read", "--metric-disk-read"),
                    new($"{Rate(now.DiskWriteBytesPerSecond)} written", "--metric-disk-write"),
                ],
                $"{Rate(now.DiskWriteBytesPerSecond)} written",
                DotMatrixSvg.Render(prefix + "disk", m.Narrow,
                [
                    new(s => s.DiskReadBytesPerSecond, "--metric-disk-read"),
                    new(s => s.DiskWriteBytesPerSecond, "--metric-disk-write"),
                ], diskScale, "Disk"),
                Caption: $"window peak {Rate(Peak(m.Narrow, s => s.DiskBytesPerSecond))}",
                Wide: false),

            new("Network", IconNetwork, "--metric-net-in",
                Rate(now.NetworkBytesPerSecond),
                [
                    new($"{Rate(now.NetworkInBytesPerSecond)} in", "--metric-net-in"),
                    new($"{Rate(now.NetworkOutBytesPerSecond)} out", "--metric-net-out"),
                ],
                $"{Rate(now.NetworkInBytesPerSecond)} in",
                DotMatrixSvg.Render(prefix + "network", m.Narrow,
                [
                    new(s => s.NetworkInBytesPerSecond, "--metric-net-in"),
                    new(s => s.NetworkOutBytesPerSecond, "--metric-net-out"),
                ], netScale, "Network"),
                Caption: $"physical NICs · window peak {Rate(Peak(m.Narrow, s => s.NetworkBytesPerSecond))}",
                Wide: false),
        ];
    }

    /// <summary>The scale of a rate chart: the window's peak with a little headroom.</summary>
    public static double RateScale(IReadOnlyList<HostSample?> columns, Func<HostSample, double> total) =>
        Math.Max(Peak(columns, total) * 1.1, RateFloor);

    public static double Peak(IReadOnlyList<HostSample?> columns, Func<HostSample, double> value) =>
        columns.Where(c => c is not null).Select(c => value(c!.Value)).DefaultIfEmpty(0).Max();

    public static int Percent(double fraction) => (int)Math.Round(Math.Clamp(fraction, 0, 1) * 100);

    public static int Percent(long part, long total) => total > 0 ? Percent((double)part / total) : 0;

    public static string Pct(double fraction) => Percent(fraction).ToString(Inv);

    /// <summary>Bytes in 1024 steps: two decimals under a hundred, one above.</summary>
    public static string Bytes(double bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var unit = 0;
        while (Math.Abs(bytes) >= 1024 && unit < units.Length - 1)
        {
            bytes /= 1024;
            unit++;
        }

        var format = unit == 0 ? "0" : bytes < 100 ? "0.00" : "0.0";
        return $"{bytes.ToString(format, Inv)} {units[unit]}";
    }

    public static string Rate(double bytesPerSecond) => Bytes(bytesPerSecond) + "/s";

    /// <summary>Time up: days and hours, hours and minutes, or minutes.</summary>
    public static string Uptime(TimeSpan span) => span switch
    {
        { TotalDays: >= 1 } => $"{(int)span.TotalDays} d {span.Hours} h",
        { TotalHours: >= 1 } => $"{span.Hours} h {span.Minutes} min",
        _ => $"{Math.Max(0, span.Minutes)} min",
    };

    public static string Load(double load) => load.ToString("0.00", Inv);

    /// <summary>"Debian 13 · Xeon … · 8 cores · up 20 d 2 h" — the page subtitle.</summary>
    public static string IdentityLine(HostMonitorView m) => string.Join(" · ", new[]
    {
        m.Identity.OperatingSystem,
        m.Identity.CpuModel,
        $"{m.Identity.Cores} cores",
        m.Identity.BootedOn is { } booted ? $"up {Uptime(m.CheckedOn - booted)}" : null,
    }.Where(part => !string.IsNullOrWhiteSpace(part)));
}

/// <summary>One legend entry; with a swatch when it's a chart series.</summary>
/// <param name="Token">The series' <c>--metric-*</c> token, or null for plain text.</param>
public sealed record ServerLegendItem(string Text, string? Token = null);

/// <summary>A monitor card: icon, headline, legend and dot matrix.</summary>
/// <param name="Tone">The <c>--metric-*</c> token the icon disc and title take.</param>
/// <param name="Detail">The strip's single line under the headline.</param>
/// <param name="Wide">CPU and memory span half a row; load, disk and network a third.</param>
public sealed record ServerMetricCard(
    string Title,
    string IconPath,
    string Tone,
    string Headline,
    IReadOnlyList<ServerLegendItem> Legend,
    string Detail,
    IHtmlContent Chart,
    string? Caption,
    bool Wide);
