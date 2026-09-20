using System.Threading.Channels;

namespace NetFirewall.Services.Processes;

/// <summary>
/// A child process whose stdout is consumed line by line while it runs — for
/// tools that produce output continuously and are stopped by us rather than
/// exiting on their own (<c>nft monitor trace</c>).
///
/// Disposal always terminates the process: a diagnostics job that is abandoned,
/// cancelled or crashes must never leave a monitor running on the firewall.
/// </summary>
public interface IRunningProcess : IAsyncDisposable
{
    /// <summary>stdout, one line per read. Completes when the process exits or is stopped.</summary>
    ChannelReader<string> Output { get; }

    /// <summary>Exit code, once the process has ended. 137 when we had to SIGKILL it.</summary>
    Task<int> Completion { get; }

    /// <summary>Lines dropped because the consumer fell behind (the channel is bounded).</summary>
    int DroppedLines { get; }

    /// <summary>SIGTERM, then SIGKILL after <paramref name="grace"/>. Safe to call more than once.</summary>
    Task StopAsync(TimeSpan? grace = null);
}
