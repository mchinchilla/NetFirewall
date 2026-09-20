using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Processes;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// The argument-vector overload is what keeps user input out of shell syntax:
/// every element must reach the child byte-for-byte, however hostile it looks.
/// </summary>
public class ProcessRunnerArgumentListTests
{
    [Fact]
    public async Task ArgumentList_DeliversEachElementVerbatim()
    {
        if (!File.Exists("/bin/echo")) return; // Windows CI — nothing to prove here

        var runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

        var result = await runner.RunAsync("/bin/echo",
            new[] { "a b", "c;d", "$HOME", "`id`", "-n" },
            TimeSpan.FromSeconds(5));

        Assert.True(result.Success, result.Error);
        // "-n" is the LAST element, so echo prints it literally instead of treating it as a flag.
        Assert.Equal("a b c;d $HOME `id` -n", result.Output.Trim());
    }

    [Fact]
    public async Task ArgumentList_NonZeroExit_IsReportedNotThrown()
    {
        if (!File.Exists("/bin/sh")) return;

        var runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

        var result = await runner.RunAsync("/bin/sh", new[] { "-c", "echo oops >&2; exit 3" }, TimeSpan.FromSeconds(5));

        Assert.False(result.Success);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("oops", result.Error);
    }

    [Fact]
    public async Task ArgumentList_Timeout_KillsAndThrowsOperationCanceled()
    {
        if (!File.Exists("/bin/sleep")) return;

        var runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            runner.RunAsync("/bin/sleep", new[] { "5" }, TimeSpan.FromMilliseconds(200)));
    }
}
