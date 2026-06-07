using Xunit;

namespace NetFirewall.Tests.Infra;

/// <summary>
/// A <see cref="FactAttribute"/> that auto-skips on non-Linux hosts. Use it for
/// tests that exercise services marked <c>[SupportedOSPlatform("linux")]</c>
/// (even mock-based ones): on macOS/Windows the test is reported as SKIPPED —
/// honest, unlike an inline <c>if (OperatingSystem.IsLinux())</c> guard which
/// would make the test pass with zero assertions (silent coverage loss). Also
/// keeps the linux-only call sites legitimately platform-gated, so CA1416 doesn't
/// fire from the cross-platform test project.
/// </summary>
public sealed class LinuxOnlyFactAttribute : FactAttribute
{
    public LinuxOnlyFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Linux-only: exercises a [SupportedOSPlatform(\"linux\")] service.";
    }
}
