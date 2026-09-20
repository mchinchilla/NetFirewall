using NetFirewall.Services.Diagnostics;

namespace NetFirewall.Tests.Diagnostics;

public class DiagnosticGateTests
{
    [Fact]
    public void Doctor_HasOneSlot_RefusesSecondUntilReleased()
    {
        var gate = new DiagnosticGate();

        var first = gate.TryEnter(DiagFamilies.Doctor);
        Assert.NotNull(first);
        Assert.Null(gate.TryEnter(DiagFamilies.Doctor));

        first.Dispose();
        using var again = gate.TryEnter(DiagFamilies.Doctor);
        Assert.NotNull(again);
    }

    [Fact]
    public void Families_AreIndependent()
    {
        var gate = new DiagnosticGate();
        using var doctor = gate.TryEnter(DiagFamilies.Doctor);
        using var ping = gate.TryEnter(DiagFamilies.Ping);
        Assert.NotNull(doctor);
        Assert.NotNull(ping);
    }

    [Fact]
    public void Ping_HasTwoSlots()
    {
        var gate = new DiagnosticGate();
        using var a = gate.TryEnter(DiagFamilies.Ping);
        using var b = gate.TryEnter(DiagFamilies.Ping);
        Assert.NotNull(a);
        Assert.NotNull(b);
        Assert.Null(gate.TryEnter(DiagFamilies.Ping));
    }

    [Fact]
    public void DoubleDispose_ReleasesOnlyOnce()
    {
        var gate = new DiagnosticGate();
        var lease = gate.TryEnter(DiagFamilies.Journal)!;
        lease.Dispose();
        lease.Dispose(); // must not over-release and grant two slots on a 1-slot family

        using var one = gate.TryEnter(DiagFamilies.Journal);
        Assert.NotNull(one);
        Assert.Null(gate.TryEnter(DiagFamilies.Journal));
    }
}
