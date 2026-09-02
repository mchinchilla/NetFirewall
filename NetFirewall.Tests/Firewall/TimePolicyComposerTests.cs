using NetFirewall.Web.Models.Firewall;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// The bedtime composer always produces a DROP. "Allow during the window"
/// inverts the schedule so the drop is live outside it; "block during"
/// uses the window as-is. Priority 2 is the default so it sits in front
/// of the usual established-allow.
/// </summary>
public class TimePolicyComposerTests
{
    private static TimePolicyFormViewModel Form(string mode = "allow-during") => new()
    {
        ScheduleId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        Mode = mode,
        Chain = "forward",
        Sources = "KIDS_PHONE, KIDS_LAPTOP",
        Priority = TimePolicyComposer.DefaultPriority,
        Enabled = true
    };

    [Fact]
    public void AllowDuring_InvertsSchedule_AndDrops()
    {
        var rule = TimePolicyComposer.Compose(Form("allow-during"), "KIDS_ONLINE");

        Assert.Equal("drop", rule.Action);
        Assert.Equal("forward", rule.Chain);
        Assert.True(rule.ScheduleInvert);
        Assert.Equal(2, rule.Priority);
        Assert.Equal(new[] { "KIDS_PHONE", "KIDS_LAPTOP" }, rule.SourceAddresses);
        Assert.Equal(TimePolicyComposer.LogPrefix, rule.LogPrefix);
        Assert.Contains("allow", rule.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("KIDS_ONLINE", rule.Description);
    }

    [Fact]
    public void BlockDuring_DoesNotInvert()
    {
        var rule = TimePolicyComposer.Compose(Form("block-during"), "DINNER");

        Assert.Equal("drop", rule.Action);
        Assert.False(rule.ScheduleInvert);
        Assert.Contains("block", rule.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DINNER", rule.Description);
    }

    [Fact]
    public void CustomDescription_WinsOverGenerated()
    {
        var form = Form();
        form.Description = "No Fortnite after ten";
        var rule = TimePolicyComposer.Compose(form, "KIDS_ONLINE");
        Assert.Equal("No Fortnite after ten", rule.Description);
    }

    [Fact]
    public void MissingSources_Throws()
    {
        var form = Form();
        form.Sources = "  ";
        Assert.Throws<ArgumentException>(() => TimePolicyComposer.Compose(form, "KIDS_ONLINE"));
    }

    [Fact]
    public void MissingSchedule_Throws()
    {
        var form = Form();
        form.ScheduleId = null;
        Assert.Throws<ArgumentException>(() => TimePolicyComposer.Compose(form, "KIDS_ONLINE"));
    }

    [Fact]
    public void SamePolicy_IgnoresSourceOrderAndCase()
    {
        var a = TimePolicyComposer.Compose(Form(), "KIDS_ONLINE");
        var b = TimePolicyComposer.Compose(Form(), "KIDS_ONLINE");
        b.SourceAddresses = new[] { "kids_laptop", "KIDS_PHONE" };
        Assert.True(TimePolicyComposer.SamePolicy(a, b));
    }

    [Fact]
    public void SamePolicy_DifferentSchedule_IsNotADuplicate()
    {
        var a = TimePolicyComposer.Compose(Form(), "KIDS_ONLINE");
        var b = TimePolicyComposer.Compose(Form(), "KIDS_ONLINE");
        b.ScheduleId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        Assert.False(TimePolicyComposer.SamePolicy(a, b));
    }

    [Fact]
    public void SamePolicy_AllowVsBlock_IsNotADuplicate()
    {
        var allow = TimePolicyComposer.Compose(Form("allow-during"), "KIDS_ONLINE");
        var block = TimePolicyComposer.Compose(Form("block-during"), "KIDS_ONLINE");
        Assert.False(TimePolicyComposer.SamePolicy(allow, block));
    }
}
