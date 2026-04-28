using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NetFirewall.Web.Services;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Filesystem-backed catalog. Tests focus on the **path-traversal guard** —
/// `ReadAsync(name)` is the only Web endpoint that takes a filename from a
/// query string and turns it into a disk read. Without the guard, a malicious
/// <c>name = "../../etc/passwd"</c> would happily exfiltrate host secrets.
/// Other tests pin the listing shape, kind classification, and the size-cap
/// safety net.
/// </summary>
public sealed class BashScriptCatalogTests : IDisposable
{
    private readonly string _root;

    public BashScriptCatalogTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "bashcat-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    private BashScriptCatalog CreateCatalog(long? maxBytes = null) =>
        new(Options.Create(new BashScriptCatalogOptions
        {
            Root = _root,
            MaxFileSizeBytes = maxBytes ?? 1_048_576
        }), NullLogger<BashScriptCatalog>.Instance);

    private void Write(string relPath, string content) =>
        File.WriteAllText(Path.Combine(_root, relPath), content);

    // ── List ───────────────────────────────────────────────────────────

    [Fact]
    public async Task ListAsync_RootMissing_ReturnsEmpty_NoCrash()
    {
        Directory.Delete(_root); // make root vanish
        var entries = await CreateCatalog().ListAsync();
        Assert.Empty(entries);
    }

    [Fact]
    public async Task ListAsync_OnlyTopLevelFiles_AlphabeticalOrder()
    {
        Write("zulu.sh",  "echo z");
        Write("alpha.conf", "table x {}");
        Write("mike.txt",  "notes");
        Directory.CreateDirectory(Path.Combine(_root, "subdir"));
        File.WriteAllText(Path.Combine(_root, "subdir", "buried.sh"), "should not appear");

        var entries = await CreateCatalog().ListAsync();

        Assert.Equal(new[] { "alpha.conf", "mike.txt", "zulu.sh" },
            entries.Select(e => e.Name));
    }

    [Theory]
    [InlineData("script.sh",   "shell")]
    [InlineData("rules.conf",  "nftables")]
    [InlineData("notes.txt",   "text")]
    [InlineData("schema.sql",  "sql")]
    [InlineData("README.md",   "other")]
    [InlineData("Makefile",    "other")] // no extension
    public async Task ListAsync_ClassifiesKindByExtension(string filename, string expectedKind)
    {
        Write(filename, "x");
        var entries = await CreateCatalog().ListAsync();
        var entry = entries.Single(e => e.Name == filename);
        Assert.Equal(expectedKind, entry.Kind);
    }

    [Fact]
    public async Task ListAsync_RecordsSizeAndLastModified()
    {
        Write("a.sh", "hello");
        var entries = await CreateCatalog().ListAsync();
        var entry = entries.Single();
        Assert.Equal(5, entry.SizeBytes);
        Assert.True(entry.LastModified > DateTime.UtcNow.AddMinutes(-1));
    }

    // ── Read happy path ────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_ExistingFile_ReturnsContents()
    {
        Write("a.sh", "echo hello");
        var content = await CreateCatalog().ReadAsync("a.sh");
        Assert.Equal("echo hello", content);
    }

    [Fact]
    public async Task ReadAsync_FileTooLarge_ReturnsPlaceholderInsteadOfDumpingMemory()
    {
        Write("big.sh", new string('x', 1024)); // 1 KiB
        var catalog = CreateCatalog(maxBytes: 100); // cap at 100 bytes

        var content = await catalog.ReadAsync("big.sh");

        Assert.NotNull(content);
        Assert.Contains("too large", content);
        // The placeholder reports the actual size and the cap.
        Assert.Contains("1,024", content);
    }

    [Fact]
    public async Task ReadAsync_FileMissing_ReturnsNull()
    {
        Assert.Null(await CreateCatalog().ReadAsync("nope.sh"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ReadAsync_EmptyOrWhitespaceName_ReturnsNull(string name)
    {
        Assert.Null(await CreateCatalog().ReadAsync(name));
    }

    // ── Path-traversal guard (security-critical) ───────────────────────

    [Fact]
    public async Task ReadAsync_DotDotEscape_ReturnsNull_DoesNotLeakOutsideRoot()
    {
        // Plant a file *outside* the catalog root that the attacker would
        // love to read. The guard must reject any path that resolves to it.
        var sibling = Path.Combine(Path.GetDirectoryName(_root)!, "secrets-" + Guid.NewGuid().ToString("N")[..6] + ".txt");
        try
        {
            File.WriteAllText(sibling, "MASTER_KEY=top-secret");

            var siblingName = Path.GetFileName(sibling);
            var content = await CreateCatalog().ReadAsync($"../{siblingName}");

            Assert.Null(content);
        }
        finally
        {
            try { File.Delete(sibling); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ReadAsync_AbsolutePathOutsideRoot_ReturnsNull()
    {
        // /etc/passwd-style absolute path must NOT bypass the guard.
        // Path.Combine ignores root and uses the abs path directly, so the
        // guard fires when it resolves to a path that doesn't start with _absRoot.
        var content = await CreateCatalog().ReadAsync("/etc/hostname");
        Assert.Null(content);
    }

    [Fact]
    public async Task ReadAsync_NestedDotDotComponents_StillRejected()
    {
        Write("a.sh", "ok");
        // Even chains like "a/../../something" must be rejected once they
        // escape the root.
        var content = await CreateCatalog().ReadAsync("a.sh/../../etc/passwd");
        Assert.Null(content);
    }
}
