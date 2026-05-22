using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Enqueues destination IPs for ASN/org enrichment. The conntrack sampler calls
/// <see cref="Enqueue"/> for each new destination it records; resolution happens
/// off the hot path in a background worker that hits ip.guide and caches the
/// result by network prefix in <c>ip_asn_cache</c>.
/// </summary>
public interface IIpAsnResolver
{
    /// <summary>Queue an IP for background ASN resolution. Non-blocking; dedups
    /// and drops silently if the queue is full or the IP is private/own.</summary>
    void Enqueue(IPAddress ip);
}

/// <summary>
/// Background worker that drains the enqueue channel, resolves each IP via
/// ip.guide (free, no token, returns ASN + org + country + prefix CIDR), and
/// upserts the result keyed by prefix so future IPs in the same prefix are cache
/// hits. Disclosures: this sends DESTINATION IPs (never LAN/source IPs or
/// payloads) to a third party; gated by <see cref="IpAsnResolverOptions.Enabled"/>.
/// </summary>
public sealed class IpAsnResolver : BackgroundService, IIpAsnResolver
{
    private readonly NpgsqlDataSource _ds;
    private readonly IHttpClientFactory _httpFactory;
    private readonly IpAsnResolverOptions _opts;
    private readonly ILogger<IpAsnResolver> _logger;

    // Bounded queue of IPs to resolve. DropWrite: if we're backed up, skip the
    // new IP rather than block the sampler — it'll be re-seen next window.
    private readonly Channel<IPAddress> _queue = Channel.CreateBounded<IPAddress>(
        new BoundedChannelOptions(4096) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });

    // In-memory dedup of IPs already enqueued/resolved this process lifetime, so
    // a repeatedly-seen destination doesn't flood the channel. Bounded-ish: it
    // tracks distinct external IPs, which for a home/SMB LAN is modest.
    private readonly HashSet<IPAddress> _seen = new();
    private readonly object _seenLock = new();

    public IpAsnResolver(
        NpgsqlDataSource ds,
        IHttpClientFactory httpFactory,
        IOptions<IpAsnResolverOptions> opts,
        ILogger<IpAsnResolver> logger)
    {
        _ds = ds;
        _httpFactory = httpFactory;
        _opts = opts.Value;
        _logger = logger;
    }

    /// <summary>Named HttpClient for ip.guide. ServiceDefaults adds the resilience
    /// handler to all clients by default.</summary>
    public const string HttpClientName = "ip-guide";

    public void Enqueue(IPAddress ip)
    {
        if (!_opts.Enabled) return;
        // Never resolve private/own — those aren't real Internet destinations and
        // ip.guide would return nothing useful.
        if (IpRanges.IsPrivate(ip)) return;

        lock (_seenLock)
        {
            if (!_seen.Add(ip)) return; // already enqueued/resolved this lifetime
        }
        _queue.Writer.TryWrite(ip); // non-blocking; DropWrite handles a full queue
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _logger.LogInformation("IP ASN resolver disabled by config — exiting.");
            return;
        }

        _logger.LogInformation("IP ASN resolver started — source {Url}, {Max}/min, fail-TTL {Days}d",
            _opts.ApiBaseUrl, _opts.MaxPerMinute, _opts.FailTtlDays);

        var minInterval = TimeSpan.FromSeconds(60.0 / Math.Max(1, _opts.MaxPerMinute));

        await foreach (var ip in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                if (await IsCachedFreshAsync(ip, stoppingToken)) continue;
                await ResolveAndCacheAsync(ip, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "ASN resolve failed for {Ip}", ip);
            }

            // Throttle politely between live API calls.
            try { await Task.Delay(minInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task<bool> IsCachedFreshAsync(IPAddress ip, CancellationToken ct)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            @"SELECT ok, resolved_at FROM ip_asn_cache WHERE prefix >>= @ip
              ORDER BY masklen(prefix) DESC LIMIT 1", conn);
        cmd.Parameters.AddWithValue("ip", ip);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return false; // not cached at all

        var ok = r.GetBoolean(0);
        var resolvedAt = r.GetFieldValue<DateTime>(1);
        // Successful hits never expire (ASN allocations are stable). Failures are
        // retried after the fail-TTL.
        if (ok) return true;
        return DateTime.UtcNow - resolvedAt < TimeSpan.FromDays(_opts.FailTtlDays);
    }

    private async Task ResolveAndCacheAsync(IPAddress ip, CancellationToken ct)
    {
        IpGuideResponse? body = null;
        try
        {
            // ip.guide upgrades to HTTPS; path is /{ip}.
            using var http = _httpFactory.CreateClient(HttpClientName);
            body = await http.GetFromJsonAsync<IpGuideResponse>(
                $"{_opts.ApiBaseUrl.TrimEnd('/')}/{ip}", ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogDebug(ex, "ip.guide request failed for {Ip}", ip);
        }

        var row = MapResponse(ip, body);
        await UpsertAsync(row.Prefix, row.Asn, row.Org, row.Country, row.City, row.Ok, ct);
        if (row.Ok)
            _logger.LogDebug("Resolved {Ip} → {Prefix} {Asn} {Org}", ip, row.Prefix, row.Asn, row.Org);
    }

    /// <summary>
    /// Maps an ip.guide response to the cache row. Pure — unit-testable without
    /// HTTP or DB. A response with a CIDR + ASN is a success; anything else
    /// (null body, missing fields) caches a failed /32 so we don't retry until
    /// the fail-TTL.
    /// </summary>
    internal static CacheRow MapResponse(IPAddress ip, IpGuideResponse? body)
    {
        var asys = body?.Network?.AutonomousSystem;
        if (body?.Network is { Cidr.Length: > 0 } net && asys is not null)
        {
            return new CacheRow(
                Prefix: net.Cidr,
                Asn: asys.Asn > 0 ? $"AS{asys.Asn}" : null,
                Org: asys.Organization ?? asys.Name,
                Country: asys.Country,
                City: body.Location?.City,
                Ok: true);
        }
        return new CacheRow($"{ip}/32", null, null, null, null, Ok: false);
    }

    internal readonly record struct CacheRow(
        string Prefix, string? Asn, string? Org, string? Country, string? City, bool Ok);

    private async Task UpsertAsync(
        string prefix, string? asn, string? org, string? country, string? city, bool ok, CancellationToken ct)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO ip_asn_cache (prefix, asn, org, country, city, ok, resolved_at)
            VALUES (@prefix::cidr, @asn, @org, @country, @city, @ok, now())
            ON CONFLICT (prefix) DO UPDATE
              SET asn = EXCLUDED.asn, org = EXCLUDED.org, country = EXCLUDED.country,
                  city = EXCLUDED.city, ok = EXCLUDED.ok, resolved_at = now()", conn);
        cmd.Parameters.AddWithValue("prefix", prefix);
        cmd.Parameters.AddWithValue("asn", (object?)asn ?? DBNull.Value);
        cmd.Parameters.AddWithValue("org", (object?)Trunc(org, 160) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("country", (object?)Trunc(country, 2) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("city", (object?)Trunc(city, 120) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ok", ok);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string? Trunc(string? s, int max)
        => string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max]);

    // ── ip.guide JSON shape (only the fields we need) ────────────────────
    internal sealed record IpGuideResponse(
        [property: JsonPropertyName("network")] IpGuideNetwork? Network,
        [property: JsonPropertyName("location")] IpGuideLocation? Location);

    internal sealed record IpGuideNetwork(
        [property: JsonPropertyName("cidr")] string? Cidr,
        [property: JsonPropertyName("autonomous_system")] IpGuideAsn? AutonomousSystem);

    internal sealed record IpGuideAsn(
        [property: JsonPropertyName("asn")] int Asn,
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("organization")] string? Organization,
        [property: JsonPropertyName("country")] string? Country);

    internal sealed record IpGuideLocation(
        [property: JsonPropertyName("city")] string? City);
}

public sealed class IpAsnResolverOptions
{
    public const string SectionName = "IpAsnResolver";

    /// <summary>Master switch. Default true (auto-enrich). Sends destination IPs
    /// to a third party (ip.guide); set false to opt out.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Base URL of the lookup API. Default ip.guide (free, no token).</summary>
    public string ApiBaseUrl { get; set; } = "https://ip.guide";

    /// <summary>Max live API calls per minute (polite throttle).</summary>
    public int MaxPerMinute { get; set; } = 60;

    /// <summary>Days before a FAILED lookup is retried. Successes never expire.</summary>
    public int FailTtlDays { get; set; } = 30;
}
