using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Synchronous, on-demand GeoIP + ASN lookup for a single IP via ip.guide. Powers
/// the login system-info card and the post-login "connecting from" card.
///
/// Why this exists alongside <see cref="IIpAsnResolver"/>: the resolver is a
/// fire-and-forget background enricher (returns <c>void</c>, caches only
/// asn/org/country/city) — it can't answer "geo for this IP, now, including
/// timezone". This service gives a synchronous answer with the full shape the UI
/// renders, and caches it in-process so repeated page loads don't hammer ip.guide.
/// </summary>
public interface IGeoIpLookupService
{
    /// <summary>Enrich a specific (public) IP.</summary>
    Task<GeoIpInfo> LookupAsync(IPAddress ip, CancellationToken ct = default);

    /// <summary>Enrich the caller's OWN public/egress IP. ip.guide's bare endpoint
    /// (no IP in the path) echoes the requester's public IP + full geo, so this is
    /// how we surface the firewall's WAN egress for on-LAN admins.</summary>
    Task<GeoIpInfo> LookupSelfAsync(CancellationToken ct = default);

    /// <summary>Pick the right lookup for a connecting client: private/null →
    /// the firewall's egress (<see cref="LookupSelfAsync"/>), public → that IP.</summary>
    Task<GeoIpInfo> LookupForClientAsync(IPAddress? clientIp, CancellationToken ct = default);
}

/// <summary>
/// ip.guide implementation. Reuses the same named HttpClient and config section as
/// <see cref="IpAsnResolver"/> so the third-party-disclosure master switch
/// (<see cref="IpAsnResolverOptions.Enabled"/>) governs both. Fail-soft: any
/// HTTP/parse error returns <see cref="GeoIpInfo.Unavailable"/> — never throws into
/// a view.
/// </summary>
public sealed class GeoIpLookupService : IGeoIpLookupService
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly IMemoryCache _cache;
    private readonly IpAsnResolverOptions _opts;
    private readonly ILogger<GeoIpLookupService> _logger;

    // Successful enrichments are stable (ASN allocations + geo rarely move) and the
    // connecting IP rarely changes between page loads, so a multi-hour TTL keeps the
    // card instant without re-hitting ip.guide. Failures cache briefly so a transient
    // outage doesn't pin "—" for hours but we also don't retry on every keystroke.
    private static readonly TimeSpan OkTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan FailTtl = TimeSpan.FromMinutes(5);

    private const string SelfCacheKey = "geoip:self";

    public GeoIpLookupService(
        IHttpClientFactory httpFactory,
        IMemoryCache cache,
        IOptions<IpAsnResolverOptions> opts,
        ILogger<GeoIpLookupService> logger)
    {
        _httpFactory = httpFactory;
        _cache = cache;
        _opts = opts.Value;
        _logger = logger;
    }

    public Task<GeoIpInfo> LookupForClientAsync(IPAddress? clientIp, CancellationToken ct = default)
        => clientIp is null || IpRanges.IsPrivate(clientIp)
            ? LookupSelfAsync(ct)
            : LookupAsync(clientIp, ct);

    public async Task<GeoIpInfo> LookupAsync(IPAddress ip, CancellationToken ct = default)
    {
        if (!_opts.Enabled) return GeoIpInfo.Unavailable(ip.ToString(), forSelf: false);
        var key = $"geoip:{ip}";
        if (_cache.TryGetValue(key, out GeoIpInfo? hit) && hit is not null) return hit;

        var result = await FetchAsync($"/{ip}", forSelf: false, ct);
        Cache(key, result);
        return result;
    }

    public async Task<GeoIpInfo> LookupSelfAsync(CancellationToken ct = default)
    {
        if (!_opts.Enabled) return GeoIpInfo.Unavailable(null, forSelf: true);
        if (_cache.TryGetValue(SelfCacheKey, out GeoIpInfo? hit) && hit is not null) return hit;

        var result = await FetchAsync(string.Empty, forSelf: true, ct);
        Cache(SelfCacheKey, result);
        return result;
    }

    private void Cache(string key, GeoIpInfo info)
        => _cache.Set(key, info, info.Ok ? OkTtl : FailTtl);

    private async Task<GeoIpInfo> FetchAsync(string pathSuffix, bool forSelf, CancellationToken ct)
    {
        IpGuideResponse? body = null;
        try
        {
            using var http = _httpFactory.CreateClient(IpAsnResolver.HttpClientName);
            body = await http.GetFromJsonAsync<IpGuideResponse>(
                $"{_opts.ApiBaseUrl.TrimEnd('/')}{pathSuffix}", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "ip.guide lookup failed for '{Path}'", pathSuffix);
        }
        return Map(body, forSelf);
    }

    /// <summary>
    /// Pure ip.guide-JSON → <see cref="GeoIpInfo"/> mapping. No HTTP/cache, so it's
    /// unit-testable directly (see GeoIpLookupMappingTests). A response carrying an
    /// ASN or any location field is a success; an empty/null body is unavailable.
    /// </summary>
    internal static GeoIpInfo Map(IpGuideResponse? body, bool forSelf)
    {
        if (body is null) return GeoIpInfo.Unavailable(null, forSelf);

        var asys = body.Network?.AutonomousSystem;
        var loc = body.Location;
        var hasAnything = asys is not null || loc is not null || !string.IsNullOrEmpty(body.Ip);
        if (!hasAnything) return GeoIpInfo.Unavailable(body.Ip, forSelf);

        return new GeoIpInfo(
            Ip: body.Ip,
            City: loc?.City,
            Country: asys?.Country ?? Iso2FromName(loc?.Country),
            CountryName: loc?.Country,
            Asn: asys is { Asn: > 0 } ? $"AS{asys.Asn}" : null,
            Org: asys?.Organization ?? asys?.Name,
            Timezone: loc?.Timezone,
            Latitude: loc?.Latitude,
            Longitude: loc?.Longitude,
            ForSelf: forSelf,
            Ok: true);
    }

    // ip.guide's autonomous_system.country is the authoritative ISO-2; location.country
    // is the full name. We only fall back to a name→code map for the rare case where the
    // AS block is absent — and even then we just leave it null rather than ship a full
    // country table. (The UI shows the full CountryName regardless.)
    private static string? Iso2FromName(string? _) => null;

    // ── ip.guide JSON shape (superset of IpAsnResolver's — adds ip + tz + lat/lon) ──
    internal sealed record IpGuideResponse(
        [property: JsonPropertyName("ip")] string? Ip,
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
        [property: JsonPropertyName("city")] string? City,
        [property: JsonPropertyName("country")] string? Country,
        [property: JsonPropertyName("timezone")] string? Timezone,
        [property: JsonPropertyName("latitude")] double? Latitude,
        [property: JsonPropertyName("longitude")] double? Longitude);
}
