# Plan: Per-destination traffic tracking with ASN enrichment

## Goal

Today the "Top hosts (24h)" panel tells you *how much* a LAN host sent/received,
but not *where to*. `ConntrackSamplerService` parses `dst=` from every flow and
then **discards it** (bucket key is `(src_ip, proto, dst_port)`). That blind spot
is exactly why diagnosing the Echo Show required dropping to the console to run
`conntrack -L -s` by hand.

This plan adds **per-destination** accounting so the panel can answer "which
hosts is device X talking to, and who owns those IPs" — and tell *Amazon* apart
from *some random provider* at a glance.

Decisions already made with the user:
- **ASN enrichment**: deferred external API + cache table. Never on the sampler
  hot path. Resolve only *new* destination IPs, in the background.
  **API: `ip.guide`** (`curl -sL ip.guide/{ip}`) — free, no token, no rate limit,
  returns ASN + org + country + the prefix CIDR in one JSON call. Preferred over
  ipinfo.io. Sample response shape:
  ```json
  {
    "ip": "154.12.104.135",
    "network": {
      "cidr": "154.12.104.0/21",
      "autonomous_system": {
        "asn": 273189,
        "name": "CA NETWORK S.A. DE C.V.",
        "organization": "CA NETWORK S.A. DE C.V.",
        "country": "HN",
        "rir": "LACNIC"
      }
    },
    "location": { "city": "Tegucigalpa", "country": "Honduras", ... }
  }
  ```
  The `network.cidr` field is a bonus: we can cache the whole prefix, not just the
  single IP, so the next IP in the same /21 is a cache hit with zero API calls.
- **Cardinality**: Top-N destinations per host per sample window (keep the N
  heaviest destinations per host, fold the rest into an "others" bucket).

Context note (from memory): tekium's schema is **not** runner-driven — `__migrations`
stopped at 00020 and `lan_traffic_samples` (00024) was applied by hand. So new
migration files go in the repo via the runner, but on tekium the `ALTER TABLE`
must be applied manually. The plan calls this out where it matters.

---

## Phase 0 — Fix the attribution bug (independent, more urgent)

**Original symptom**: the Echo Show showed ~29 GB upload in 24h — looked
implausible for an alarm-clock device.

**Resolved by measurement — the totals are NOT a bug.** 24h totals for
192.168.99.126: `up=29 GB, down=109 GB, flows=131,058`, matching the panel
screenshot (↓109 / ↑29). The up/down split is **correct** — TCP tuple order was
verified (forward `src=LAN … dport=443` printed first, reply second). The device
genuinely streams ~138 GB/day, consistent with an always-on Echo Show display
(Amazon Photos slideshow, featured content, video). Not a compromise — a usage
finding. The "direction inverted" and "double-counting" hypotheses were
**disproven by the data**.

Two **real, confirmed** defects remain — both about *attribution quality*, not
inflated totals:

1. **Broken service-port classification.** `serverPort = Math.Min(sport, dport)`
   mislabels the service. Confirmed: the heaviest UDP flows are actually **DNS**
   (`src=LAN sport=54938 dport=53 → 1.1.1.1`), but `Math.Min(54938, 53)`… picks
   53 correctly there — yet for media/ephemeral-vs-ephemeral flows it picks a
   meaningless high port, which is why the panel showed buckets like `udp 10920`,
   `udp 5881`. The "top services" view is unreliable for any flow whose service
   port isn't the numeric minimum.
   - Fix: stop using `Math.Min`. Identify the LAN host's tuple by **matching its
     IP** (not tuple index), then take `dst_port` = that tuple's `dport` (the port
     the LAN host connected *to* = the real service port). For flows with no
     well-known port on either side, store proto with `dst_port = NULL` rather
     than a bogus ephemeral number.

2. **Firewall's own WAN IPs appear as destinations.** Confirmed: reply tuples
   carry `dst=154.12.104.135` (a firewall WAN IP) after SNAT. Today it's harmless
   (dst is discarded), but **Phase 1 will record dst_ip**, and without a guard the
   per-destination stats would be polluted with the firewall's own addresses
   instead of the real destination. The host's own IPs are: `154.12.104.135`,
   `190.107.150.161`, `192.168.3.2` (WANs), `192.168.99.1` (LAN gw), `127.0.0.1`.
   - Fix: when recording the destination, always use the **forward** tuple's `dst`
     (the real pre-NAT destination), never the reply tuple's `dst` (= our WAN IP).
     Build an `IReadOnlySet<IPAddress>` of the host's own IPs at startup
     (DI-wrapped `NetworkInterface.GetAllNetworkInterfaces()`) and reject any flow
     whose recorded dst is an own-IP or RFC1918 (intra-LAN/management noise).

Note: the **totals don't change** — these fixes correct *which port* and *which
destination* get recorded, which is what makes Phase 1's per-destination data
trustworthy.

**Tests**: LAN-side tuple selection + port derivation becomes a pure function over
(parsed flow, ownIps) — unit-test in NetFirewall.Tests: DNS → 53, media flow →
NULL port (not ephemeral), dst = forward-tuple dst (not WAN IP), own-IP/RFC1918
dst rejected, genuine egress still counted.

This phase ships **before** Phase 1 — no schema change, and it makes Phase 1's
per-destination data correct from day one.

---

## Phase 1 — Capture the destination (the core fix)

### 1.1 Schema migration — add destination columns

New file `NetFirewall.Services/sql/migrations/00028_lan_traffic_dst.sql`:

```sql
BEGIN;

-- Per-destination accounting. dst_ip NULL = the "others" rollup bucket
-- (traffic to destinations that didn't make the per-host top-N this window).
ALTER TABLE lan_traffic_samples
    ADD COLUMN IF NOT EXISTS dst_ip inet;

-- Index for per-host-per-destination queries.
CREATE INDEX IF NOT EXISTS idx_lan_traffic_src_dst
    ON lan_traffic_samples (src_ip, dst_ip, sampled_at DESC);

COMMIT;
```

`dst_ip` is **nullable** on purpose:
- existing rows keep working (they predate the column),
- the per-window "others" rollup is stored as a row with `dst_ip IS NULL`.

### 1.2 ASN/org cache table

New file `NetFirewall.Services/sql/migrations/00029_ip_asn_cache.sql`:

```sql
BEGIN;

-- Cache keyed by PREFIX (ip.guide returns network.cidr), so every IP inside an
-- already-seen prefix is a cache hit with zero further API calls. Lookups match
-- with the inet containment operator:  WHERE prefix >>= @ip.
CREATE TABLE IF NOT EXISTS ip_asn_cache (
    prefix      cidr                     PRIMARY KEY,  -- e.g. 154.12.104.0/21
    asn         varchar(16),             -- e.g. "AS273189"
    org         varchar(160),            -- e.g. "CA NETWORK S.A. DE C.V."
    country     varchar(2),              -- ISO-3166 alpha-2
    city        varchar(120),
    resolved_at timestamp with time zone NOT NULL DEFAULT now(),
    -- failed lookups get a row too (org NULL) so we don't hammer the API;
    -- retried only after the row ages past the resolver's TTL.
    ok          boolean                  NOT NULL DEFAULT true
);

-- GiST index on the cidr column makes the >>= containment lookup fast.
CREATE INDEX IF NOT EXISTS idx_ip_asn_prefix_gist ON ip_asn_cache USING gist (prefix inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_asn_resolved_at ON ip_asn_cache (resolved_at);

COMMIT;
```

Lookup join becomes `LEFT JOIN ip_asn_cache c ON c.prefix >>= s.dst_ip` (prefix
contains the destination IP). When ip.guide fails to return a CIDR, fall back to
caching the single `/32`.

### 1.3 ConntrackSamplerService changes

In `SampleOnceAsync` (NetFirewall.Services/Monitoring/ConntrackSamplerService.cs):

- Change `BucketKey` from `(SrcIp, Proto, DstPort)` to
  `(SrcIp, DstIp, Proto, DstPort)`. The parser already extracts `dst` (line 237)
  — stop discarding it in `IsLanSrc` (the dst is the **forward** tuple's dst,
  i.e. the *real* pre-NAT destination, which is what we want — confirmed during
  the Echo Show diagnosis).
- After aggregating per-(src,dst,proto,dport) buckets, apply **Top-N per host**:
  - group buckets by `SrcIp`,
  - sort each host's destinations by total bytes desc,
  - keep top N (config, default 20),
  - sum the tail into one bucket with `DstIp = null` (the "others" rollup).
- `InsertAsync` writes `dst_ip` (or NULL for the rollup).
- Feed every *new* `dst_ip` to the ASN resolver's enqueue method (fire-and-forget
  into a channel; never blocks the sample cycle).

New config knob on `ConntrackSamplerOptions`:
- `TopDestinationsPerHost` (int, default 20).

### 1.4 ASN resolver service (deferred, cached, off hot path)

New `IIpAsnResolver` + `IpAsnResolver : BackgroundService` in
`NetFirewall.Services/Monitoring/`:

- Bounded `Channel<IPAddress>` of IPs to resolve (dedup against an in-memory
  `HashSet` of recently-enqueued IPs + the `ip_asn_cache` table).
- Worker loop: dequeue, skip private/LAN/bogon ranges, check cache freshness
  (`SELECT ... WHERE prefix >>= @ip`), call `https://ip.guide/{ip}` via injected
  `HttpClient` (use `ServiceDefaults` resilience pipeline), parse `network.cidr`
  + `network.autonomous_system.{asn,organization,country}` + `location.city`,
  upsert into `ip_asn_cache` keyed by the returned prefix.
- ip.guide is free with no documented rate limit, but we still throttle politely
  (token-bucket, configurable) to be a good citizen and survive transient 429s
  via the resilience pipeline.
- Failed lookups still get a row (`ok=false`, single `/32`) so we don't retry
  constantly; re-resolve only after a TTL (e.g. 30 days, configurable).
- Registered as a singleton hosted service in
  `NetFirewall.Daemon/Program.cs` (confirmed: the sampler runs in the **daemon**,
  next to `ConntrackSamplerService` at line 127, NOT in DhcpServer).

Config: `IpAsnResolverOptions { Enabled, ApiBaseUrl="https://ip.guide", MaxPerMinute, FailTtlDays }`.
No token needed.

**Privacy/authorization note**: this sends destination IPs your network talks to
to ip.guide. That's an outbound disclosure to a third party. Conscious choice
made by the user: **`Enabled=true` by default** (auto-enrich from first boot).
We only ever send *destination* IPs, never source/LAN IPs or payloads. The flag
exists so it can be turned off.

---

## Phase 2 — Surface it in the API + UI

### 2.1 TopTalkersService — new query

Add `GetTopDestinationsForHostAsync(srcIp, hours, limit)` to
`ITopTalkersService` + `TopTalkersService`:

```sql
SELECT s.dst_ip,
       SUM(s.bytes_in)::bigint  AS bin,
       SUM(s.bytes_out)::bigint AS bout,
       SUM(s.flow_count)::int   AS flows,
       c.asn, c.org, c.country
FROM lan_traffic_samples s
LEFT JOIN ip_asn_cache c ON c.prefix >>= s.dst_ip
WHERE s.src_ip = @src
  AND s.sampled_at > now() - make_interval(hours => @hours)
GROUP BY s.dst_ip, c.asn, c.org, c.country
ORDER BY (SUM(s.bytes_in) + SUM(s.bytes_out)) DESC
LIMIT @limit
```

New record `TopTalkerDestination(DstIp, Org, Asn, Country, BytesIn, BytesOut, FlowCount)`.
`dst_ip IS NULL` row renders as "others".

### 2.2 Daemon endpoint

New: `GET /v1/system/top-talkers/host/{srcIp}/destinations?hours=24&limit=10`
in `SystemEndpoints.cs`, delegating to the service (controllers/endpoints
compose, services do — per CLAUDE.md rule 10).

### 2.3 Web UI — drill-down

- Make each host row in `_TopTalkersLive.cshtml` expandable (HTMX `hx-get` to a
  new MonitoringController action → new partial `_HostDestinations.cshtml`).
- The partial lists destinations with org/ASN/country badge, bytes in/out.
- Reuse existing toast/feedback + theme tokens (CLAUDE.md rules 6 & 9).
- New controller action in `MonitoringController` calls
  `_daemon.GetHostDestinationsAsync(...)` — no SQL in the controller.
- `IDaemonClient` gets the matching client method.

All async, typed `ServiceResponse<T>`, partials, theme tokens — per project rules.

---

## Phase 3 (optional, follow-up) — alerting

Out of scope for this plan, noted for later: alert when a host uploads > X bytes
to a destination/ASN not seen before in Y window. Depends on Phases 1–2 landing.

---

## Open question for the user before coding

- **ASN resolver default state**: ship `Enabled=true` (auto-enrich, sends dst IPs
  to ipinfo.io) or `Enabled=false` (opt-in, no external calls until you flip it)?
  Given the firewall context I lean **opt-in default (false)** and let you enable
  it knowingly.

## Testing & rollout

- Unit tests: Top-N-per-host rollup logic (pure function, no IO) in
  NetFirewall.Tests; ASN cache upsert/freshness logic with a mocked HttpClient.
- The sampler delta logic is unchanged; only the bucket key + insert widen.
- **tekium rollout**: apply `00028`/`00029` SQL by hand (schema not runner-driven
  there). Verify with `\d lan_traffic_samples`.
- No nftables changes — this is observability only. Bandwidth *control* (mangle/
  QoS per host) remains a separate, larger effort not in this plan.
```