-- ASN / organisation cache for destination IPs, used to enrich the top-talkers
-- per-destination view ("Amazon" vs "some provider in HN" at a glance).
--
-- Keyed by PREFIX, not single IP: ip.guide returns network.cidr alongside the
-- ASN, so we cache the whole prefix. Every other IP inside an already-seen
-- prefix is then a cache hit with zero further API calls. Lookups use the inet
-- containment operator:  WHERE prefix >>= @ip.
--
-- Resolution happens off the sampler hot path in a background worker
-- (IpAsnResolver) that calls https://ip.guide/{ip}. Failed lookups still get a
-- row (ok=false, single /32) so we don't hammer the API; they're retried only
-- after the resolver's fail-TTL.

BEGIN;

CREATE TABLE IF NOT EXISTS ip_asn_cache (
    prefix      cidr                     PRIMARY KEY,   -- e.g. 154.12.104.0/21
    asn         varchar(16),                            -- e.g. "AS273189"
    org         varchar(160),                           -- e.g. "CA NETWORK S.A. DE C.V."
    country     varchar(2),                             -- ISO-3166 alpha-2
    city        varchar(120),
    ok          boolean                  NOT NULL DEFAULT true,
    resolved_at timestamp with time zone NOT NULL DEFAULT now()
);

-- GiST index makes the >>= containment lookup fast.
CREATE INDEX IF NOT EXISTS idx_ip_asn_prefix_gist ON ip_asn_cache USING gist (prefix inet_ops);
-- For the resolver's TTL sweep / retry of stale failures.
CREATE INDEX IF NOT EXISTS idx_ip_asn_resolved_at ON ip_asn_cache (resolved_at);

COMMIT;
