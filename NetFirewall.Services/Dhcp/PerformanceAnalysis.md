# DHCP Server Performance Analysis

## Critical Path: DHCP DISCOVER → OFFER

```
Client DISCOVER packet arrives
        │
        ▼ (< 1µs)
┌─────────────────────────────────┐
│ 1. UDP Receive (kernel)         │
│    - Zero-copy with ArrayPool   │
└─────────────────────────────────┘
        │
        ▼ (< 5µs)
┌─────────────────────────────────┐
│ 2. Channel.WriteAsync           │
│    - Lock-free queue            │
└─────────────────────────────────┘
        │
        ▼ (< 10µs)
┌─────────────────────────────────┐
│ 3. Parse DHCP packet            │
│    - Span<byte> parsing         │
│    - stackalloc for MAC         │
│    - No heap allocations        │
└─────────────────────────────────┘
        │
        ▼ (< 5µs)
┌─────────────────────────────────┐
│ 4. Find subnet (cached)         │
│    - ConcurrentDictionary       │
│    - 5-min cache                │
└─────────────────────────────────┘
        │
        ▼ (100-500µs) ← BOTTLENECK
┌─────────────────────────────────┐
│ 5. Database: Find available IP  │
│    - PostgreSQL query           │
│    - Network roundtrip          │
└─────────────────────────────────┘
        │
        ▼ (< 20µs)
┌─────────────────────────────────┐
│ 6. Build OFFER packet           │
│    - ArrayPool buffer           │
│    - Direct byte writes         │
└─────────────────────────────────┘
        │
        ▼ (< 5µs)
┌─────────────────────────────────┐
│ 7. UDP Send                     │
└─────────────────────────────────┘

Total: ~150-550µs per DISCOVER
Theoretical max: ~2,000-6,500 requests/second (single core)
```

## Bottleneck Analysis

### 1. Database Roundtrip (Primary Bottleneck)
- **Current**: 100-500µs per query
- **Mitigation**:
  - Connection pooling (implemented)
  - Prepared statements
  - In-memory lease cache with write-through

### 2. Potential Optimizations

```csharp
// A. In-memory lease cache (reduce DB hits by 90%)
private static readonly ConcurrentDictionary<string, LeaseInfo> _leaseCache = new();

// B. Batch writes with periodic flush
private readonly Channel<LeaseUpdate> _writeQueue = Channel.CreateBounded<LeaseUpdate>(1000);

// C. Read replicas for lookups
// Primary for writes, replica for reads
```

## Memory Profile

```
Per DHCP Request:
├── ArrayPool buffer (1024 bytes, reused)    = 0 allocations
├── DhcpRequest struct                       = ~200 bytes (stack possible)
├── Span<byte> parsing                       = 0 allocations
├── MAC string (if new client)               = 17 bytes
├── Response buffer (reused)                 = 0 allocations
└── Total new allocations                    ≈ 0-50 bytes per request

GC Pressure: MINIMAL (Gen0 only, infrequent)
```

## Scalability

### Single Server
- **CPU**: 1 core can handle ~3,000-5,000 leases/sec
- **Memory**: ~100MB base + 1KB per cached lease
- **Network**: 1 Gbps easily handles 50,000+ DHCP packets/sec

### With Failover (2 servers)
- **Active-Active**: Each handles 50% load (hash-based split)
- **Active-Passive**: Failover in < 60 seconds
- **Throughput**: 2x single server with proper split

### Horizontal Scaling Options
1. **Subnet sharding**: Different servers for different VLANs
2. **Geographic distribution**: Regional DHCP servers
3. **PostgreSQL clustering**: Patroni/Citus for DB scaling

## Comparison: Memory-based vs PostgreSQL-backed

| Aspect | In-Memory (ISC-DHCP) | PostgreSQL (NetFirewall) |
|--------|---------------------|--------------------------|
| Speed | 10,000+ leases/s | 3,000-8,000 leases/s |
| Durability | Crash = data loss | ACID guaranteed |
| Replication | Manual | Built-in streaming |
| Queryability | None | Full SQL |
| Monitoring | Log parsing | SQL queries |
| Backup | File copy | pg_dump, PITR |
| HA | Custom scripts | Patroni, pgpool |

## Recommended Production Config

```ini
# PostgreSQL tuning
shared_buffers = 256MB
effective_cache_size = 1GB
max_connections = 100
checkpoint_completion_target = 0.9

# .NET tuning (runtimeconfig.json)
{
  "configProperties": {
    "System.GC.Server": true,
    "System.GC.Concurrent": true,
    "System.Threading.ThreadPool.MinThreads": 16
  }
}
```

## Future Optimizations

1. **Redis caching layer** for lease lookups
2. **Native AOT compilation** for faster startup
3. **io_uring** on Linux for better I/O
4. **Memory-mapped lease file** + async PostgreSQL sync
5. **DPDK** for kernel bypass (extreme performance)
