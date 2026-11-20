# NetFirewall.Benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org/) harness for empirically validating
the per-packet allocation budget claimed in [`docs/PerformanceAnalysis.md`](../docs/PerformanceAnalysis.md).

## Run

From the repo root, **always in Release config**:

```bash
# All benchmarks, default (medium) precision — takes a few minutes
dotnet run --project NetFirewall.Benchmarks -c Release

# Filter to one set, faster smoke run (less precise time numbers, allocation
# numbers are still credible)
dotnet run --project NetFirewall.Benchmarks -c Release -- \
  --filter "*ProcessSinglePacket*" --job short
```

## What's measured

| Benchmark | What it covers |
|---|---|
| `ProcessSinglePacketBenchmarks` | `DhcpWorker.ProcessSinglePacketAsync` with a fixed-reply fake `IDhcpServerService` and a recording send seam — parse + DI scope + dispatch + send-prep, no DB or socket. Variants: Discover/Request × empty/non-empty reply. |
| `FullPipelineBenchmarks` | Raw packet → worker → a DI scope per packet → the REAL `DhcpServerService` (subnet selection, class match, address choice, every option incl. DNS/NTP/domain search/121 routes, serialization). Only the DB-backed services are faked (pre-completed tasks). This is the per-lease CPU cost. |

### Measured (2026-11-20, Apple M-series arm64, Workstation GC like production, in-process)

| Benchmark | .NET 10.0.14 | .NET 11.0.0 | Allocated |
|---|---|---|---|
| FullPipeline — Discover | 904 ns | 864–887 ns | 2.69 KB |
| FullPipeline — Request | 885 ns | 873–903 ns | 2.80 KB |
| ProcessSinglePacket (worker only) | — | 189–232 ns | 1.0–1.1 KB |

Same code on both runtimes: .NET 11 is **neutral** for the DHCP hot path (within noise). With
Server GC .NET 11 measured ~17 % slower (4× more gen0 GCs for the same bytes) — irrelevant
today because the DHCP server runs Workstation GC; re-measure before ever switching it.

**Run with `DOTNET_gcServer=0`** to match production (this project's csproj enables Server GC).
**Never use `[IterationSetup]`** in these benchmarks: it forces one invocation per iteration,
so times become noise and allocations unmeasurable — the old "`Allocated: -` = zero allocations"
claim came from exactly that. Never use Moq on a benchmarked path: it records every invocation
and the run stalls. The gate is **no regression vs the numbers above**, not zero.

## Why a separate project

Benchmarks need:
- Release-built code with no test instrumentation
- No xUnit collection / test discovery overhead
- `<ServerGarbageCollection>true</ServerGarbageCollection>` to mirror production GC
- Reference to internals of DhcpServer (via `InternalsVisibleTo`) so we can
  drive `ProcessSinglePacketAsync` and override `SendResponseAsync`

Keeping them in `NetFirewall.Tests` would either pollute the test suite (every
`dotnet test` would try to discover them) or require ifdefs. Separate project
is cleaner.

## Adding a new benchmark

1. New class in this project with `[MemoryDiagnoser]` and `[Benchmark]` methods.
2. Use `[GlobalSetup]` / `[IterationSetup]` for fixture work that shouldn't be timed.
3. Run once with `--job short` to sanity-check, then commit and run with default
   job for the headline numbers.
4. Update `docs/PerformanceAnalysis.md` with the validated figures.
