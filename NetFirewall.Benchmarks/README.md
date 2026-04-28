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
| `ProcessSinglePacketBenchmarks` | Full `DhcpWorker.ProcessSinglePacketAsync` loop with mocked `IDhcpServerService` and recording send seam — measures parse + dispatch + counter increment + send-prep, no DB or socket. Variants: Discover/Request × empty/non-empty service response. |

The headline number is the **`Allocated`** column. After the perf passes documented
in `docs/PerformanceAnalysis.md`, every variant should show `-` (zero managed
allocations per operation). A regression to non-zero means someone reintroduced
LINQ, `string.Join`, `new byte[N]`, boxing, or similar in the hot path —
investigate before merging.

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
