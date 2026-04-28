using BenchmarkDotNet.Running;
using NetFirewall.Benchmarks;

// Entry point — pick a benchmark by class name (e.g. `dotnet run -c Release -- --filter '*ProcessSinglePacket*'`)
// or run them all with `dotnet run -c Release`.
BenchmarkSwitcher.FromAssembly(typeof(ProcessSinglePacketBenchmarks).Assembly).Run(args);
