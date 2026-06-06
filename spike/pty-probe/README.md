# Phase 3a transport spikes (web terminal)

Two unknowns had to be de-risked before building the terminal. **One is already
proven; the other needs you to run it on tekium.**

## ✅ Spike 1 — `ClientWebSocket` over the Unix socket (DONE, passed locally)

Confirmed on macOS that `ClientWebSocket.ConnectAsync(uri, HttpMessageInvoker, ct)`
— using the *exact* UDS `ConnectCallback` from `DaemonClient` — connects to a
Kestrel `ListenUnixSocket` + `HttpProtocols.Http1` listener, sends/receives
frames, and the `X-NetFw-Session` header survives the upgrade. The macOS sandbox
is irrelevant to this question (it's a pure .NET-API integration test), so a local
pass is conclusive. **No manual HTTP/1.1 Upgrade fallback needed.**

## ⏳ Spike 2 — PTY allocation under the hardened systemd sandbox (RUN ON TEKIUM)

This is the one that can only be answered on a real systemd host: can we allocate
a PTY, spawn a child through it, resize it, read it back, and reap it, **under
`PrivateDevices=yes` + the daemon's `SystemCallFilter`**? Dev hosts apply none of
those, so only tekium's answer counts.

### How to run

Copy `pty-probe.cs` to tekium (needs the .NET 10 SDK, already present). Then:

**A) Baseline — plain root (proves the code works at all):**
```
dotnet run pty-probe.cs
```
(run as root; it P/Invokes libutil `openpty`/`forkpty`)

**B) The real test — under the daemon's sandbox:**
The probe prints a ready-to-paste `systemd-run` command at the end of run (A)
that wraps it in the same key sandbox directives as `netfirewall-daemon.service`
(`PrivateDevices=yes`, `ProtectSystem=strict`, the `SystemCallFilter` pair). Run
that. If `dotnet run <file>` is awkward under `systemd-run`, build first:
```
dotnet build pty-probe.cs -o /tmp/ptyprobe
systemd-run --pty --same-dir --wait --collect \
  -p PrivateDevices=yes -p ProtectSystem=strict -p NoNewPrivileges=yes \
  -p 'SystemCallFilter=@system-service' \
  -p 'SystemCallFilter=~@mount @swap @reboot @raw-io @cpu-emulation' \
  /tmp/ptyprobe/pty-probe
```

### What to send back

The whole output of **both** runs. The lines that matter:
- `SPIKE-PTY: PASS` or `FAIL`
- the `openpty()` line (and its errno if it failed — that's the sandbox blocking it)
- `/dev/ptmx exists` / `/dev/pts/ptmx exists`
- the verbatim child output block (should contain `/dev/pts/N`, `COLUMNS=120`, `PTY_CHILD_OK`)

### What each outcome means for the build

- **Both PASS** → green light. Real impl uses `openpty` + `posix_spawn`
  (`POSIX_SPAWN_SETSID`) in the daemon; no unit changes needed beyond the nginx
  WebSocket fix.
- **A passes, B fails at `openpty` (EACCES/ENODEV)** → `PrivateDevices=yes` is
  blocking `/dev/ptmx`. Fixes, in order of preference: open `/dev/pts/ptmx`
  explicitly; add `DeviceAllow=/dev/ptmx rw`; or last resort relax
  `PrivateDevices` for the daemon. I'll adapt the impl + unit to whichever the
  probe shows works.
- **B fails at a later step (ioctl/forkpty/waitpid with a syscall errno)** → the
  `SystemCallFilter` is too tight; I'll add the specific syscall to an allow line.

This directory is a throwaway spike — not wired into the build or the solution.
Delete `spike/` once the terminal lands.
