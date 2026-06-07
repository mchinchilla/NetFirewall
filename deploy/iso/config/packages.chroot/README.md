# config/packages.chroot/

live-build installs every `*.deb` dropped here into the appliance chroot at build
time, **offline**, resolving its dependencies against the packages pulled by
`config/package-lists/netfirewall.list.chroot`.

CI (`.github/workflows/build-iso.yml`, job `deb`) builds `netfirewall_*.deb` and
copies it here before running `lb build`:

```
cp netfirewall_*.deb deploy/iso/config/packages.chroot/
```

The `.deb` itself is **gitignored** (see `deploy/iso/.gitignore`) — never commit
a built package into the source tree. This README is the only tracked file in
this directory.
