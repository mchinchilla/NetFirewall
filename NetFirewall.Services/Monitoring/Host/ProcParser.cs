using System.Buffers.Text;

namespace NetFirewall.Services.Monitoring.Host;

/// <summary>CPU counters from <c>/proc/stat</c>, in ticks since boot.</summary>
/// <param name="User">user + nice.</param>
/// <param name="System">system + irq + softirq.</param>
/// <param name="Total">The first eight fields. guest and guest_nice are already inside user and aren't added again.</param>
internal readonly record struct CpuTimes(long User, long System, long IoWait, long Total);

/// <summary>The parts of <c>/proc/meminfo</c> the monitor shows, in bytes.</summary>
internal readonly record struct MemoryCounters(long Total, long Used, long Cache, long SwapTotal, long SwapUsed);

/// <summary>A mounted filesystem, from <c>/proc/self/mountinfo</c>.</summary>
internal sealed record MountedFilesystem(string MountPoint, string Format, string Device);

/// <summary>
/// Parses <c>/proc</c> files over the raw bytes, never decoding to text: they're
/// read every second and the monitor must not spend on that what it takes from
/// the firewall. Pure functions, no IO — the sampler owns the reads.
/// </summary>
internal static class ProcParser
{
    /// <summary><c>/proc/diskstats</c> sectors are always 512 bytes, whatever the disk.</summary>
    private const long SectorBytes = 512;

    /// <summary>The <c>PF_KTHREAD</c> flag in field 9 of <c>/proc/[pid]/stat</c>.</summary>
    private const long KernelThreadFlag = 0x00200000;

    public static bool TryParseCpu(ReadOnlySpan<byte> stat, out CpuTimes cpu, out int cores)
    {
        cpu = default;
        cores = 0;
        bool found = false;
        Span<long> fields = stackalloc long[8];

        foreach (Range range in stat.Split((byte)'\n'))
        {
            ReadOnlySpan<byte> line = stat[range];
            if (!line.StartsWith("cpu"u8))
            {
                // CPU lines come together at the top: past the last one there are no more.
                if (found)
                {
                    break;
                }

                continue;
            }

            if (line.Length > 3 && IsDigit(line[3]))
            {
                cores++;
                continue;
            }

            fields.Clear();
            ReadOnlySpan<byte> rest = line[3..];
            for (int i = 0; i < fields.Length && Utf8Parser.TryParse(NextToken(ref rest), out long value, out _); i++)
            {
                fields[i] = value;
            }

            cpu = new CpuTimes(
                fields[0] + fields[1],
                fields[2] + fields[5] + fields[6],
                fields[4],
                fields[0] + fields[1] + fields[2] + fields[3] + fields[4] + fields[5] + fields[6] + fields[7]);
            found = true;
        }

        return found && cores > 0;
    }

    public static bool TryParseMemory(ReadOnlySpan<byte> meminfo, out MemoryCounters memory)
    {
        long total = 0, available = -1, free = 0, buffers = 0, cached = 0, reclaimable = 0, swapTotal = 0, swapFree = 0;

        foreach (Range range in meminfo.Split((byte)'\n'))
        {
            ReadOnlySpan<byte> line = meminfo[range];
            int colon = line.IndexOf((byte)':');
            if (colon <= 0)
            {
                continue;
            }

            ReadOnlySpan<byte> rest = line[(colon + 1)..];
            if (!Utf8Parser.TryParse(NextToken(ref rest), out long kilobytes, out _))
            {
                continue;
            }

            long bytes = kilobytes * 1024;
            ReadOnlySpan<byte> key = line[..colon];
            Assign(key, "MemTotal"u8, bytes, ref total);
            Assign(key, "MemAvailable"u8, bytes, ref available);
            Assign(key, "MemFree"u8, bytes, ref free);
            Assign(key, "Buffers"u8, bytes, ref buffers);
            Assign(key, "Cached"u8, bytes, ref cached);
            Assign(key, "SReclaimable"u8, bytes, ref reclaimable);
            Assign(key, "SwapTotal"u8, bytes, ref swapTotal);
            Assign(key, "SwapFree"u8, bytes, ref swapFree);
        }

        if (total <= 0)
        {
            memory = default;
            return false;
        }

        // MemAvailable exists since 3.14; before that, free plus what can be released.
        if (available < 0)
        {
            available = free + buffers + cached;
        }

        memory = new MemoryCounters(total, Math.Max(0, total - available), buffers + cached + reclaimable, swapTotal, Math.Max(0, swapTotal - swapFree));
        return true;
    }

    public static bool TryParseLoad(ReadOnlySpan<byte> loadavg, out double load1, out double load5, out double load15)
    {
        load5 = load15 = 0;

        return Utf8Parser.TryParse(NextToken(ref loadavg), out load1, out _)
               && Utf8Parser.TryParse(NextToken(ref loadavg), out load5, out _)
               && Utf8Parser.TryParse(NextToken(ref loadavg), out load15, out _);
    }

    public static bool TryParseUptime(ReadOnlySpan<byte> uptime, out double seconds) =>
        Utf8Parser.TryParse(NextToken(ref uptime), out seconds, out _);

    /// <summary>Bytes read and written since boot, adding whole disks only.</summary>
    public static bool TryParseDisks(ReadOnlySpan<byte> diskstats, out long read, out long written)
    {
        read = written = 0;
        bool any = false;

        foreach (Range range in diskstats.Split((byte)'\n'))
        {
            ReadOnlySpan<byte> rest = diskstats[range];
            NextToken(ref rest);
            NextToken(ref rest);
            if (!IsWholeDisk(NextToken(ref rest)))
            {
                continue;
            }

            // reads, reads merged, sectors read, ms; writes, writes merged, sectors written.
            NextToken(ref rest);
            NextToken(ref rest);
            long sectorsRead = Number(NextToken(ref rest));
            NextToken(ref rest);
            NextToken(ref rest);
            NextToken(ref rest);
            long sectorsWritten = Number(NextToken(ref rest));

            read += sectorsRead * SectorBytes;
            written += sectorsWritten * SectorBytes;
            any = true;
        }

        return any;
    }

    /// <summary>
    /// A whole disk — not a partition, loop, LVM (<c>dm-</c>) or RAID (<c>md</c>), which
    /// would count again what the disk underneath already counts.
    /// </summary>
    public static bool IsWholeDisk(ReadOnlySpan<byte> name)
    {
        if (name.StartsWith("nvme"u8))
        {
            return name.Length > 4 && name[4..].IndexOf((byte)'p') < 0;
        }

        if (name.StartsWith("mmcblk"u8))
        {
            return name.Length > 6 && name[6..].IndexOf((byte)'p') < 0;
        }

        if (name.StartsWith("xvd"u8))
        {
            return AllLetters(name[3..]);
        }

        return (name.StartsWith("sd"u8) || name.StartsWith("vd"u8) || name.StartsWith("hd"u8)) && AllLetters(name[2..]);
    }

    /// <summary>
    /// Bytes received and sent since boot on the physical NICs. Loopback,
    /// container bridges, IFB (QoS ingress mirror) and tunnels are skipped: each
    /// of them re-counts bytes a physical NIC already counted.
    /// </summary>
    public static bool TryParseNetwork(ReadOnlySpan<byte> netdev, out long received, out long sent)
    {
        received = sent = 0;
        bool any = false;

        foreach (Range range in netdev.Split((byte)'\n'))
        {
            ReadOnlySpan<byte> line = netdev[range];
            int colon = line.IndexOf((byte)':');
            if (colon <= 0)
            {
                continue;
            }

            ReadOnlySpan<byte> name = line[..colon].Trim((byte)' ');
            if (name.IsEmpty || IsVirtualInterface(name))
            {
                continue;
            }

            ReadOnlySpan<byte> rest = line[(colon + 1)..];
            long rx = Number(NextToken(ref rest));
            for (int i = 0; i < 7; i++)
            {
                NextToken(ref rest);
            }

            long tx = Number(NextToken(ref rest));
            received += rx;
            sent += tx;
            any = true;
        }

        return any;
    }

    /// <summary>
    /// One <c>/proc/[pid]/stat</c> line. The name sits in parentheses and may hold
    /// spaces and parentheses of its own, so fields are counted from the last <c>)</c>.
    /// </summary>
    /// <param name="ticks">utime + stime.</param>
    /// <param name="residentPages">rss, in pages.</param>
    public static bool TryParseProcess(ReadOnlySpan<byte> stat, out ReadOnlySpan<byte> name, out long ticks, out long residentPages, out bool kernelThread)
    {
        name = default;
        ticks = residentPages = 0;
        kernelThread = false;

        int open = stat.IndexOf((byte)'(');
        int close = stat.LastIndexOf((byte)')');
        if (open < 0 || close <= open)
        {
            return false;
        }

        name = stat[(open + 1)..close];
        ReadOnlySpan<byte> rest = stat[(close + 1)..];

        // The first field after the name is #3 (state): field N is token N - 3.
        long utime = 0, stime = 0, flags = 0;
        for (int field = 3; field <= 24; field++)
        {
            ReadOnlySpan<byte> token = NextToken(ref rest);
            if (token.IsEmpty)
            {
                return false;
            }

            switch (field)
            {
                case 9: flags = Number(token); break;
                case 14: utime = Number(token); break;
                case 15: stime = Number(token); break;
                case 24: residentPages = Number(token); break;
            }
        }

        ticks = utime + stime;
        kernelThread = (flags & KernelThreadFlag) != 0;
        return true;
    }

    /// <summary>An unreadable counter counts zero: half a sample beats none.</summary>
    private static long Number(ReadOnlySpan<byte> token) => Utf8Parser.TryParse(token, out long value, out _) ? value : 0;

    /// <summary>Local disk formats. Network filesystems are skipped: a hung NFS would hang the sampler.</summary>
    private static readonly HashSet<string> LocalFormats = new(StringComparer.Ordinal)
    {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat",
    };

    /// <summary>
    /// Mounted local disks, one per device. systemd's <c>ReadWritePaths</c> and
    /// <c>PrivateTmp</c> are bind mounts of the same disk: they're recognised by not
    /// mounting their root, and if a device still repeats the first mount wins.
    /// </summary>
    public static IReadOnlyList<MountedFilesystem> ParseMounts(string mountinfo)
    {
        ArgumentNullException.ThrowIfNull(mountinfo);
        var byDevice = new Dictionary<string, MountedFilesystem>(StringComparer.Ordinal);

        foreach (string line in mountinfo.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // id parent major:minor root mountpoint options [optional...] - fstype source superoptions
            string[] fields = line.Split(' ');
            int dash = Array.IndexOf(fields, "-");
            if (fields.Length < 5 || dash < 5 || dash + 1 >= fields.Length
                || fields[3] != "/" || !LocalFormats.Contains(fields[dash + 1]))
            {
                continue;
            }

            var mount = new MountedFilesystem(Unescape(fields[4]), fields[dash + 1], fields[2]);
            byDevice.TryAdd(mount.Device, mount);
        }

        return [.. byDevice.Values.OrderBy(mount => mount.MountPoint, StringComparer.Ordinal)];
    }

    /// <summary>The kernel writes spaces and friends in octal: <c>\040</c>.</summary>
    private static string Unescape(string value)
    {
        if (!value.Contains('\\', StringComparison.Ordinal))
        {
            return value;
        }

        var text = new System.Text.StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 3 < value.Length && IsOctal(value[i + 1]) && IsOctal(value[i + 2]) && IsOctal(value[i + 3]))
            {
                text.Append((char)(((value[i + 1] - '0') << 6) | ((value[i + 2] - '0') << 3) | (value[i + 3] - '0')));
                i += 3;
            }
            else
            {
                text.Append(value[i]);
            }
        }

        return text.ToString();
    }

    private static void Assign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> wanted, long value, ref long target)
    {
        if (key.SequenceEqual(wanted))
        {
            target = value;
        }
    }

    private static bool IsVirtualInterface(ReadOnlySpan<byte> name) =>
        name.SequenceEqual("lo"u8)
        || name.StartsWith("veth"u8)
        || name.StartsWith("docker"u8)
        || name.StartsWith("br-"u8)
        || name.StartsWith("virbr"u8)
        || name.StartsWith("ifb"u8)
        || name.StartsWith("wg"u8)
        || name.StartsWith("tun"u8);

    private static ReadOnlySpan<byte> NextToken(ref ReadOnlySpan<byte> text)
    {
        int start = 0;
        while (start < text.Length && IsSpace(text[start]))
        {
            start++;
        }

        int end = start;
        while (end < text.Length && !IsSpace(text[end]))
        {
            end++;
        }

        ReadOnlySpan<byte> token = text[start..end];
        text = text[end..];
        return token;
    }

    private static bool IsSpace(byte value) => value is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';

    private static bool IsOctal(char value) => value is >= '0' and <= '7';

    private static bool IsDigit(byte value) => value is >= (byte)'0' and <= (byte)'9';

    private static bool AllLetters(ReadOnlySpan<byte> text)
    {
        if (text.IsEmpty)
        {
            return false;
        }

        foreach (byte value in text)
        {
            if (value is < (byte)'a' or > (byte)'z')
            {
                return false;
            }
        }

        return true;
    }
}
