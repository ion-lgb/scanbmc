using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ScanBMC.Core;

public sealed record IPv4Cidr(uint Network, int PrefixLength)
{
    public uint Mask => PrefixLength == 0 ? 0u : ~((1u << (32 - PrefixLength)) - 1u);
    public uint Broadcast => Network | ~Mask;
    public long TotalAddresses => 1L << (32 - PrefixLength);
    public long UsableHosts => PrefixLength >= 31 ? TotalAddresses : TotalAddresses - 2;

    public bool IsLoopback => (Network & 0xFF000000u) == 0x7F000000u;
    public bool IsLinkLocal => (Network & 0xFFFF0000u) == 0xA9FE0000u;

    public IEnumerable<uint> EnumerateHosts()
    {
        if (PrefixLength >= 31)
        {
            for (long i = Network; i <= Broadcast; i++)
                yield return (uint)i;
            yield break;
        }
        for (long i = (long)Network + 1; i < Broadcast; i++)
            yield return (uint)i;
    }

    public override string ToString() => $"{NetworkDiscovery.UIntToIp(Network)}/{PrefixLength}";
}

public readonly record struct IPv4Range(uint Start, uint End)
{
    public long Count => (long)End - Start + 1;
    public bool Contains(uint ip) => ip >= Start && ip <= End;
}

public static partial class NetworkDiscovery
{
    public const int DefaultMaxExpandTargets = 1_048_576;

    public static uint IpToUInt(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        if (b.Length != 4)
            throw new ArgumentException($"仅支持 IPv4 地址: {ip}");
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static string UIntToIp(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    /// <summary>严格解析点分四段十进制 IPv4，避免 IPAddress.TryParse 接受 "192.168.1" 等 inet_aton 简写。</summary>
    public static bool TryParseStrictIPv4(string text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Trim().Split('.');
        if (parts.Length != 4) return false;
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (parts[i].Length == 0 ||
                !byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[i]))
            {
                return false;
            }
        }
        ip = new IPAddress(bytes);
        return true;
    }

    public static int? NetmaskToPrefix(string mask)
    {
        uint value;
        mask = mask.Trim();
        if (mask.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!uint.TryParse(mask[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
                return null;
        }
        else if (mask.Contains('.'))
        {
            if (!TryParseStrictIPv4(mask, out var ip))
                return null;
            value = IpToUInt(ip);
        }
        else if (int.TryParse(mask, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) && prefix is >= 0 and <= 32)
        {
            return prefix;
        }
        else
        {
            return null;
        }

        uint inverted = ~value;
        if ((inverted & (inverted + 1)) != 0)
            return null;
        int zeroBits = 0;
        uint tmp = inverted;
        while (tmp != 0)
        {
            zeroBits++;
            tmp >>= 1;
        }
        return 32 - zeroBits;
    }

    public static IPv4Cidr ParseCidr(string text)
    {
        var parts = text.Split('/');
        if (parts.Length != 2 ||
            !TryParseStrictIPv4(parts[0].Trim(), out var ip) ||
            !int.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) ||
            prefix < 0 || prefix > 32)
        {
            throw new FormatException($"非法 CIDR 网段: {text}");
        }
        uint mask = prefix == 0 ? 0u : ~((1u << (32 - prefix)) - 1u);
        uint net = IpToUInt(ip) & mask;
        return new IPv4Cidr(net, prefix);
    }

    /// <summary>将单个目标表达式解析为闭区间 [Start, End]（不展开 IP，避免大网段 OOM）。</summary>
    public static IPv4Range? ParseTargetRange(string token)
    {
        token = token.Trim();
        if (string.IsNullOrEmpty(token))
            return null;

        if (token.Contains('/'))
        {
            var cidr = ParseCidr(token);
            return cidr.PrefixLength >= 31
                ? new IPv4Range(cidr.Network, cidr.Broadcast)
                : new IPv4Range(cidr.Network + 1, cidr.Broadcast - 1);
        }

        if (token.Contains('-'))
        {
            var idx = token.IndexOf('-');
            var left = token[..idx].Trim();
            var right = token[(idx + 1)..].Trim();

            if (!TryParseStrictIPv4(left, out var startIp))
                throw new FormatException($"非法起始 IP: {token}");

            IPAddress endIp;
            if (right.Contains('.'))
            {
                if (!TryParseStrictIPv4(right, out endIp))
                    throw new FormatException($"非法结束 IP: {token}");
            }
            else
            {
                if (!byte.TryParse(right, NumberStyles.None, CultureInfo.InvariantCulture, out byte endOctet))
                    throw new FormatException($"非法结束段: {token}");
                byte[] b = startIp.GetAddressBytes();
                endIp = new IPAddress(new[] { b[0], b[1], b[2], endOctet });
            }

            uint s = IpToUInt(startIp);
            uint e = IpToUInt(endIp);
            if (e < s)
                throw new FormatException($"区间起止顺序错误: {token}");

            return new IPv4Range(s, e);
        }

        if (!TryParseStrictIPv4(token, out var single))
            throw new FormatException($"非法 IP 地址: {token}");
        uint v = IpToUInt(single);
        return new IPv4Range(v, v);
    }

    /// <summary>支持 CIDR(192.168.1.0/24)、单 IP、区间(192.168.1.10-50 或 10.0.0.1-10.0.0.99)。</summary>
    public static List<uint> ParseTarget(string token, int maxTargets = DefaultMaxExpandTargets)
    {
        var range = ParseTargetRange(token);
        if (range is null)
            return new List<uint>();

        var r = range.Value;
        if (r.Count > maxTargets)
            throw new InvalidOperationException($"目标数 {r.Count} 超过上限 {maxTargets}，请缩小网段范围。");

        var list = new List<uint>((int)r.Count);
        for (long i = r.Start; i <= r.End; i++)
            list.Add((uint)i);
        return list;
    }

    private static List<IPv4Range> MergeRanges(List<IPv4Range> ranges)
    {
        if (ranges.Count <= 1) return ranges;
        ranges.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));

        var merged = new List<IPv4Range>(ranges.Count) { ranges[0] };
        for (int i = 1; i < ranges.Count; i++)
        {
            var cur = merged[^1];
            var next = ranges[i];
            if (next.Start <= (long)cur.End + 1)
            {
                if (next.End > cur.End)
                    merged[^1] = new IPv4Range(cur.Start, next.End);
            }
            else
            {
                merged.Add(next);
            }
        }
        return merged;
    }

    private static List<IPv4Range> SubtractRanges(List<IPv4Range> includes, List<IPv4Range> excludes)
    {
        if (includes.Count == 0 || excludes.Count == 0)
            return includes;

        var result = new List<IPv4Range>(includes.Count);
        int exIdx = 0;

        foreach (var inc in includes)
        {
            while (exIdx < excludes.Count && excludes[exIdx].End < inc.Start)
                exIdx++;

            long curStart = inc.Start;
            int j = exIdx;
            while (j < excludes.Count && excludes[j].Start <= inc.End)
            {
                var ex = excludes[j];
                if (ex.Start > curStart)
                    result.Add(new IPv4Range((uint)curStart, ex.Start - 1));

                if (ex.End >= inc.End)
                {
                    curStart = (long)inc.End + 1;
                    break;
                }
                curStart = Math.Max(curStart, (long)ex.End + 1);
                j++;
            }

            if (curStart <= inc.End)
                result.Add(new IPv4Range((uint)curStart, inc.End));
        }

        return result;
    }

    public static List<string> BuildTargets(
        IEnumerable<string> specs,
        IEnumerable<string>? excludes = null,
        int? maxTargets = null)
    {
        var includeRanges = new List<IPv4Range>();
        foreach (var spec in specs)
        {
            if (ParseTargetRange(spec) is { } r)
                includeRanges.Add(r);
        }

        var merged = MergeRanges(includeRanges);

        if (excludes is not null)
        {
            var excludeRanges = new List<IPv4Range>();
            foreach (var spec in excludes)
            {
                if (ParseTargetRange(spec) is { } r)
                    excludeRanges.Add(r);
            }
            if (excludeRanges.Count > 0)
                merged = SubtractRanges(merged, MergeRanges(excludeRanges));
        }

        long totalCount = 0;
        int limit = maxTargets ?? DefaultMaxExpandTargets;
        foreach (var r in merged)
        {
            totalCount += r.Count;
            if (totalCount > limit)
                throw new InvalidOperationException($"目标数超过上限 {limit}，请缩小网段范围。");
        }

        var targets = new List<string>((int)totalCount);
        foreach (var r in merged)
        {
            for (long i = r.Start; i <= r.End; i++)
                targets.Add(UIntToIp((uint)i));
        }
        return targets;
    }

    public static List<string> FilterToSpecs(IEnumerable<string> ips, IEnumerable<string> specs)
    {
        var rawRanges = new List<IPv4Range>();
        foreach (var spec in specs)
        {
            if (ParseTargetRange(spec) is { } r)
                rawRanges.Add(r);
        }
        var allowed = MergeRanges(rawRanges);

        var result = new List<string>();
        var added = new HashSet<string>();
        foreach (var ipStr in ips)
        {
            if (IPAddress.TryParse(ipStr, out var addr) &&
                addr.AddressFamily == AddressFamily.InterNetwork)
            {
                uint v = IpToUInt(addr);
                bool hit = false;
                foreach (var r in allowed)
                {
                    if (r.Contains(v))
                    {
                        hit = true;
                        break;
                    }
                    if (r.Start > v) break;
                }
                if (hit && added.Add(ipStr))
                    result.Add(ipStr);
            }
        }
        return result;
    }

    public static List<int> ParsePorts(string spec)
    {
        var ports = new SortedSet<int>();
        foreach (var rawPart in spec.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var part = rawPart.Trim();
            if (string.IsNullOrEmpty(part)) continue;
            if (part.Contains('-'))
            {
                var seg = part.Split('-', 2);
                if (!int.TryParse(seg[0].Trim(), out int a) || !int.TryParse(seg[1].Trim(), out int b) || a > b)
                    throw new FormatException($"非法端口区间: {part}");
                for (int p = a; p <= b; p++)
                {
                    if (p is < 1 or > 65535) throw new FormatException($"非法端口: {p}");
                    ports.Add(p);
                }
            }
            else
            {
                if (!int.TryParse(part, out int p) || p is < 1 or > 65535)
                    throw new FormatException($"非法端口: {part}");
                ports.Add(p);
            }
        }
        return ports.ToList();
    }

    /// <summary>直接使用 .NET 原生 NetworkInterface API 检测本机活动 IPv4 网段（精确获取真实掩码，无需解析 ipconfig 文本）。</summary>
    public static List<IPv4Cidr> DetectLocalNetworks()
    {
        var result = new List<IPv4Cidr>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    int prefix = ua.PrefixLength;
                    if (prefix is <= 0 or >= 31) continue;

                    uint mask = ~((1u << (32 - prefix)) - 1u);
                    uint net = IpToUInt(ua.Address) & mask;
                    var cidr = new IPv4Cidr(net, prefix);
                    if (cidr.IsLoopback || cidr.IsLinkLocal) continue;
                    if (!result.Contains(cidr))
                        result.Add(cidr);
                }
            }
        }
        catch
        {
            // 忽略网卡枚举异常，尝试兜底
        }
        return result;
    }

    [GeneratedRegex(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")]
    private static partial Regex Ipv4Regex();

    public static List<string> ParseArpOutput(string output)
    {
        var seen = new List<string>();
        var dedup = new HashSet<string>();
        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("Interface:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("接口:", StringComparison.Ordinal))
            {
                continue;
            }
            foreach (Match m in Ipv4Regex().Matches(line))
            {
                var token = m.Groups[1].Value;
                if (!IPAddress.TryParse(token, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork)
                    continue;
                uint v = IpToUInt(addr);
                // 过滤多播 (224.0.0.0/4) 与受限广播 (255.255.255.255)
                if ((v & 0xF0000000u) == 0xE0000000u || v == 0xFFFFFFFFu)
                    continue;
                if (dedup.Add(token))
                    seen.Add(token);
            }
        }
        return seen;
    }

    public static async Task<List<string>> GetArpNeighborsAsync(CancellationToken ct = default)
    {
        try
        {
            var psi = new ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return new List<string>();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                string output = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token).ConfigureAwait(false);
                await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                return ParseArpOutput(output);
            }
            catch
            {
                try { if (!proc.HasExited) proc.Kill(); } catch { }
                return new List<string>();
            }
        }
        catch
        {
            return new List<string>();
        }
    }

    public static List<string> GetArpNeighbors() =>
        GetArpNeighborsAsync().GetAwaiter().GetResult();
}
