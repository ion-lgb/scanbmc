using System.Diagnostics;
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

public static partial class NetworkDiscovery
{
    public static uint IpToUInt(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        if (b.Length != 4)
            throw new ArgumentException($"仅支持 IPv4 地址: {ip}");
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static string UIntToIp(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    public static int? NetmaskToPrefix(string mask)
    {
        uint value;
        mask = mask.Trim();
        if (mask.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!uint.TryParse(mask[2..], System.Globalization.NumberStyles.HexNumber, null, out value))
                return null;
        }
        else if (mask.Contains('.'))
        {
            if (!IPAddress.TryParse(mask, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                return null;
            value = IpToUInt(ip);
        }
        else if (int.TryParse(mask, out int prefix) && prefix is >= 0 and <= 32)
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
            !IPAddress.TryParse(parts[0].Trim(), out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1].Trim(), out int prefix) ||
            prefix < 0 || prefix > 32)
        {
            throw new FormatException($"非法 CIDR 网段: {text}");
        }
        uint mask = prefix == 0 ? 0u : ~((1u << (32 - prefix)) - 1u);
        uint net = IpToUInt(ip) & mask;
        return new IPv4Cidr(net, prefix);
    }

    /// <summary>支持 CIDR(192.168.1.0/24)、单 IP、区间(192.168.1.10-50 或 10.0.0.1-10.0.0.99)。</summary>
    public static List<uint> ParseTarget(string token)
    {
        token = token.Trim();
        if (string.IsNullOrEmpty(token))
            return new List<uint>();

        if (token.Contains('/'))
            return ParseCidr(token).EnumerateHosts().ToList();

        if (token.Contains('-'))
        {
            var idx = token.IndexOf('-');
            var left = token[..idx].Trim();
            var right = token[(idx + 1)..].Trim();

            if (!IPAddress.TryParse(left, out var startIp) || startIp.AddressFamily != AddressFamily.InterNetwork)
                throw new FormatException($"非法起始 IP: {token}");

            IPAddress? endIp;
            if (right.Contains('.'))
            {
                if (!IPAddress.TryParse(right, out endIp) || endIp.AddressFamily != AddressFamily.InterNetwork)
                    throw new FormatException($"非法结束 IP: {token}");
            }
            else
            {
                var octets = left.Split('.');
                if (octets.Length != 4 || !IPAddress.TryParse($"{octets[0]}.{octets[1]}.{octets[2]}.{right}", out endIp))
                    throw new FormatException($"非法结束段: {token}");
            }

            uint s = IpToUInt(startIp);
            uint e = IpToUInt(endIp);
            if (e < s)
                throw new FormatException($"区间起止顺序错误: {token}");

            var list = new List<uint>((int)Math.Min((long)e - s + 1, 65536));
            for (long i = s; i <= e; i++)
                list.Add((uint)i);
            return list;
        }

        if (!IPAddress.TryParse(token, out var single) || single.AddressFamily != AddressFamily.InterNetwork)
            throw new FormatException($"非法 IP 地址: {token}");
        return new List<uint> { IpToUInt(single) };
    }

    public static List<string> BuildTargets(IEnumerable<string> specs, IEnumerable<string>? excludes = null)
    {
        var seen = new SortedSet<uint>();
        foreach (var spec in specs)
        {
            foreach (var ip in ParseTarget(spec))
                seen.Add(ip);
        }

        if (excludes is not null)
        {
            foreach (var spec in excludes)
            {
                foreach (var ip in ParseTarget(spec))
                    seen.Remove(ip);
            }
        }

        return seen.Select(UIntToIp).ToList();
    }

    public static List<string> FilterToSpecs(IEnumerable<string> ips, IEnumerable<string> specs)
    {
        var allowed = new HashSet<uint>();
        foreach (var spec in specs)
        {
            foreach (var ip in ParseTarget(spec))
                allowed.Add(ip);
        }

        var result = new List<string>();
        var added = new HashSet<string>();
        foreach (var ipStr in ips)
        {
            if (IPAddress.TryParse(ipStr, out var addr) &&
                addr.AddressFamily == AddressFamily.InterNetwork &&
                allowed.Contains(IpToUInt(addr)) &&
                added.Add(ipStr))
            {
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

    public static List<string> GetArpNeighbors()
    {
        try
        {
            var psi = new ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return new List<string>();
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return ParseArpOutput(output);
        }
        catch
        {
            return new List<string>();
        }
    }
}
