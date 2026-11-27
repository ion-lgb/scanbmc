using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace ScanBMC.Core;

public static class ScanConstants
{
    public const string Version = "2.0.0";
    public const int IpmiUdpPort = 623;

    public const string ConfConfirmed = "确认";
    public const string ConfLikely = "可能";
    public const string ConfPossible = "疑似";

    public static readonly IReadOnlyDictionary<int, string> DefaultTcpPorts = new Dictionary<int, string>
    {
        [80] = "HTTP 管理页",
        [443] = "HTTPS 管理页 / Redfish",
        [623] = "IPMI over TCP(少见)",
        [5900] = "iKVM / VNC 远程控制台",
        [5985] = "WS-Man (HTTP)",
        [5988] = "CIM/WBEM (HTTP)",
        [5989] = "CIM/WBEM (HTTPS)",
        [17990] = "HP iLO 远程控制台",
    };

    /// <summary>需要走 HTTP 指纹识别的端口 -> 是否使用 TLS</summary>
    public static readonly IReadOnlyDictionary<int, bool> WebPorts = new Dictionary<int, bool>
    {
        [443] = true,
        [5989] = true,
        [80] = false,
        [5985] = false,
        [5988] = false,
    };

    public static readonly IReadOnlySet<int> RedfishPorts = new HashSet<int> { 443, 80 };

    public static int ConfidenceRank(string confidence) => confidence switch
    {
        ConfConfirmed => 3,
        ConfLikely => 2,
        ConfPossible => 1,
        _ => 0,
    };
}

public sealed class PortResult
{
    public int Port { get; init; }
    public string Proto { get; init; } = "tcp";
    public string Service { get; init; } = "";
    public string Banner { get; init; } = "";
}

public sealed class IpmiInfo
{
    public bool Ipmi { get; init; } = true;
    public int CompletionCode { get; init; }
    public string Note { get; init; } = "";
    public int Channel { get; init; }
    public List<string> Versions { get; init; } = new();
    public List<string> AuthTypes { get; init; } = new();
    public bool AnonymousLogin { get; init; }
    public bool NullUsernames { get; init; }
    public bool NonNullUsernames { get; init; }
    public bool KgStatusDefault { get; init; }
    public int OemId { get; init; }
    public string OemVendor { get; init; } = "";
}

public sealed class AsfPongInfo
{
    public bool AsfPong { get; init; } = true;
    public uint? OemIana { get; init; }
    public bool IpmiSupported { get; init; }
}

public sealed class DeviceIdInfo
{
    public bool Ipmi { get; init; } = true;
    public int CompletionCode { get; init; }
    public string Note { get; init; } = "";
    public byte DeviceId { get; init; }
    public string Firmware { get; init; } = "";
    public string IpmiVersion { get; init; } = "";
    public int ManufacturerId { get; init; }
    public string Manufacturer { get; init; } = "";
    public int ProductId { get; init; }
    public bool Available { get; init; } = true;
}

public sealed class CertInfo
{
    public string SubjectCn { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string NotAfter { get; init; } = "";
    public int DaysLeft { get; init; }
    public bool Expired { get; init; }
}

public sealed class WebInfo
{
    public int Port { get; init; }
    public string Scheme { get; init; } = "http";
    public int Status { get; init; }
    public string Server { get; init; } = "";
    public string Title { get; init; } = "";
    public string Location { get; init; } = "";
    public string Realm { get; init; } = "";
    public CertInfo? Cert { get; init; }

    [JsonIgnore]
    public string Haystack { get; init; } = "";
}

public sealed class RedfishInfo
{
    public int Port { get; init; }
    public int Status { get; init; }
    public string Server { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string Product { get; init; } = "";
    public string Version { get; init; } = "";
    public List<string> OemKeys { get; init; } = new();
    public CertInfo? Cert { get; init; }

    [JsonIgnore]
    public string Haystack { get; init; } = "";
}

public sealed class HostResult
{
    public string Ip { get; init; } = "";
    public List<PortResult> Ports { get; init; } = new();
    public IpmiInfo? Ipmi { get; set; }
    public bool AsfPong { get; set; }
    public DeviceIdInfo? DeviceId { get; set; }
    public RedfishInfo? Redfish { get; set; }
    public List<WebInfo> Web { get; init; } = new();
    public string Vendor { get; set; } = "";
    public string Confidence { get; set; } = "";
    public List<string> Evidence { get; set; } = new();

    [JsonIgnore]
    public bool IsAlive => Ports.Count > 0 || Ipmi is not null || AsfPong || DeviceId is not null;

    [JsonIgnore]
    public bool IsBmc => Confidence is ScanConstants.ConfConfirmed or ScanConstants.ConfLikely or ScanConstants.ConfPossible;

    [JsonIgnore]
    public List<string> Warnings => Evidence.Where(e => e.StartsWith("⚠", StringComparison.Ordinal)).ToList();

    [JsonIgnore]
    public bool HasWarnings => Evidence.Any(e => e.StartsWith("⚠", StringComparison.Ordinal));

    public string OpenPortsString()
    {
        var items = new List<string>();
        if (Ipmi is not null || AsfPong || DeviceId is not null)
        {
            items.Add("623/udp");
        }
        items.AddRange(Ports.OrderBy(p => p.Port).Select(p => $"{p.Port}/{p.Proto}"));
        return string.Join(",", items);
    }

    public string PreferredUrl()
    {
        var open = Ports.Select(p => p.Port).ToHashSet();
        if (open.Contains(443)) return $"https://{Ip}/";
        if (open.Contains(5989)) return $"https://{Ip}:5989/";
        if (open.Contains(80)) return $"http://{Ip}/";
        if (open.Contains(5985)) return $"http://{Ip}:5985/";
        if (open.Contains(5988)) return $"http://{Ip}:5988/";
        return $"https://{Ip}/";
    }
}

public sealed class ScanConfig
{
    public List<int> TcpPorts { get; init; } = ScanConstants.DefaultTcpPorts.Keys.OrderBy(p => p).ToList();
    public int Concurrency { get; init; } = 256;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(1.0);
    public int Retries { get; init; } = 0;
    public bool EnableUdp { get; init; } = true;
    public bool EnableWeb { get; init; } = true;
    public bool EnableRedfish { get; init; } = true;
    public int IpmiUdpPort { get; init; } = ScanConstants.IpmiUdpPort;
    public IReadOnlyDictionary<int, bool>? WebPortsOverride { get; init; }
    public IReadOnlySet<int>? RedfishPortsOverride { get; init; }
}

public sealed record ScanProgress(int Done, int Total, string Phase);

/// <summary>线程安全的探测统计，用于区分本机侧系统性故障与空地址 HostDown。</summary>
public sealed class ProbeStats
{
    private static readonly HashSet<SocketError> SystemicErrors = new()
    {
        SocketError.NetworkDown,
        SocketError.NetworkUnreachable,
        SocketError.NoBufferSpaceAvailable,
        SocketError.TooManyOpenSockets,
        SocketError.AddressNotAvailable,
        SocketError.AccessDenied,
    };

    private static readonly HashSet<SocketError> HostDownErrors = new()
    {
        SocketError.HostDown,
        SocketError.HostUnreachable,
    };

    private readonly ConcurrentDictionary<string, int> _counts = new();

    public void Add(string key) => _counts.AddOrUpdate(key, 1, (_, v) => v + 1);

    public void AddSocketError(SocketError error)
    {
        if (SystemicErrors.Contains(error))
            Add($"sys:{error}");
        else if (HostDownErrors.Contains(error))
            Add($"hostdown:{error}");
        else
            Add($"err:{error}");
    }

    public static bool IsSystemic(SocketError error) => SystemicErrors.Contains(error);
    public static bool IsHostDown(SocketError error) => HostDownErrors.Contains(error);

    public int Total => _counts.Values.Sum();
    public int SystemicFailures => _counts.Where(kv => kv.Key.StartsWith("sys:", StringComparison.Ordinal)).Sum(kv => kv.Value);
    public int HostDown => _counts.Where(kv => kv.Key.StartsWith("hostdown:", StringComparison.Ordinal)).Sum(kv => kv.Value);
    public int Responded => _counts.GetValueOrDefault("open") + _counts.GetValueOrDefault("refused");

    public double SystemicRatio => Total > 0 ? (double)SystemicFailures / Total : 0.0;
    public bool IsDegraded => SystemicRatio >= 0.5 && SystemicFailures > 0;

    public Dictionary<string, int> Snapshot() => new(_counts);
}
