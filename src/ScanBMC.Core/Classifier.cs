using System.Text.RegularExpressions;

namespace ScanBMC.Core;

/// <summary>证据加权判定与厂商指纹识别。</summary>
public static class Classifier
{
    private static readonly HashSet<string> PlaceholderValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "-", "n/a", "na", "none", "null", "unknown", "unspecified",
        "redfish server", "root service", "default string", "to be filled by o.e.m.",
    };

    private static readonly (Regex Pattern, string Label)[] WebSignatures =
    {
        (new Regex(@"idrac|integrated\s+dell\s+remote\s+access", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Dell iDRAC"),
        (new Regex(@"\bilo\b|hp-?ilo|integrated\s+lights-?out", RegexOptions.IgnoreCase | RegexOptions.Compiled), "HPE iLO"),
        (new Regex(@"\bcimc\b|cisco\s+integrated\s+management", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Cisco IMC"),
        (new Regex(@"\birmc\b|fujitsu.{0,40}(?:irmc|primergy|bmc)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Fujitsu iRMC"),
        (new Regex(@"xclarity|\bxcc\b|integrated\s+management\s+module|\bimm2?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Lenovo XClarity / IBM IMM"),
        (new Regex(@"\bibmc\b|huawei.{0,40}(?:ibmc|bmc|fusionserver|taishan|rack|blade)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Huawei iBMC"),
        (new Regex(@"supermicro", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Supermicro BMC"),
        (new Regex(@"megarac", RegexOptions.IgnoreCase | RegexOptions.Compiled), "AMI MegaRAC BMC"),
        (new Regex(@"\baten\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ATEN / Supermicro BMC"),
        (new Regex(@"inspur", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Inspur BMC"),
        (new Regex(@"\bhdm\b|h3c.{0,40}(?:hdm|bmc|uniserver)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "H3C HDM"),
        (new Regex(@"asrock\s*rack", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ASRock Rack BMC"),
        (new Regex(@"gigabyte.{0,40}(?:bmc|megarac|ipmi|server\s+management)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Gigabyte BMC"),
        (new Regex(@"\btyan\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Tyan BMC"),
        (new Regex(@"openbmc", RegexOptions.IgnoreCase | RegexOptions.Compiled), "OpenBMC"),
        (new Regex(@"aspeed", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ASPEED 芯片组 BMC"),
        (new Regex(@"\bbmc\b|baseboard\s+management", RegexOptions.IgnoreCase | RegexOptions.Compiled), "通用 BMC"),
    };

    public static string CleanValue(string? value)
    {
        string text = (value ?? "").Trim();
        return PlaceholderValues.Contains(text) ? "" : text;
    }

    public static string MatchSignature(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        foreach (var (pattern, label) in WebSignatures)
        {
            if (pattern.IsMatch(text))
                return label;
        }
        return "";
    }

    public static void Classify(HostResult host)
    {
        var evidence = new List<string>();
        string vendor = "";
        string confidence = "";

        // 证据 1：IPMI RMCP 应答（最强）
        if (host.Ipmi is { } ipmi)
        {
            string versions = ipmi.Versions.Count > 0 ? string.Join("/", ipmi.Versions) : "?";
            evidence.Add($"IPMI RMCP 应答 (v{versions})");
            confidence = ScanConstants.ConfConfirmed;

            if (!string.IsNullOrEmpty(ipmi.OemVendor) && !ipmi.OemVendor.StartsWith("IANA-", StringComparison.Ordinal))
            {
                vendor = $"{ipmi.OemVendor} BMC";
                evidence.Add($"IPMI OEM ID={ipmi.OemId} → {ipmi.OemVendor}");
            }
            else if (!string.IsNullOrEmpty(ipmi.OemVendor))
            {
                evidence.Add($"IPMI OEM ID={ipmi.OemId}（未收录）");
            }

            if (ipmi.AnonymousLogin) evidence.Add("⚠ 允许匿名登录");
            if (ipmi.NullUsernames) evidence.Add("⚠ 允许空用户名");
        }
        else if (host.AsfPong)
        {
            string asfDesc = "ASF Presence Pong (UDP/623)";
            if (host.AsfInfo?.IpmiSupported == true)
                asfDesc += " [支持 IPMI]";
            evidence.Add(asfDesc);
            confidence = ScanConstants.ConfConfirmed;

            if (host.AsfInfo?.OemIana is uint iana && iana != 4542 && iana <= int.MaxValue &&
                IpmiProtocol.OemIds.TryGetValue((int)iana, out var asfVendor))
            {
                vendor = $"{asfVendor} BMC";
                evidence.Add($"ASF OEM IANA={iana} → {asfVendor}");
            }
        }

        // 证据 1b：Get Device ID（auth-cap 被静默时兜底）
        if (host.DeviceId is { CompletionCode: 0 } dev)
        {
            var desc = "IPMI Get Device ID 应答";
            if (!string.IsNullOrEmpty(dev.Firmware)) desc += $" (固件 {dev.Firmware})";
            if (!string.IsNullOrEmpty(dev.IpmiVersion)) desc += $" (IPMI {dev.IpmiVersion})";
            evidence.Add(desc);

            if (dev.ProductId != 0)
                evidence.Add($"产品 ID=0x{dev.ProductId:X4}");
            if (!dev.Available)
                evidence.Add("⚠ 设备处于固件更新/不可用状态");
            if (host.Ipmi is null)
                confidence = ScanConstants.ConfConfirmed;

            if (!string.IsNullOrEmpty(dev.Manufacturer))
            {
                if (dev.Manufacturer.StartsWith("IANA-", StringComparison.Ordinal))
                {
                    evidence.Add($"Get Device ID 厂商 ID={dev.ManufacturerId}（未收录）");
                }
                else if (string.IsNullOrEmpty(vendor))
                {
                    vendor = $"{dev.Manufacturer} BMC";
                    evidence.Add($"Get Device ID 厂商 ID={dev.ManufacturerId} → {dev.Manufacturer}");
                }
            }
        }
        else if (host.DeviceId is { } devErr)
        {
            evidence.Add($"IPMI Get Device ID 应答 (完成码 0x{devErr.CompletionCode:X2})");
            if (host.Ipmi is null && !host.AsfPong)
                confidence = ScanConstants.ConfConfirmed;
        }

        // 证据 2：Redfish
        if (host.Redfish is { } rf)
        {
            var desc = $"Redfish /redfish/v1/ → HTTP {rf.Status}";
            if (!string.IsNullOrEmpty(rf.Version)) desc += $" (Redfish {rf.Version})";
            evidence.Add(desc);
            confidence = ScanConstants.ConfConfirmed;

            if (!string.IsNullOrEmpty(rf.Product) && rf.Product != rf.Vendor)
                evidence.Add($"Redfish 型号: {rf.Product}");

            string serverMatch = MatchSignature(rf.Server);
            if (!string.IsNullOrEmpty(serverMatch) && !string.IsNullOrEmpty(rf.Server))
                evidence.Add($"Redfish Server 头: {rf.Server} → {serverMatch}");

            if (string.IsNullOrEmpty(vendor))
            {
                if (!string.IsNullOrEmpty(rf.Vendor))
                    vendor = $"{rf.Vendor} (Redfish)";
                else if (!string.IsNullOrEmpty(serverMatch))
                    vendor = serverMatch;
                else if (!string.IsNullOrEmpty(rf.Product))
                    vendor = $"{rf.Product} (Redfish)";
                else
                {
                    string hay = $"{rf.Haystack} {string.Join(" ", rf.OemKeys)}";
                    string matched = MatchSignature(hay);
                    if (!string.IsNullOrEmpty(matched))
                        vendor = matched;
                }
            }
        }

        // 证据 3：Web 指纹
        foreach (var w in host.Web)
        {
            string matched = MatchSignature(w.Haystack);
            if (!string.IsNullOrEmpty(matched))
            {
                evidence.Add($"{w.Scheme}://{host.Ip}:{w.Port} 指纹 → {matched}");
                if (string.IsNullOrEmpty(vendor) || vendor == "通用 BMC")
                    vendor = matched;
                if (ScanConstants.ConfidenceRank(confidence) < ScanConstants.ConfidenceRank(ScanConstants.ConfLikely))
                    confidence = matched != "通用 BMC" ? ScanConstants.ConfLikely : ScanConstants.ConfPossible;
            }
            else if (!string.IsNullOrEmpty(w.Title) || !string.IsNullOrEmpty(w.Server))
            {
                evidence.Add(
                    $"{w.Scheme}://{host.Ip}:{w.Port} server={(string.IsNullOrEmpty(w.Server) ? "-" : w.Server)} title={(string.IsNullOrEmpty(w.Title) ? "-" : w.Title)}");
            }
        }

        // 证据 3b：TLS 证书有效期
        CertInfo? cert = host.Redfish?.Cert ?? host.Web.FirstOrDefault(w => w.Cert is not null)?.Cert;
        if (cert is not null)
        {
            if (cert.Expired)
                evidence.Add($"⚠ TLS 证书已过期（{cert.NotAfter}）");
            else if (cert.DaysLeft <= 30)
                evidence.Add($"⚠ TLS 证书将于 {cert.DaysLeft} 天后过期（{cert.NotAfter}）");
            else
                evidence.Add($"TLS 证书 CN={(string.IsNullOrEmpty(cert.SubjectCn) ? "-" : cert.SubjectCn)} 有效期至 {cert.NotAfter}");
        }

        // 证据 4：端口组合（弱）
        var openTcp = host.Ports.Select(p => p.Port).ToHashSet();
        if (string.IsNullOrEmpty(confidence) && openTcp.Count > 0)
        {
            if (openTcp.Contains(ScanConstants.IpmiUdpPort))
            {
                evidence.Add("端口特征：623/tcp 开放，但 UDP/623 无 IPMI 应答");
                confidence = ScanConstants.ConfPossible;
            }
            else if (openTcp.Contains(5900) && (openTcp.Contains(443) || openTcp.Contains(80)))
            {
                evidence.Add("端口特征：5900(iKVM) + Web 端口");
                confidence = ScanConstants.ConfPossible;
            }
            else if (openTcp.Contains(5988) || openTcp.Contains(5989) || openTcp.Contains(17990))
            {
                evidence.Add("端口特征：CIM/WBEM 或 iLO 控制台端口开放");
                confidence = ScanConstants.ConfPossible;
            }
        }

        foreach (var p in host.Ports)
        {
            if (p.Port == 5900 && p.Banner.StartsWith("RFB", StringComparison.Ordinal))
                evidence.Add($"5900/tcp banner: {p.Banner}");
        }

        host.Vendor = !string.IsNullOrEmpty(vendor) ? vendor : (!string.IsNullOrEmpty(confidence) ? "未知型号 BMC" : "");
        host.Confidence = confidence;
        host.Evidence = evidence;
    }
}
