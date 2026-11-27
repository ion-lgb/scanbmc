using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ScanBMC.Core;
using Xunit;

namespace ScanBMC.Core.Tests;

public class ProtocolTests
{
    [Fact]
    public void NetmaskToPrefix_HandlesDottedAndHexAndRejectsInvalid()
    {
        Assert.Equal(24, NetworkDiscovery.NetmaskToPrefix("255.255.255.0"));
        Assert.Equal(22, NetworkDiscovery.NetmaskToPrefix("255.255.252.0"));
        Assert.Equal(24, NetworkDiscovery.NetmaskToPrefix("0xffffff00"));
        Assert.Equal(16, NetworkDiscovery.NetmaskToPrefix("0xffff0000"));
        Assert.Null(NetworkDiscovery.NetmaskToPrefix("0xff00ff00"));
        Assert.Null(NetworkDiscovery.NetmaskToPrefix("not-a-mask"));
    }

    [Fact]
    public void BuildTargets_SupportsCidrRangeSingleAndExclude()
    {
        var targets = NetworkDiscovery.BuildTargets(
            new[] { "192.168.1.0/29", "10.0.0.8-10" },
            new[] { "192.168.1.2", "10.0.0.9" });

        Assert.Contains("192.168.1.1", targets);
        Assert.DoesNotContain("192.168.1.0", targets);
        Assert.DoesNotContain("192.168.1.7", targets);
        Assert.DoesNotContain("192.168.1.2", targets);
        Assert.Contains("10.0.0.8", targets);
        Assert.DoesNotContain("10.0.0.9", targets);
        Assert.Contains("10.0.0.10", targets);
    }

    [Fact]
    public void ParseArpOutput_SkipsInterfaceHeadersAndMulticast()
    {
        string arp = """
            接口: 192.168.1.23 --- 0x5
              Internet 地址         物理地址              类型
              192.168.1.1           aa-bb-cc-dd-ee-ff     动态
              192.168.1.50          11-22-33-44-55-66     动态
              224.0.0.22            01-00-5e-00-00-16     静态
              255.255.255.255       ff-ff-ff-ff-ff-ff     静态

            Interface: 10.20.0.7 --- 0x9
              10.20.0.1             de-ad-be-ef-00-01     dynamic
            """;

        var ips = NetworkDiscovery.ParseArpOutput(arp);
        Assert.Equal(new[] { "192.168.1.1", "192.168.1.50", "10.20.0.1" }, ips);
    }

    [Fact]
    public void ParsePorts_ValidatesRangeAndRejectsInvalid()
    {
        Assert.Equal(new[] { 80, 81, 82, 443 }, NetworkDiscovery.ParsePorts("443, 80-82, 80"));
        Assert.Throws<FormatException>(() => NetworkDiscovery.ParsePorts("70000"));
    }

    [Fact]
    public void IpmiPackets_HaveValidChecksums()
    {
        var pkt = IpmiProtocol.GetChannelAuthCapPacket;
        Assert.Equal(pkt.Length - 14, pkt[13]);
        Assert.Equal((byte)(-(pkt[14] + pkt[15])), pkt[16]);
        int sum2 = pkt[17] + pkt[18] + pkt[19] + pkt[20] + pkt[21];
        Assert.Equal((byte)(-sum2), pkt[22]);

        var dev = IpmiProtocol.GetDeviceIdPacket;
        Assert.Equal(dev.Length - 14, dev[13]);
        Assert.Equal((byte)(-(dev[17] + dev[18] + dev[19])), dev[20]);
    }

    [Fact]
    public void ParseChannelAuthCap_ExtractsVersionsOemAndWarnings()
    {
        byte[] payload = { 0x01, 0x95, 0x03, 0x03, 0x7C, 0x2A, 0x00, 0x00 }; // OEM 10876 = Supermicro
        byte[] body = new byte[] { 0x81, 0x1C, 0x63, 0x20, 0x00, 0x38, 0x00 }.Concat(payload).ToArray();
        byte[] resp = new byte[] { 0x06, 0x00, 0xFF, 0x07 }
            .Concat(new byte[9])
            .Concat(new[] { (byte)body.Length })
            .Concat(body).ToArray();

        var info = IpmiProtocol.ParseChannelAuthCap(resp);
        Assert.NotNull(info);
        Assert.Equal(new[] { "1.5", "2.0" }, info!.Versions);
        Assert.Equal("Supermicro", info.OemVendor);
        Assert.True(info.AnonymousLogin);
        Assert.True(info.NullUsernames);
    }

    [Fact]
    public void ParseDeviceId_AlignsWithIpmi20Spec()
    {
        // IPMI 2.0 Table 20-2:
        // fw1=0x06(可用 bit7=0, 主版本二进制 6), fw2=0x26(次版本 BCD 26), ipmi_ver=0x51(IPMI 1.5), OEM=10876, Product=0x0100
        byte[] payload = { 0x20, 0x01, 0x06, 0x26, 0x51, 0x00, 0x7C, 0x2A, 0x00, 0x00, 0x01 };
        byte[] body = new byte[] { 0x81, 0x1C, 0x63, 0x20, 0x00, 0x01, 0x00 }.Concat(payload).ToArray();
        byte[] resp = new byte[] { 0x06, 0x00, 0xFF, 0x07 }
            .Concat(new byte[9])
            .Concat(new[] { (byte)body.Length })
            .Concat(body).ToArray();

        var info = IpmiProtocol.ParseDeviceId(resp);
        Assert.NotNull(info);
        Assert.Equal("6.26", info!.Firmware);
        Assert.Equal("1.5", info.IpmiVersion);
        Assert.Equal("Supermicro", info.Manufacturer);
        Assert.Equal(0x0100, info.ProductId);
        Assert.True(info.Available);

        // 主版本二进制 >= 16 (0x10) 且 bit7=1 (更新中/不可用) => 0x90，次版本 BCD 0x08 => 16.08
        byte[] payload2 = { 0x20, 0x01, 0x90, 0x08, 0x02, 0x00, 0x7C, 0x2A, 0x00, 0x00, 0x01 };
        byte[] body2 = new byte[] { 0x81, 0x1C, 0x63, 0x20, 0x00, 0x01, 0x00 }.Concat(payload2).ToArray();
        byte[] resp2 = new byte[] { 0x06, 0x00, 0xFF, 0x07 }
            .Concat(new byte[9])
            .Concat(new[] { (byte)body2.Length })
            .Concat(body2).ToArray();

        var info2 = IpmiProtocol.ParseDeviceId(resp2);
        Assert.NotNull(info2);
        Assert.Equal("16.08", info2!.Firmware);
        Assert.Equal("2.0", info2.IpmiVersion);
        Assert.False(info2.Available);
    }

    [Fact]
    public void ParseRedfishResponse_RejectsGenericJsonApiAndAcceptsRealRedfish()
    {
        // 普通 401/403/200 JSON API 不应误判为 Redfish
        var generic401 = new HttpProbe.RawHttpResponse
        {
            Status = 401,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
                ["server"] = "nginx/1.24.0",
            },
            Body = "{\"error\":\"Unauthorized\",\"message\":\"Token required\"}",
        };
        Assert.Null(HttpProbe.ParseRedfishResponse(443, generic401));

        var generic200 = new HttpProbe.RawHttpResponse
        {
            Status = 200,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
            },
            Body = "{\"status\":\"ok\",\"version\":\"1.0\"}",
        };
        Assert.Null(HttpProbe.ParseRedfishResponse(443, generic200));

        // 真实 Redfish 200 ServiceRoot
        var real200 = new HttpProbe.RawHttpResponse
        {
            Status = 200,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
                ["odata-version"] = "4.0",
            },
            Body = "{\"@odata.type\":\"#ServiceRoot.v1_5_0.ServiceRoot\",\"@odata.id\":\"/redfish/v1/\",\"RedfishVersion\":\"1.8.0\",\"Vendor\":\"Dell\"}",
        };
        var rf200 = HttpProbe.ParseRedfishResponse(443, real200);
        Assert.NotNull(rf200);
        Assert.Equal("1.8.0", rf200!.Version);
        Assert.Equal("Dell", rf200.Vendor);

        // 401 但带有 Redfish Error Schema
        var redfish401 = new HttpProbe.RawHttpResponse
        {
            Status = 401,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
            },
            Body = "{\"error\":{\"code\":\"Base.1.0.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.0.NoValidSession\"}]}}",
        };
        Assert.NotNull(HttpProbe.ParseRedfishResponse(443, redfish401));

        // 截断的 Redfish JSON
        var truncatedRedfish = new HttpProbe.RawHttpResponse
        {
            Status = 200,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/json",
            },
            Body = "{\"@odata.type\":\"#ServiceRoot.v1_5_0.ServiceRoot\",\"RedfishVersion\":\"1.6.0\"",
        };
        Assert.NotNull(HttpProbe.ParseRedfishResponse(443, truncatedRedfish));
    }

    [Fact]
    public void BuildTargets_AndFilterToSpecs_HandleLargeCidrSafely()
    {
        // 大网段超限时应在展开前立即抛错，不会 OOM
        Assert.Throws<InvalidOperationException>(() =>
            NetworkDiscovery.BuildTargets(new[] { "10.0.0.0/8" }, maxTargets: 8192));
        Assert.Throws<InvalidOperationException>(() =>
            NetworkDiscovery.BuildTargets(new[] { "0.0.0.0/0" }, maxTargets: 8192));

        // 扣除大范围排除后若在上限内，应正常返回剩余地址
        var trimmed = NetworkDiscovery.BuildTargets(
            new[] { "10.0.0.0/16" },
            new[] { "10.0.0.5-10.0.255.254" },
            maxTargets: 16);
        Assert.Equal(new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4" }, trimmed);

        // FilterToSpecs 对超大网段应使用区间匹配而不展开
        var filtered = NetworkDiscovery.FilterToSpecs(
            new[] { "10.20.30.40", "192.168.1.5", "10.20.30.40" },
            new[] { "10.0.0.0/8" });
        Assert.Equal(new[] { "10.20.30.40" }, filtered);
    }

    [Fact]
    public void ExtractCertInfo_DoesNotDisposeCallerCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=bmc-test.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));

        var info = HttpProbe.ExtractCertInfo(cert);
        Assert.NotNull(info);
        Assert.Equal("bmc-test.local", info!.SubjectCn);
        Assert.False(info.Expired);

        // 确认外部传入的 cert 未被 ExtractCertInfo 提前 Dispose
        Assert.Contains("bmc-test.local", cert.Subject);
        Assert.True(cert.NotAfter > DateTime.UtcNow);
    }

    [Fact]
    public void DecodeBody_HandlesChunkedAndTruncatedGzip()
    {
        string html = "<html><head><title>MegaRAC SP-X</title></head><body>" + new string('A', 20000) + "</body></html>";
        byte[] gzipped;
        using (var ms = new MemoryStream())
        {
            using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                gz.Write(Encoding.UTF8.GetBytes(html));
            }
            gzipped = ms.ToArray();
        }

        byte[] truncated = gzipped[..Math.Min(1500, gzipped.Length)];
        var headers = new Dictionary<string, string> { ["content-encoding"] = "gzip" };
        string decoded = Encoding.UTF8.GetString(HttpProbe.DecodeBody(headers, truncated));
        Assert.Contains("MegaRAC SP-X", decoded);

        byte[] chunked = Encoding.ASCII.GetBytes("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        var chunkHeaders = new Dictionary<string, string> { ["transfer-encoding"] = "chunked" };
        Assert.Equal("hello world", Encoding.UTF8.GetString(HttpProbe.DecodeBody(chunkHeaders, chunked)));
    }

    [Fact]
    public void Classifier_PrioritizesEvidenceAndFiltersPlaceholders()
    {
        var host = new HostResult { Ip = "192.168.0.70" };
        host.Ports.Add(new PortResult { Port = 443 });
        host.Redfish = new RedfishInfo
        {
            Port = 443,
            Status = 200,
            Server = "AMI MegaRAC Redfish Service",
            Vendor = Classifier.CleanValue("N/A"),
            Product = "4UGPUServer",
            Version = "1.15.1",
            Cert = new CertInfo { SubjectCn = "bmc", NotAfter = "2020-01-01", DaysLeft = -500, Expired = true },
        };

        Classifier.Classify(host);
        Assert.Equal(ScanConstants.ConfConfirmed, host.Confidence);
        Assert.Equal("AMI MegaRAC BMC", host.Vendor);
        Assert.True(host.HasWarnings);
        Assert.Contains(host.Evidence, e => e.Contains("证书已过期"));
        Assert.Contains(host.Evidence, e => e.Contains("4UGPUServer"));
    }

    [Fact]
    public void Exporters_ProduceValidJsonAndCsv()
    {
        var host = new HostResult { Ip = "192.168.1.50" };
        host.Ipmi = new IpmiInfo { Versions = new() { "2.0" }, OemId = 21317, OemVendor = "Supermicro", NullUsernames = true };
        Classifier.Classify(host);

        string json = Exporters.ToJson(new[] { host }, false, new { targets = 1 });
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("192.168.1.50", doc.RootElement.GetProperty("results")[0].GetProperty("ip").GetString());

        string csv = Exporters.ToCsv(new[] { host }, false);
        Assert.StartsWith("ip,confidence,vendor,open_ports", csv);
        Assert.Contains("Supermicro BMC", csv);
    }

    [Fact]
    public void Classifier_AvoidsNetworkEquipmentFalsePositives()
    {
        // 普通交换机/路由器/扫描仪页面不应误报为 BMC
        Assert.Equal("", Classifier.MatchSignature("Huawei S5700 Switch Web Login"));
        Assert.Equal("", Classifier.MatchSignature("H3C Comware Web Management"));
        Assert.Equal("", Classifier.MatchSignature("Fujitsu Document Scanner"));
        Assert.Equal("", Classifier.MatchSignature("GIGABYTE Gaming Motherboard"));

        // 真实 BMC 特征应准确命中
        Assert.Equal("Huawei iBMC", Classifier.MatchSignature("Huawei iBMC Login"));
        Assert.Equal("Huawei iBMC", Classifier.MatchSignature("Huawei FusionServer Management"));
        Assert.Equal("H3C HDM", Classifier.MatchSignature("H3C HDM Web Console"));
        Assert.Equal("H3C HDM", Classifier.MatchSignature("H3C UniServer Management"));
        Assert.Equal("Fujitsu iRMC", Classifier.MatchSignature("Fujitsu PRIMERGY iRMC S5"));
        Assert.Equal("Gigabyte BMC", Classifier.MatchSignature("Gigabyte Server BMC Console"));
    }

    [Fact]
    public void Classifier_HandlesNonZeroDeviceIdAndAsfOem()
    {
        var devErrHost = new HostResult
        {
            Ip = "192.168.1.60",
            DeviceId = new DeviceIdInfo { CompletionCode = 0xD4, Note = "Get Device ID 被拒绝" },
        };
        Classifier.Classify(devErrHost);
        Assert.Equal(ScanConstants.ConfConfirmed, devErrHost.Confidence);
        Assert.Contains(devErrHost.Evidence, e => e.Contains("0xD4"));

        var asfHost = new HostResult
        {
            Ip = "192.168.1.61",
            AsfPong = true,
            AsfInfo = new AsfPongInfo { OemIana = 674, IpmiSupported = true },
        };
        Classifier.Classify(asfHost);
        Assert.Equal(ScanConstants.ConfConfirmed, asfHost.Confidence);
        Assert.Equal("Dell BMC", asfHost.Vendor);
        Assert.Contains(asfHost.Evidence, e => e.Contains("支持 IPMI"));
    }

    [Fact]
    public void Exporters_NeutralizesCsvFormulaInjection()
    {
        var host = new HostResult
        {
            Ip = "192.168.1.99",
            Vendor = "=cmd|'/C calc'!A0",
            Confidence = ScanConstants.ConfLikely,
            Evidence = new List<string> { "+1+1", "@SUM(A1:A2)" },
        };
        string csv = Exporters.ToCsv(new[] { host }, false);
        Assert.Contains("'=cmd|'/C calc'!A0", csv);
        Assert.Contains("'+1+1 | @SUM(A1:A2)", csv);
    }

    [Fact]
    public void Dechunk_HandlesHugeMalformedChunkSizeWithoutOverflow()
    {
        byte[] malformed = Encoding.ASCII.GetBytes("7FFFFFFF\r\nhello");
        byte[] decoded = HttpProbe.Dechunk(malformed);
        Assert.Equal("hello", Encoding.ASCII.GetString(decoded));
    }

    [Fact]
    public void NetworkDiscovery_RejectsShorthandIPv4()
    {
        Assert.Throws<FormatException>(() => NetworkDiscovery.ParseTargetRange("192.168.1"));
        Assert.Throws<FormatException>(() => NetworkDiscovery.ParseTargetRange("10"));
        Assert.Throws<FormatException>(() => NetworkDiscovery.ParseTargetRange("192.168.1/24"));
        Assert.Throws<FormatException>(() => NetworkDiscovery.ParseTargetRange("192.168.1.1-0x10"));
    }

    [Fact]
    public void Version_MatchesAssemblyMetadataWithoutBuildSuffix()
    {
        Assert.False(string.IsNullOrWhiteSpace(ScanConstants.Version));
        Assert.DoesNotContain('+', ScanConstants.Version);
        Assert.Matches(@"^\d+\.\d+\.\d+", ScanConstants.Version);
    }
}
