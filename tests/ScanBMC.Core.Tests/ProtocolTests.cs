using System.IO.Compression;
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
        // fw1=0x26(可用, 次版本 26), fw2=0x06(主版本 6), ipmi_ver=0x51(IPMI 1.5), OEM=10876, Product=0x0100
        byte[] payload = { 0x20, 0x01, 0x26, 0x06, 0x51, 0x00, 0x7C, 0x2A, 0x00, 0x00, 0x01 };
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
}
