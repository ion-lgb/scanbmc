using System.Net;
using System.Net.Sockets;
using System.Text;
using ScanBMC.Core;
using Xunit;

namespace ScanBMC.Core.Tests;

public class IntegrationTests
{
    [Fact]
    public async Task ScanAsync_DetectsLocalFakeBmcEndToEnd()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // 1) 启动假 UDP IPMI/ASF 服务
        using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
        var udpTask = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                UdpReceiveResult req;
                try
                {
                    req = await udpServer.ReceiveAsync(cts.Token);
                }
                catch
                {
                    break;
                }

                if (req.Buffer.Length > 3 && req.Buffer[3] == 0x07)
                {
                    if (req.Buffer.Length > 19 && req.Buffer[19] == 0x01)
                    {
                        byte[] payload = { 0x20, 0x01, 0x26, 0x06, 0x02, 0x00, 0x7C, 0x2A, 0x00, 0x00, 0x01 };
                        byte[] body = new byte[] { 0x81, 0x1C, 0x63, 0x20, 0x00, 0x01, 0x00 }.Concat(payload).ToArray();
                        byte[] resp = new byte[] { 0x06, 0x00, 0xFF, 0x07 }.Concat(new byte[9]).Concat(new[] { (byte)body.Length }).Concat(body).ToArray();
                        await udpServer.SendAsync(resp, req.RemoteEndPoint, cts.Token);
                    }
                    else
                    {
                        byte[] payload = { 0x01, 0x95, 0x02, 0x02, 0x7C, 0x2A, 0x00, 0x00 };
                        byte[] body = new byte[] { 0x81, 0x1C, 0x63, 0x20, 0x00, 0x38, 0x00 }.Concat(payload).ToArray();
                        byte[] resp = new byte[] { 0x06, 0x00, 0xFF, 0x07 }.Concat(new byte[9]).Concat(new[] { (byte)body.Length }).Concat(body).ToArray();
                        await udpServer.SendAsync(resp, req.RemoteEndPoint, cts.Token);
                    }
                }
                else if (req.Buffer.Length > 3 && req.Buffer[3] == 0x06)
                {
                    byte[] pong = new byte[] { 0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, req.Buffer[9], 0x00, 0x10, 0x00, 0x00, 0x11, 0xBE, 0, 0, 0, 0, 0x81, 0, 0, 0, 0, 0, 0, 0 };
                    await udpServer.SendAsync(pong, req.RemoteEndPoint, cts.Token);
                }
            }
        });

        // 2) 启动假 HTTP + Redfish 服务
        var tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start();
        int httpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        var httpTask = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await tcpListener.AcceptTcpClientAsync(cts.Token);
                }
                catch
                {
                    break;
                }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        var stream = client.GetStream();
                        byte[] buf = new byte[1024];
                        int n = await stream.ReadAsync(buf, cts.Token);
                        string reqText = Encoding.ASCII.GetString(buf, 0, n);
                        string respStr = reqText.StartsWith("GET /redfish/v1/")
                            ? "HTTP/1.1 401 Unauthorized\r\nServer: AMI MegaRAC Redfish Service\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"Vendor\":\"Dell\",\"RedfishVersion\":\"1.6.0\"}"
                            : "HTTP/1.1 200 OK\r\nServer: Mbedthis-Appweb/2.4.2\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><head><title>iDRAC9 Login</title></head></html>";
                        byte[] outBytes = Encoding.UTF8.GetBytes(respStr);
                        await stream.WriteAsync(outBytes, cts.Token);
                    }
                });
            }
        });

        try
        {
            var cfg = new ScanConfig
            {
                TcpPorts = new List<int> { httpPort },
                Concurrency = 16,
                Timeout = TimeSpan.FromSeconds(1),
                Retries = 0,
                EnableUdp = true,
                EnableWeb = true,
                EnableRedfish = true,
                IpmiUdpPort = udpPort,
                WebPortsOverride = new Dictionary<int, bool> { [httpPort] = false },
                RedfishPortsOverride = new HashSet<int> { httpPort },
            };

            var results = await Scanner.ScanAsync(new[] { "127.0.0.1" }, cfg, ct: cts.Token);
            Assert.Single(results);
            var host = results[0];
            Assert.Equal(ScanConstants.ConfConfirmed, host.Confidence);
            Assert.Equal("Supermicro BMC", host.Vendor);
            Assert.NotNull(host.Ipmi);
            Assert.NotNull(host.DeviceId);
            Assert.Equal("6.26", host.DeviceId!.Firmware);
            Assert.NotNull(host.Redfish);
            Assert.Equal(401, host.Redfish!.Status);
            Assert.True(host.HasWarnings);
        }
        finally
        {
            cts.Cancel();
            tcpListener.Stop();
            await Task.WhenAll(udpTask, httpTask);
        }
    }
}
