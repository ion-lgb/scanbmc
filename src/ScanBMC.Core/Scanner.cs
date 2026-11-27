using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ScanBMC.Core;

/// <summary>纯异步高并发两阶段 BMC 扫描引擎（无线程池爆炸、支持 CancellationToken 即时取消）。</summary>
public static class Scanner
{
    public static async Task<PortResult?> TcpProbeAsync(
        string ip,
        int port,
        TimeSpan timeout,
        int retries,
        IReadOnlyDictionary<int, bool> webPorts,
        ProbeStats? stats,
        CancellationToken ct)
    {
        for (int attempt = 0; attempt <= retries; attempt++)
        {
            if (ct.IsCancellationRequested) return null;

            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeout);

            try
            {
                await tcp.ConnectAsync(ip, port, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                if (attempt < retries) continue;
                stats?.Add("timeout");
                return null;
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                stats?.Add("refused");
                return null;
            }
            catch (SocketException ex)
            {
                if (ProbeStats.IsSystemic(ex.SocketErrorCode) || ProbeStats.IsHostDown(ex.SocketErrorCode))
                {
                    stats?.AddSocketError(ex.SocketErrorCode);
                    return null;
                }
                if (attempt < retries) continue;
                stats?.AddSocketError(ex.SocketErrorCode);
                return null;
            }

            string banner = "";
            if (!webPorts.ContainsKey(port))
            {
                try
                {
                    using var bCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    bCts.CancelAfter(timeout < TimeSpan.FromSeconds(1) ? timeout : TimeSpan.FromSeconds(1));
                    byte[] buf = new byte[128];
                    int n = await tcp.GetStream().ReadAsync(buf, bCts.Token).ConfigureAwait(false);
                    if (n > 0)
                        banner = Encoding.UTF8.GetString(buf, 0, n).Trim();
                }
                catch
                {
                    banner = "";
                }
            }

            stats?.Add("open");
            ScanConstants.DefaultTcpPorts.TryGetValue(port, out var svc);
            return new PortResult
            {
                Port = port,
                Proto = "tcp",
                Service = svc ?? "",
                Banner = banner,
            };
        }
        return null;
    }

    public delegate T? PacketParser<T>(ReadOnlySpan<byte> data) where T : class;

    public static async Task<T?> UdpSendAsync<T>(
        string ip,
        int udpPort,
        byte[] packet,
        TimeSpan timeout,
        int retries,
        PacketParser<T> parser,
        ProbeStats? stats,
        CancellationToken ct) where T : class
    {
        var (result, _) = await UdpSendInternalAsync(ip, udpPort, packet, timeout, retries, parser, stats, ct)
            .ConfigureAwait(false);
        return result;
    }

    private static async Task<(T? Result, bool StopHost)> UdpSendInternalAsync<T>(
        string ip,
        int udpPort,
        byte[] packet,
        TimeSpan timeout,
        int retries,
        PacketParser<T> parser,
        ProbeStats? stats,
        CancellationToken ct) where T : class
    {
        var remoteEp = new IPEndPoint(IPAddress.Parse(ip), udpPort);

        for (int attempt = 0; attempt <= retries; attempt++)
        {
            if (ct.IsCancellationRequested) return (null, true);

            using var udp = new UdpClient(AddressFamily.InterNetwork);
            try
            {
                await udp.SendAsync(packet, remoteEp, ct).ConfigureAwait(false);
                var deadline = DateTime.UtcNow + timeout;

                while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
                {
                    var remain = deadline - DateTime.UtcNow;
                    if (remain <= TimeSpan.Zero) break;

                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    linked.CancelAfter(remain);

                    UdpReceiveResult recv;
                    try
                    {
                        recv = await udp.ReceiveAsync(linked.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (!recv.RemoteEndPoint.Address.Equals(remoteEp.Address) ||
                        recv.RemoteEndPoint.Port != remoteEp.Port)
                    {
                        continue;
                    }

                    T? parsed = parser(recv.Buffer);
                    if (parsed is not null)
                        return (parsed, false);
                }
            }
            catch (OperationCanceledException)
            {
                return (null, true);
            }
            catch (SocketException ex)
            {
                if (ProbeStats.IsSystemic(ex.SocketErrorCode) || ProbeStats.IsHostDown(ex.SocketErrorCode))
                {
                    stats?.AddSocketError(ex.SocketErrorCode);
                    return (null, true);
                }
                if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    return (null, true);
                if (attempt < retries) continue;
                return (null, false);
            }
        }
        return (null, false);
    }

    public static async Task<List<HostResult>> ScanAsync(
        IReadOnlyList<string> targets,
        ScanConfig config,
        ProbeStats? stats = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var webPorts = config.WebPortsOverride ?? ScanConstants.WebPorts;
        var redfishPorts = config.RedfishPortsOverride ?? ScanConstants.RedfishPorts;

        var hosts = new ConcurrentDictionary<string, HostResult>();
        var hostLocks = new ConcurrentDictionary<string, object>();
        foreach (var ip in targets)
        {
            hosts[ip] = new HostResult { Ip = ip };
            hostLocks[ip] = new object();
        }

        // ---- 阶段一：TCP + UDP 异步端口与协议发现 ----
        var probeItems = new List<(string Kind, string Ip, int Port)>();
        foreach (var ip in targets)
        {
            if (config.EnableUdp)
                probeItems.Add(("udp_bmc", ip, config.IpmiUdpPort));
            foreach (var port in config.TcpPorts)
                probeItems.Add(("tcp", ip, port));
        }

        int total1 = probeItems.Count;
        int done1 = 0;
        int reportStep1 = Math.Max(4, total1 / 200);
        int maxConcurrency = Math.Max(1, config.Concurrency);

        using (var sem = new SemaphoreSlim(maxConcurrency, maxConcurrency))
        {
            var tasks = new List<Task>(total1);
            foreach (var item in probeItems)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    await sem.WaitAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (ct.IsCancellationRequested) return;
                        if (item.Kind == "udp_bmc")
                        {
                            // 同主机 UDP/623 串行发送，避免低性能嵌入式 BMC 并发丢包，并在明确不可达时提前短路
                            var (ipmi, stop1) = await UdpSendInternalAsync(
                                item.Ip, item.Port, IpmiProtocol.GetChannelAuthCapPacket,
                                config.Timeout, config.Retries, IpmiProtocol.ParseChannelAuthCap,
                                stats, ct).ConfigureAwait(false);
                            if (ipmi is not null)
                                lock (hostLocks[item.Ip]) hosts[item.Ip].Ipmi = ipmi;
                            if (stop1 || ct.IsCancellationRequested) return;

                            var (devId, stop2) = await UdpSendInternalAsync(
                                item.Ip, item.Port, IpmiProtocol.GetDeviceIdPacket,
                                config.Timeout, config.Retries, IpmiProtocol.ParseDeviceId,
                                stats, ct).ConfigureAwait(false);
                            if (devId is not null)
                                lock (hostLocks[item.Ip]) hosts[item.Ip].DeviceId = devId;
                            if (stop2 || ct.IsCancellationRequested) return;

                            // 已确认 IPMI 应答则无需补发 ASF Presence Ping
                            if (ipmi is null && devId is null)
                            {
                                var (pong, _) = await UdpSendInternalAsync(
                                    item.Ip, item.Port, IpmiProtocol.AsfPresencePingPacket,
                                    config.Timeout, config.Retries, IpmiProtocol.ParseAsfPong,
                                    stats, ct).ConfigureAwait(false);
                                if (pong is not null)
                                {
                                    lock (hostLocks[item.Ip])
                                    {
                                        hosts[item.Ip].AsfPong = true;
                                        hosts[item.Ip].AsfInfo = pong;
                                    }
                                }
                            }
                        }
                        else
                        {
                            var tcpRes = await TcpProbeAsync(
                                item.Ip, item.Port, config.Timeout, config.Retries,
                                webPorts, stats, ct).ConfigureAwait(false);
                            if (tcpRes is not null)
                                lock (hostLocks[item.Ip]) hosts[item.Ip].Ports.Add(tcpRes);
                        }
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        stats?.Add($"bug:{ex.GetType().Name}");
                    }
                    finally
                    {
                        sem.Release();
                        if (!ct.IsCancellationRequested)
                        {
                            int cur = Interlocked.Increment(ref done1);
                            if (cur == total1 || cur % reportStep1 == 0)
                                progress?.Report(new ScanProgress(cur, total1, "probe"));
                        }
                    }
                }, CancellationToken.None));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        // ---- 阶段二：Web / Redfish 指纹识别 ----
        if (!ct.IsCancellationRequested)
        {
            var fpItems = new List<(string Kind, string Ip, int Port, bool Tls)>();
            foreach (var host in hosts.Values)
            {
                if (!host.IsAlive) continue;
                foreach (var p in host.Ports)
                {
                    if (!webPorts.TryGetValue(p.Port, out bool tls)) continue;
                    if (config.EnableWeb)
                        fpItems.Add(("web", host.Ip, p.Port, tls));
                    if (config.EnableRedfish && redfishPorts.Contains(p.Port))
                        fpItems.Add(("redfish", host.Ip, p.Port, tls));
                }
            }

            if (fpItems.Count > 0)
            {
                int total2 = fpItems.Count;
                int done2 = 0;
                int fpWorkers = Math.Min(maxConcurrency, 64);
                TimeSpan fpTimeout = TimeSpan.FromTicks(config.Timeout.Ticks * 2);

                using var sem2 = new SemaphoreSlim(fpWorkers, fpWorkers);
                var fpTasks = new List<Task>(total2);

                foreach (var item in fpItems)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        await sem2.WaitAsync(ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    fpTasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            if (ct.IsCancellationRequested) return;
                            if (item.Kind == "web")
                            {
                                var w = await HttpProbe.ProbeWebAsync(
                                    item.Ip, item.Port, item.Tls, fpTimeout, config.Retries, ct).ConfigureAwait(false);
                                if (w is not null)
                                    lock (hostLocks[item.Ip]) hosts[item.Ip].Web.Add(w);
                            }
                            else
                            {
                                var rf = await HttpProbe.ProbeRedfishAsync(
                                    item.Ip, item.Port, item.Tls, fpTimeout, config.Retries, ct).ConfigureAwait(false);
                                if (rf is not null)
                                {
                                    lock (hostLocks[item.Ip])
                                    {
                                        var existing = hosts[item.Ip].Redfish;
                                        bool existingIsTls = existing is not null && webPorts.GetValueOrDefault(existing.Port);
                                        bool preferNew = existing is null
                                            || (item.Tls && !existingIsTls)
                                            || (item.Port == 443 && existing.Port != 443);
                                        if (preferNew)
                                            hosts[item.Ip].Redfish = rf;
                                    }
                                }
                            }
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            stats?.Add($"bug:{ex.GetType().Name}");
                        }
                        finally
                        {
                            sem2.Release();
                            if (!ct.IsCancellationRequested)
                            {
                                int cur = Interlocked.Increment(ref done2);
                                progress?.Report(new ScanProgress(cur, total2, "fp"));
                            }
                        }
                    }, CancellationToken.None));
                }

                await Task.WhenAll(fpTasks).ConfigureAwait(false);
            }
        }

        // 汇总与分类（先排序端口与 Web 列表，确保并发写入下输出完全确定）
        var results = hosts.Values.Where(h => h.IsAlive).ToList();
        foreach (var host in results)
        {
            host.Ports.Sort((a, b) => a.Port.CompareTo(b.Port));
            host.Web.Sort((a, b) =>
            {
                int tlsCmp = (a.Scheme != "https").CompareTo(b.Scheme != "https");
                return tlsCmp != 0 ? tlsCmp : a.Port.CompareTo(b.Port);
            });
            Classifier.Classify(host);
        }

        results.Sort((a, b) =>
        {
            int cmp = ScanConstants.ConfidenceRank(b.Confidence).CompareTo(ScanConstants.ConfidenceRank(a.Confidence));
            if (cmp != 0) return cmp;
            return NetworkDiscovery.IpToUInt(IPAddress.Parse(a.Ip))
                .CompareTo(NetworkDiscovery.IpToUInt(IPAddress.Parse(b.Ip)));
        });

        return results;
    }
}
