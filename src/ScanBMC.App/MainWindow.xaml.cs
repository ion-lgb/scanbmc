using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using ScanBMC.Core;

namespace ScanBMC.App;

public sealed class HostRow
{
    public HostResult Raw { get; }
    public string Ip => Raw.Ip;
    public uint IpSortKey { get; }
    public int ConfidenceRank => ScanConstants.ConfidenceRank(Raw.Confidence);
    public string ConfidenceDisplay => string.IsNullOrEmpty(Raw.Confidence) ? "—" : Raw.Confidence;
    public string VendorDisplay => string.IsNullOrEmpty(Raw.Vendor) ? "—" : Raw.Vendor;
    public string OpenPorts { get; }
    public bool HasWarnings => Raw.HasWarnings;
    public string WarningSummary { get; }
    public string EvidenceSummary { get; }

    public Brush ConfidenceBg { get; }
    public Brush ConfidenceFg { get; }
    public Brush ConfidenceBorder { get; }

    private static readonly Brush ConfirmedBg = Freeze(new SolidColorBrush(Color.FromRgb(0xE6, 0xF4, 0xEA)));
    private static readonly Brush ConfirmedFg = Freeze(new SolidColorBrush(Color.FromRgb(0x13, 0x73, 0x33)));
    private static readonly Brush ConfirmedBd = Freeze(new SolidColorBrush(Color.FromRgb(0xB7, 0xDF, 0xC1)));

    private static readonly Brush LikelyBg = Freeze(new SolidColorBrush(Color.FromRgb(0xE8, 0xF0, 0xFE)));
    private static readonly Brush LikelyFg = Freeze(new SolidColorBrush(Color.FromRgb(0x17, 0x4E, 0xA6)));
    private static readonly Brush LikelyBd = Freeze(new SolidColorBrush(Color.FromRgb(0xAE, 0xCB, 0xFA)));

    private static readonly Brush PossibleBg = Freeze(new SolidColorBrush(Color.FromRgb(0xF1, 0xF3, 0xF4)));
    private static readonly Brush PossibleFg = Freeze(new SolidColorBrush(Color.FromRgb(0x44, 0x47, 0x46)));
    private static readonly Brush PossibleBd = Freeze(new SolidColorBrush(Color.FromRgb(0xDA, 0xDC, 0xE0)));

    private static Brush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    public HostRow(HostResult raw)
    {
        Raw = raw;
        IpSortKey = NetworkDiscovery.IpToUInt(IPAddress.Parse(raw.Ip));
        OpenPorts = raw.OpenPortsString();
        WarningSummary = string.Join("；", raw.Warnings);
        EvidenceSummary = string.Join("；", raw.Evidence.Where(e => !e.StartsWith("⚠", StringComparison.Ordinal)));

        (ConfidenceBg, ConfidenceFg, ConfidenceBorder) = raw.Confidence switch
        {
            ScanConstants.ConfConfirmed => (ConfirmedBg, ConfirmedFg, ConfirmedBd),
            ScanConstants.ConfLikely => (LikelyBg, LikelyFg, LikelyBd),
            ScanConstants.ConfPossible => (PossibleBg, PossibleFg, PossibleBd),
            _ => (Brushes.Transparent, PossibleFg, Brushes.Transparent),
        };
    }

    public string FormatOverview()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"IP 地址  : {Raw.Ip}");
        sb.AppendLine($"置信度   : {ConfidenceDisplay}");
        sb.AppendLine($"设备类型 : {VendorDisplay}");
        sb.AppendLine($"开放端口 : {(string.IsNullOrEmpty(OpenPorts) ? "-" : OpenPorts)}");
        sb.AppendLine($"管理地址 : {Raw.PreferredUrl()}");
        return sb.ToString().TrimEnd();
    }

    public string FormatFullDetails()
    {
        var sb = new StringBuilder();
        if (Raw.Evidence.Count > 0)
        {
            foreach (var ev in Raw.Evidence)
                sb.AppendLine($"• {ev}");
        }
        else
        {
            sb.AppendLine("• 无 BMC 特征证据（普通存活主机）");
        }

        if (Raw.Ipmi is { CompletionCode: 0 } ipmi)
        {
            sb.AppendLine();
            sb.AppendLine($"[IPMI] 通道={ipmi.Channel}  版本={string.Join("/", ipmi.Versions)}  认证方式={string.Join(",", ipmi.AuthTypes)}");
        }
        if (Raw.DeviceId is { CompletionCode: 0 } dev)
        {
            sb.AppendLine($"[Device ID] 固件={dev.Firmware}  IPMI={dev.IpmiVersion}  厂商ID={dev.ManufacturerId}  产品ID=0x{dev.ProductId:X4}  状态={(dev.Available ? "正常" : "更新/不可用")}");
        }
        if (Raw.Redfish is { } rf)
        {
            sb.AppendLine($"[Redfish] HTTP {rf.Status}  版本={rf.Version}  Server={rf.Server}  Vendor={rf.Vendor}  Product={rf.Product}");
        }
        CertInfo? cert = Raw.Redfish?.Cert ?? Raw.Web.FirstOrDefault(w => w.Cert is not null)?.Cert;
        if (cert is not null)
        {
            sb.AppendLine($"[TLS 证书] CN={cert.SubjectCn}  颁发者={cert.Issuer}  到期={cert.NotAfter}（剩余 {cert.DaysLeft} 天）");
        }
        return sb.ToString().TrimEnd();
    }
}

public partial class MainWindow : Window
{
    private const int MaxHosts = 8192;

    private readonly ObservableCollection<HostRow> _visibleRows = new();
    private List<HostResult> _allResults = new();
    private object _lastMeta = new();
    private CancellationTokenSource? _cts;
    private bool _isScanning;

    public MainWindow()
    {
        InitializeComponent();
        PortsBox.Text = string.Join(",", ScanConstants.DefaultTcpPorts.Keys.OrderBy(p => p));
        ResultsGrid.ItemsSource = _visibleRows;

        // 冒烟测试钩子：SCANBMC_GUI_SMOKE=1 时 2 秒自动退出
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SCANBMC_GUI_SMOKE")))
        {
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (_, _) => { timer.Stop(); Close(); };
            timer.Start();
        }
    }

    private void AdvancedToggle_Changed(object sender, RoutedEventArgs e)
    {
        bool open = AdvancedToggle.IsChecked == true;
        AdvancedPanel.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
        AdvancedToggle.Content = open ? "高级参数 ▴" : "高级参数 ▾";
    }

    private void TargetsBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && !_isScanning)
            StartBtn_Click(sender, e);
    }

    private async void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;

        List<string> targets;
        List<int> tcpPorts;
        int concurrency;
        double timeoutSec;
        int retries;
        List<string> usedSpecs;

        try
        {
            usedSpecs = TargetsBox.Text
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();

            if (usedSpecs.Count == 0)
            {
                var nets = NetworkDiscovery.DetectLocalNetworks();
                if (nets.Count == 0)
                {
                    MessageBox.Show(this, "无法自动检测本机活动网段，请在「目标」栏手动输入（如 192.168.1.0/24）。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                usedSpecs = nets.Select(n => n.ToString()).ToList();
            }

            var excludes = ExcludeBox.Text
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();

            if (ArpOnlyCheck.IsChecked == true)
            {
                var neighbors = NetworkDiscovery.FilterToSpecs(NetworkDiscovery.GetArpNeighbors(), usedSpecs);
                if (neighbors.Count == 0)
                {
                    MessageBox.Show(this, "ARP 表中没有落在目标范围内的地址，请取消「ARP 快速模式」或更换目标网段。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                targets = NetworkDiscovery.BuildTargets(neighbors, excludes);
            }
            else
            {
                targets = NetworkDiscovery.BuildTargets(usedSpecs, excludes);
            }

            string portSpec = string.IsNullOrWhiteSpace(PortsBox.Text)
                ? string.Join(",", ScanConstants.DefaultTcpPorts.Keys.OrderBy(p => p))
                : PortsBox.Text;
            tcpPorts = NetworkDiscovery.ParsePorts(portSpec);

            if (!int.TryParse(ConcurrencyBox.Text.Trim(), out concurrency) || concurrency < 1 || concurrency > 2048)
                throw new FormatException("并发数需为 1~2048 的整数");
            if (!double.TryParse(TimeoutBox.Text.Trim(), out timeoutSec) || timeoutSec < 0.1 || timeoutSec > 30)
                throw new FormatException("超时需为 0.1~30 之间的秒数");
            if (!int.TryParse(RetriesBox.Text.Trim(), out retries) || retries < 0 || retries > 5)
                throw new FormatException("重试次数需为 0~5 的整数");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"参数错误：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        if (targets.Count == 0)
        {
            MessageBox.Show(this, "目标列表为空，请检查目标与排除设置。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (targets.Count > MaxHosts)
        {
            MessageBox.Show(this, $"目标数 {targets.Count} 超过上限 {MaxHosts}，请缩小网段范围。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var cfg = new ScanConfig
        {
            TcpPorts = tcpPorts,
            Concurrency = concurrency,
            Timeout = TimeSpan.FromSeconds(timeoutSec),
            Retries = retries,
            EnableUdp = UdpCheck.IsChecked == true,
            EnableWeb = WebCheck.IsChecked == true,
            EnableRedfish = RedfishCheck.IsChecked == true,
        };

        SetBusy(true);
        _allResults.Clear();
        _visibleRows.Clear();
        ClearDetailPane();
        SummaryText.Text = "";
        StatusText.Text = $"正在扫描 {string.Join(", ", usedSpecs)}（共 {targets.Count} 个目标）...";
        ScanProgressBar.Visibility = Visibility.Visible;
        ScanProgressBar.Value = 0;

        _cts = new CancellationTokenSource();
        var stats = new ProbeStats();
        var sw = Stopwatch.StartNew();

        var progress = new Progress<ScanProgress>(p =>
        {
            if (_cts?.IsCancellationRequested == true) return;
            string phaseName = p.Phase == "probe" ? "端口与 IPMI 发现" : "Web / Redfish 指纹识别";
            ScanProgressBar.Maximum = Math.Max(1, p.Total);
            ScanProgressBar.Value = p.Done;
            StatusText.Text = $"{phaseName}：{p.Done} / {p.Total}";
        });

        try
        {
            var results = await Scanner.ScanAsync(targets, cfg, stats, progress, _cts.Token);
            sw.Stop();

            _allResults = results;
            int alive = results.Count;
            int bmc = results.Count(r => r.IsBmc);
            int warned = results.Count(r => r.IsBmc && r.HasWarnings);

            _lastMeta = new
            {
                version = ScanConstants.Version,
                networks = usedSpecs,
                targets = targets.Count,
                elapsed_seconds = Math.Round(sw.Elapsed.TotalSeconds, 2),
                alive,
                bmc,
                degraded = stats.IsDegraded,
            };

            RefreshFilteredRows();

            if (_cts.IsCancellationRequested)
            {
                StatusText.Text = $"已停止，展示已发现的 {alive} 台存活主机（BMC {bmc} 台）";
            }
            else
            {
                StatusText.Text = $"完成：扫描 {targets.Count} 个地址，耗时 {sw.Elapsed.TotalSeconds:F1}s";
            }

            SummaryText.Text = $"存活 {alive}  |  BMC {bmc}  |  告警 {warned}";

            if (stats.IsDegraded && !_cts.IsCancellationRequested)
            {
                MessageBox.Show(
                    this,
                    $"本机侧有 {stats.SystemicRatio:P0} 的探测发包失败（网卡未连接 / 无路由 / 句柄受限），本次扫描结果不可信。",
                    "扫描结果不可信",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"扫描过程出错：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            StatusText.Text = "扫描失败";
        }
        finally
        {
            ScanProgressBar.Visibility = Visibility.Collapsed;
            _cts?.Dispose();
            _cts = null;
            SetBusy(false);
        }
    }

    private void StopBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_cts is not null && !_cts.IsCancellationRequested)
        {
            StatusText.Text = "正在停止...";
            _cts.Cancel();
        }
    }

    private void SetBusy(bool busy)
    {
        _isScanning = busy;
        StartBtn.IsEnabled = !busy;
        StopBtn.IsEnabled = busy;
        TargetsBox.IsEnabled = !busy;
        AdvancedPanel.IsEnabled = !busy;
    }

    private void FilterChanged(object sender, RoutedEventArgs e) => RefreshFilteredRows();

    private void RefreshFilteredRows()
    {
        string kw = FilterBox.Text.Trim();
        bool showAll = ShowAllCheck.IsChecked == true;
        bool warnOnly = WarnOnlyCheck.IsChecked == true;

        _visibleRows.Clear();
        foreach (var host in _allResults)
        {
            if (!showAll && !host.IsBmc) continue;
            if (warnOnly && !host.HasWarnings) continue;
            if (!string.IsNullOrEmpty(kw))
            {
                bool match = host.Ip.Contains(kw, StringComparison.OrdinalIgnoreCase)
                    || host.Vendor.Contains(kw, StringComparison.OrdinalIgnoreCase)
                    || host.OpenPortsString().Contains(kw, StringComparison.OrdinalIgnoreCase)
                    || host.Evidence.Any(ev => ev.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (!match) continue;
            }
            _visibleRows.Add(new HostRow(host));
        }

        if (_visibleRows.Count > 0 && ResultsGrid.SelectedItem is null)
            ResultsGrid.SelectedIndex = 0;
        else if (_visibleRows.Count == 0)
            ClearDetailPane();
    }

    private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
        {
            DetailOverviewBox.Text = row.FormatOverview();
            DetailEvidenceBox.Text = row.FormatFullDetails();
            OpenBrowserBtn.IsEnabled = true;
            CopyIpBtn.IsEnabled = true;
            CopyDetailBtn.IsEnabled = true;
        }
        else
        {
            ClearDetailPane();
        }
    }

    private void ClearDetailPane()
    {
        DetailOverviewBox.Text = "选中上方列表中的任意设备查看完整协议与证书详情（双击可直接打开管理页）。";
        DetailEvidenceBox.Text = "";
        OpenBrowserBtn.IsEnabled = false;
        CopyIpBtn.IsEnabled = false;
        CopyDetailBtn.IsEnabled = false;
    }

    private void ResultsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
            OpenUrl(row.Raw.PreferredUrl());
    }

    private void CtxOpenPreferred_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
            OpenUrl(row.Raw.PreferredUrl());
    }

    private void CtxOpenHttps_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
            OpenUrl($"https://{row.Ip}/");
    }

    private void CtxOpenHttp_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
            OpenUrl($"http://{row.Ip}/");
    }

    private void CtxCopyIp_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
        {
            Clipboard.SetText(row.Ip);
            StatusText.Text = $"已复制 IP：{row.Ip}";
        }
    }

    private void CtxCopyDetails_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is HostRow row)
        {
            Clipboard.SetText($"{row.FormatOverview()}\r\n\r\n{row.FormatFullDetails()}");
            StatusText.Text = $"已复制 {row.Ip} 的完整诊断信息";
        }
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            StatusText.Text = $"已在浏览器中打开 {url}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"无法打开浏览器：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportJsonBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.Count == 0)
        {
            MessageBox.Show(this, "还没有可导出的扫描结果，请先运行扫描。", "导出 JSON", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new SaveFileDialog { Filter = "JSON 文件 (*.json)|*.json", FileName = "scanbmc-results.json" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dlg.FileName, Exporters.ToJson(_allResults, ShowAllCheck.IsChecked == true, _lastMeta), Encoding.UTF8);
            StatusText.Text = $"已导出 JSON：{dlg.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"写入失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportCsvBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.Count == 0)
        {
            MessageBox.Show(this, "还没有可导出的扫描结果，请先运行扫描。", "导出 CSV", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new SaveFileDialog { Filter = "CSV 文件 (*.csv)|*.csv", FileName = "scanbmc-results.csv" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            // 带 UTF-8 BOM 方便 Excel 直接双击打开不乱码
            File.WriteAllText(dlg.FileName, Exporters.ToCsv(_allResults, ShowAllCheck.IsChecked == true), new UTF8Encoding(true));
            StatusText.Text = $"已导出 CSV：{dlg.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"写入失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _cts?.Cancel();
        base.OnClosed(e);
    }
}
