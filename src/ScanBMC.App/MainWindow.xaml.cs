using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using ScanBMC.Core;

namespace ScanBMC.App;

public sealed class EvidenceItem
{
    public string Text { get; init; } = "";
    public Brush Bg { get; init; } = Brushes.Transparent;
    public Brush Border { get; init; } = Brushes.Transparent;
    public Thickness BorderThickness { get; init; } = new(0);
    public Brush Fg { get; init; } = Brushes.Black;
    public Brush Dot { get; init; } = Brushes.Gray;
}

public sealed class HostRow
{
    public HostResult Raw { get; }
    public string Ip => Raw.Ip;
    public uint IpSortKey { get; }
    public int ConfidenceRank => ScanConstants.ConfidenceRank(Raw.Confidence);
    public string ConfidenceDisplay => string.IsNullOrEmpty(Raw.Confidence) ? "存活" : Raw.Confidence;
    public string VendorDisplay => string.IsNullOrEmpty(Raw.Vendor) ? "—" : Raw.Vendor;
    public string OpenPorts { get; }
    public string CompactPorts { get; }
    public int WarningCount => Raw.Warnings.Count;
    public Visibility WarningVisibility => Raw.HasWarnings ? Visibility.Visible : Visibility.Collapsed;
    public string WarningShort { get; }
    public string ProtocolSummary { get; }

    public Brush ConfidenceBg { get; }
    public Brush ConfidenceFg { get; }
    public Brush ConfidenceBorder { get; }

    public Brush WarningBg { get; }
    public Brush WarningFg { get; }
    public Brush WarningBorder { get; }

    private static readonly Brush ConfirmedBg = Freeze(new SolidColorBrush(Color.FromRgb(0xDF, 0xF6, 0xDD)));
    private static readonly Brush ConfirmedFg = Freeze(new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10)));
    private static readonly Brush ConfirmedBd = Freeze(new SolidColorBrush(Color.FromRgb(0xBC, 0xE8, 0xB7)));

    private static readonly Brush LikelyBg = Freeze(new SolidColorBrush(Color.FromRgb(0xE8, 0xF2, 0xFC)));
    private static readonly Brush LikelyFg = Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0x5A, 0x9E)));
    private static readonly Brush LikelyBd = Freeze(new SolidColorBrush(Color.FromRgb(0xB8, 0xD7, 0xF5)));

    private static readonly Brush NeutralBg = Freeze(new SolidColorBrush(Color.FromRgb(0xF3, 0xF3, 0xF3)));
    private static readonly Brush NeutralFg = Freeze(new SolidColorBrush(Color.FromRgb(0x5E, 0x5E, 0x5E)));
    private static readonly Brush NeutralBd = Freeze(new SolidColorBrush(Color.FromRgb(0xE0, 0xE0, 0xE0)));

    private static readonly Brush WarnAmberBg = Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0xF4, 0xCE)));
    private static readonly Brush WarnAmberFg = Freeze(new SolidColorBrush(Color.FromRgb(0x8A, 0x53, 0x00)));
    private static readonly Brush WarnAmberBd = Freeze(new SolidColorBrush(Color.FromRgb(0xF0, 0xD2, 0x8B)));

    private static readonly Brush WarnRedBg = Freeze(new SolidColorBrush(Color.FromRgb(0xFD, 0xE7, 0xE9)));
    private static readonly Brush WarnRedFg = Freeze(new SolidColorBrush(Color.FromRgb(0xA4, 0x26, 0x2C)));
    private static readonly Brush WarnRedBd = Freeze(new SolidColorBrush(Color.FromRgb(0xF1, 0xB8, 0xBE)));

    private static readonly Brush NormalFg = Freeze(new SolidColorBrush(Color.FromRgb(0x2B, 0x2B, 0x2B)));
    private static readonly Brush NormalDot = Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0x67, 0xC0)));

    private static Brush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    public HostRow(HostResult raw)
    {
        Raw = raw;
        IpSortKey = NetworkDiscovery.IpToUInt(IPAddress.Parse(raw.Ip));
        OpenPorts = raw.OpenPortsString();
        CompactPorts = BuildCompactPorts(raw);

        var warns = raw.Warnings;
        if (warns.Count > 0)
        {
            string first = warns[0].TrimStart('⚠', ' ');
            WarningShort = warns.Count > 1 ? $"{first} (+{warns.Count - 1})" : first;
            bool severe = warns.Any(w => w.Contains("已过期") || w.Contains("匿名登录"));
            (WarningBg, WarningFg, WarningBorder) = severe
                ? (WarnRedBg, WarnRedFg, WarnRedBd)
                : (WarnAmberBg, WarnAmberFg, WarnAmberBd);
        }
        else
        {
            WarningShort = "";
            (WarningBg, WarningFg, WarningBorder) = (Brushes.Transparent, Brushes.Transparent, Brushes.Transparent);
        }

        ProtocolSummary = BuildProtocolSummary(raw);

        (ConfidenceBg, ConfidenceFg, ConfidenceBorder) = raw.Confidence switch
        {
            ScanConstants.ConfConfirmed => (ConfirmedBg, ConfirmedFg, ConfirmedBd),
            ScanConstants.ConfLikely => (LikelyBg, LikelyFg, LikelyBd),
            _ => (NeutralBg, NeutralFg, NeutralBd),
        };
    }

    private static string BuildCompactPorts(HostResult r)
    {
        var list = new List<string>();
        if (r.Ipmi is not null || r.AsfPong || r.DeviceId is not null)
            list.Add("623/udp");
        list.AddRange(r.Ports.OrderBy(p => p.Port).Select(p => p.Port.ToString()));
        return list.Count > 0 ? string.Join(", ", list) : "—";
    }

    private static string BuildProtocolSummary(HostResult r)
    {
        var parts = new List<string>();
        if (r.Ipmi is { } ipmi)
        {
            string v = ipmi.Versions.Count > 0 ? $"v{string.Join("/", ipmi.Versions)}" : "";
            parts.Add($"IPMI {v}".Trim());
        }
        else if (r.AsfPong)
        {
            parts.Add("ASF Pong");
        }

        if (r.DeviceId is { CompletionCode: 0 } dev && !string.IsNullOrEmpty(dev.Firmware))
            parts.Add($"FW {dev.Firmware}");

        if (r.Redfish is { } rf)
            parts.Add(string.IsNullOrEmpty(rf.Version) ? $"Redfish ({rf.Status})" : $"Redfish {rf.Version}");

        CertInfo? cert = r.Redfish?.Cert ?? r.Web.FirstOrDefault(w => w.Cert is not null)?.Cert;
        if (cert is not null && !cert.Expired)
            parts.Add($"TLS 至 {cert.NotAfter}");

        if (parts.Count == 0)
        {
            var nonWarn = r.Evidence.Where(e => !e.StartsWith("⚠", StringComparison.Ordinal)).Take(2);
            return string.Join(" · ", nonWarn);
        }
        return string.Join("  ·  ", parts);
    }

    public List<EvidenceItem> BuildEvidenceItems()
    {
        var items = new List<EvidenceItem>();
        // 告警条目置顶显示，其余按原序排列
        var ordered = Raw.Evidence
            .OrderByDescending(e => e.StartsWith("⚠", StringComparison.Ordinal))
            .ToList();

        if (ordered.Count == 0)
        {
            items.Add(new EvidenceItem
            {
                Text = "无 BMC 特征证据（普通局域网存活主机）",
                Fg = NeutralFg,
                Dot = NeutralFg,
            });
            return items;
        }

        foreach (var ev in ordered)
        {
            if (ev.StartsWith("⚠", StringComparison.Ordinal))
            {
                bool severe = ev.Contains("已过期") || ev.Contains("匿名登录");
                items.Add(new EvidenceItem
                {
                    Text = ev.TrimStart('⚠', ' '),
                    Bg = severe ? WarnRedBg : WarnAmberBg,
                    Border = severe ? WarnRedBd : WarnAmberBd,
                    BorderThickness = new Thickness(1),
                    Fg = severe ? WarnRedFg : WarnAmberFg,
                    Dot = severe ? WarnRedFg : WarnAmberFg,
                });
            }
            else
            {
                items.Add(new EvidenceItem
                {
                    Text = ev,
                    Fg = NormalFg,
                    Dot = NormalDot,
                });
            }
        }
        return items;
    }

    public string FormatFullReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"IP 地址  : {Raw.Ip}");
        sb.AppendLine($"置信度   : {ConfidenceDisplay}");
        sb.AppendLine($"设备类型 : {VendorDisplay}");
        sb.AppendLine($"开放端口 : {(string.IsNullOrEmpty(OpenPorts) ? "-" : OpenPorts)}");
        sb.AppendLine($"管理地址 : {Raw.PreferredUrl()}");
        sb.AppendLine();
        sb.AppendLine("判定依据:");
        foreach (var ev in Raw.Evidence)
            sb.AppendLine($"  - {ev}");
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

        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SCANBMC_GUI_SMOKE")))
        {
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (_, _) => { timer.Stop(); Close(); };
            timer.Start();
        }
    }

    private void DetectNetBtn_Click(object sender, RoutedEventArgs e)
    {
        var nets = NetworkDiscovery.DetectLocalNetworks();
        if (nets.Count == 0)
        {
            StatusText.Text = "未检测到活动 IPv4 网段，请手动输入目标。";
            return;
        }
        TargetsBox.Text = string.Join(", ", nets.Select(n => n.ToString()));
        StatusText.Text = $"已检测到 {nets.Count} 个本机网段：{TargetsBox.Text}";
    }

    private void AdvancedToggle_Changed(object sender, RoutedEventArgs e)
    {
        bool open = AdvancedToggle.IsChecked == true;
        AdvancedPanel.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
        AdvancedToggleText.Text = open ? "选项 ▴" : "选项 ▾";
    }

    private void ExportMenuBtn_Click(object sender, RoutedEventArgs e)
    {
        if (ExportMenuBtn.ContextMenu is { } menu)
        {
            menu.PlacementTarget = ExportMenuBtn;
            menu.Placement = PlacementMode.Bottom;
            menu.IsOpen = true;
        }
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
                    MessageBox.Show(this, "无法自动检测本机活动网段，请在「扫描目标」手动输入（如 192.168.1.0/24）。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                    MessageBox.Show(this, "ARP 表中没有落在目标范围内的地址，请取消「仅扫描 ARP 邻居」或更换目标网段。", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
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
        ClearInspector();
        UpdateSegmentCounts();
        EmptyTitle.Text = "正在扫描…";
        EmptySubtitle.Text = $"目标网段：{string.Join(", ", usedSpecs)}（共 {targets.Count} 个地址）";
        EmptyOverlay.Visibility = Visibility.Visible;
        SummaryText.Text = "";
        StatusText.Text = $"正在扫描 {string.Join(", ", usedSpecs)}（{targets.Count} 个地址）…";
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

            UpdateSegmentCounts();
            RefreshFilteredRows();

            StatusText.Text = _cts.IsCancellationRequested
                ? $"已停止（耗时 {sw.Elapsed.TotalSeconds:F1}s）"
                : $"扫描完成：{string.Join(", ", usedSpecs)}，耗时 {sw.Elapsed.TotalSeconds:F1}s";

            SummaryText.Text = $"目标 {targets.Count}   ·   存活 {alive}   ·   BMC {bmc}   ·   告警 {warned}";

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
            StatusText.Text = "正在停止…";
            _cts.Cancel();
        }
    }

    private void SetBusy(bool busy)
    {
        _isScanning = busy;
        StartBtn.IsEnabled = !busy;
        StopBtn.IsEnabled = busy;
        TargetsBox.IsEnabled = !busy;
        DetectNetBtn.IsEnabled = !busy;
        AdvancedPanel.IsEnabled = !busy;
    }

    private void UpdateSegmentCounts()
    {
        if (_allResults.Count == 0)
        {
            ModeBmcRadio.Content = "BMC";
            ModeWarnRadio.Content = "告警";
            ModeAllRadio.Content = "全部存活";
            return;
        }
        int bmc = _allResults.Count(r => r.IsBmc);
        int warn = _allResults.Count(r => r.IsBmc && r.HasWarnings);
        int alive = _allResults.Count;
        ModeBmcRadio.Content = $"BMC ({bmc})";
        ModeWarnRadio.Content = $"告警 ({warn})";
        ModeAllRadio.Content = $"全部 ({alive})";
    }

    private void FilterChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        RefreshFilteredRows();
    }

    private void RefreshFilteredRows()
    {
        string kw = FilterBox.Text.Trim();
        bool modeAll = ModeAllRadio.IsChecked == true;
        bool modeWarn = ModeWarnRadio.IsChecked == true;

        _visibleRows.Clear();
        foreach (var host in _allResults)
        {
            if (!modeAll && !host.IsBmc) continue;
            if (modeWarn && !host.HasWarnings) continue;
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

        if (_visibleRows.Count > 0)
        {
            EmptyOverlay.Visibility = Visibility.Collapsed;
            if (ResultsGrid.SelectedItem is null)
                ResultsGrid.SelectedIndex = 0;
        }
        else
        {
            ClearInspector();
            if (!_isScanning)
            {
                EmptyTitle.Text = _allResults.Count == 0 ? "未发现存活设备" : "无匹配筛选条件的设备";
                EmptySubtitle.Text = _allResults.Count == 0
                    ? "请确认目标网段可达，或适当增大超时时间后重试"
                    : "尝试清空搜索词或切换上方视图过滤选项";
                EmptyOverlay.Visibility = Visibility.Visible;
            }
        }
    }

    private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not HostRow row)
        {
            ClearInspector();
            return;
        }

        var r = row.Raw;
        InspectorTitle.Text = r.Ip;
        InspectorVendor.Text = $"{row.VendorDisplay}  ·  {row.ConfidenceDisplay}";

        PropUrlText.Text = r.PreferredUrl();
        PropPortsText.Text = string.IsNullOrEmpty(row.OpenPorts) ? "—" : row.OpenPorts;

        if (r.Ipmi is { CompletionCode: 0 } ipmi)
        {
            string ver = ipmi.Versions.Count > 0 ? $"v{string.Join("/", ipmi.Versions)}" : "IPMI";
            string auth = ipmi.AuthTypes.Count > 0 ? $"  ({string.Join(", ", ipmi.AuthTypes)})" : "";
            PropIpmiText.Text = $"{ver} · 通道 {ipmi.Channel}{auth}";
        }
        else if (r.AsfPong)
        {
            PropIpmiText.Text = "仅响应 ASF Presence Pong";
        }
        else
        {
            PropIpmiText.Text = "—";
        }

        if (r.DeviceId is { CompletionCode: 0 } dev)
        {
            string prod = dev.ProductId != 0 ? $"  ·  产品 0x{dev.ProductId:X4}" : "";
            string state = dev.Available ? "" : "  [更新/不可用]";
            PropFirmwareText.Text = $"FW {dev.Firmware}  ·  IPMI {dev.IpmiVersion}{prod}{state}";
        }
        else
        {
            PropFirmwareText.Text = "—";
        }

        if (r.Redfish is { } rf)
        {
            var sb = new StringBuilder($"HTTP {rf.Status}");
            if (!string.IsNullOrEmpty(rf.Version)) sb.Append($" · v{rf.Version}");
            if (!string.IsNullOrEmpty(rf.Product)) sb.Append($" · {rf.Product}");
            PropRedfishText.Text = sb.ToString();
        }
        else
        {
            PropRedfishText.Text = "—";
        }

        CertInfo? cert = r.Redfish?.Cert ?? r.Web.FirstOrDefault(w => w.Cert is not null)?.Cert;
        if (cert is not null)
        {
            string cn = string.IsNullOrEmpty(cert.SubjectCn) ? "-" : cert.SubjectCn;
            PropCertText.Text = cert.Expired
                ? $"已过期 ({cert.NotAfter}) · CN={cn}"
                : $"有效期至 {cert.NotAfter}（剩余 {cert.DaysLeft} 天）· CN={cn}";
            PropCertText.Foreground = cert.Expired
                ? new SolidColorBrush(Color.FromRgb(0xA4, 0x26, 0x2C))
                : cert.DaysLeft <= 30
                    ? new SolidColorBrush(Color.FromRgb(0x8A, 0x53, 0x00))
                    : (Brush)FindResource("TextPrimaryBrush");
        }
        else
        {
            PropCertText.Text = "—";
            PropCertText.Foreground = (Brush)FindResource("TextPrimaryBrush");
        }

        EvidenceList.ItemsSource = row.BuildEvidenceItems();
        OpenBrowserBtn.IsEnabled = true;
        CopyIpBtn.IsEnabled = true;
        CopyDetailBtn.IsEnabled = true;
    }

    private void ClearInspector()
    {
        InspectorTitle.Text = "设备详情";
        InspectorVendor.Text = "";
        PropUrlText.Text = "—";
        PropPortsText.Text = "—";
        PropIpmiText.Text = "—";
        PropFirmwareText.Text = "—";
        PropRedfishText.Text = "—";
        PropCertText.Text = "—";
        PropCertText.Foreground = (Brush)FindResource("TextPrimaryBrush");
        EvidenceList.ItemsSource = null;
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
            Clipboard.SetText(row.FormatFullReport());
            StatusText.Text = $"已复制 {row.Ip} 的完整设备报告";
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
            bool showAll = ModeAllRadio.IsChecked == true;
            File.WriteAllText(dlg.FileName, Exporters.ToJson(_allResults, showAll, _lastMeta), Encoding.UTF8);
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
            bool showAll = ModeAllRadio.IsChecked == true;
            File.WriteAllText(dlg.FileName, Exporters.ToCsv(_allResults, showAll), new UTF8Encoding(true));
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
