<div align="center">

# ScanBMC

**Windows 原生局域网服务器 BMC（基板管理控制器）发现与巡检工具**

[![Build Status](https://img.shields.io/github/actions/workflow/status/ion-lgb/scanbmc/build.yml?branch=main&style=flat-square&label=build)](https://github.com/ion-lgb/scanbmc/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/ion-lgb/scanbmc?style=flat-square)](https://github.com/ion-lgb/scanbmc/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square)](https://github.com/ion-lgb/scanbmc/releases)
[![.NET](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square)](https://dotnet.microsoft.com/download/dotnet/8.0)
[![License](https://img.shields.io/github/license/ion-lgb/scanbmc?style=flat-square)](LICENSE)

[English](README.md) | **简体中文**

</div>

---

## 项目简介

**ScanBMC** 是一款基于 **C# (.NET 8 + WPF)** 构建的 Windows 原生局域网 BMC 发现与安全巡检工具，面向系统管理员、数据中心运维与服务器硬件工程师。

区别于仅凭开放端口猜测设备类型的普通扫描器，ScanBMC 通过发送**真实管理协议探测报文**（IPMI RMCP、`Get Device ID`、ASF Presence Ping、Redfish 服务根与 HTTP/HTTPS 正文解压指纹）对设备进行验证，避免把普通 Web 服务器误报为 BMC。

> **严格只读**：ScanBMC 绝不尝试登录、不发送凭据、不进行任何形式的弱口令或认证爆破。

---

## 核心特性

- **真实协议验证**：支持 UDP/623 IPMI `Get Channel Authentication Capabilities`、免认证 `Get Device ID`（对齐 IPMI 2.0 Table 20-2 规范）、ASF Presence Ping 与 `/redfish/v1/` 探测。
- **高准确度厂商识别**：
  - 支持 **Dell iDRAC**、**HPE iLO**、**Supermicro / ATEN**、**AMI MegaRAC**、**华为 iBMC**、**联想 XClarity / IBM IMM**、**Cisco IMC**、**Fujitsu iRMC**、**浪潮**、**H3C HDM**、**ASRock Rack**、**Gigabyte**、**Tyan**、**OpenBMC** 等主流 BMC。
  - 内置 Redfish 占位符过滤（屏蔽 `N/A`、`Redfish Server`、`To Be Filled By O.E.M.` 等无效值），并结合 `Server` 头与 `Oem` 字段识别固件来源。
  - 支持截断的 `chunked` 与 `gzip` / `deflate` 响应解压，确保预压缩页面（如嵌入式 `lighttpd`）的指纹准确命中。
- **运维与安全巡检告警**：
  - 自动标记 IPMI 弱配置告警（**允许匿名登录** / **允许空用户名**）。
  - 提取 HTTPS 对端 X.509 证书有效期，自动标出**已过期**或 **30 天内即将到期** 的证书。
  - 区分本机网络故障（网卡断开 / 无路由 / 句柄耗尽）与局域网正常空地址，避免网络异常时静默误报“无设备”。
- **Windows 原生桌面体验**：
  - 纯异步高并发扫描引擎（`async/await` + `SemaphoreSlim` + `CancellationToken`），停止响应迅速。
  - 通过 .NET 原生 `NetworkInterface` API 精准获取本机活动网段与真实子网掩码，同时支持 ARP 邻居快速扫描模式。
  - 现代 Windows 11 Fluent 界面：支持关键词实时筛选、分段视图切换（`BMC` / `告警` / `全部存活`）、任意列排序、底部结构化设备详情检查器、双击打开管理页、右键菜单与按当前视图一键导出 **CSV（带 UTF-8 BOM 与 Excel 公式注入防护，直开不乱码）** / **JSON**。

---

## 判定机制

证据按强弱分级，**只有拿到真实管理协议应答才会给出「确认」**：

| 探测项 / 证据 | 置信度 | 说明 |
| :--- | :---: | :--- |
| UDP/623 IPMI RMCP（`Get Channel Auth Cap`） | **确认** | 解析 IPMI 1.5/2.0 支持、认证方式、IANA OEM ID 及匿名/空用户名标志 |
| UDP/623 IPMI（`Get Device ID`） | **确认** | 免认证兜底探测，可获取固件版本、IPMI 版本、厂商与产品 ID |
| UDP/623 ASF Presence Pong | **确认** | 针对屏蔽 IPMI 命令但仍响应 ASF Ping 的 BMC 设备 |
| `/redfish/v1/` JSON 应答 | **确认** | 返回 HTTP `200` / `401` / `403` 的 JSON 响应且命中 Redfish/OData 协议特征（`RedfishVersion`、`@odata.*`、`OData-Version` 等）即确认存在 Redfish 服务根 |
| HTTP(S) Web 指纹 | **可能** | 匹配 `Server` 头、`<title>`、认证 realm、Cookie 与解压后的正文特征 |
| 管理端口组合 | **疑似** | 弱特征启发式（`623/tcp`、`5900` iKVM + Web、或 CIM/WBEM / iLO 控制台端口） |

**默认扫描端口**：TCP `80, 443, 623, 5900, 5985, 5988, 5989, 17990` + UDP `623`。

---

## 下载与使用

前往 [GitHub Releases](https://github.com/ion-lgb/scanbmc/releases) 下载 Windows 单文件版：

- **`ScanBMC-<版本>-windows-x64.exe`**：Windows 10/11 (x64) 独立单文件版，双击即用，无需安装 .NET 运行时或任何第三方依赖。

### 快速上手

1. 双击打开 `ScanBMC.exe`。
2. 留空「扫描目标」即可自动检测本机活动 IPv4 网段，也可手动输入 CIDR 或 IP 区间（如 `192.168.1.0/24`、`10.0.0.1-100`）。
3. 点击 **开始扫描**（或直接按回车键）。
4. 选中结果列表中的设备即可在底部检查器查看完整协议详情、固件信息与 TLS 证书到期天数；双击行可直接在浏览器中打开管理页。

> **未签名程序提示**：发布产物未使用商业代码签名证书。Windows SmartScreen 首次提示时点击「更多信息 → 仍要运行」即可；若 Windows 11 系统开启了「智能应用控制（Smart App Control）」导致拦截，建议从源码自行构建或按需调整系统策略。

---

## 从源码构建

### 环境要求

- Windows 10 / 11 (x64)
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### 常用命令

```powershell
# 运行单元测试与本地回环集成测试
dotnet test ScanBMC.sln -c Release

# 启动 WPF 桌面应用
dotnet run --project src/ScanBMC.App

# 打包独立单文件 exe（无需目标机器安装 .NET）
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:DebugType=none `
  -o publish/win-x64

# 打包轻量单文件 exe（约 280 KB，需系统已安装 .NET 8 桌面运行时）
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj `
  -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true `
  -p:DebugType=none `
  -o publish/win-x64-lite
```

---

## 目录结构

```text
ScanBMC.sln
├── Directory.Build.props          # 统一版本号配置
├── src/
│   ├── ScanBMC.Core/              # 零第三方依赖的 .NET 8 扫描核心库
│   │   ├── Models.cs              # 数据结构、ScanConfig、ProbeStats
│   │   ├── NetworkDiscovery.cs    # 原生 NetworkInterface 网段探测、CIDR/区间/ARP 解析
│   │   ├── IpmiProtocol.cs        # IPMI RMCP、Get Device ID (Table 20-2)、ASF Ping/Pong
│   │   ├── HttpProbe.cs           # 异步 Socket/SslStream HTTP(S)、gzip/chunked 解压、X.509 证书解析
│   │   ├── Classifier.cs          # 证据加权判定与告警规则
│   │   ├── Scanner.cs             # 异步两阶段高并发扫描引擎
│   │   └── Exporters.cs           # JSON 与 Excel 兼容 CSV 导出
│   └── ScanBMC.App/               # Windows 原生 WPF Fluent 桌面界面
│       ├── Assets/                # 多分辨率应用图标
│       ├── Themes/FluentTheme.xaml
│       ├── MainWindow.xaml(.cs)
│       └── App.xaml(.cs)
└── tests/
    └── ScanBMC.Core.Tests/        # xUnit 协议单元测试与 127.0.0.1 假 BMC 端到端集成测试
```

---

## 安全与合规声明

- 请仅在**自有或已获明确授权的局域网**中使用本工具。
- 本程序仅执行只读网络探测，不收集或上传任何遥测数据。
- 欢迎通过 Issue / PR 补充未收录的 BMC 厂商指纹或 IANA OEM ID 映射，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 许可证

本项目基于 [MIT 许可证](LICENSE) 开源。
