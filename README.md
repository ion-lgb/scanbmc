<div align="center">

# ScanBMC

**Native Windows LAN Baseboard Management Controller (BMC) Discovery & Audit Tool**

[![Build Status](https://img.shields.io/github/actions/workflow/status/ion-lgb/scanbmc/build.yml?branch=main&style=flat-square&label=build)](https://github.com/ion-lgb/scanbmc/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/ion-lgb/scanbmc?style=flat-square)](https://github.com/ion-lgb/scanbmc/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square)](https://github.com/ion-lgb/scanbmc/releases)
[![.NET](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square)](https://dotnet.microsoft.com/download/dotnet/8.0)
[![License](https://img.shields.io/github/license/ion-lgb/scanbmc?style=flat-square)](LICENSE)

**English** | [简体中文](README.zh-CN.md)

</div>

---

## Overview

**ScanBMC** is a lightweight, read-only LAN discovery and security-hygiene utility built with **C# (.NET 8 + WPF)** for Windows system administrators and data center engineers.

Unlike generic port scanners that guess device types from open TCP ports, ScanBMC validates each host with **real management protocols** (IPMI RMCP, Get Device ID, ASF Presence Ping, Redfish, and decompressed HTTP/HTTPS fingerprinting) so ordinary web servers are never misclassified as BMCs.

> **Strictly Read-Only**: ScanBMC never attempts authentication, never sends credentials, and never performs brute-force checks.

---

## Key Features

- **Protocol-Verified Discovery**: Sends real UDP/623 IPMI `Get Channel Authentication Capabilities`, unauthenticated `Get Device ID` (aligned with IPMI 2.0 Table 20-2), ASF Presence Ping, and `/redfish/v1/` probes.
- **High-Accuracy Vendor Identification**:
  - Recognizes **Dell iDRAC**, **HPE iLO**, **Supermicro / ATEN**, **AMI MegaRAC**, **Huawei iBMC**, **Lenovo XClarity / IBM IMM**, **Cisco IMC**, **Fujitsu iRMC**, **Inspur**, **H3C HDM**, **ASRock Rack**, **Gigabyte**, **Tyan**, and **OpenBMC**.
  - Filters Redfish placeholder fields (`N/A`, `Redfish Server`, `To Be Filled By O.E.M.`) and falls back to `Server` header & OEM keys.
  - Handles truncated `chunked` + `gzip` / `deflate` HTTP responses (common on embedded `lighttpd` BMCs).
- **Operational & Security Auditing**:
  - Flags weak IPMI channel configurations (**anonymous login** / **null usernames enabled**).
  - Extracts peer X.509 certificates over HTTPS and flags **expired** or **expiring within 30 days** TLS certificates.
  - Detects system-level local network failures (disconnected NIC / no route / socket exhaustion) separately from normal empty LAN addresses.
- **Native Windows Desktop Workflow**:
  - High-concurrency asynchronous engine (`async/await` + `SemaphoreSlim` + `CancellationToken`).
  - Automatic local subnet discovery via native .NET `NetworkInterface` APIs, plus ARP neighbor fast mode.
  - Real-time search, segmented filtering (`BMC` / `Alerts` / `All Alive`), column sorting, structured device inspector, browser launch, and one-click **CSV (UTF-8 BOM)** / **JSON** export.

---

## Detection Methodology

Evidence is weighted from strongest to weakest; only verified management protocol responses produce a **Confirmed** classification:

| Probe / Evidence | Confidence | Details |
| :--- | :---: | :--- |
| UDP/623 IPMI RMCP (`Get Channel Auth Cap`) | **Confirmed** | Extracts IPMI 1.5/2.0 support, authentication types, IANA OEM ID, and anonymous/null-user flags |
| UDP/623 IPMI (`Get Device ID`) | **Confirmed** | Unauthenticated fallback when auth-cap is blocked; retrieves firmware revision, IPMI version, manufacturer, and product ID |
| UDP/623 ASF Presence Pong | **Confirmed** | Fallback for BMCs that block IPMI commands while still answering ASF Ping |
| `/redfish/v1/` JSON response | **Confirmed** | HTTP `200`, `401`, or `403` with JSON payload confirms a Redfish service root |
| HTTP(S) Web Fingerprint | **Likely** | Matches `Server` header, HTML `<title>`, `WWW-Authenticate` realm, cookies, and decompressed response body |
| Management Port Combination | **Possible** | Weak heuristic (`623/tcp`, `5900` iKVM + Web, or CIM/WBEM / iLO console ports) |

**Default Probed Ports**: TCP `80, 443, 623, 5900, 5985, 5988, 5989, 17990` + UDP `623`.

---

## Download & Usage

Download the latest Windows binary from [GitHub Releases](https://github.com/ion-lgb/scanbmc/releases):

- **`ScanBMC-<version>-windows-x64.exe`** — Self-contained single-file executable for Windows 10/11 (x64). No .NET runtime or external dependencies required.

### Quick Start

1. Launch `ScanBMC.exe`.
2. Leave **Target** empty to auto-detect active local IPv4 subnets, or enter CIDR / IP ranges (e.g., `192.168.1.0/24`, `10.0.0.1-100`).
3. Click **Start Scan** (or press `Enter`).
4. Select any discovered device to inspect full protocol details, firmware info, and TLS certificate expiration; double-click a row to open its management console in your browser.

> **Note on Unsigned Binaries**: Release binaries are not commercially code-signed. Windows SmartScreen may display an "Unknown publisher" prompt on first run (click **More info → Run anyway**). On Windows 11 systems with **Smart App Control** enabled, unsigned executables may be blocked by OS policy; you can build from source locally instead.

---

## Build from Source

### Prerequisites

- Windows 10 or Windows 11 (x64)
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Commands

```powershell
# Run unit and loopback integration tests
dotnet test ScanBMC.sln -c Release

# Run the WPF desktop application
dotnet run --project src/ScanBMC.App

# Publish a self-contained single-file executable
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:DebugType=none `
  -o publish/win-x64

# Publish a framework-dependent lightweight executable (~280 KB, requires .NET 8 Desktop Runtime)
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj `
  -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true `
  -p:DebugType=none `
  -o publish/win-x64-lite
```

---

## Project Structure

```text
ScanBMC.sln
├── src/
│   ├── ScanBMC.Core/              # Zero-dependency .NET 8 scanning engine
│   │   ├── Models.cs              # Domain models, ScanConfig, ProbeStats
│   │   ├── NetworkDiscovery.cs    # Native NetworkInterface subnet detection, CIDR/range/ARP parsers
│   │   ├── IpmiProtocol.cs        # IPMI RMCP, Get Device ID (Table 20-2), ASF Ping/Pong
│   │   ├── HttpProbe.cs           # Async Socket/SslStream HTTP(S), gzip/chunked decoding, X.509 extraction
│   │   ├── Classifier.cs          # Weighted evidence classification & alert rules
│   │   ├── Scanner.cs             # Async two-phase concurrent scanner
│   │   └── Exporters.cs           # JSON and Excel-friendly CSV exporters
│   └── ScanBMC.App/               # Native Windows WPF Fluent UI
│       ├── Assets/                # Multi-resolution application icon
│       ├── Themes/FluentTheme.xaml
│       ├── MainWindow.xaml(.cs)
│       └── App.xaml(.cs)
└── tests/
    └── ScanBMC.Core.Tests/        # xUnit protocol unit tests & loopback Fake BMC integration tests
```

---

## Security & Responsible Use

- Use ScanBMC **only on networks you own or are explicitly authorized to audit**.
- ScanBMC performs read-only network discovery probes and collects no telemetry.
- Found an unrecognized BMC vendor or OEM ID? Contributions and fingerprint reports are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Licensed under the [MIT License](LICENSE).
