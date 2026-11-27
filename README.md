# ScanBMC

Windows 原生局域网服务器 BMC（基板管理控制器）扫描器，基于 **C# (.NET 8 + WPF)** 实现，零第三方运行库依赖、无需管理员权限，只做只读探测（不登录、不爆破）。

支持识别 Dell iDRAC、HPE iLO、Supermicro / AMI MegaRAC、华为 iBMC、联想 XClarity、Cisco IMC、Fujitsu iRMC、浪潮、H3C HDM、OpenBMC 等常见 BMC。

## 特性

- **真实协议验证**：UDP/623 IPMI RMCP（`Get Channel Authentication Capabilities` + 免认证 `Get Device ID`）、ASF Presence Pong、`/redfish/v1/` JSON、Web 指纹（支持 chunked + gzip/deflate 解压）。
- **运维安全告警**：自动标出 IPMI 匿名登录 / 空用户名弱配置，以及 HTTPS 证书已过期或 30 天内到期（`⚠`）。
- **原生 Windows 体验**：
  - 顶部单行紧凑工具栏 + 可折叠高级参数面板
  - 原生 `DataGrid` 支持任意列排序、实时搜索筛选、「仅告警」过滤、右键菜单（打开 HTTPS/HTTP 管理页、复制 IP/完整诊断）
  - 底部可拖拽「设备详情」面板完整展示所有协议细节与证书信息，不再被截断
  - 一键导出 JSON / CSV（CSV 带 UTF-8 BOM，Excel 双击直开不乱码）

## 开发与构建

需要 [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)：

```powershell
# 运行测试
dotnet test ScanBMC.sln

# 启动调试
dotnet run --project src/ScanBMC.App

# 发布单文件 exe（依赖系统 .NET 8 桌面运行时，仅数百 KB）
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish/fdd

# 发布独立单文件 exe（开箱即用，无需目标机器装 .NET）
dotnet publish src/ScanBMC.App/ScanBMC.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish/self-contained
```

## 代码签名政策

本项目拟通过 [SignPath.io](https://signpath.io/) 与 [SignPath Foundation](https://signpath.org/) 为开源发布产物提供免费代码签名，详见 [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)。本程序仅执行用户主动触发的局域网只读探测，不收集或上传任何遥测与用户数据。

## 许可证

本项目以 MIT 许可证开源，详见 [LICENSE](LICENSE)。
