# AGENTS.md — ScanBMC

Windows 原生局域网 BMC（基板管理控制器）扫描器，基于 C# (.NET 8 + WPF) 实现，扫描核心零第三方依赖，仅做只读探测。

## Project Structure

- `ScanBMC.sln`：解决方案入口
- `src/ScanBMC.Core/`：纯 .NET 8 扫描核心库（零第三方包）
  - `Models.cs`：数据结构（`HostResult`、`ScanConfig`、`ProbeStats` 等）
  - `NetworkDiscovery.cs`：原生 `NetworkInterface` 网段检测、ARP 邻居解析、CIDR/区间/排除/端口解析
  - `IpmiProtocol.cs`：RMCP/IPMI auth-cap、Get Device ID（对齐 IPMI 2.0 Table 20-2）、ASF Ping/Pong 报文构造与解析
  - `HttpProbe.cs`：原生异步 Socket/SslStream HTTP(S) 探测、chunked + gzip/deflate 截断解压、X.509 证书有效期提取、Web 指纹与 Redfish 探测
  - `Classifier.cs`：证据加权判定（确认/可能/疑似）、占位符过滤、弱配置与证书告警
  - `Scanner.cs`：纯异步高并发两阶段扫描引擎（`Task` + `SemaphoreSlim` + `CancellationToken`）
  - `Exporters.cs`：JSON / CSV 导出
- `src/ScanBMC.App/`：Windows 原生 WPF 桌面应用（`net8.0-windows`）
- `tests/ScanBMC.Core.Tests/`：xUnit 单元测试与本地 `127.0.0.1` 假 BMC 集成测试

## Commands

- 测试：`dotnet test ScanBMC.sln`
- 运行：`dotnet run --project src/ScanBMC.App`
- 打包单文件：`dotnet publish src/ScanBMC.App/ScanBMC.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish/win-x64`

## Conventions

- `ScanBMC.Core` 不引入第三方 NuGet 依赖；测试项目使用 xUnit。
- 标识符用英文，注释与 UI 文案用中文。
- 判定必须基于真实协议证据（IPMI/ASF/Redfish 才可报「确认」），避免把普通 Web 服务器误判为 BMC。
