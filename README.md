# scanbmc

局域网服务器 BMC（基板管理控制器）扫描器。纯 Python 3.8+ 标准库实现，**无第三方依赖、无需 root 权限**。

支持识别 Dell iDRAC、HPE iLO、Supermicro / AMI MegaRAC、华为 iBMC、联想 XClarity、
Cisco IMC、Fujitsu iRMC、浪潮、H3C HDM、OpenBMC 等常见 BMC。

## 下载即用（GUI 单文件版）

不想装 Python？到 [Releases](https://github.com/ion-lgb/scanbmc/releases) 下载对应平台的一个文件，双击即可运行（无需安装任何依赖）：

| 文件 | 平台 |
|------|------|
| `ScanBMC-<版本>-macos-universal2` | macOS，Intel 与 Apple Silicon 通用 |
| `ScanBMC-<版本>-windows-x86_64.exe` | Windows 10/11 |
| `ScanBMC-<版本>-linux-x86_64` | Linux x86_64 |

推送形如 `v1.0.0` 的 git tag 即触发 GitHub Actions 自动构建这三大平台并发布 Release（也可在 Actions 页面手动触发构建）。构建脚本见 `.github/workflows/build.yml`。

各平台首次运行的注意事项：

- **macOS**：未签名应用会被 Gatekeeper 拦截，首次请右键点文件 →「打开」，或在终端执行 `xattr -cr <文件>` 后再双击。
- **Windows**：SmartScreen 提示时点「更多信息 → 仍要运行」（未签名应用属正常现象）。
- **Linux**：需要系统带常见 Qt 运行库；Ubuntu/Debian 若提示缺少库，执行 `sudo apt install libxcb-cursor0 libegl1`。

只想用命令行？`python3 scanbmc.py` 零依赖直接跑，见下文。

## 快速开始

```bash
python3 scanbmc.py
```

不带参数即可：自动检测本机网段 → 扫描 → 输出结果。

## 工作原理

准确性的关键在于**不只看端口是否开放**，而是发真实协议报文验证。判定证据由强到弱：

| 证据 | 判定 | 说明 |
|------|------|------|
| UDP/623 IPMI RMCP 应答 | **确认** | 发送真实的 `Get Channel Authentication Capabilities` 命令，可解析出 IPMI 1.5/2.0 支持情况、认证方式和厂商 OEM ID |
| UDP/623 IPMI Get Device ID | **确认** | 免认证命令，多数屏蔽 auth-cap 查询的 BMC 也会应答，可拿到固件版本、IPMI 版本、厂商与产品 ID |
| UDP/623 ASF Presence Pong | **确认** | 部分 BMC 屏蔽 IPMI 命令但仍响应 ASF Ping |
| `/redfish/v1/` 返回 JSON | **确认** | 返回 401/403 同样算确认——能给出 Redfish 服务根的只可能是 BMC |
| Web 指纹命中厂商 | **可能** | Server 头、`<title>`、认证 realm、页面特征 |
| 端口组合特征 | **疑似** | 如 623/tcp 开放、5900(iKVM) + Web 端口、CIM/WBEM 端口 |

只有前三类证据能给出"确认"，因此不会把一台普通的 nginx 服务器误报成 BMC。

### 型号识别的几个细节

这几处都是实测踩出来的，直接影响识别率：

- **Redfish 响应的 `Server` 头优先于服务根 JSON**。实测中不少 BMC 把 `Vendor` 填成
  `"N/A"`、`Product` 填成 `"Redfish Server"`，反而是 `Server: AMI MegaRAC Redfish Service`
  准确暴露了固件来源。程序内置占位符过滤，不会把 `N/A` 当厂商名显示。
- **正文要解压再做指纹**。很多 BMC 的 lighttpd 直接返回预压缩的 `index.html.gz`，
  且无视 `Accept-Encoding: identity`。不解压的话 `<title>` 永远抓不到，
  页面指纹等于失效。程序支持 gzip / deflate / chunked，截断的响应也能解出可用部分。
- **机箱型号 ≠ BMC 厂商**。`Product=4UGPUServer` 这类是机箱型号，会记进证据，
  但不会盖掉 Server 头识别出的固件厂商。
- **Get Device ID 兜底确认**。部分 BMC（或防火墙策略）会静默丢弃
  `Get Channel Authentication Capabilities` 查询，但对免认证的 `Get Device ID`（cmd 0x01）
  照常应答。此时仅凭 Device ID 应答也能确认设备是 BMC，并给出固件版本与厂商。
- **TLS 证书有效期告警**。HTTPS 端口握手后读取对端证书，解析到期时间：
  证书已过期或 30 天内到期会在判定依据里标 `⚠`（GUI 中整行黄底）。
  BMC 自签证书过期后 iDRAC/iLO 会拒绝连接，是高频运维事故。

### 默认扫描端口

TCP `80, 443, 623, 5900, 5985, 5988, 5989, 17990` + UDP `623`。

## 常用示例

```bash
python3 scanbmc.py -t 192.168.1.0/24
```

```bash
python3 scanbmc.py -t 10.0.0.1-99 -c 256 -T 2.0 -r 2
```

```bash
python3 scanbmc.py -v --all
```

```bash
python3 scanbmc.py -o json > bmc.json
```

```bash
python3 scanbmc.py -t 10.0.0.0/16 --arp-only
```

## 参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `-t, --targets` | 目标，逗号分隔。支持 CIDR / 单 IP / 区间（`10.0.0.1-99`） | 自动检测本机网段 |
| `-x, --exclude` | 排除的目标，格式同 `--targets` | 无 |
| `-p, --ports` | TCP 端口列表，支持 `80,443` 和 `5900-5910` | 见上 |
| `-c, --concurrency` | 并发数 | 128 |
| `-T, --timeout` | 单次探测超时（秒） | 1.5 |
| `-r, --retries` | 超时重试次数 | 1 |
| `-o, --output` | `table` / `json` / `csv` | table |
| `-v, --verbose` | 显示每台设备的判定依据 | 关 |
| `--all` | 输出所有存活主机，而不仅是 BMC | 关 |
| `--arp-only` | 只扫 ARP 邻居表中的地址，适合大网段快速排查 | 关 |
| `--no-udp` / `--no-web` / `--no-redfish` | 关闭对应探测阶段 | 全开 |
| `--max-hosts` | 目标数量上限保护 | 8192 |
| `--list-networks` | 只列出检测到的本机网段 | — |

## 输出示例

```
IP 地址        置信度  设备类型          开放端口
-------------  ------  ----------------  --------------------------
192.168.1.50   确认    Supermicro BMC    623/udp,80/tcp,443/tcp,5900/tcp
    · IPMI RMCP 应答 (v2.0)
    · IPMI OEM ID=10876 → Supermicro
    · ⚠ 允许空用户名
    · Redfish /redfish/v1/ → HTTP 401 (Redfish 1.6.0)
```

`-v` 会列出每条判定依据。IPMI 层若探测到**匿名登录**或**允许空用户名**，会标记 `⚠`——
这是实际环境中最常见的 BMC 弱配置。

## 退出码

| 码 | 含义 |
|----|------|
| 0 | 正常完成 |
| 2 | 参数错误 |
| 3 | 扫描结果不可信（本机侧大量发包失败：网卡未连接 / 网段无路由 / 句柄耗尽） |
| 130 | 用户中断 |

退出码 3 是刻意设计的：网络异常时如果安静地报告"未发现设备"，比报错更危险。
注意程序会区分两种情况——空地址的 `EHOSTDOWN`（扫整段网络时完全正常）不会触发告警，
只有 `ENETDOWN`/`ENETUNREACH`/`EMFILE` 这类本机侧系统性故障才会。

## 性能参考

实测一个 /24 网段（254 个地址 × 8 个 TCP 端口 + UDP）：

| 场景 | 参数 | 耗时 |
|------|------|------|
| 同网段直连 | `-c 128 -T 1.0` | 约 26 秒 |
| 跨路由（二级路由 → 一级路由网段） | `-c 256 -T 1.5` | 约 31 秒 |

跨路由扫描前建议先确认路由可达（`route -n get <目标IP>`）。若中间设备对不存在的地址
既不回 RST 也不回 ICMP，空地址会走满超时，耗时会显著上升——这种情况下用 `--arp-only`
或缩小目标范围更划算。

调大 `-c`、调小 `-T` 可以更快，但在丢包环境下会漏报；丢包严重时再配合 `-r 2`。
注意 `-T 2.0 -r 2` 会让耗时翻一倍以上（同一网段 31s → 73s），在响应正常的网络里没必要。

### 关于并发数与文件句柄

每个并发探测占一个文件句柄，而 **macOS 交互式 shell 的默认软上限只有 256**，
`-c 256` 会正好撞上 `Errno 24: Too many open files`。程序启动时会自动处理：

- 优先把本进程的软上限抬到所需值（不需要 root，硬上限通常极大）；
- 抬不动时（例如 shell 用 `ulimit -n` 把硬上限也压低了）自动收敛并发数并提示。

想要更高并发可以先手动放宽：

```bash
ulimit -n 4096
```

## 测试

```bash
python3 -m unittest discover -p 'test_*.py' -v
```

共 85 个用例：`test_scanbmc.py` 覆盖网段计算、IPMI 报文构造与解析、正文解压/分块解码、
指纹匹配、占位符过滤、句柄上限收敛、判定逻辑；`test_integration.py` 在 127.0.0.1 上起一台
"假 BMC"（IPMI UDP 应答 + iDRAC 风格 Web + Redfish 接口）跑完整扫描链路，
并验证网络故障告警不会误报、句柄耗尽不会丢失已有结果。

## 说明

- 仅扫描本机可达的局域网，请在获得授权的网络中使用。
- 程序只做**只读探测**：不尝试登录、不发送凭据、不做任何认证爆破。
- IPMI OEM ID 到厂商的映射表为尽力而为，未收录的会原样显示为 `IANA-<编号>`。
