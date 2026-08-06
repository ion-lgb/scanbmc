# AGENTS.md — scanbmc

局域网 BMC（基板管理控制器）扫描器：纯 Python 3.8+ 标准库实现，无第三方依赖、无需 root，只做只读探测（不登录、不爆破）。

## Project

- 单文件 CLI：`scanbmc.py`（约 1450 行，`__version__ = "1.0.0"`），入口 `main()`（scanbmc.py:1296），`if __name__ == "__main__"` 在 scanbmc.py:1434。
- 识别 Dell iDRAC / HPE iLO / Supermicro AMI MegaRAC / 华为 iBMC / 联想 XClarity / OpenBMC 等。
- 判定证据由强到弱：UDP/623 IPMI RMCP 应答、ASF Pong、`/redfish/v1/` JSON（401 也算）→「确认」；Web 指纹 →「可能」；端口组合 →「疑似」。
- 默认端口：TCP 80,443,623,5900,5985,5988,5989,17990 + UDP 623。

## Commands

- 运行(CLI)：`python3 scanbmc.py`（无参数自动检测本机网段）；`-t` 目标（CIDR/单 IP/区间）、`-c` 并发、`-T` 超时、`-o table|json|csv`、`-v`、`--all`、`--arp-only`、`--no-udp/--no-web/--no-redfish`。
- 运行(GUI)：`./.venv/bin/python scanbmc_gui.py`（PySide6，依赖 `.venv`）。
- 测试：`python3 -m unittest discover -p 'test_*.py' -v`（85 个用例，约 4s）。GUI 验证：`SCANBMC_GUI_SMOKE=1 .venv/bin/python scanbmc_gui.py`（2 秒自动退出冒烟）。
- 打包 .app：`./build_app.sh` → `dist/ScanBMC.app`（pyinstaller `--windowed`；缓存重定向到 `.pyinstaller_cache`，因沙箱可能禁止写 `~/Library/Application Support`）。
- 全平台单文件打包：GitHub Actions `.github/workflows/build.yml`（push tag `v*` 触发，macOS universal2 / Windows / Linux 三平台 PyInstaller `--onefile` 并发布 Release；也可 `workflow_dispatch` 手动触发）。
- 环境：Homebrew python 是 externally-managed，装依赖必须用 venv（`python3 -m venv .venv && .venv/bin/pip install PySide6 pyinstaller`），直接 pip install 会被 PEP 668 拒绝。
- 无 lint / build / 打包配置，无依赖清单——扫描核心不要引入第三方库（GUI 层例外）。

## Architecture

- 目标解析：`parse_target` / `build_targets` / `detect_local_networks` / `parse_ifconfig` / `parse_ip_addr` / `arp_neighbors` / `primary_ipv4`（scanbmc.py:296–514）。
- 探测层：`tcp_probe`（:516）、`udp_probe`+`_udp_send`（:645–689，IPMI 报文构造与重试）、`parse_ipmi_response`（:576，含 OEM ID）、`parse_asf_pong`（:630）。
- HTTP：`_http_request`（:732，原生 socket HTTP/1.1，TLS、超时截断）、`_decode_body`+`_dechunk`（:690–731，gzip/deflate/chunked——很多 BMC 返回预压缩页面）、`web_fingerprint`（:821）、`redfish_probe`（:853）。
- 判定：`classify`（:906，证据加权）、`match_signature`（:899）、`_clean_value`（:129，过滤 `N/A` 等占位符；`Server` 头优先于 Redfish 服务根 JSON）。
- 输出：`render_table/json/csv`（:1173–1234），`_display_width`/`_pad`（:1155–1172）处理 CJK 等宽对齐。
- GUI（scanbmc_gui.py）：`ScanWorker(QThread)` 后台跑 `scan()`，信号回传进度/结果；`MainWindow` 参数表单 + QTableWidget 结果表（⚠ 弱配置行黄底、置信度着色）。复用 `ScanConfig.cancel_event`（协作式停止）与 `progress_cb`（进度回调）。
- 基础设施：`ensure_fd_limit`+`cap_workers`（:371–403，macOS 默认软上限 256 个句柄，抬不动则自动降并发）、`ProbeStats`（:188，区分本机系统性故障与空地址 EHOSTDOWN）、`Progress`（:1008，支持 `on_step` 回调）、`ThreadPoolExecutor`。

## Conventions

- 只允许标准库；Python 3.8 兼容语法（`typing.Dict/List/Optional`，不用 `dict[str, ...]` 简写），文件头 `from __future__ import annotations`。
- 标识符用英文，注释/docstring/输出文案用中文。
- 结果用 `@dataclass`（`PortResult`/`HostResult`），序列化走 `HostResult.to_dict`。
- 判定必须基于证据：没有 IPMI/ASF/Redfish 证据不得报「确认」，避免把普通 Web 服务误报成 BMC。
- 退出码：0 正常、2 参数错误、3 扫描结果不可信（本机侧 ENETDOWN/ENETUNREACH/EMFILE 等系统性故障）、130 中断。空地址 `EHOSTDOWN` 是正常现象，不算系统性故障。
- 测试：单元测试在 `test_scanbmc.py`（网段计算、报文构造/解析、解码、指纹、判定）；`test_integration.py` 在 127.0.0.1 起假 BMC 跑完整链路。新逻辑尽量补用例。

## Notes

（待补充）
