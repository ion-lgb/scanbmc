#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanbmc —— 局域网 BMC（基板管理控制器）扫描器

仅依赖 Python 3.8+ 标准库，无需第三方包，无需 root 权限。

判定思路（由强到弱）：
  1. UDP/623 发送真实 IPMI RMCP 报文（Get Channel Authentication Capabilities），
     能收到合法应答即可确认是 BMC，并可解出 IPMI 1.5/2.0 支持情况与厂商 OEM ID。
  2. UDP/623 ASF Presence Ping（部分 BMC 屏蔽 IPMI 命令但仍回 Pong）。
  3. HTTP(S) 访问 /redfish/v1/，返回 JSON（哪怕 401）即可确认是 BMC。
  4. Web 指纹：Server 头、<title>、认证 realm、页面特征串匹配厂商。
  5. 端口组合特征（623 + 5900/443 等），作为弱证据。
"""

from __future__ import annotations

import argparse
import collections
import csv
import errno
import ipaddress
import json
import re
import zlib
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# 常量定义
# --------------------------------------------------------------------------- #

# 默认 TCP 端口表：端口 -> 用途说明
DEFAULT_TCP_PORTS: Dict[int, str] = {
    80: "HTTP 管理页",
    443: "HTTPS 管理页 / Redfish",
    623: "IPMI over TCP(少见)",
    5900: "iKVM / VNC 远程控制台",
    5985: "WS-Man (HTTP)",
    5988: "CIM/WBEM (HTTP)",
    5989: "CIM/WBEM (HTTPS)",
    17990: "HP iLO 远程控制台",
}

# 需要走 HTTP 指纹识别的端口 -> 是否 TLS
WEB_PORTS: Dict[int, bool] = {
    443: True,
    5989: True,
    80: False,
    5985: False,
    5988: False,
}

# 在这些端口上尝试 Redfish 服务根
REDFISH_PORTS = {443, 80}

IPMI_UDP_PORT = 623

# RMCP + IPMI v1.5 会话封装 + Get Channel Authentication Capabilities
# 06 00 ff 07 | 00 | 00000000 | 00000000 | 09 | 20 18 c8 81 00 38 8e 04 b5
#                                                              ^^ 通道 0x0E(当前) | 0x80(请求 v2 信息)
#                                                                 ^^ 权限等级 0x04 = ADMIN
IPMI_GET_CHANNEL_AUTH_CAP = bytes(
    [
        0x06, 0x00, 0xFF, 0x07,                          # RMCP 头（class 0x07 = IPMI）
        0x00,                                            # 认证类型 NONE
        0x00, 0x00, 0x00, 0x00,                          # 会话序列号
        0x00, 0x00, 0x00, 0x00,                          # 会话 ID
        0x09,                                            # 载荷长度
        0x20, 0x18, 0xC8,                                # rsAddr / netFn(App)+lun / checksum1
        0x81, 0x00, 0x38,                                # rqAddr / rqSeq+lun / cmd 0x38
        0x8E, 0x04,                                      # 数据：通道 | 请求权限
        0xB5,                                            # checksum2
    ]
)

# RMCP + IPMI v1.5 会话封装 + Get Device ID（App netFn, cmd 0x01，无请求数据）
# 06 00 ff 07 | 00 | 00000000 | 00000000 | 07 | 20 18 c8 81 00 01 7e
#                                              ^^ 载荷长度 7（IPMI 消息）
IPMI_GET_DEVICE_ID = bytes(
    [
        0x06, 0x00, 0xFF, 0x07,                          # RMCP 头（class 0x07 = IPMI）
        0x00,                                            # 认证类型 NONE
        0x00, 0x00, 0x00, 0x00,                          # 会话序列号
        0x00, 0x00, 0x00, 0x00,                          # 会话 ID
        0x07,                                            # 载荷长度
        0x20, 0x18, 0xC8,                                # rsAddr / netFn(App)+lun / checksum1
        0x81, 0x00, 0x01,                                # rqAddr / rqSeq+lun / cmd 0x01
        0x7E,                                            # checksum2 = -(0x81+0x00+0x01)
    ]
)

# RMCP + ASF Presence Ping（class 0x06）
ASF_PRESENCE_PING = bytes(
    [
        0x06, 0x00, 0xFF, 0x06,                          # RMCP 头（class 0x06 = ASF）
        0x00, 0x00, 0x11, 0xBE,                          # ASF IANA = 4542
        0x80,                                            # 消息类型：Presence Ping
        0xC0,                                            # 消息 Tag
        0x00,                                            # 保留
        0x00,                                            # 数据长度
    ]
)

# IPMI OEM ID（IANA 企业编号）-> 厂商。best-effort，未收录的会原样显示为 IANA-<n>。
IPMI_OEM_IDS: Dict[int, str] = {
    2: "IBM",
    9: "Cisco",
    11: "HP / HPE",
    343: "Intel",
    674: "Dell",
    2011: "Huawei",
    4337: "AMI (American Megatrends)",
    7244: "Quanta",
    10876: "Supermicro",
    19046: "Lenovo",
    # 21317 未见于 IANA 企业编号注册表，但在实测中由 Supermicro 主板一致上报：
    # 同一批设备里，有的通过 Redfish 自报 Vendor=Supermicro，其余 Web 指纹命中
    # ATEN/Supermicro。属经验值，若在其它厂商设备上见到请修正。
    21317: "Supermicro",
    42297: "Wiwynn",
    47488: "Supermicro",
}

# Redfish 里常见的占位符，不能拿来当厂商名显示
PLACEHOLDER_VALUES = {
    "", "-", "n/a", "na", "none", "null", "unknown", "unspecified",
    "redfish server", "root service", "default string", "to be filled by o.e.m.",
}


def _clean_value(value: object) -> str:
    """过滤掉 Redfish 字段里的占位符，返回可用于展示的字符串。"""
    text = str(value or "").strip()
    return "" if text.lower() in PLACEHOLDER_VALUES else text

# Web 指纹：(正则, 厂商/产品标签)。按顺序匹配，先命中先返回。
WEB_SIGNATURES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"idrac|integrated\s+dell\s+remote\s+access", re.I), "Dell iDRAC"),
    (re.compile(r"\bilo\b|hp-?ilo|integrated\s+lights-?out", re.I), "HPE iLO"),
    (re.compile(r"\bcimc\b|cisco\s+integrated\s+management", re.I), "Cisco IMC"),
    (re.compile(r"\birmc\b|fujitsu", re.I), "Fujitsu iRMC"),
    (re.compile(r"xclarity|\bxcc\b|integrated\s+management\s+module|\bimm2?\b", re.I), "Lenovo XClarity / IBM IMM"),
    (re.compile(r"\bibmc\b|huawei", re.I), "Huawei iBMC"),
    (re.compile(r"supermicro", re.I), "Supermicro BMC"),
    (re.compile(r"megarac", re.I), "AMI MegaRAC BMC"),
    (re.compile(r"\baten\b", re.I), "ATEN / Supermicro BMC"),
    (re.compile(r"inspur", re.I), "Inspur BMC"),
    (re.compile(r"\bh3c\b|\bhdm\b", re.I), "H3C HDM"),
    (re.compile(r"asrock\s*rack", re.I), "ASRock Rack BMC"),
    (re.compile(r"gigabyte", re.I), "Gigabyte BMC"),
    (re.compile(r"\btyan\b", re.I), "Tyan BMC"),
    (re.compile(r"openbmc", re.I), "OpenBMC"),
    (re.compile(r"aspeed", re.I), "ASPEED 芯片组 BMC"),
    (re.compile(r"\bbmc\b|baseboard\s+management", re.I), "通用 BMC"),
]

TITLE_RE = re.compile(rb"<title[^>]*>(.{0,200}?)</title>", re.I | re.S)

# 置信度
CONF_CONFIRMED = "确认"
CONF_LIKELY = "可能"
CONF_POSSIBLE = "疑似"
CONF_ORDER = {CONF_CONFIRMED: 3, CONF_LIKELY: 2, CONF_POSSIBLE: 1, "": 0}


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #


# 系统性故障：本机侧根本发不出包，整轮扫描结果都不可信
# （网卡关闭、目标网段无路由、句柄/缓冲区耗尽等）。
SYSTEMIC_ERRNOS = {
    errno.ENETDOWN,
    errno.ENETUNREACH,
    errno.ENOBUFS,
    errno.EMFILE,
    errno.ENFILE,
    errno.EADDRNOTAVAIL,
    errno.EACCES,
    errno.EPERM,
}

# 单机不可达：局域网里 ARP 解析不到该地址时会立刻返回这类错误。
# 对"扫一整个网段、其中大部分地址本来就空着"来说，这是完全正常的结果，
# 不能当成故障告警——否则每次扫描都会误报。
HOST_DOWN_ERRNOS = {errno.EHOSTUNREACH, errno.EHOSTDOWN}


class ProbeStats:
    """线程安全的探测结果统计，用于事后判断扫描是否可信。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counter: "collections.Counter[str]" = collections.Counter()

    def add(self, key: str) -> None:
        with self._lock:
            self.counter[key] += 1

    def add_oserror(self, exc: OSError) -> None:
        name = errno.errorcode.get(exc.errno, exc.errno)
        if exc.errno in SYSTEMIC_ERRNOS:
            self.add(f"sys:{name}")
        elif exc.errno in HOST_DOWN_ERRNOS:
            self.add(f"hostdown:{name}")
        else:
            self.add(f"err:{name}")

    @property
    def total(self) -> int:
        return sum(self.counter.values())

    def _count(self, prefix: str) -> int:
        return sum(v for k, v in self.counter.items() if k.startswith(prefix))

    @property
    def systemic_failures(self) -> int:
        """本机侧发包失败次数（网卡/路由/句柄问题）。"""
        return self._count("sys:")

    @property
    def host_down(self) -> int:
        """目标地址无 ARP 响应的次数（网段内空地址，属正常现象）。"""
        return self._count("hostdown:")

    @property
    def responded(self) -> int:
        """对端明确给了反馈（端口开放或拒绝连接）的次数。"""
        return self.counter.get("open", 0) + self.counter.get("refused", 0)

    def systemic_ratio(self) -> float:
        """系统性失败占比。接近 1 说明这次扫描的结果不可信。"""
        return self.systemic_failures / self.total if self.total else 0.0

    def summary(self) -> Dict[str, int]:
        return dict(self.counter)


@dataclass
class PortResult:
    port: int
    proto: str = "tcp"
    service: str = ""
    banner: str = ""


@dataclass
class HostResult:
    ip: str
    ports: List[PortResult] = field(default_factory=list)
    ipmi: Optional[dict] = None          # IPMI RMCP 应答解析结果
    asf_pong: bool = False               # 是否收到 ASF Pong
    device_id: Optional[dict] = None     # Get Device ID 应答解析结果
    redfish: Optional[dict] = None       # Redfish 探测结果
    web: List[dict] = field(default_factory=list)   # 各 Web 端口的指纹信息
    vendor: str = ""                     # 推断出的设备类型/厂商
    confidence: str = ""                 # 置信度
    evidence: List[str] = field(default_factory=list)

    @property
    def is_alive(self) -> bool:
        return bool(self.ports) or self.ipmi is not None or self.asf_pong or self.device_id is not None

    @property
    def is_bmc(self) -> bool:
        return self.confidence in (CONF_CONFIRMED, CONF_LIKELY, CONF_POSSIBLE)

    def open_ports_str(self) -> str:
        items = []
        if self.ipmi is not None or self.asf_pong or self.device_id is not None:
            items.append("623/udp")
        items.extend(f"{p.port}/{p.proto}" for p in sorted(self.ports, key=lambda x: x.port))
        return ",".join(items)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "confidence": self.confidence,
            "vendor": self.vendor,
            "open_ports": self.open_ports_str(),
            "ipmi": self.ipmi,
            "asf_pong": self.asf_pong,
            "device_id": self.device_id,
            "redfish": self.redfish,
            "web": self.web,
            "evidence": self.evidence,
            "ports": [
                {"port": p.port, "proto": p.proto, "service": p.service, "banner": p.banner}
                for p in sorted(self.ports, key=lambda x: x.port)
            ],
        }


# --------------------------------------------------------------------------- #
# 1. 本机网段自动探测
# --------------------------------------------------------------------------- #


def _netmask_to_prefix(mask: str) -> Optional[int]:
    """把 '0xffffff00' / '255.255.255.0' 形式的掩码转成前缀长度。"""
    try:
        if mask.lower().startswith("0x"):
            value = int(mask, 16)
        elif "." in mask:
            value = int(ipaddress.IPv4Address(mask))
        else:
            value = int(mask)
    except ValueError:
        return None
    # 掩码必须是连续的 1 后跟连续的 0
    inverted = (~value) & 0xFFFFFFFF
    if inverted & (inverted + 1) != 0:
        return None
    return 32 - inverted.bit_length()


def parse_ifconfig(output: str) -> List[ipaddress.IPv4Network]:
    """解析 BSD/macOS 风格 ifconfig 输出。"""
    nets: List[ipaddress.IPv4Network] = []
    current_flags = ""
    for line in output.splitlines():
        header = re.match(r"^(\S+):\s+flags=\S*<([^>]*)>", line)
        if header:
            current_flags = header.group(2)
            continue
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
        if not m:
            continue
        if "LOOPBACK" in current_flags or "UP" not in current_flags:
            continue
        prefix = _netmask_to_prefix(m.group(2))
        if prefix is None:
            continue
        try:
            nets.append(ipaddress.ip_network(f"{m.group(1)}/{prefix}", strict=False))
        except ValueError:
            continue
    return nets


def parse_ip_addr(output: str) -> List[ipaddress.IPv4Network]:
    """解析 Linux `ip -o -4 addr show` 输出。"""
    nets: List[ipaddress.IPv4Network] = []
    for line in output.splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not m:
            continue
        if re.search(r"\bscope\s+host\b", line):
            continue
        try:
            nets.append(ipaddress.ip_network(m.group(1), strict=False))
        except ValueError:
            continue
    return nets


def primary_ipv4() -> Optional[str]:
    """通过一个不发包的 UDP connect 拿到出口网卡 IP。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


# 除了探测用的 socket，还要给 stdin/stdout/证书等留出余量
FD_HEADROOM = 48


def ensure_fd_limit(needed: int) -> Tuple[int, int]:
    """尽量把本进程的文件句柄软上限抬到 needed。

    macOS 交互式 shell 的默认软上限只有 256，而每个并发探测都要占一个句柄，
    所以 -c 256 会直接撞上 EMFILE。硬上限通常很大，抬升软上限不需要 root。

    返回 (最终软上限, 硬上限)；拿不到 resource 模块（如 Windows）时返回 (0, 0)。
    """
    try:
        import resource
    except ImportError:
        return 0, 0

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= needed:
        return soft, hard

    target = needed if hard == resource.RLIM_INFINITY else min(needed, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        soft = target
    except (ValueError, OSError):
        pass
    return soft, hard


def cap_workers(workers: int, soft_limit: int) -> int:
    """按句柄上限收敛并发数，至少保留 1。"""
    if soft_limit <= 0:
        return workers
    return max(1, min(workers, soft_limit - FD_HEADROOM))


def _run(cmd: Sequence[str]) -> str:
    exe = shutil.which(cmd[0])
    if not exe:
        return ""
    try:
        proc = subprocess.run(
            [exe, *cmd[1:]], capture_output=True, text=True, timeout=10, check=False
        )
        return proc.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def detect_local_networks() -> List[ipaddress.IPv4Network]:
    """自动检测本机所在的 IPv4 网段（已去重、去回环/链路本地）。"""
    nets: List[ipaddress.IPv4Network] = []

    out = _run(["ip", "-o", "-4", "addr", "show"])
    if out:
        nets.extend(parse_ip_addr(out))
    if not nets:
        out = _run(["ifconfig", "-a"])
        if out:
            nets.extend(parse_ifconfig(out))

    if not nets:
        ip = primary_ipv4()
        if ip:
            nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))

    result: List[ipaddress.IPv4Network] = []
    for net in nets:
        if net.is_loopback or net.is_link_local or net.prefixlen >= 31:
            continue
        if net not in result:
            result.append(net)
    return result


def arp_neighbors() -> List[str]:
    """读取本机 ARP/邻居表中的 IPv4 地址（用于 --arp-only 快速模式）。"""
    out = _run(["arp", "-a", "-n"]) or _run(["arp", "-an"]) or _run(["ip", "neigh", "show"])
    seen: List[str] = []
    for ip in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", out):
        if ip not in seen:
            seen.append(ip)
    return seen


# --------------------------------------------------------------------------- #
# 2. 目标解析
# --------------------------------------------------------------------------- #


def parse_target(token: str) -> List[ipaddress.IPv4Address]:
    """支持 CIDR(192.168.1.0/24)、单 IP、区间(192.168.1.10-50 或 10.0.0.1-10.0.0.99)。"""
    token = token.strip()
    if not token:
        return []
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.prefixlen >= 31:
            return list(net)
        return list(net.hosts())
    if "-" in token:
        left, right = token.split("-", 1)
        start = ipaddress.IPv4Address(left.strip())
        right = right.strip()
        if "." in right:
            end = ipaddress.IPv4Address(right)
        else:
            end = ipaddress.IPv4Address(".".join(left.strip().split(".")[:3] + [right]))
        if int(end) < int(start):
            raise ValueError(f"区间起止顺序错误: {token}")
        return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]
    return [ipaddress.IPv4Address(token)]


def filter_to_specs(ips: Sequence[str], specs: Sequence[str]) -> List[str]:
    """把一组 IP 收缩到目标网段/区间范围内（用于 ARP 表筛选）。"""
    allowed = {int(a) for spec in specs for a in parse_target(spec)}
    out: List[str] = []
    for ip in ips:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if int(addr) in allowed and ip not in out:
            out.append(ip)
    return out


def build_targets(specs: Sequence[str], excludes: Sequence[str] = ()) -> List[str]:
    """展开目标列表，去重、排序、剔除排除项。"""
    seen: Dict[int, ipaddress.IPv4Address] = {}
    for spec in specs:
        for addr in parse_target(spec):
            seen[int(addr)] = addr

    excluded = set()
    for spec in excludes:
        for addr in parse_target(spec):
            excluded.add(int(addr))

    return [str(seen[k]) for k in sorted(seen) if k not in excluded]


# --------------------------------------------------------------------------- #
# 3. 探测原语
# --------------------------------------------------------------------------- #


def tcp_probe(
    ip: str,
    port: int,
    timeout: float,
    retries: int,
    grab_banner: bool = True,
    stats: Optional[ProbeStats] = None,
) -> Optional[PortResult]:
    """TCP connect 探测。连接被拒绝视为确定关闭，直接返回，不再重试。"""
    for attempt in range(retries + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            # 例如 EMFILE：并发开太大，句柄耗尽。这不是"端口关闭"。
            if stats:
                stats.add_oserror(exc)
            return None
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except (socket.timeout, TimeoutError):
            sock.close()
            if attempt < retries:
                continue
            if stats:
                stats.add("timeout")
            return None
        except ConnectionRefusedError:
            sock.close()
            if stats:
                stats.add("refused")
            return None
        except OSError as exc:
            sock.close()
            # 主机/网络不可达是即时失败，重试没有意义
            if exc.errno in SYSTEMIC_ERRNOS or exc.errno in HOST_DOWN_ERRNOS:
                if stats:
                    stats.add_oserror(exc)
                return None
            if attempt < retries:
                continue
            if stats:
                stats.add_oserror(exc)
            return None

        banner = ""
        if grab_banner and port not in WEB_PORTS:
            try:
                sock.settimeout(min(timeout, 1.0))
                data = sock.recv(128)
                banner = data.decode("utf-8", "replace").strip()
            except OSError:
                banner = ""
        sock.close()
        if stats:
            stats.add("open")
        return PortResult(port=port, proto="tcp", service=DEFAULT_TCP_PORTS.get(port, ""), banner=banner)
    return None


def parse_ipmi_response(data: bytes) -> Optional[dict]:
    """解析 Get Channel Authentication Capabilities 应答。"""
    # 最小合法应答 = RMCP 头 4 + 会话头 9 + 载荷长度 1 + IPMI 消息 7 = 21 字节。
    # 命令被拒绝（completion code 非 0）时 BMC 不带附加数据，只回这 21 字节；
    # 门槛若定成 22 会把这些"确实是 IPMI"的应答全丢，丢失确认证据。
    if len(data) < 21 or data[0] != 0x06 or data[3] != 0x07:
        return None
    payload_len = data[13]
    body = data[14 : 14 + payload_len] if payload_len else data[14:]
    if len(body) < 7:
        body = data[14:]
    if len(body) < 7 or body[5] != 0x38:
        return None
    completion = body[6]
    if completion != 0x00:
        # 命令被拒绝（比如权限不足），但对端确实说的是 IPMI
        return {"ipmi": True, "completion_code": completion, "note": "IPMI 应答但命令未成功"}

    payload = body[7:]
    if len(payload) < 8:
        return {"ipmi": True, "completion_code": 0}

    auth_support = payload[1]
    auth_status = payload[2]
    ext_cap = payload[3]
    oem_id = payload[4] | (payload[5] << 8) | (payload[6] << 16)

    # auth_support 的 bit7 = 支持 IPMI v2.0 扩展能力，此时 ext_cap 才有意义
    versions: List[str] = []
    if auth_support & 0x80:
        if ext_cap & 0x01:
            versions.append("1.5")
        if ext_cap & 0x02:
            versions.append("2.0")
    if not versions:
        versions.append("1.5")

    auth_types = []
    for bit, name in ((0x01, "none"), (0x02, "MD2"), (0x04, "MD5"), (0x10, "password"), (0x20, "OEM")):
        if auth_support & bit:
            auth_types.append(name)

    return {
        "ipmi": True,
        "completion_code": 0,
        "channel": payload[0] & 0x0F,
        "versions": versions,
        "auth_types": auth_types,
        "anonymous_login": bool(auth_status & 0x01),
        "null_usernames": bool(auth_status & 0x02),
        "non_null_usernames": bool(auth_status & 0x04),
        "kg_status_default": not bool(auth_status & 0x20),
        "oem_id": oem_id,
        "oem_vendor": IPMI_OEM_IDS.get(oem_id, f"IANA-{oem_id}" if oem_id else ""),
    }


def parse_asf_pong(data: bytes) -> Optional[dict]:
    """解析 ASF Presence Pong。"""
    if len(data) < 12 or data[0] != 0x06 or data[3] != 0x06:
        return None
    if data[4:8] != b"\x00\x00\x11\xbe" or data[8] != 0x40:
        return None
    result = {"asf_pong": True}
    if len(data) >= 22:
        oem_iana = struct.unpack(">I", data[12:16])[0]
        entities = data[20]
        result["oem_iana"] = oem_iana
        result["ipmi_supported"] = bool(entities & 0x80)
    return result


def parse_device_id(data: bytes) -> Optional[dict]:
    """解析 Get Device ID（cmd 0x01）应答。

    该命令无需认证，大多数 BMC 即使屏蔽 auth-cap 查询也会应答，
    可拿到固件版本、IPMI 版本、厂商 ID 与产品 ID。
    """
    if len(data) < 21 or data[0] != 0x06 or data[3] != 0x07:
        return None
    payload_len = data[13]
    body = data[14 : 14 + payload_len] if payload_len else data[14:]
    if len(body) < 7:
        body = data[14:]
    if len(body) < 7 or body[5] != 0x01:
        return None
    completion = body[6]
    if completion != 0x00:
        return {"ipmi": True, "completion_code": completion, "note": "Get Device ID 被拒绝"}
    payload = body[7:]
    if len(payload) < 9:
        return {"ipmi": True, "completion_code": 0, "note": "Get Device ID 应答不完整"}

    fw_major = (payload[1] >> 4) & 0x0F
    fw_minor = payload[2]
    ipmi_ver = payload[3]
    manufacturer = payload[4] | (payload[5] << 8) | (payload[6] << 16)
    product_id = payload[7] | (payload[8] << 8)

    if ipmi_ver == 0x02:
        ver_str = "2.0"
    elif ipmi_ver == 0x00:
        ver_str = ""
    else:
        ver_str = f"{ipmi_ver >> 4}.{ipmi_ver & 0x0F}"

    return {
        "ipmi": True,
        "completion_code": 0,
        "device_id": payload[0],
        "firmware": f"{fw_major}.{fw_minor:02d}",
        "ipmi_version": ver_str,
        "manufacturer_id": manufacturer,
        "manufacturer": IPMI_OEM_IDS.get(manufacturer, f"IANA-{manufacturer}" if manufacturer else ""),
        "product_id": product_id,
        "available": bool(payload[9] & 0x80) if len(payload) > 9 else True,
    }


def udp_probe(
    ip: str, timeout: float, retries: int, stats: Optional["ProbeStats"] = None
) -> Tuple[Optional[dict], bool, Optional[dict]]:
    """UDP/623 探测：并行发 IPMI auth-cap、ASF Ping 与 Get Device ID（互不依赖）。

    顺序发送时无响应地址要等 3×(retries+1)×timeout；并行后最坏只等一轮，
    对“黑洞”网段（不回 ICMP 不可达）提速明显。

    返回 (auth_cap, 是否收到 Pong, device_id)。
    """
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="udp-probe") as pool:
        f_ipmi = pool.submit(
            _udp_send, ip, IPMI_GET_CHANNEL_AUTH_CAP, timeout, retries,
            parse_ipmi_response, stats,
        )
        f_pong = pool.submit(
            _udp_send, ip, ASF_PRESENCE_PING, timeout, retries, parse_asf_pong, stats
        )
        f_devid = pool.submit(
            _udp_send, ip, IPMI_GET_DEVICE_ID, timeout, retries, parse_device_id, stats
        )
        ipmi_info = f_ipmi.result()
        pong = f_pong.result()
        devid = f_devid.result()
    return ipmi_info, pong is not None, devid


def _udp_send(ip: str, packet: bytes, timeout: float, retries: int, parser,
              stats: Optional["ProbeStats"] = None):
    for _ in range(retries + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            # 句柄耗尽等本机侧故障：记账后放弃，不能让异常掀翻整轮扫描
            if stats:
                stats.add_oserror(exc)
            return None
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, IPMI_UDP_PORT))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                data, addr = sock.recvfrom(2048)
                if addr[0] != ip:
                    continue
                parsed = parser(data)
                if parsed is not None:
                    return parsed
        except (socket.timeout, TimeoutError):
            pass
        except OSError:
            # ICMP port unreachable 会在部分平台上以 ConnectionRefused/ECONNRESET 抛出
            return None
        finally:
            sock.close()
    return None


def _dechunk(body: bytes) -> bytes:
    """解析 chunked 传输编码。截断的响应按已拿到的部分返回。"""
    out = bytearray()
    while body:
        line, sep, rest = body.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size:].lstrip(b"\r\n")
    return bytes(out)


def _decode_body(headers: Dict[str, str], body: bytes) -> bytes:
    """还原正文：先解 chunked，再解压。

    很多 BMC 直接返回预压缩的 index.html.gz，即使请求方没有声明支持压缩。
    不解压的话页面指纹就完全失效（title 永远抓不到）。
    """
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)

    encoding = headers.get("content-encoding", "").lower()
    if not encoding or not body:
        return body
    # 用 decompressobj 而不是 gzip.decompress：我们只读了正文的前若干 KB，
    # 数据是截断的，decompressobj 能返回已解出的部分而不是直接报错。
    for wbits in ((16 + zlib.MAX_WBITS,) if "gzip" in encoding else (zlib.MAX_WBITS, -zlib.MAX_WBITS)):
        try:
            decoded = zlib.decompressobj(wbits).decompress(body)
            if decoded:
                return decoded
        except zlib.error:
            continue
    return body


def _der_children(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """遍历 DER 编码的顶层 TLV 序列。格式非法时抛 ValueError。"""
    i = 0
    n = len(data)
    while i < n:
        tag = data[i]
        i += 1
        if i >= n:
            raise ValueError("DER 截断")
        length = data[i]
        i += 1
        if length & 0x80:
            num = length & 0x7F
            if num > 4 or i + num > n:
                raise ValueError("DER 长度字段非法")
            length = int.from_bytes(data[i : i + num], "big")
            i += num
        if i + length > n:
            raise ValueError("DER 截断")
        yield tag, data[i : i + length]
        i += length


def _der_time(text: str) -> Optional[datetime]:
    """解析 DER 里的 UTCTime / GeneralizedTime。"""
    text = text.strip().rstrip("Z")
    try:
        if len(text) == 12:  # YYMMDDHHMMSS
            yy = int(text[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime.strptime(f"{year}{text[2:]}", "%Y%m%d%H%M%S")
        if len(text) == 14:  # YYYYMMDDHHMMSS
            return datetime.strptime(text, "%Y%m%d%H%M%S")
    except ValueError:
        pass
    return None


def _name_field(name_der: bytes, *oids: bytes) -> str:
    """从 X.509 Name 的 DER 里取指定 OID 的属性值（CN=2.5.4.3、O=2.5.4.10）。"""
    try:
        for _tag, rdn in _der_children(name_der):           # SET OF
            for _t2, ava in _der_children(rdn):             # SEQUENCE
                fields = list(_der_children(ava))
                if len(fields) != 2 or fields[0][0] != 0x06:
                    continue
                if fields[0][1] in oids:
                    tag, value = fields[1]
                    if tag == 0x0C:                         # UTF8String
                        return value.decode("utf-8", "replace").strip()
                    return value.decode("latin-1", "replace").strip()
    except ValueError:
        pass
    return ""


def _parse_x509_der(der: bytes) -> Optional[dict]:
    """最小 X.509 DER 解析：取有效期与 subject/issuer 名称。

    不依赖 ssl 私有 API（各 Python 版本的 _test_decode_cert 签名不一致），
    解析不了就返回 None，不影响扫描主流程。
    """
    try:
        # Certificate SEQUENCE → 第一个子元素才是 tbsCertificate
        cert_value = next(_der_children(der))[1]
        tbs = next(_der_children(cert_value))[1]
        seq_index = 0
        issuer = subject = validity = None
        for tag, value in _der_children(tbs):
            if tag == 0xA0:                                 # version [0]，跳过
                continue
            if tag != 0x30:
                continue                                    # serialNumber 等
            seq_index += 1
            if seq_index == 2:
                issuer = value
            elif seq_index == 3:
                validity = value
            elif seq_index == 4:
                subject = value
        if validity is None or subject is None:
            return None
        times = [
            _der_time(v.decode("ascii", "replace"))
            for tag, v in _der_children(validity)
            if tag in (0x17, 0x18)
        ]
        not_after = times[1] if len(times) >= 2 else None
        if not_after is None:
            return None
        return {
            "subject_cn": _name_field(subject, b"\x55\x04\x03"),
            "issuer": _name_field(issuer, b"\x55\x04\x0a", b"\x55\x04\x03"),
            "not_after": not_after,
        }
    except (ValueError, StopIteration):
        return None


def _cert_summary(not_after: datetime, subject_cn: str, issuer: str) -> dict:
    """把证书关键字段整理成展示用的摘要，并计算剩余天数。"""
    days_left = (not_after - datetime.utcnow()).days
    return {
        "subject_cn": subject_cn,
        "issuer": issuer,
        "not_after": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "expired": days_left < 0,
    }


def _cert_info(cert: dict) -> Optional[dict]:
    """从 ssl 的 getpeercert() 结果里提取证书摘要。

    BMC 自签证书普遍有效期只有几年，过期后 iDRAC/iLO 等会直接拒绝
    浏览器连接，是高频运维事故——这里把到期时间与剩余天数算出来。
    """
    if not cert or "notAfter" not in cert:
        return None
    try:
        not_after = datetime.strptime(
            cert["notAfter"].replace("GMT", "").strip(), "%b %d %H:%M:%S %Y"
        )
    except ValueError:
        return None

    def _first(parts: object, key: str) -> str:
        for part in parts or ():
            for k, v in part:
                if k == key:
                    return v
        return ""

    return _cert_summary(
        not_after,
        _first(cert.get("subject"), "commonName"),
        _first(cert.get("issuer"), "organizationName")
        or _first(cert.get("issuer"), "commonName"),
    )


def _cert_info_der(der: bytes) -> Optional[dict]:
    """从 DER 二进制证书提取摘要（getpeercert() 无详情时的兜底）。"""
    parsed = _parse_x509_der(der)
    if parsed is None:
        return None
    return _cert_summary(parsed["not_after"], parsed["subject_cn"], parsed["issuer"])


def _http_request(ip: str, port: int, tls: bool, path: str, timeout: float) -> Optional[dict]:
    """发一个最小化的 HTTP GET，返回状态行 / 头 / 部分正文。"""
    host = f"[{ip}]" if ":" in ip else ip
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: scanbmc/1.0\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # BMC 上大量老设备只支持旧协议/弱套件，放宽以便识别
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                except (AttributeError, ValueError):
                    pass
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            sock = ctx.wrap_socket(sock, server_hostname=None, do_handshake_on_connect=True)
        cert = None
        if tls:
            try:
                cert = _cert_info(sock.getpeercert())
                if cert is None:
                    # server_hostname=None 时 CPython 不解析证书详情，getpeercert()
                    # 返回空 dict。不传 SNI 是为了兼容部分老 BMC 的 TLS 栈，
                    # 证书信息改用 DER 二进制格式兜底解析。
                    der = sock.getpeercert(binary_form=True)
                    if der:
                        cert = _cert_info_der(der)
            except (ssl.SSLError, ValueError):
                cert = None
        sock.sendall(request)

        chunks = []
        total = 0
        while total < 16384:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError, ssl.SSLError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not raw:
        return None

    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.decode("latin-1", "replace").partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()

    status = 0
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", status_line)
    if m:
        status = int(m.group(1))

    body = _decode_body(headers, body)

    title = ""
    tm = TITLE_RE.search(body)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1).decode("utf-8", "replace")).strip()

    return {
        "status": status,
        "headers": headers,
        "title": title,
        "body": body[:8192].decode("utf-8", "replace"),
        "cert": cert,
    }


def web_fingerprint(ip: str, port: int, tls: bool, timeout: float, retries: int) -> Optional[dict]:
    """抓取 Web 管理页特征。"""
    resp = None
    for _ in range(retries + 1):
        resp = _http_request(ip, port, tls, "/", timeout)
        if resp is not None:
            break
    if resp is None:
        return None
    info = {
        "port": port,
        "scheme": "https" if tls else "http",
        "status": resp["status"],
        "server": resp["headers"].get("server", ""),
        "title": resp["title"],
        "location": resp["headers"].get("location", ""),
        "realm": resp["headers"].get("www-authenticate", ""),
        "cert": resp.get("cert"),
    }
    haystack = " ".join(
        [
            info["server"],
            info["title"],
            info["location"],
            info["realm"],
            resp["headers"].get("set-cookie", ""),
            resp["body"][:4096],
        ]
    )
    info["_haystack"] = haystack
    return info


def redfish_probe(ip: str, port: int, tls: bool, timeout: float, retries: int) -> Optional[dict]:
    """探测 Redfish 服务根。返回 200/401 且内容像 JSON，即可确认是 BMC。"""
    resp = None
    for _ in range(retries + 1):
        resp = _http_request(ip, port, tls, "/redfish/v1/", timeout)
        if resp is not None:
            break
    if resp is None or resp["status"] not in (200, 401, 403):
        return None

    ctype = resp["headers"].get("content-type", "")
    body = resp["body"].strip()
    looks_json = "json" in ctype.lower() or body.startswith("{")
    if not looks_json:
        return None

    # Redfish 服务的 Server 头往往比服务根 JSON 更能说明厂商
    # （例如 "AMI MegaRAC Redfish Service"）
    info = {
        "port": port,
        "status": resp["status"],
        "server": resp["headers"].get("server", ""),
        "vendor": "",
        "product": "",
        "version": "",
        "cert": resp.get("cert"),
    }
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        doc = {}
    if isinstance(doc, dict):
        info["vendor"] = _clean_value(doc.get("Vendor"))
        info["product"] = _clean_value(doc.get("Product"))
        info["version"] = str(doc.get("RedfishVersion", "") or "")
        oem = doc.get("Oem")
        if isinstance(oem, dict) and oem:
            info["oem_keys"] = [k for k in list(oem.keys())[:5] if _clean_value(k)]
    info["_haystack"] = " ".join([info["server"], body[:4096]])
    return info


# --------------------------------------------------------------------------- #
# 4. 判定与分类
# --------------------------------------------------------------------------- #


def match_signature(text: str) -> str:
    for pattern, label in WEB_SIGNATURES:
        if pattern.search(text):
            return label
    return ""


def classify(host: HostResult) -> None:
    """综合所有证据，填充 vendor / confidence / evidence。"""
    evidence: List[str] = []
    vendor = ""
    confidence = ""

    # 证据 1：IPMI RMCP 应答（最强）
    if host.ipmi:
        versions = "/".join(host.ipmi.get("versions", [])) or "?"
        evidence.append(f"IPMI RMCP 应答 (v{versions})")
        confidence = CONF_CONFIRMED
        oem = host.ipmi.get("oem_vendor") or ""
        if oem and not oem.startswith("IANA-"):
            vendor = f"{oem} BMC"
            evidence.append(f"IPMI OEM ID={host.ipmi.get('oem_id')} → {oem}")
        elif oem:
            evidence.append(f"IPMI OEM ID={host.ipmi.get('oem_id')}（未收录）")
        if host.ipmi.get("anonymous_login"):
            evidence.append("⚠ 允许匿名登录")
        if host.ipmi.get("null_usernames"):
            evidence.append("⚠ 允许空用户名")
    elif host.asf_pong:
        evidence.append("ASF Presence Pong (UDP/623)")
        confidence = CONF_CONFIRMED

    # 证据 1b：Get Device ID（真实 IPMI 应答；auth-cap 被拒/静默时兜底）
    if host.device_id:
        dev = host.device_id
        if dev.get("completion_code") == 0:
            desc = "IPMI Get Device ID 应答"
            if dev.get("firmware"):
                desc += f" (固件 {dev['firmware']})"
            if dev.get("ipmi_version"):
                desc += f" (IPMI {dev['ipmi_version']})"
            evidence.append(desc)
            if dev.get("product_id"):
                evidence.append(f"产品 ID=0x{dev['product_id']:04X}")
            if not dev.get("available", True):
                evidence.append("⚠ 设备处于固件更新/不可用状态")
            if host.ipmi is None:
                # auth-cap 没拿到应答，但 Device ID 足以确认是 IPMI 设备
                confidence = CONF_CONFIRMED
            mfr = dev.get("manufacturer") or ""
            if mfr:
                if mfr.startswith("IANA-"):
                    evidence.append(
                        f"Get Device ID 厂商 ID={dev.get('manufacturer_id')}（未收录）"
                    )
                elif not vendor:
                    vendor = f"{mfr} BMC"
                    evidence.append(
                        f"Get Device ID 厂商 ID={dev.get('manufacturer_id')} → {mfr}"
                    )

    # 证据 2：Redfish
    if host.redfish:
        rv = host.redfish
        desc = f"Redfish /redfish/v1/ → HTTP {rv['status']}"
        if rv.get("version"):
            desc += f" (Redfish {rv['version']})"
        evidence.append(desc)
        confidence = CONF_CONFIRMED
        # 型号信息即使不足以当厂商名，也值得记进证据里
        model = rv.get("product", "")
        if model and model != rv.get("vendor", ""):
            evidence.append(f"Redfish 型号: {model}")
        server_match = match_signature(rv.get("server", ""))
        if server_match and rv.get("server"):
            evidence.append(f"Redfish Server 头: {rv['server']} → {server_match}")
        if not vendor:
            rf_vendor = rv.get("vendor", "")
            if rf_vendor:
                vendor = f"{rf_vendor} (Redfish)"
            elif server_match:
                # Server 头（如 "AMI MegaRAC Redfish Service"）比机箱型号更能说明
                # BMC 固件来源
                vendor = server_match
            elif model:
                vendor = f"{model} (Redfish)"
            else:
                # 都是占位符时，退回全文指纹匹配（含 Oem 厂商键名）
                hay = " ".join([rv.get("_haystack", ""), " ".join(rv.get("oem_keys", []))])
                matched = match_signature(hay)
                if matched:
                    vendor = matched

    # 证据 3：Web 指纹
    for w in host.web:
        matched = match_signature(w.get("_haystack", ""))
        if matched:
            evidence.append(f"{w['scheme']}://{host.ip}:{w['port']} 指纹 → {matched}")
            if not vendor or vendor == "通用 BMC":
                vendor = matched
            if CONF_ORDER[confidence] < CONF_ORDER[CONF_LIKELY]:
                confidence = CONF_LIKELY if matched != "通用 BMC" else CONF_POSSIBLE
        elif w.get("title") or w.get("server"):
            evidence.append(
                f"{w['scheme']}://{host.ip}:{w['port']} "
                f"server={w.get('server') or '-'} title={w.get('title') or '-'}"
            )

    # 证据 3b：TLS 证书有效期（HTTPS 端口）。证书过期是 BMC 高频运维事故。
    cert = None
    if host.redfish and host.redfish.get("cert"):
        cert = host.redfish["cert"]
    if cert is None:
        for w in host.web:
            if w.get("cert"):
                cert = w["cert"]
                break
    if cert:
        if cert.get("expired"):
            evidence.append(f"⚠ TLS 证书已过期（{cert.get('not_after')}）")
        elif cert.get("days_left", 365) <= 30:
            evidence.append(
                f"⚠ TLS 证书将于 {cert.get('days_left')} 天后过期（{cert.get('not_after')}）"
            )
        else:
            evidence.append(
                f"TLS 证书 CN={cert.get('subject_cn') or '-'} 有效期至 {cert.get('not_after')}"
            )

    # 证据 4：端口组合（弱）
    open_tcp = {p.port for p in host.ports}
    if not confidence and open_tcp:
        if IPMI_UDP_PORT in open_tcp:
            # 623 是 IANA 分配给 ASF/IPMI 的端口，TCP 上开放值得留意，
            # 但 UDP 侧没应答，所以只能算弱证据
            evidence.append("端口特征：623/tcp 开放，但 UDP/623 无 IPMI 应答")
            confidence = CONF_POSSIBLE
        elif 5900 in open_tcp and (443 in open_tcp or 80 in open_tcp):
            evidence.append("端口特征：5900(iKVM) + Web 端口")
            confidence = CONF_POSSIBLE
        elif {5988, 5989, 17990} & open_tcp:
            evidence.append("端口特征：CIM/WBEM 或 iLO 控制台端口开放")
            confidence = CONF_POSSIBLE

    # VNC banner 也算一条弱证据
    for p in host.ports:
        if p.port == 5900 and p.banner.startswith("RFB"):
            evidence.append(f"5900/tcp banner: {p.banner}")

    host.vendor = vendor or ("未知型号 BMC" if confidence else "")
    host.confidence = confidence
    host.evidence = evidence


# --------------------------------------------------------------------------- #
# 5. 扫描调度
# --------------------------------------------------------------------------- #


class Progress:
    """极简进度条，只在 stderr 且是 TTY 时输出。

    on_step 为可选的进度回调 (done, total, phase)，供 GUI 等外部界面使用：
    无论是否 TTY 都会调用，以便界面拿到实时进度。phase 区分扫描阶段
    （"probe" 端口发现 / "fp" 指纹识别）。
    """

    def __init__(
        self,
        total: int,
        enabled: bool,
        on_step: Optional[Callable[[int, int, str], None]] = None,
        phase: str = "probe",
    ):
        self.total = total
        self.done = 0
        self.enabled = enabled and sys.stderr.isatty()
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.on_step = on_step
        self.phase = phase

    def step(self, n: int = 1) -> None:
        with self.lock:
            self.done += n
            if self.on_step is not None:
                self.on_step(self.done, self.total, self.phase)
            if not self.enabled:
                return
            if self.done % 5 and self.done != self.total:
                return
            pct = 100.0 * self.done / self.total if self.total else 100.0
            elapsed = time.monotonic() - self.start
            sys.stderr.write(f"\r  扫描中 {self.done}/{self.total} ({pct:5.1f}%)  用时 {elapsed:5.1f}s ")
            sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 60 + "\r")
            sys.stderr.flush()


@dataclass
class ScanConfig:
    tcp_ports: List[int]
    workers: int = 128
    timeout: float = 1.5
    retries: int = 1
    udp: bool = True
    web: bool = True
    redfish: bool = True
    progress: bool = True
    # GUI 等外部界面用：协作式取消标志与进度回调 (done, total, phase)
    cancel_event: Optional[threading.Event] = None
    progress_cb: Optional[Callable[[int, int, str], None]] = None


def _shutdown_pool(pool: ThreadPoolExecutor) -> None:
    """关闭线程池：Python 3.8 的 shutdown() 没有 cancel_futures 参数。"""
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except TypeError:
        pool.shutdown(wait=False)


def scan(
    targets: Sequence[str], cfg: ScanConfig, stats: Optional[ProbeStats] = None
) -> List[HostResult]:
    """两阶段扫描：先端口/UDP 发现，再对存活主机做 Web/Redfish 指纹。

    stats 为可选的出参，用于回传探测失败的分布（判断结果是否可信）。
    """
    hosts: Dict[str, HostResult] = {ip: HostResult(ip=ip) for ip in targets}

    # ---- 阶段一：端口发现 ----
    tasks: List[Tuple[str, str, int]] = []
    for ip in targets:
        if cfg.udp:
            tasks.append(("udp", ip, IPMI_UDP_PORT))
        for port in cfg.tcp_ports:
            tasks.append(("tcp", ip, port))

    progress = Progress(len(tasks), cfg.progress, on_step=cfg.progress_cb, phase="probe")
    lock = threading.Lock()

    def run_probe(task: Tuple[str, str, int]):
        # 单个探测出任何意外都只影响这一个目标：绝不能让异常沿着 pool.map
        # 冒泡上去，否则扫到 90% 崩一次就丢掉全部已有结果。
        # 取消已置位时排队任务直接退出，让“停止”尽快生效。
        if cfg.cancel_event is not None and cfg.cancel_event.is_set():
            return
        kind, ip, port = task
        try:
            if kind == "udp":
                ipmi, pong, devid = udp_probe(ip, cfg.timeout, cfg.retries, stats=stats)
                with lock:
                    hosts[ip].ipmi = ipmi
                    hosts[ip].asf_pong = pong
                    hosts[ip].device_id = devid
            else:
                res = tcp_probe(ip, port, cfg.timeout, cfg.retries, stats=stats)
                if res:
                    with lock:
                        hosts[ip].ports.append(res)
        except OSError as exc:
            if stats:
                stats.add_oserror(exc)
        except Exception as exc:  # noqa: BLE001 - 探测器不能因未知异常整体停摆
            if stats:
                stats.add(f"bug:{type(exc).__name__}")
        finally:
            progress.step()

    pool = ThreadPoolExecutor(max_workers=cfg.workers)
    try:
        # 分批提交，批次间检查取消标志，让 GUI 能及时停下
        batch = max(cfg.workers, 1)
        for start in range(0, len(tasks), batch):
            list(pool.map(run_probe, tasks[start : start + batch]))
            if cfg.cancel_event is not None and cfg.cancel_event.is_set():
                break
    finally:
        _shutdown_pool(pool)
    progress.finish()
    cancelled = cfg.cancel_event is not None and cfg.cancel_event.is_set()

    # ---- 阶段二：Web / Redfish 指纹 ----
    fp_tasks: List[Tuple[str, str, int, bool]] = []
    for host in hosts.values():
        if not host.is_alive:
            continue
        for p in host.ports:
            if p.port not in WEB_PORTS:
                continue
            tls = WEB_PORTS[p.port]
            if cfg.web:
                fp_tasks.append(("web", host.ip, p.port, tls))
            if cfg.redfish and p.port in REDFISH_PORTS:
                fp_tasks.append(("redfish", host.ip, p.port, tls))

    if not cancelled and fp_tasks:
        progress2 = Progress(len(fp_tasks), cfg.progress, on_step=cfg.progress_cb, phase="fp")

        def run_fp(task: Tuple[str, str, int, bool]):
            if cfg.cancel_event is not None and cfg.cancel_event.is_set():
                return
            kind, ip, port, tls = task
            # Web 指纹要读正文，给更宽松的超时
            timeout = cfg.timeout * 2
            try:
                if kind == "web":
                    info = web_fingerprint(ip, port, tls, timeout, cfg.retries)
                    if info:
                        with lock:
                            hosts[ip].web.append(info)
                else:
                    info = redfish_probe(ip, port, tls, timeout, cfg.retries)
                    if info:
                        with lock:
                            # 保留 https 的结果优先
                            if hosts[ip].redfish is None or port == 443:
                                hosts[ip].redfish = info
            except OSError as exc:
                if stats:
                    stats.add_oserror(exc)
            except Exception as exc:  # noqa: BLE001 - 指纹失败不应影响已有结果
                if stats:
                    stats.add(f"bug:{type(exc).__name__}")
            finally:
                progress2.step()

        fp_workers = min(cfg.workers, 64)
        pool2 = ThreadPoolExecutor(max_workers=fp_workers)
        try:
            batch = max(fp_workers, 1)
            for start in range(0, len(fp_tasks), batch):
                list(pool2.map(run_fp, fp_tasks[start : start + batch]))
                if cfg.cancel_event is not None and cfg.cancel_event.is_set():
                    break
        finally:
            _shutdown_pool(pool2)
        progress2.finish()

    results = [h for h in hosts.values() if h.is_alive]
    for host in results:
        classify(host)
    results.sort(key=lambda h: (-CONF_ORDER[h.confidence], int(ipaddress.IPv4Address(h.ip))))
    return results


# --------------------------------------------------------------------------- #
# 6. 输出
# --------------------------------------------------------------------------- #


def _display_width(text: str) -> int:
    """粗略计算显示宽度（CJK 按 2 列算）。"""
    width = 0
    for ch in text:
        width += 2 if unicodedata_east_asian(ch) else 1
    return width


def unicodedata_east_asian(ch: str) -> bool:
    import unicodedata

    return unicodedata.east_asian_width(ch) in ("W", "F")


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def render_table(results: List[HostResult], show_all: bool, verbose: bool) -> str:
    rows = [r for r in results if show_all or r.is_bmc]
    if not rows:
        return "未发现符合条件的 BMC 设备。"

    headers = ["IP 地址", "置信度", "设备类型", "开放端口"]
    table = [
        [r.ip, r.confidence or "-", r.vendor or "-", r.open_ports_str() or "-"]
        for r in rows
    ]
    widths = [
        max(_display_width(headers[i]), max(_display_width(row[i]) for row in table))
        for i in range(4)
    ]

    lines = ["  ".join(_pad(headers[i], widths[i]) for i in range(4))]
    lines.append("  ".join("-" * widths[i] for i in range(4)))
    for row, host in zip(table, rows):
        lines.append("  ".join(_pad(row[i], widths[i]) for i in range(4)))
        if verbose:
            for ev in host.evidence:
                lines.append(f"    · {ev}")
    return "\n".join(lines)


def render_json(results: List[HostResult], show_all: bool, meta: dict) -> str:
    rows = [r.to_dict() for r in results if show_all or r.is_bmc]
    for row in rows:
        for w in row.get("web", []):
            w.pop("_haystack", None)
        if row.get("redfish"):
            row["redfish"].pop("_haystack", None)
    return json.dumps({"meta": meta, "results": rows}, ensure_ascii=False, indent=2)


def render_csv(results: List[HostResult], show_all: bool) -> str:
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "confidence", "vendor", "open_ports", "ipmi_versions", "evidence"])
    for r in results:
        if not (show_all or r.is_bmc):
            continue
        writer.writerow(
            [
                r.ip,
                r.confidence,
                r.vendor,
                r.open_ports_str(),
                "/".join((r.ipmi or {}).get("versions", [])),
                " | ".join(r.evidence),
            ]
        )
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# 7. CLI
# --------------------------------------------------------------------------- #


def parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"非法端口: {bad}")
    return sorted(set(ports))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanbmc",
        description="扫描局域网内的服务器 BMC（IPMI/iDRAC/iLO/MegaRAC 等）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                                # 自动检测本机网段并扫描
  %(prog)s -t 192.168.1.0/24              # 指定网段
  %(prog)s -t 10.0.0.1-99 -c 256 -T 2.0   # 指定区间、256 并发、2 秒超时
  %(prog)s --list-networks                # 只列出检测到的本机网段
  %(prog)s -o json > bmc.json             # JSON 输出
  %(prog)s -v --all                       # 显示所有存活主机和判定依据
""",
    )
    parser.add_argument("-t", "--targets", help="目标，逗号分隔。支持 CIDR / 单 IP / 区间；缺省为自动检测网段")
    parser.add_argument("-x", "--exclude", default="", help="排除的目标，格式同 --targets")
    parser.add_argument(
        "-p",
        "--ports",
        default=",".join(str(p) for p in sorted(DEFAULT_TCP_PORTS)),
        help="TCP 端口列表（默认: %(default)s）",
    )
    parser.add_argument("-c", "--concurrency", type=int, default=128, help="并发数（默认: %(default)s）")
    parser.add_argument("-T", "--timeout", type=float, default=1.5, help="单次探测超时秒数（默认: %(default)s）")
    parser.add_argument("-r", "--retries", type=int, default=1, help="超时重试次数（默认: %(default)s）")
    parser.add_argument("-o", "--output", choices=["table", "json", "csv"], default="table", help="输出格式")
    parser.add_argument("--all", action="store_true", help="输出所有存活主机，而不仅是判定为 BMC 的")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示每台设备的判定依据")
    parser.add_argument("--no-udp", action="store_true", help="跳过 UDP/623 IPMI 探测")
    parser.add_argument("--no-web", action="store_true", help="跳过 HTTP(S) 指纹识别")
    parser.add_argument("--no-redfish", action="store_true", help="跳过 Redfish 探测")
    parser.add_argument(
        "--arp-only",
        action="store_true",
        help="快速模式：只扫描本机 ARP/邻居表中、且落在目标范围内的地址（适合大网段）",
    )
    parser.add_argument("--max-hosts", type=int, default=8192, help="目标数量上限保护（默认: %(default)s）")
    parser.add_argument("--list-networks", action="store_true", help="只列出检测到的本机网段后退出")
    parser.add_argument("-q", "--quiet", action="store_true", help="不输出进度和统计信息")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Windows 控制台默认 cp1252 等编码无法打印中文，强制 UTF-8（Python 3.7+ 支持）
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    log = (lambda *a: None) if args.quiet else (lambda *a: print(*a, file=sys.stderr))

    # 1) 确定目标网段
    if args.targets:
        specs = [s.strip() for s in args.targets.split(",") if s.strip()]
    else:
        nets = detect_local_networks()
        if not nets:
            print("错误：无法自动检测本机网段，请用 -t 手动指定。", file=sys.stderr)
            return 2
        specs = [str(n) for n in nets]
        log(f"自动检测到本机网段: {', '.join(specs)}")

    if args.list_networks:
        for spec in specs:
            net = ipaddress.ip_network(spec, strict=False)
            print(f"{net}  可用主机数 {net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses}")
        return 0

    excludes = [s.strip() for s in args.exclude.split(",") if s.strip()]

    try:
        if args.arp_only:
            neighbors = filter_to_specs(arp_neighbors(), specs)
            if not neighbors:
                print("错误：ARP 表中没有落在目标范围内的地址。", file=sys.stderr)
                return 2
            log(f"ARP 快速模式：从邻居表取到 {len(neighbors)} 个地址")
            targets = build_targets(neighbors, excludes)
        else:
            targets = build_targets(specs, excludes)
        tcp_ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    if not targets:
        print("错误：目标列表为空。", file=sys.stderr)
        return 2
    if len(targets) > args.max_hosts:
        print(
            f"错误：目标数 {len(targets)} 超过上限 {args.max_hosts}。"
            f"请缩小网段或调大 --max-hosts。",
            file=sys.stderr,
        )
        return 2

    # 每个并发探测占一个句柄。macOS 交互式 shell 默认软上限只有 256，
    # 直接用 -c 256 会撞 EMFILE，所以先尝试抬升上限，抬不动就收敛并发数。
    requested_workers = max(1, args.concurrency)
    soft_limit, _hard = ensure_fd_limit(requested_workers + FD_HEADROOM)
    workers = cap_workers(requested_workers, soft_limit)
    if workers < requested_workers:
        log(
            f"提示：本进程文件句柄上限为 {soft_limit}，并发数已从 "
            f"{requested_workers} 收敛到 {workers}。\n"
            f"      如需更高并发，请先执行 ulimit -n 4096 再运行。"
        )

    cfg = ScanConfig(
        tcp_ports=tcp_ports,
        workers=workers,
        timeout=max(0.1, args.timeout),
        retries=max(0, args.retries),
        udp=not args.no_udp,
        web=not args.no_web,
        redfish=not args.no_redfish,
        progress=not args.quiet,
    )

    log(
        f"目标 {len(targets)} 个 | TCP 端口 {','.join(map(str, tcp_ports))}"
        f"{' + UDP 623' if cfg.udp else ''} | 并发 {cfg.workers} | "
        f"超时 {cfg.timeout}s | 重试 {cfg.retries}"
    )

    started = time.monotonic()
    stats = ProbeStats()
    try:
        results = scan(targets, cfg, stats=stats)
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return 130
    elapsed = time.monotonic() - started

    # 大量"本机发不出包"的错误说明这次扫描不可信（网卡关闭、路由缺失、
    # 句柄耗尽等），必须明确告警，而不是安静地报告"未发现设备"。
    # 注意：空地址的 EHOSTDOWN 不算故障，否则扫整段网络时会次次误报。
    systemic = stats.systemic_ratio()
    degraded = systemic >= 0.5 and stats.systemic_failures > 0
    # 整段网络无一应答（连拒绝连接都没有），提示但不判为故障
    silent = not degraded and stats.total > 0 and stats.responded == 0 and not results

    meta = {
        "version": __version__,
        "networks": specs,
        "targets": len(targets),
        "tcp_ports": tcp_ports,
        "udp_probe": cfg.udp,
        "elapsed_seconds": round(elapsed, 2),
        "alive": len(results),
        "bmc": sum(1 for r in results if r.is_bmc),
        "probe_stats": stats.summary(),
        "degraded": degraded,
    }

    if degraded:
        detail = ", ".join(
            f"{k[4:]}×{v}" for k, v in sorted(stats.summary().items()) if k.startswith("sys:")
        )
        print(
            f"警告：{systemic:.0%} 的探测在本机侧就失败了（{detail}），本次结果不可信。\n"
            f"      常见原因：网卡未连接 / 目标网段无路由 / 并发过高耗尽句柄。"
            f"请检查网络后重试，或降低 -c 并发数。",
            file=sys.stderr,
        )
    elif silent:
        log(
            f"提示：{len(targets)} 个地址全部无应答。若确信网段内有设备，"
            f"请确认本机已接入该网段，或适当调大 -T 超时。"
        )

    if args.output == "json":
        print(render_json(results, args.all, meta))
    elif args.output == "csv":
        sys.stdout.write(render_csv(results, args.all))
    else:
        print(render_table(results, args.all, args.verbose))

    log(
        f"\n完成：耗时 {elapsed:.1f}s，存活主机 {meta['alive']} 台，"
        f"判定为 BMC {meta['bmc']} 台。"
    )
    return 3 if degraded else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
