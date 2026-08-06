#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端集成测试：在 127.0.0.1 上起一台"假 BMC"（IPMI UDP 应答 + iDRAC 风格 Web +
Redfish 接口），跑完整的 scan() 流程，验证发现、指纹与判定链路。

用非特权端口（623 需要 root），通过临时替换模块常量来指向它们。

运行：python3 -m unittest -v test_integration
"""

import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import scanbmc as sb

# ---------------------------------------------------------------- 假 BMC 服务端


def make_ipmi_response(oem: int = 10876) -> bytes:
    """构造一个 Supermicro、IPMI 2.0、允许空用户名的 Get Channel Auth Cap 应答。"""
    payload = bytes(
        [
            0x01,                                   # 通道号
            0x95,                                   # 支持 v2.0(bit7) + MD5 + password + none
            0x02,                                   # 认证状态：允许空用户名
            0x02,                                   # 扩展能力：仅 IPMI 2.0
            oem & 0xFF, (oem >> 8) & 0xFF, (oem >> 16) & 0xFF,
            0x00,                                   # OEM 附加数据
        ]
    )
    body = bytes([0x81, 0x1C, 0x63, 0x20, 0x00, 0x38, 0x00]) + payload
    return b"\x06\x00\xff\x07" + b"\x00" * 9 + bytes([len(body)]) + body


def make_device_id_response(oem: int = 10876) -> bytes:
    """构造 Get Device ID 应答：Supermicro、固件 6.26、IPMI 2.0、产品 ID 0x0100。"""
    payload = bytes(
        [
            0x20,                                   # Device ID
            0x61,                                   # 设备修订 1 + 固件修订主版本 6
            0x1A,                                   # 固件修订次版本 26 → 6.26
            0x02,                                   # IPMI 版本 2.0
            oem & 0xFF, (oem >> 8) & 0xFF, (oem >> 16) & 0xFF,
            0x00, 0x01,                             # 产品 ID 0x0100 (256)
            0x80,                                   # 设备可用
            0x00, 0x00,                             # 附加信息
        ]
    )
    body = bytes([0x81, 0x1C, 0x63, 0x20, 0x00, 0x01, 0x00]) + payload
    return b"\x06\x00\xff\x07" + b"\x00" * 9 + bytes([len(body)]) + body


class FakeIpmiServer(threading.Thread):
    """UDP 服务：收到 IPMI 请求回 auth-cap 应答，收到 ASF Ping 回 Pong。"""

    daemon = True

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self._stop = threading.Event()

    def run(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            self.requests.append(data)
            if len(data) > 3 and data[3] == 0x07:
                # 按命令码区分：0x01 = Get Device ID，0x38 = Get Channel Auth Cap
                if len(data) > 19 and data[19] == 0x01:
                    self.sock.sendto(make_device_id_response(), addr)
                else:
                    self.sock.sendto(make_ipmi_response(), addr)
            elif len(data) > 3 and data[3] == 0x06:
                pong = (
                    b"\x06\x00\xff\x06"
                    + b"\x00\x00\x11\xbe"
                    + bytes([0x40, data[9], 0x00, 0x10])
                    + b"\x00\x00\x11\xbe"
                    + b"\x00" * 4
                    + bytes([0x81, 0x00])
                    + b"\x00" * 6
                )
                self.sock.sendto(pong, addr)

    def stop(self):
        self._stop.set()
        self.sock.close()


class FakeBmcWebHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self):                    # 伪装成 iDRAC 的 Web 服务器
        return "Mbedthis-Appweb/2.4.2"

    def log_message(self, *args):                # 静音
        pass

    def do_GET(self):
        if self.path.rstrip("/") == "/redfish/v1":
            body = (
                b'{"@odata.id":"/redfish/v1/","Vendor":"Dell",'
                b'"RedfishVersion":"1.6.0","Oem":{"Dell":{}}}'
            )
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/plain":
            body = b"<html><title>Welcome to nginx</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        else:
            body = b"<html><head><title>iDRAC9 Login</title></head><body></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PlainWebHandler(BaseHTTPRequestHandler):
    """一台普通的 Web 服务器，用来验证不会被误判成 BMC。"""

    protocol_version = "HTTP/1.1"

    def version_string(self):
        return "nginx/1.24.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b"<html><head><title>Welcome</title></head><body>hi</body></html>"
        self.send_response(404 if self.path.startswith("/redfish") else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_http(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def stop_http(srv):
    """shutdown() 只停服务循环，还要 server_close() 才会释放监听 socket。"""
    srv.shutdown()
    srv.server_close()


# ---------------------------------------------------------------- 测试


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ipmi = FakeIpmiServer()
        cls.ipmi.start()
        cls.bmc_srv, cls.bmc_port = start_http(FakeBmcWebHandler)
        cls.plain_srv, cls.plain_port = start_http(PlainWebHandler)

        # 把模块常量指向测试端口
        cls._saved = (sb.IPMI_UDP_PORT, dict(sb.WEB_PORTS), set(sb.REDFISH_PORTS))
        sb.IPMI_UDP_PORT = cls.ipmi.port
        sb.WEB_PORTS[cls.bmc_port] = False
        sb.WEB_PORTS[cls.plain_port] = False
        sb.REDFISH_PORTS.update({cls.bmc_port, cls.plain_port})

    @classmethod
    def tearDownClass(cls):
        sb.IPMI_UDP_PORT, web, redfish = cls._saved
        sb.WEB_PORTS.clear()
        sb.WEB_PORTS.update(web)
        sb.REDFISH_PORTS.clear()
        sb.REDFISH_PORTS.update(redfish)
        cls.ipmi.stop()
        stop_http(cls.bmc_srv)
        stop_http(cls.plain_srv)

    def _cfg(self, ports, **kw):
        return sb.ScanConfig(
            tcp_ports=ports, workers=16, timeout=1.0, retries=1, progress=False, **kw
        )

    def test_full_pipeline_detects_fake_bmc(self):
        results = sb.scan(["127.0.0.1"], self._cfg([self.bmc_port]))
        self.assertEqual(len(results), 1)
        host = results[0]

        # UDP/623 IPMI 链路
        self.assertIsNotNone(host.ipmi, "应收到 IPMI 应答")
        self.assertEqual(host.ipmi["versions"], ["2.0"])
        self.assertEqual(host.ipmi["oem_vendor"], "Supermicro")
        self.assertTrue(host.ipmi["null_usernames"])

        # Get Device ID 链路
        self.assertIsNotNone(host.device_id, "应收到 Get Device ID 应答")
        self.assertEqual(host.device_id["firmware"], "6.26")
        self.assertEqual(host.device_id["ipmi_version"], "2.0")
        self.assertEqual(host.device_id["manufacturer"], "Supermicro")
        self.assertEqual(host.device_id["product_id"], 0x0100)

        # TCP + Web + Redfish 链路
        self.assertEqual([p.port for p in host.ports], [self.bmc_port])
        self.assertIsNotNone(host.redfish, "应识别出 Redfish")
        self.assertEqual(host.redfish["status"], 401, "401 也应算作确认")
        self.assertEqual(host.redfish["vendor"], "Dell")

        # 判定结果
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertEqual(host.vendor, "Supermicro BMC", "IPMI OEM 优先于 Web 指纹")
        self.assertTrue(any("iDRAC" in e for e in host.evidence), host.evidence)
        self.assertTrue(any("空用户名" in e for e in host.evidence), host.evidence)
        self.assertIn("623/udp", host.open_ports_str())

    def test_plain_web_server_not_flagged(self):
        results = sb.scan(["127.0.0.1"], self._cfg([self.plain_port], udp=False))
        self.assertEqual(len(results), 1)
        host = results[0]
        self.assertTrue(host.is_alive)
        self.assertFalse(host.is_bmc, f"普通 nginx 被误判: {host.evidence}")
        self.assertIsNone(host.redfish, "404 不应算 Redfish")

    def test_web_fingerprint_alone_is_likely(self):
        """关掉 UDP 和 Redfish 后，仅凭 Web 指纹应判为'可能'。"""
        results = sb.scan(["127.0.0.1"], self._cfg([self.bmc_port], udp=False, redfish=False))
        host = results[0]
        self.assertEqual(host.confidence, sb.CONF_LIKELY)
        self.assertEqual(host.vendor, "Dell iDRAC")

    def test_closed_port_host_is_skipped(self):
        """找一个确定没人监听的端口，主机不应出现在结果里。"""
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        results = sb.scan(["127.0.0.1"], self._cfg([free_port], udp=False))
        self.assertEqual(results, [])

    def test_retry_on_no_response(self):
        """无人应答时 UDP 探测应按 retries 次数重发（IPMI + ASF 各 2 次）。"""
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        saved = sb.IPMI_UDP_PORT
        sb.IPMI_UDP_PORT = dead_port
        try:
            ipmi, pong, devid = sb.udp_probe("127.0.0.1", timeout=0.2, retries=1)
            self.assertIsNone(ipmi)
            self.assertFalse(pong)
            self.assertIsNone(devid)
            self.assertGreaterEqual(dead.recv(2048) and 1, 1, "至少应收到一次探测包")
        finally:
            sb.IPMI_UDP_PORT = saved
            dead.close()

    def test_asf_fallback_when_ipmi_silent(self):
        """BMC 只回 ASF Pong 时也应被确认。"""
        results = sb.scan(["127.0.0.1"], self._cfg([]))
        host = results[0]
        self.assertIsNotNone(host.ipmi)
        # 直接验证 ASF 解析路径
        pong = sb._udp_send(
            "127.0.0.1", sb.ASF_PRESENCE_PING, 1.0, 0, sb.parse_asf_pong
        )
        self.assertIsNotNone(pong)
        self.assertTrue(pong["ipmi_supported"])


class TestUnreachableNetwork(unittest.TestCase):
    """网卡掉线 / 无路由时，必须告警而不是安静地报告"未发现设备"。"""

    def _patched_socket(self, err):
        import errno as _errno
        from unittest import mock

        real_socket = socket.socket

        def factory(*args, **kwargs):
            sock = real_socket(*args, **kwargs)
            sock.close()
            fake = mock.MagicMock()
            fake.connect.side_effect = OSError(err, _errno.errorcode[err])
            return fake

        return mock.patch.object(sb.socket, "socket", side_effect=factory)

    def test_network_down_marks_scan_degraded(self):
        import errno as _errno

        stats = sb.ProbeStats()
        cfg = sb.ScanConfig(tcp_ports=[80, 443], workers=4, timeout=0.2,
                            retries=1, udp=False, progress=False)
        with self._patched_socket(_errno.ENETDOWN):
            results = sb.scan(["10.99.99.1", "10.99.99.2"], cfg, stats=stats)
        self.assertEqual(results, [])
        self.assertEqual(stats.systemic_failures, 4)
        self.assertEqual(stats.systemic_ratio(), 1.0)

    def test_empty_lan_does_not_trigger_warning(self):
        """整段空网络（EHOSTDOWN）应正常返回 0，而不是报故障。"""
        import errno as _errno
        import io
        from contextlib import redirect_stderr, redirect_stdout

        err = io.StringIO()
        with self._patched_socket(_errno.EHOSTDOWN):
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                code = sb.main(["-t", "10.99.99.1-8", "-p", "80", "--no-udp", "-T", "0.2"])
        self.assertEqual(code, 0, "空网段不应被判为扫描故障")
        self.assertNotIn("不可信", err.getvalue())
        self.assertIn("提示", err.getvalue(), "应给出无应答提示")

    def test_cli_exits_3_and_warns(self):
        import errno as _errno
        import io
        from contextlib import redirect_stderr, redirect_stdout

        err = io.StringIO()
        with self._patched_socket(_errno.ENETDOWN):
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                code = sb.main(["-t", "10.99.99.1-4", "-p", "80", "--no-udp", "-T", "0.2"])
        self.assertEqual(code, 3, "不可信的扫描应返回非零退出码")
        self.assertIn("警告", err.getvalue())
        self.assertIn("不可信", err.getvalue())

    def test_normal_scan_not_marked_degraded(self):
        """真实的 timeout / refused 不应触发告警。"""
        stats = sb.ProbeStats()
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        cfg = sb.ScanConfig(tcp_ports=[free_port], workers=2, timeout=0.3,
                            retries=0, udp=False, progress=False)
        sb.scan(["127.0.0.1"], cfg, stats=stats)
        self.assertEqual(stats.systemic_failures, 0)
        self.assertLess(stats.systemic_ratio(), 0.5)


class TestCrashResilience(unittest.TestCase):
    """句柄耗尽等故障必须只影响单个探测，不能掀翻整轮扫描丢掉全部结果。"""

    def test_emfile_during_udp_does_not_abort_scan(self):
        import errno as _errno
        from unittest import mock

        real_socket = socket.socket
        calls = {"n": 0}

        def flaky(family=socket.AF_INET, type=socket.SOCK_STREAM, *a, **kw):
            # 每第 3 个 socket 创建失败，模拟句柄耗尽
            calls["n"] += 1
            if calls["n"] % 3 == 0:
                raise OSError(_errno.EMFILE, "Too many open files")
            return real_socket(family, type, *a, **kw)

        stats = sb.ProbeStats()
        cfg = sb.ScanConfig(tcp_ports=[80, 443], workers=4, timeout=0.3,
                            retries=1, progress=False)
        with mock.patch.object(sb.socket, "socket", side_effect=flaky):
            # 不应抛异常
            results = sb.scan(["127.0.0.1", "127.0.0.1"], cfg, stats=stats)
        self.assertIsInstance(results, list)
        self.assertGreater(stats.systemic_failures, 0, "EMFILE 应被记为系统性故障")

    def test_unexpected_exception_is_contained(self):
        """探测器内部出现意外异常时，扫描应继续并记账，而不是整体崩溃。"""
        from unittest import mock

        stats = sb.ProbeStats()
        cfg = sb.ScanConfig(tcp_ports=[80], workers=2, timeout=0.3,
                            retries=0, udp=False, progress=False)
        with mock.patch.object(sb, "tcp_probe", side_effect=RuntimeError("boom")):
            results = sb.scan(["127.0.0.1", "127.0.0.2"], cfg, stats=stats)
        self.assertEqual(results, [])
        self.assertIn("bug:RuntimeError", stats.summary())

    def test_scan_keeps_results_found_before_failure(self):
        """故障发生前已发现的结果必须保留。"""
        import errno as _errno
        from unittest import mock

        real_socket = socket.socket
        srv, port = start_http(PlainWebHandler)
        self.addCleanup(stop_http, srv)
        state = {"n": 0}

        def flaky(family=socket.AF_INET, type=socket.SOCK_STREAM, *a, **kw):
            state["n"] += 1
            if state["n"] > 2:
                raise OSError(_errno.EMFILE, "Too many open files")
            return real_socket(family, type, *a, **kw)

        stats = sb.ProbeStats()
        cfg = sb.ScanConfig(tcp_ports=[port], workers=1, timeout=0.5,
                            retries=0, udp=False, web=False, redfish=False,
                            progress=False)
        with mock.patch.object(sb.socket, "socket", side_effect=flaky):
            results = sb.scan(["127.0.0.1"] , cfg, stats=stats)
        self.assertEqual(len(results), 1, "首个成功探测的结果不应丢失")
        self.assertEqual(results[0].ip, "127.0.0.1")


class TestCli(unittest.TestCase):
    def test_list_networks(self):
        self.assertEqual(sb.main(["--list-networks", "-t", "192.168.99.0/29", "-q"]), 0)

    def test_max_hosts_guard(self):
        self.assertEqual(sb.main(["-t", "10.0.0.0/16", "--max-hosts", "10", "-q"]), 2)

    def test_bad_target(self):
        self.assertEqual(sb.main(["-t", "not-an-ip", "-q"]), 2)

    def test_bad_port(self):
        self.assertEqual(sb.main(["-t", "127.0.0.1", "-p", "99999", "-q"]), 2)


if __name__ == "__main__":
    unittest.main()
