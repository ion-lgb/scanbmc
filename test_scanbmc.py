#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanbmc 纯逻辑单元测试：python3 -m unittest -v test_scanbmc"""

import unittest

import scanbmc as sb


class TestNetmask(unittest.TestCase):
    def test_hex_mask(self):
        self.assertEqual(sb._netmask_to_prefix("0xffffff00"), 24)
        self.assertEqual(sb._netmask_to_prefix("0xffff0000"), 16)
        self.assertEqual(sb._netmask_to_prefix("0xffffffff"), 32)
        self.assertEqual(sb._netmask_to_prefix("0x00000000"), 0)

    def test_dotted_mask(self):
        self.assertEqual(sb._netmask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(sb._netmask_to_prefix("255.255.252.0"), 22)

    def test_non_contiguous_mask_rejected(self):
        self.assertIsNone(sb._netmask_to_prefix("0xff00ff00"))
        self.assertIsNone(sb._netmask_to_prefix("not-a-mask"))


class TestInterfaceParsing(unittest.TestCase):
    IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.20.0.7 netmask 0xfffffc00 broadcast 10.20.3.255
en9: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
\tinet 172.16.0.1 netmask 0xffffff00
"""

    IP_ADDR = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\\       valid_lft forever\n"
        "3: eth1    inet 172.31.9.4/16 brd 172.31.255.255 scope global eth1\\  valid_lft forever\n"
    )

    def test_ifconfig(self):
        nets = [str(n) for n in sb.parse_ifconfig(self.IFCONFIG)]
        self.assertIn("192.168.1.0/24", nets)
        self.assertIn("10.20.0.0/22", nets)
        self.assertNotIn("127.0.0.0/8", nets, "回环网卡不应被采集")
        self.assertNotIn("172.16.0.0/24", nets, "未 UP 的网卡不应被采集")

    def test_ip_addr(self):
        nets = [str(n) for n in sb.parse_ip_addr(self.IP_ADDR)]
        self.assertEqual(nets, ["10.0.0.0/24", "172.31.0.0/16"])


class TestTargets(unittest.TestCase):
    def test_cidr_excludes_network_and_broadcast(self):
        hosts = sb.parse_target("192.168.1.0/29")
        self.assertEqual([str(h) for h in hosts],
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3",
                          "192.168.1.4", "192.168.1.5", "192.168.1.6"])

    def test_single_ip(self):
        self.assertEqual([str(h) for h in sb.parse_target("10.1.2.3")], ["10.1.2.3"])

    def test_short_range(self):
        self.assertEqual([str(h) for h in sb.parse_target("10.0.0.8-11")],
                         ["10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11"])

    def test_full_range(self):
        self.assertEqual([str(h) for h in sb.parse_target("10.0.0.254-10.0.1.1")],
                         ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"])

    def test_reversed_range_rejected(self):
        with self.assertRaises(ValueError):
            sb.parse_target("10.0.0.9-2")

    def test_build_targets_dedup_sort_exclude(self):
        out = sb.build_targets(["192.168.1.0/30", "192.168.1.1"], excludes=["192.168.1.2"])
        self.assertEqual(out, ["192.168.1.1"])

    def test_arp_filter_keeps_only_in_scope(self):
        out = sb.filter_to_specs(
            ["192.168.1.200", "8.8.8.8", "192.168.1.1", "192.168.1.200", "garbage"],
            ["192.168.1.0/24"],
        )
        self.assertEqual(out, ["192.168.1.200", "192.168.1.1"], "去重并保持原顺序")
        self.assertNotIn("8.8.8.8", out, "网段外的 ARP 邻居不应被扫描")

    def test_arp_filter_respects_ranges(self):
        out = sb.filter_to_specs(["10.0.0.5", "10.0.0.99"], ["10.0.0.1-10"])
        self.assertEqual(out, ["10.0.0.5"])

    def test_ports(self):
        self.assertEqual(sb.parse_ports("80,443,5900"), [80, 443, 5900])
        self.assertEqual(sb.parse_ports("80-83,80"), [80, 81, 82, 83])
        with self.assertRaises(ValueError):
            sb.parse_ports("70000")


class TestIpmiPacket(unittest.TestCase):
    def test_request_checksums(self):
        """校验硬编码的 IPMI 请求报文两个校验和都正确。"""
        pkt = sb.IPMI_GET_CHANNEL_AUTH_CAP
        self.assertEqual(pkt[:4], b"\x06\x00\xff\x07")
        self.assertEqual(pkt[13], len(pkt) - 14, "载荷长度字段与实际长度不符")
        cs1 = (-(pkt[14] + pkt[15])) & 0xFF
        self.assertEqual(pkt[16], cs1)
        cs2 = (-sum(pkt[17:22])) & 0xFF
        self.assertEqual(pkt[22], cs2)
        self.assertEqual(pkt[19], 0x38, "命令码应为 Get Channel Auth Capabilities")

    @staticmethod
    def _response(auth_support=0x95, auth_status=0x04, ext_cap=0x02,
                  oem=674, completion=0x00):
        payload = bytes([0x01, auth_support, auth_status, ext_cap,
                         oem & 0xFF, (oem >> 8) & 0xFF, (oem >> 16) & 0xFF, 0x00])
        body = bytes([0x81, 0x1C, 0x63, 0x20, 0x00, 0x38, completion]) + payload
        return (b"\x06\x00\xff\x07" + b"\x00" + b"\x00" * 4 + b"\x00" * 4
                + bytes([len(body)]) + body)

    def test_parse_dell_v2(self):
        info = sb.parse_ipmi_response(self._response())
        self.assertIsNotNone(info)
        self.assertTrue(info["ipmi"])
        self.assertEqual(info["versions"], ["2.0"])
        self.assertEqual(info["oem_id"], 674)
        self.assertEqual(info["oem_vendor"], "Dell")
        self.assertIn("MD5", info["auth_types"])
        self.assertFalse(info["anonymous_login"])
        self.assertTrue(info["non_null_usernames"])

    def test_parse_v15_only(self):
        info = sb.parse_ipmi_response(self._response(auth_support=0x15, ext_cap=0x00))
        self.assertEqual(info["versions"], ["1.5"])

    def test_parse_both_versions(self):
        info = sb.parse_ipmi_response(self._response(auth_support=0x95, ext_cap=0x03))
        self.assertEqual(info["versions"], ["1.5", "2.0"])

    def test_anonymous_login_flagged(self):
        info = sb.parse_ipmi_response(self._response(auth_status=0x03))
        self.assertTrue(info["anonymous_login"])
        self.assertTrue(info["null_usernames"])

    def test_unknown_oem_kept_raw(self):
        info = sb.parse_ipmi_response(self._response(oem=99999))
        self.assertEqual(info["oem_vendor"], "IANA-99999")

    def test_nonzero_completion_still_ipmi(self):
        info = sb.parse_ipmi_response(self._response(completion=0xC1))
        self.assertTrue(info["ipmi"])
        self.assertEqual(info["completion_code"], 0xC1)

    def test_minimal_failure_response_accepted(self):
        """BMC 拒绝命令时只回 21 字节的最小应答（无附加数据），
        也应当被识别为 IPMI 而不是丢弃。"""
        body = bytes([0x81, 0x1C, 0x63, 0x20, 0x00, 0x38, 0xC1])
        resp = b"\x06\x00\xff\x07" + b"\x00" * 9 + bytes([len(body)]) + body
        self.assertEqual(len(resp), 21, "最小失败应答应为 21 字节")
        info = sb.parse_ipmi_response(resp)
        self.assertIsNotNone(info)
        self.assertTrue(info["ipmi"])
        self.assertEqual(info["completion_code"], 0xC1)

    def test_below_minimal_length_rejected(self):
        """20 字节连 IPMI 消息都装不下，必须拒绝。"""
        resp = b"\x06\x00\xff\x07" + b"\x00" * 9 + bytes([6]) + b"\x00" * 6
        self.assertEqual(len(resp), 20)
        self.assertIsNone(sb.parse_ipmi_response(resp))

    def test_garbage_rejected(self):
        self.assertIsNone(sb.parse_ipmi_response(b""))
        self.assertIsNone(sb.parse_ipmi_response(b"\x00" * 40))
        self.assertIsNone(sb.parse_ipmi_response(b"HTTP/1.1 400 Bad Request\r\n\r\n"))
        # class 字节是 ASF(0x06) 而不是 IPMI(0x07)
        self.assertIsNone(sb.parse_ipmi_response(b"\x06\x00\xff\x06" + b"\x00" * 30))


class TestDeviceId(unittest.TestCase):
    @staticmethod
    def _response(fw1=0x61, fw2=0x1A, ipmi_ver=0x02, oem=10876,
                  product=0x0100, available=0x80, completion=0x00):
        payload = bytes([
            0x20, fw1, fw2, ipmi_ver,
            oem & 0xFF, (oem >> 8) & 0xFF, (oem >> 16) & 0xFF,
            product & 0xFF, (product >> 8) & 0xFF,
            available, 0x00, 0x00,
        ])
        body = bytes([0x81, 0x1C, 0x63, 0x20, 0x00, 0x01, completion]) + payload
        return b"\x06\x00\xff\x07" + b"\x00" * 9 + bytes([len(body)]) + body

    def test_request_checksums(self):
        """Get Device ID 请求报文两个校验和都要正确。"""
        pkt = sb.IPMI_GET_DEVICE_ID
        self.assertEqual(pkt[:4], b"\x06\x00\xff\x07")
        self.assertEqual(pkt[13], len(pkt) - 14, "载荷长度字段与实际长度不符")
        self.assertEqual(pkt[19], 0x01, "命令码应为 Get Device ID")
        cs1 = (-(pkt[14] + pkt[15])) & 0xFF
        self.assertEqual(pkt[16], cs1)
        # 无请求数据：checksum2 覆盖 rqAddr+rqSeq+cmd 三个字节
        cs2 = (-sum(pkt[17:20])) & 0xFF
        self.assertEqual(pkt[20], cs2)

    def test_parse_supermicro(self):
        info = sb.parse_device_id(self._response())
        self.assertIsNotNone(info)
        self.assertTrue(info["ipmi"])
        self.assertEqual(info["firmware"], "6.26")
        self.assertEqual(info["ipmi_version"], "2.0")
        self.assertEqual(info["manufacturer"], "Supermicro")
        self.assertEqual(info["manufacturer_id"], 10876)
        self.assertEqual(info["product_id"], 0x0100)
        self.assertTrue(info["available"])

    def test_parse_firmware_zero_padded(self):
        """固件次版本要按两位补零显示（6.05 而不是 6.5）。"""
        info = sb.parse_device_id(self._response(fw2=0x05))
        self.assertEqual(info["firmware"], "6.05")

    def test_parse_ipmi_v15(self):
        info = sb.parse_device_id(self._response(ipmi_ver=0x15))
        self.assertEqual(info["ipmi_version"], "1.5")

    def test_parse_unknown_oem(self):
        info = sb.parse_device_id(self._response(oem=99999))
        self.assertEqual(info["manufacturer"], "IANA-99999")

    def test_parse_not_available(self):
        """bit7=0 表示设备处于固件更新/不可用状态。"""
        info = sb.parse_device_id(self._response(available=0x00))
        self.assertFalse(info["available"])

    def test_nonzero_completion_still_ipmi(self):
        info = sb.parse_device_id(self._response(completion=0xC1))
        self.assertTrue(info["ipmi"])
        self.assertEqual(info["completion_code"], 0xC1)

    def test_garbage_rejected(self):
        self.assertIsNone(sb.parse_device_id(b""))
        self.assertIsNone(sb.parse_device_id(b"\x00" * 40))
        # 命令码不是 0x01 的 IPMI 应答不应被认成 Device ID
        auth_cap = TestIpmiPacket._response()
        self.assertIsNone(sb.parse_device_id(auth_cap))


class TestAsfPong(unittest.TestCase):
    def test_request_shape(self):
        pkt = sb.ASF_PRESENCE_PING
        self.assertEqual(pkt[:4], b"\x06\x00\xff\x06")
        self.assertEqual(pkt[4:8], b"\x00\x00\x11\xbe")
        self.assertEqual(pkt[8], 0x80)

    def test_parse_pong(self):
        pong = (b"\x06\x00\xff\x06" + b"\x00\x00\x11\xbe" + bytes([0x40, 0xC0, 0x00, 0x10])
                + b"\x00\x00\x11\xbe" + b"\x00" * 4 + bytes([0x81, 0x00]) + b"\x00" * 6)
        info = sb.parse_asf_pong(pong)
        self.assertIsNotNone(info)
        self.assertTrue(info["ipmi_supported"])

    def test_reject_ipmi_class(self):
        self.assertIsNone(sb.parse_asf_pong(b"\x06\x00\xff\x07" + b"\x00" * 30))
        self.assertIsNone(sb.parse_asf_pong(b"\x06\x00\xff\x06" + b"\x00" * 4))


class TestFingerprint(unittest.TestCase):
    def test_vendor_signatures(self):
        cases = {
            "Server: Mbedthis-Appweb/2.4.2 ... iDRAC9": "Dell iDRAC",
            "<title>HP Integrated Lights-Out 4</title>": "HPE iLO",
            "Server: lighttpd ATEN <title>Supermicro</title>": "Supermicro BMC",
            "MegaRAC SP-X": "AMI MegaRAC BMC",
            "Huawei iBMC login": "Huawei iBMC",
            "Lenovo XClarity Controller": "Lenovo XClarity / IBM IMM",
            "Cisco CIMC": "Cisco IMC",
            "<title>Baseboard Management Controller</title>": "通用 BMC",
        }
        for text, expected in cases.items():
            self.assertEqual(sb.match_signature(text), expected, text)

    def test_no_match_on_ordinary_web_server(self):
        self.assertEqual(sb.match_signature("Server: nginx/1.24.0 <title>Welcome</title>"), "")


class TestClassify(unittest.TestCase):
    def test_ipmi_response_is_confirmed(self):
        host = sb.HostResult(ip="10.0.0.1")
        host.ipmi = {"ipmi": True, "versions": ["2.0"], "oem_id": 674,
                     "oem_vendor": "Dell", "anonymous_login": False}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertEqual(host.vendor, "Dell BMC")
        self.assertEqual(host.open_ports_str(), "623/udp")

    def test_anonymous_login_warned(self):
        host = sb.HostResult(ip="10.0.0.1")
        host.ipmi = {"ipmi": True, "versions": ["2.0"], "oem_vendor": "",
                     "anonymous_login": True, "null_usernames": True}
        sb.classify(host)
        self.assertTrue(any("匿名登录" in e for e in host.evidence))

    def test_redfish_placeholder_vendor_rejected(self):
        """实测中 BMC 会把 Vendor 填成 'N/A'、Product 填成 'Redfish Server'，
        这类占位符不能当厂商名显示。"""
        host = sb.HostResult(ip="10.0.0.8")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 200, "vendor": "", "product": "",
                        "version": "1.11.0", "_haystack": "{}"}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertEqual(host.vendor, "未知型号 BMC")
        self.assertNotIn("N/A", host.vendor)

    def test_redfish_server_header_identifies_vendor(self):
        """服务根 JSON 全是占位符时，Server 头仍能认出厂商。"""
        host = sb.HostResult(ip="10.0.0.10")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 200, "vendor": "", "product": "",
                        "version": "1.11.0", "server": "AMI MegaRAC Redfish Service",
                        "_haystack": "AMI MegaRAC Redfish Service {}"}
        sb.classify(host)
        self.assertEqual(host.vendor, "AMI MegaRAC BMC")
        self.assertTrue(any("Server 头" in e for e in host.evidence))

    def test_server_header_preferred_over_chassis_model(self):
        """机箱型号说明不了 BMC 固件来源，Server 头优先，型号进证据。"""
        host = sb.HostResult(ip="10.0.0.11")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 200, "vendor": "", "product": "4UGPUServer",
                        "version": "1.9.0", "server": "AMI MegaRAC Redfish Service",
                        "_haystack": "AMI MegaRAC Redfish Service {}"}
        sb.classify(host)
        self.assertEqual(host.vendor, "AMI MegaRAC BMC")
        self.assertTrue(any("4UGPUServer" in e for e in host.evidence))

    def test_real_vendor_field_wins_over_server_header(self):
        host = sb.HostResult(ip="10.0.0.12")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 200, "vendor": "Supermicro", "product": "",
                        "version": "1.21.0", "server": "AMI MegaRAC Redfish Service",
                        "_haystack": "x"}
        sb.classify(host)
        self.assertEqual(host.vendor, "Supermicro (Redfish)")

    def test_redfish_product_used_when_vendor_is_placeholder(self):
        host = sb.HostResult(ip="10.0.0.9")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 200, "vendor": "", "product": "4UGPUServer",
                        "version": "1.9.0", "_haystack": "{}"}
        sb.classify(host)
        self.assertEqual(host.vendor, "4UGPUServer (Redfish)")
        self.assertTrue(any("4UGPUServer" in e for e in host.evidence))

    def test_clean_value_filters_placeholders(self):
        for junk in ("N/A", "n/a", " None ", "Unknown", "Redfish Server", "", "-",
                     "To Be Filled By O.E.M."):
            self.assertEqual(sb._clean_value(junk), "", junk)
        self.assertEqual(sb._clean_value(" Supermicro "), "Supermicro")
        self.assertEqual(sb._clean_value(None), "")

    def test_supermicro_oem_id_21317(self):
        """实测网络中 Supermicro 主板上报的 OEM ID。"""
        self.assertEqual(sb.IPMI_OEM_IDS[21317], "Supermicro")

    def test_redfish_is_confirmed(self):
        host = sb.HostResult(ip="10.0.0.2")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 401, "vendor": "HPE",
                        "version": "1.6.0", "_haystack": "{}"}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertIn("HPE", host.vendor)

    def test_web_signature_is_likely(self):
        host = sb.HostResult(ip="10.0.0.3")
        host.ports = [sb.PortResult(port=443)]
        host.web = [{"port": 443, "scheme": "https", "server": "Appweb",
                     "title": "iDRAC9", "_haystack": "Appweb iDRAC9"}]
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_LIKELY)
        self.assertEqual(host.vendor, "Dell iDRAC")

    def test_port_pattern_only_is_possible(self):
        host = sb.HostResult(ip="10.0.0.4")
        host.ports = [sb.PortResult(port=443), sb.PortResult(port=5900, banner="RFB 003.008")]
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_POSSIBLE)

    def test_tcp_623_alone_is_possible(self):
        host = sb.HostResult(ip="10.0.0.6")
        host.ports = [sb.PortResult(port=623)]
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_POSSIBLE)
        self.assertTrue(any("623/tcp" in e for e in host.evidence))

    def test_udp_ipmi_beats_tcp_623_hint(self):
        """UDP 有应答时不该再输出'UDP 无应答'的弱证据。"""
        host = sb.HostResult(ip="10.0.0.7")
        host.ports = [sb.PortResult(port=623)]
        host.ipmi = {"ipmi": True, "versions": ["2.0"], "oem_vendor": "Dell"}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertFalse(any("无 IPMI 应答" in e for e in host.evidence))

    def test_plain_web_server_not_bmc(self):
        host = sb.HostResult(ip="10.0.0.5")
        host.ports = [sb.PortResult(port=80)]
        host.web = [{"port": 80, "scheme": "http", "server": "nginx/1.24.0",
                     "title": "Welcome", "_haystack": "nginx Welcome"}]
        sb.classify(host)
        self.assertEqual(host.confidence, "")
        self.assertFalse(host.is_bmc)
        self.assertTrue(host.is_alive)

    def test_device_id_alone_confirms(self):
        """auth-cap 被静默，但 Get Device ID 应答足以确认是 BMC。"""
        host = sb.HostResult(ip="10.0.0.13")
        host.device_id = {"ipmi": True, "completion_code": 0, "firmware": "6.26",
                          "ipmi_version": "2.0", "manufacturer_id": 10876,
                          "manufacturer": "Supermicro", "product_id": 0x0100,
                          "available": True}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertEqual(host.vendor, "Supermicro BMC")
        self.assertTrue(any("固件 6.26" in e for e in host.evidence))
        self.assertIn("623/udp", host.open_ports_str())

    def test_device_id_enriches_confirmed_ipmi(self):
        """auth-cap 已确认时，Device ID 只补充细节，不改厂商。"""
        host = sb.HostResult(ip="10.0.0.14")
        host.ipmi = {"ipmi": True, "versions": ["2.0"], "oem_vendor": "Dell"}
        host.device_id = {"ipmi": True, "completion_code": 0, "firmware": "6.26",
                          "ipmi_version": "2.0", "manufacturer_id": 10876,
                          "manufacturer": "Supermicro", "product_id": 0x0100,
                          "available": True}
        sb.classify(host)
        self.assertEqual(host.confidence, sb.CONF_CONFIRMED)
        self.assertEqual(host.vendor, "Dell BMC", "已有厂商不被 Device ID 覆盖")
        self.assertTrue(any("固件 6.26" in e for e in host.evidence))

    def test_device_id_unavailable_warned(self):
        host = sb.HostResult(ip="10.0.0.15")
        host.device_id = {"ipmi": True, "completion_code": 0, "firmware": "",
                          "ipmi_version": "", "manufacturer_id": 0,
                          "manufacturer": "", "product_id": 0, "available": False}
        sb.classify(host)
        self.assertTrue(any("不可用" in e for e in host.evidence))

    def test_cert_expired_warned(self):
        host = sb.HostResult(ip="10.0.0.16")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 401, "vendor": "HPE",
                        "version": "1.6.0", "_haystack": "{}",
                        "cert": {"subject_cn": "idrac", "not_after": "2020-01-01",
                                 "days_left": -200, "expired": True}}
        sb.classify(host)
        self.assertTrue(any("证书已过期" in e for e in host.evidence))

    def test_cert_expiring_soon_warned(self):
        host = sb.HostResult(ip="10.0.0.17")
        host.ports = [sb.PortResult(port=443)]
        host.web = [{"port": 443, "scheme": "https", "_haystack": "",
                     "cert": {"subject_cn": "ilo", "not_after": "2026-08-01",
                              "days_left": 10, "expired": False}}]
        sb.classify(host)
        self.assertTrue(any("天后过期" in e for e in host.evidence))

    def test_cert_fine_recorded(self):
        host = sb.HostResult(ip="10.0.0.18")
        host.ports = [sb.PortResult(port=443)]
        host.redfish = {"port": 443, "status": 401, "vendor": "",
                        "version": "", "_haystack": "{}",
                        "cert": {"subject_cn": "bmc-1", "not_after": "2030-01-01",
                                 "days_left": 1200, "expired": False}}
        sb.classify(host)
        self.assertTrue(any("CN=bmc-1" in e for e in host.evidence))


class TestBodyDecoding(unittest.TestCase):
    """很多 BMC 直接返回预压缩的 index.html.gz，不解压则页面指纹完全失效。"""

    HTML = b"<html><head><title>MegaRAC SP-X</title></head><body>x</body></html>"

    def test_gzip_body_decoded(self):
        import gzip

        packed = gzip.compress(self.HTML)
        out = sb._decode_body({"content-encoding": "gzip"}, packed)
        self.assertEqual(out, self.HTML)

    def test_truncated_gzip_returns_partial(self):
        """我们只读正文前若干 KB，截断的 gzip 也要尽量解出内容。"""
        import gzip

        big = b"<html><title>MegaRAC</title>" + b"A" * 40000 + b"</html>"
        packed = gzip.compress(big)[:2000]
        out = sb._decode_body({"content-encoding": "gzip"}, packed)
        self.assertIn(b"MegaRAC", out)

    def test_deflate_body_decoded(self):
        import zlib as _zlib

        out = sb._decode_body({"content-encoding": "deflate"}, _zlib.compress(self.HTML))
        self.assertEqual(out, self.HTML)

    def test_raw_deflate_body_decoded(self):
        import zlib as _zlib

        comp = _zlib.compressobj(wbits=-_zlib.MAX_WBITS)
        raw = comp.compress(self.HTML) + comp.flush()
        self.assertEqual(sb._decode_body({"content-encoding": "deflate"}, raw), self.HTML)

    def test_identity_body_untouched(self):
        self.assertEqual(sb._decode_body({}, self.HTML), self.HTML)

    def test_corrupt_body_returned_as_is(self):
        junk = b"\x1f\x8b not really gzip"
        self.assertEqual(sb._decode_body({"content-encoding": "gzip"}, junk), junk)

    def test_chunked_body(self):
        chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        out = sb._decode_body({"transfer-encoding": "chunked"}, chunked)
        self.assertEqual(out, b"hello world")

    def test_chunked_then_gzip(self):
        import gzip

        packed = gzip.compress(self.HTML)
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(packed), packed)
        out = sb._decode_body(
            {"transfer-encoding": "chunked", "content-encoding": "gzip"}, chunked
        )
        self.assertEqual(out, self.HTML)

    def test_truncated_chunked_keeps_partial_tail(self):
        """正文是我们主动截断读取的，最后一个不完整分块也要保留——
        指纹匹配拿到的文本越多越好。"""
        out = sb._decode_body({"transfer-encoding": "chunked"}, b"5\r\nhello\r\n6\r\n wor")
        self.assertEqual(out, b"hello wor")

    def test_empty_body_safe(self):
        self.assertEqual(sb._decode_body({"content-encoding": "gzip"}, b""), b"")


class TestCertInfo(unittest.TestCase):
    def test_parses_valid_cert(self):
        cert = {
            "subject": ((("commonName", "idrac-192.168.1.50"),),),
            "issuer": ((("organizationName", "Dell Inc."),),),
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }
        info = sb._cert_info(cert)
        self.assertIsNotNone(info)
        self.assertEqual(info["subject_cn"], "idrac-192.168.1.50")
        self.assertEqual(info["issuer"], "Dell Inc.")
        self.assertEqual(info["not_after"], "2030-12-31")
        self.assertGreater(info["days_left"], 0)
        self.assertFalse(info["expired"])

    def test_expired_cert(self):
        cert = {"subject": (), "issuer": (), "notAfter": "Jan 01 00:00:00 2020 GMT"}
        info = sb._cert_info(cert)
        self.assertTrue(info["expired"])
        self.assertLess(info["days_left"], 0)

    def test_missing_or_garbage_rejected(self):
        self.assertIsNone(sb._cert_info({}))
        self.assertIsNone(sb._cert_info(None))
        self.assertIsNone(sb._cert_info({"notAfter": "not a date"}))

    # ---- DER 二进制证书（getpeercert 无详情时的兜底路径） ----

    @staticmethod
    def _der(tag: int, value: bytes) -> bytes:
        n = len(value)
        if n < 128:
            return bytes([tag, n]) + value
        b = n.to_bytes(4, "big").lstrip(b"\x00")
        return bytes([tag, 0x80 | len(b)]) + b + value

    @classmethod
    def _make_cert(cls, cn: str, not_after: str, issuer: str = "issuer") -> bytes:
        """手工构造一个最小 X.509 证书 DER（只含解析需要的字段）。"""
        cn_oid = b"\x55\x04\x03"                       # 2.5.4.3 commonName

        def name(text: str) -> bytes:
            return cls._der(
                0x30, cls._der(0x31, cls._der(0x30, cls._der(0x06, cn_oid) + cls._der(0x0C, text.encode())))
            )

        tbs = cls._der(
            0x30,
            cls._der(0xA0, cls._der(0x02, b"\x02")) +               # version
            cls._der(0x02, b"\x01") +                               # serialNumber
            cls._der(0x30, cls._der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")) +  # signature
            name(issuer) +
            cls._der(0x30, cls._der(0x17, b"240101000000Z") + cls._der(0x17, not_after.encode())) +  # validity
            name(cn) +
            cls._der(0x30, b"\x00"),                                # SPKI 占位
        )
        return cls._der(0x30, tbs + cls._der(0x30, b"\x00") + cls._der(0x03, b"\x00"))

    def test_der_cert_parsed(self):
        cert = self._make_cert("test-bmc", "340101000000Z")   # UTCTime 2034-01-01
        info = sb._cert_info_der(cert)
        self.assertIsNotNone(info)
        self.assertEqual(info["subject_cn"], "test-bmc")
        self.assertEqual(info["issuer"], "issuer")
        self.assertEqual(info["not_after"], "2034-01-01")
        self.assertFalse(info["expired"])

    def test_der_cert_expired(self):
        cert = self._make_cert("old-bmc", "200101000000Z")   # UTCTime 2020-01-01
        info = sb._cert_info_der(cert)
        self.assertTrue(info["expired"])
        self.assertLess(info["days_left"], 0)

    def test_der_garbage_rejected(self):
        self.assertIsNone(sb._cert_info_der(b""))
        self.assertIsNone(sb._cert_info_der(b"\x30\x03\x01\x02\x03"))
        self.assertIsNone(sb._cert_info_der(b"not a cert at all"))


class TestFdLimit(unittest.TestCase):
    """macOS 交互式 shell 默认软上限 256，-c 256 会直接撞 EMFILE。"""

    def test_workers_capped_to_fd_limit(self):
        self.assertEqual(sb.cap_workers(256, 256), 256 - sb.FD_HEADROOM)
        self.assertLess(sb.cap_workers(256, 256), 256)

    def test_workers_untouched_when_limit_is_ample(self):
        self.assertEqual(sb.cap_workers(256, 1048576), 256)

    def test_workers_never_below_one(self):
        self.assertEqual(sb.cap_workers(256, 8), 1)
        self.assertEqual(sb.cap_workers(1, 0), 1)

    def test_unknown_limit_leaves_workers_alone(self):
        """拿不到 resource 模块（如 Windows）时不应瞎收敛。"""
        self.assertEqual(sb.cap_workers(128, 0), 128)

    def test_ensure_fd_limit_raises_soft_limit(self):
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        except (ValueError, OSError):
            self.skipTest("无法调整本进程句柄上限")
        try:
            new_soft, _ = sb.ensure_fd_limit(2048)
            self.assertGreaterEqual(new_soft, 2048)
            self.assertEqual(sb.cap_workers(1024, new_soft), 1024)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


class TestProbeStats(unittest.TestCase):
    """网络不可达必须与'端口关闭'区分开，否则网卡掉线会被报成'未发现设备'。"""

    def test_systemic_errors_counted_separately(self):
        import errno as _errno

        stats = sb.ProbeStats()
        for _ in range(9):
            stats.add_oserror(OSError(_errno.ENETDOWN, "network is down"))
        stats.add("open")
        self.assertEqual(stats.total, 10)
        self.assertEqual(stats.systemic_failures, 9)
        self.assertAlmostEqual(stats.systemic_ratio(), 0.9)
        self.assertIn("sys:ENETDOWN", stats.summary())

    def test_empty_lan_addresses_are_not_a_failure(self):
        """扫一整段网络时，空地址返回 EHOSTDOWN 是正常现象，不能误报为故障。"""
        import errno as _errno

        stats = sb.ProbeStats()
        for _ in range(250):
            stats.add_oserror(OSError(_errno.EHOSTDOWN, "host is down"))
        for _ in range(4):
            stats.add("open")
        self.assertEqual(stats.systemic_failures, 0)
        self.assertEqual(stats.systemic_ratio(), 0.0)
        self.assertEqual(stats.host_down, 250)
        self.assertEqual(stats.responded, 4)

    def test_host_unreachable_is_per_host_not_systemic(self):
        import errno as _errno

        stats = sb.ProbeStats()
        stats.add_oserror(OSError(_errno.EHOSTUNREACH, "no route to host"))
        self.assertEqual(stats.systemic_failures, 0)
        self.assertEqual(stats.host_down, 1)

    def test_timeouts_and_refusals_are_not_systemic(self):
        stats = sb.ProbeStats()
        for _ in range(5):
            stats.add("timeout")
        for _ in range(5):
            stats.add("refused")
        self.assertEqual(stats.systemic_failures, 0)
        self.assertEqual(stats.systemic_ratio(), 0.0)
        self.assertEqual(stats.responded, 5)

    def test_empty_stats_safe(self):
        stats = sb.ProbeStats()
        self.assertEqual(stats.systemic_ratio(), 0.0)
        self.assertEqual(stats.responded, 0)

    def test_emfile_is_systemic(self):
        import errno as _errno

        stats = sb.ProbeStats()
        stats.add_oserror(OSError(_errno.EMFILE, "too many open files"))
        self.assertEqual(stats.systemic_failures, 1)

    def test_thread_safety(self):
        import threading as _threading

        stats = sb.ProbeStats()

        def worker():
            for _ in range(500):
                stats.add("timeout")

        threads = [_threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(stats.total, 4000)


class TestRender(unittest.TestCase):
    def _sample(self):
        host = sb.HostResult(ip="192.168.1.50")
        host.ipmi = {"ipmi": True, "versions": ["2.0"], "oem_id": 10876,
                     "oem_vendor": "Supermicro", "anonymous_login": False}
        host.ports = [sb.PortResult(port=443), sb.PortResult(port=5900)]
        sb.classify(host)
        return [host]

    def test_table_contains_key_fields(self):
        out = sb.render_table(self._sample(), show_all=False, verbose=True)
        self.assertIn("192.168.1.50", out)
        self.assertIn("623/udp", out)
        self.assertIn("Supermicro", out)

    def test_json_strips_internal_keys(self):
        import json
        host = self._sample()[0]
        host.web = [{"port": 443, "scheme": "https", "_haystack": "秘密内部字段"}]
        doc = json.loads(sb.render_json([host], show_all=False, meta={"targets": 1}))
        self.assertNotIn("_haystack", doc["results"][0]["web"][0])
        self.assertEqual(doc["results"][0]["ip"], "192.168.1.50")

    def test_csv_header(self):
        out = sb.render_csv(self._sample(), show_all=False)
        self.assertTrue(out.startswith("ip,confidence,vendor,open_ports"))
        self.assertIn("192.168.1.50", out)

    def test_empty_result(self):
        self.assertIn("未发现", sb.render_table([], show_all=False, verbose=False))


if __name__ == "__main__":
    unittest.main()
