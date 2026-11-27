using System.Buffers.Binary;

namespace ScanBMC.Core;

/// <summary>IPMI RMCP / Get Device ID / ASF Presence Ping 报文构造与解析。</summary>
public static class IpmiProtocol
{
    // RMCP + IPMI v1.5 会话封装 + Get Channel Authentication Capabilities (cmd 0x38)
    public static readonly byte[] GetChannelAuthCapPacket =
    {
        0x06, 0x00, 0xFF, 0x07,             // RMCP 头 (class 0x07 = IPMI)
        0x00,                               // 认证类型 NONE
        0x00, 0x00, 0x00, 0x00,             // 会话序列号
        0x00, 0x00, 0x00, 0x00,             // 会话 ID
        0x09,                               // 载荷长度
        0x20, 0x18, 0xC8,                   // rsAddr / netFn(App)+lun / checksum1
        0x81, 0x00, 0x38,                   // rqAddr / rqSeq+lun / cmd 0x38
        0x8E, 0x04,                         // 通道 0x0E|0x80(v2) / 权限 ADMIN
        0xB5,                               // checksum2
    };

    // RMCP + IPMI v1.5 会话封装 + Get Device ID (cmd 0x01，免认证)
    public static readonly byte[] GetDeviceIdPacket =
    {
        0x06, 0x00, 0xFF, 0x07,
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07,
        0x20, 0x18, 0xC8,
        0x81, 0x00, 0x01,
        0x7E,
    };

    // RMCP + ASF Presence Ping (class 0x06)
    public static readonly byte[] AsfPresencePingPacket =
    {
        0x06, 0x00, 0xFF, 0x06,
        0x00, 0x00, 0x11, 0xBE,             // ASF IANA = 4542
        0x80,                               // Presence Ping
        0xC0,                               // Tag
        0x00,
        0x00,
    };

    // IPMI OEM ID (IANA 企业编号) -> 厂商
    public static readonly IReadOnlyDictionary<int, string> OemIds = new Dictionary<int, string>
    {
        [2] = "IBM",
        [9] = "Cisco",
        [11] = "HP / HPE",
        [343] = "Intel",
        [674] = "Dell",
        [2011] = "Huawei",
        [4337] = "AMI (American Megatrends)",
        [7244] = "Quanta",
        [10876] = "Supermicro",
        [19046] = "Lenovo",
        // 实测网络中由 Supermicro 主板一致上报的经验值
        [21317] = "Supermicro",
        [42297] = "Wiwynn",
        [47488] = "Supermicro",
    };

    private static string ResolveOem(int oemId) =>
        OemIds.TryGetValue(oemId, out var name) ? name : (oemId != 0 ? $"IANA-{oemId}" : "");

    private static int Bcd(int value) => ((value >> 4) * 10) + (value & 0x0F);

    public static IpmiInfo? ParseChannelAuthCap(ReadOnlySpan<byte> data)
    {
        if (data.Length < 21 || data[0] != 0x06 || data[3] != 0x07)
            return null;

        int payloadLen = data[13];
        ReadOnlySpan<byte> body = payloadLen > 0 && 14 + payloadLen <= data.Length
            ? data.Slice(14, payloadLen)
            : data[14..];
        if (body.Length < 7)
            body = data[14..];
        if (body.Length < 7 || body[5] != 0x38)
            return null;

        int completion = body[6];
        if (completion != 0x00)
        {
            return new IpmiInfo
            {
                Ipmi = true,
                CompletionCode = completion,
                Note = "IPMI 应答但命令未成功",
            };
        }

        ReadOnlySpan<byte> payload = body[7..];
        if (payload.Length < 8)
            return new IpmiInfo { Ipmi = true, CompletionCode = 0 };

        byte authSupport = payload[1];
        byte authStatus = payload[2];
        byte extCap = payload[3];
        int oemId = payload[4] | (payload[5] << 8) | (payload[6] << 16);

        var versions = new List<string>();
        if ((authSupport & 0x80) != 0)
        {
            if ((extCap & 0x01) != 0) versions.Add("1.5");
            if ((extCap & 0x02) != 0) versions.Add("2.0");
        }
        if (versions.Count == 0)
            versions.Add("1.5");

        var authTypes = new List<string>();
        if ((authSupport & 0x01) != 0) authTypes.Add("none");
        if ((authSupport & 0x02) != 0) authTypes.Add("MD2");
        if ((authSupport & 0x04) != 0) authTypes.Add("MD5");
        if ((authSupport & 0x10) != 0) authTypes.Add("password");
        if ((authSupport & 0x20) != 0) authTypes.Add("OEM");

        return new IpmiInfo
        {
            Ipmi = true,
            CompletionCode = 0,
            Channel = payload[0] & 0x0F,
            Versions = versions,
            AuthTypes = authTypes,
            AnonymousLogin = (authStatus & 0x01) != 0,
            NullUsernames = (authStatus & 0x02) != 0,
            NonNullUsernames = (authStatus & 0x04) != 0,
            KgStatusDefault = (authStatus & 0x20) == 0,
            OemId = oemId,
            OemVendor = ResolveOem(oemId),
        };
    }

    public static AsfPongInfo? ParseAsfPong(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12 || data[0] != 0x06 || data[3] != 0x06)
            return null;
        if (data[4] != 0x00 || data[5] != 0x00 || data[6] != 0x11 || data[7] != 0xBE || data[8] != 0x40)
            return null;

        if (data.Length >= 22)
        {
            uint iana = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(12, 4));
            bool ipmiSup = (data[20] & 0x80) != 0;
            return new AsfPongInfo { AsfPong = true, OemIana = iana, IpmiSupported = ipmiSup };
        }
        return new AsfPongInfo { AsfPong = true };
    }

    /// <summary>解析 Get Device ID (cmd 0x01) 应答（对齐 IPMI 2.0 Table 20-2 规范）。</summary>
    public static DeviceIdInfo? ParseDeviceId(ReadOnlySpan<byte> data)
    {
        if (data.Length < 21 || data[0] != 0x06 || data[3] != 0x07)
            return null;

        int payloadLen = data[13];
        ReadOnlySpan<byte> body = payloadLen > 0 && 14 + payloadLen <= data.Length
            ? data.Slice(14, payloadLen)
            : data[14..];
        if (body.Length < 7)
            body = data[14..];
        if (body.Length < 7 || body[5] != 0x01)
            return null;

        int completion = body[6];
        if (completion != 0x00)
        {
            return new DeviceIdInfo
            {
                Ipmi = true,
                CompletionCode = completion,
                Note = "Get Device ID 被拒绝",
            };
        }

        ReadOnlySpan<byte> payload = body[7..];
        if (payload.Length < 11)
        {
            return new DeviceIdInfo
            {
                Ipmi = true,
                CompletionCode = 0,
                Note = "Get Device ID 应答不完整",
            };
        }

        int fwMajor = Bcd(payload[3]);
        int fwMinor = Bcd(payload[2] & 0x7F);
        bool available = (payload[2] & 0x80) == 0;

        byte ipmiVer = payload[4];
        string verStr = ipmiVer == 0x00 ? "" : $"{ipmiVer & 0x0F}.{ipmiVer >> 4}";

        int manufacturer = payload[6] | (payload[7] << 8) | (payload[8] << 16);
        int productId = payload[9] | (payload[10] << 8);

        return new DeviceIdInfo
        {
            Ipmi = true,
            CompletionCode = 0,
            DeviceId = payload[0],
            Firmware = $"{fwMajor}.{fwMinor:D2}",
            IpmiVersion = verStr,
            ManufacturerId = manufacturer,
            Manufacturer = ResolveOem(manufacturer),
            ProductId = productId,
            Available = available,
        };
    }
}
