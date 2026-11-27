using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ScanBMC.Core;

public static partial class HttpProbe
{
    [GeneratedRegex(@"HTTP/\d\.\d\s+(\d{3})")]
    private static partial Regex StatusLineRegex();

    [GeneratedRegex(@"<title[^>]*>(.{0,200}?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TitleRegex();

    [GeneratedRegex(@"\s+")]
    private static partial Regex MultiSpaceRegex();

    public sealed class RawHttpResponse
    {
        public int Status { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string Title { get; init; } = "";
        public string Body { get; init; } = "";
        public CertInfo? Cert { get; init; }
    }

    public static byte[] Dechunk(byte[] body)
    {
        using var ms = new MemoryStream();
        int pos = 0;
        while (pos < body.Length)
        {
            int crlf = IndexOfCrlf(body, pos);
            if (crlf < 0) break;

            string line = Encoding.ASCII.GetString(body, pos, crlf - pos);
            int semi = line.IndexOf(';');
            if (semi >= 0) line = line[..semi];
            if (!int.TryParse(line.Trim(), System.Globalization.NumberStyles.HexNumber, null, out int size) || size <= 0)
                break;

            int dataStart = crlf + 2;
            int available = Math.Min(size, body.Length - dataStart);
            if (available > 0)
                ms.Write(body, dataStart, available);

            pos = dataStart + size;
            while (pos < body.Length && (body[pos] == '\r' || body[pos] == '\n'))
                pos++;
        }
        return ms.ToArray();
    }

    private static int IndexOfCrlf(byte[] buf, int start)
    {
        for (int i = start; i + 1 < buf.Length; i++)
        {
            if (buf[i] == '\r' && buf[i + 1] == '\n')
                return i;
        }
        return -1;
    }

    /// <summary>解 chunked + 解压 gzip/deflate（兼容截断响应，尽量解出已收到的前半段文本）。</summary>
    public static byte[] DecodeBody(IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        if (headers.TryGetValue("transfer-encoding", out var te) &&
            te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            body = Dechunk(body);
        }

        if (!headers.TryGetValue("content-encoding", out var ce) ||
            string.IsNullOrWhiteSpace(ce) ||
            body.Length == 0)
        {
            return body;
        }

        if (ce.Contains("gzip", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = TryDecompressPartial(body, s => new GZipStream(s, CompressionMode.Decompress));
            if (decoded.Length > 0) return decoded;
        }
        else if (ce.Contains("deflate", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = TryDecompressPartial(body, s => new ZLibStream(s, CompressionMode.Decompress));
            if (decoded.Length > 0) return decoded;
            decoded = TryDecompressPartial(body, s => new DeflateStream(s, CompressionMode.Decompress));
            if (decoded.Length > 0) return decoded;
        }

        return body;
    }

    private static byte[] TryDecompressPartial(byte[] data, Func<Stream, Stream> wrap)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        try
        {
            using var ds = wrap(input);
            byte[] buf = new byte[1024];
            int n;
            while ((n = ds.Read(buf, 0, buf.Length)) > 0)
            {
                output.Write(buf, 0, n);
                if (output.Length >= 32768) break;
            }
        }
        catch
        {
            // 截断的 gzip/deflate 流末尾会抛异常，保留已解压出的部分
        }
        return output.ToArray();
    }

    public static CertInfo? ExtractCertInfo(X509Certificate? remoteCert)
    {
        if (remoteCert is null) return null;
        try
        {
            using var cert2 = remoteCert as X509Certificate2 ?? new X509Certificate2(remoteCert);
            DateTime notAfterUtc = cert2.NotAfter.ToUniversalTime();
            int daysLeft = (int)Math.Floor((notAfterUtc - DateTime.UtcNow).TotalDays);
            string cn = cert2.GetNameInfo(X509NameType.SimpleName, false) ?? "";
            string issuer = cert2.GetNameInfo(X509NameType.SimpleName, true) ?? cert2.Issuer;
            return new CertInfo
            {
                SubjectCn = cn.Trim(),
                Issuer = issuer.Trim(),
                NotAfter = notAfterUtc.ToString("yyyy-MM-dd"),
                DaysLeft = daysLeft,
                Expired = daysLeft < 0,
            };
        }
        catch
        {
            return null;
        }
    }

    public static async Task<RawHttpResponse?> SendRequestAsync(
        string ip,
        int port,
        bool tls,
        string path,
        TimeSpan timeout,
        CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);

        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            await tcp.ConnectAsync(ip, port, linked.Token).ConfigureAwait(false);
            Stream stream = tcp.GetStream();
            CertInfo? certInfo = null;

            if (tls)
            {
                var ssl = new SslStream(stream, false, (_, cert, _, _) =>
                {
                    certInfo = ExtractCertInfo(cert);
                    return true;
                });
                try
                {
#pragma warning disable SYSLIB0039 // 兼容老旧 BMC 的 TLS 1.0/1.1
                    var sslOpts = new SslClientAuthenticationOptions
                    {
                        TargetHost = "",
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 | SslProtocols.Tls11 | SslProtocols.Tls,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    };
#pragma warning restore SYSLIB0039
                    await ssl.AuthenticateAsClientAsync(sslOpts, linked.Token).ConfigureAwait(false);
                    certInfo ??= ExtractCertInfo(ssl.RemoteCertificate);
                    stream = ssl;
                }
                catch
                {
                    await ssl.DisposeAsync().ConfigureAwait(false);
                    return null;
                }
            }

            string host = ip.Contains(':') ? $"[{ip}]" : ip;
            byte[] reqBytes = Encoding.ASCII.GetBytes(
                $"GET {path} HTTP/1.1\r\n" +
                $"Host: {host}\r\n" +
                $"User-Agent: scanbmc/{ScanConstants.Version}\r\n" +
                "Accept: */*\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Connection: close\r\n\r\n");

            await stream.WriteAsync(reqBytes, linked.Token).ConfigureAwait(false);
            await stream.FlushAsync(linked.Token).ConfigureAwait(false);

            using var ms = new MemoryStream();
            byte[] buffer = new byte[4096];
            while (ms.Length < 16384)
            {
                int read;
                try
                {
                    read = await stream.ReadAsync(buffer, linked.Token).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }
                if (read <= 0) break;
                ms.Write(buffer, 0, read);
            }

            byte[] raw = ms.ToArray();
            if (raw.Length == 0) return null;

            return ParseRawHttp(raw, certInfo);
        }
        catch
        {
            return null;
        }
    }

    public static RawHttpResponse ParseRawHttp(byte[] raw, CertInfo? certInfo)
    {
        int sepIdx = -1;
        for (int i = 0; i + 3 < raw.Length; i++)
        {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
            {
                sepIdx = i;
                break;
            }
        }

        byte[] headBytes = sepIdx >= 0 ? raw[..sepIdx] : raw;
        byte[] bodyBytes = sepIdx >= 0 ? raw[(sepIdx + 4)..] : Array.Empty<byte>();

        string headText = Encoding.Latin1.GetString(headBytes);
        string[] lines = headText.Split("\r\n");
        string statusLine = lines.Length > 0 ? lines[0] : "";

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');
            if (colon <= 0) continue;
            string k = lines[i][..colon].Trim().ToLowerInvariant();
            string v = lines[i][(colon + 1)..].Trim();
            headers[k] = headers.TryGetValue(k, out var existing) ? $"{existing}; {v}" : v;
        }

        int status = 0;
        var sm = StatusLineRegex().Match(statusLine);
        if (sm.Success)
            int.TryParse(sm.Groups[1].Value, out status);

        byte[] decodedBody = DecodeBody(headers, bodyBytes);
        string bodyStr = Encoding.UTF8.GetString(decodedBody, 0, Math.Min(decodedBody.Length, 8192));

        string title = "";
        var tm = TitleRegex().Match(bodyStr);
        if (tm.Success)
            title = MultiSpaceRegex().Replace(tm.Groups[1].Value, " ").Trim();

        return new RawHttpResponse
        {
            Status = status,
            Headers = headers,
            Title = title,
            Body = bodyStr,
            Cert = certInfo,
        };
    }

    public static async Task<WebInfo?> ProbeWebAsync(
        string ip, int port, bool tls, TimeSpan timeout, int retries, CancellationToken ct)
    {
        RawHttpResponse? resp = null;
        for (int i = 0; i <= retries; i++)
        {
            resp = await SendRequestAsync(ip, port, tls, "/", timeout, ct).ConfigureAwait(false);
            if (resp is not null) break;
        }
        if (resp is null) return null;

        resp.Headers.TryGetValue("server", out var server);
        resp.Headers.TryGetValue("location", out var location);
        resp.Headers.TryGetValue("www-authenticate", out var realm);
        resp.Headers.TryGetValue("set-cookie", out var cookie);

        string bodySnippet = resp.Body.Length > 4096 ? resp.Body[..4096] : resp.Body;
        string haystack = string.Join(" ", server ?? "", resp.Title, location ?? "", realm ?? "", cookie ?? "", bodySnippet);

        return new WebInfo
        {
            Port = port,
            Scheme = tls ? "https" : "http",
            Status = resp.Status,
            Server = server ?? "",
            Title = resp.Title,
            Location = location ?? "",
            Realm = realm ?? "",
            Cert = resp.Cert,
            Haystack = haystack,
        };
    }

    public static async Task<RedfishInfo?> ProbeRedfishAsync(
        string ip, int port, bool tls, TimeSpan timeout, int retries, CancellationToken ct)
    {
        RawHttpResponse? resp = null;
        for (int i = 0; i <= retries; i++)
        {
            resp = await SendRequestAsync(ip, port, tls, "/redfish/v1/", timeout, ct).ConfigureAwait(false);
            if (resp is not null) break;
        }
        if (resp is null || resp.Status is not (200 or 401 or 403))
            return null;

        resp.Headers.TryGetValue("content-type", out var ctype);
        string body = resp.Body.Trim();
        bool looksJson = (ctype?.Contains("json", StringComparison.OrdinalIgnoreCase) ?? false) || body.StartsWith('{');
        if (!looksJson) return null;

        resp.Headers.TryGetValue("server", out var server);
        string vendor = "";
        string product = "";
        string version = "";
        var oemKeys = new List<string>();

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("Vendor", out var vEl) && vEl.ValueKind == JsonValueKind.String)
                    vendor = Classifier.CleanValue(vEl.GetString());
                if (doc.RootElement.TryGetProperty("Product", out var pEl) && pEl.ValueKind == JsonValueKind.String)
                    product = Classifier.CleanValue(pEl.GetString());
                if (doc.RootElement.TryGetProperty("RedfishVersion", out var rvEl) && rvEl.ValueKind == JsonValueKind.String)
                    version = rvEl.GetString() ?? "";
                if (doc.RootElement.TryGetProperty("Oem", out var oemEl) && oemEl.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in oemEl.EnumerateObject().Take(5))
                    {
                        if (!string.IsNullOrEmpty(Classifier.CleanValue(prop.Name)))
                            oemKeys.Add(prop.Name);
                    }
                }
            }
        }
        catch
        {
            // 截断或非标准 JSON 仍可凭状态码与 Server 头确认 Redfish
        }

        string bodySnippet = body.Length > 4096 ? body[..4096] : body;
        return new RedfishInfo
        {
            Port = port,
            Status = resp.Status,
            Server = server ?? "",
            Vendor = vendor,
            Product = product,
            Version = version,
            OemKeys = oemKeys,
            Cert = resp.Cert,
            Haystack = $"{server ?? ""} {bodySnippet}",
        };
    }
}
