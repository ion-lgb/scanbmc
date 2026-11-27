using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ScanBMC.Core;

public static class Exporters
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static string ToJson(IEnumerable<HostResult> results, bool showAll, object meta)
    {
        var rows = results.Where(r => showAll || r.IsBmc).Select(r => new
        {
            r.Ip,
            r.Confidence,
            r.Vendor,
            OpenPorts = r.OpenPortsString(),
            r.Ipmi,
            r.AsfPong,
            r.DeviceId,
            r.Redfish,
            r.Web,
            r.Evidence,
            Ports = r.Ports.OrderBy(p => p.Port).ToList(),
        }).ToList();

        return JsonSerializer.Serialize(new { meta, results = rows }, JsonOptions);
    }

    public static string ToCsv(IEnumerable<HostResult> results, bool showAll)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ip,confidence,vendor,open_ports,ipmi_versions,warnings,evidence");
        foreach (var r in results)
        {
            if (!showAll && !r.IsBmc) continue;
            string ipmiVer = r.Ipmi is not null ? string.Join("/", r.Ipmi.Versions) : "";
            string warns = string.Join(" | ", r.Warnings);
            string ev = string.Join(" | ", r.Evidence);
            sb.AppendLine(string.Join(",",
                CsvEscape(r.Ip),
                CsvEscape(r.Confidence),
                CsvEscape(r.Vendor),
                CsvEscape(r.OpenPortsString()),
                CsvEscape(ipmiVer),
                CsvEscape(warns),
                CsvEscape(ev)));
        }
        return sb.ToString();
    }

    private static string CsvEscape(string s)
    {
        // 防范 Excel 公式注入（CSV Injection）：对来自远端的不可信文本做前置单引号转义
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            s = "'" + s;
        if (s.Contains('"') || s.Contains(',') || s.Contains('\n') || s.Contains('\r'))
            return $"\"{s.Replace("\"", "\"\"")}\"";
        return s;
    }
}
