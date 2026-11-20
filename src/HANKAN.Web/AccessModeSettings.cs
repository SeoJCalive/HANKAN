using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HANKAN.Web;

public sealed record AccessModeSettings
{
    public int Version { get; init; }
    public string Mode { get; init; } = "";
    public string[] TrustedProxyIps { get; init; } = [];
    public DirectAccessSettings? Direct { get; init; }
    public TunnelAccessSettings? Tunnel { get; init; }

    public static AccessModeSettings Local => new() { Version = 1, Mode = "local" };

    public static AccessModeSettings Load(string dataDirectory, string webRoot, int localPort)
    {
        var path = Path.Combine(dataDirectory, "access-mode.json");
        AccessSecrets.CheckPath(path, webRoot);
        if (!File.Exists(path)) return Local;
        AccessSecrets.CheckPermissions(path, allowAdministrators: true);
        var marker = Path.Combine(dataDirectory, "access-mode.initialized");
        AccessSecrets.CheckPath(marker, webRoot);
        if (!File.Exists(marker)) File.WriteAllText(marker, "v1");
        return Parse(File.ReadAllText(path), dataDirectory, webRoot, localPort);
    }

    public static AccessModeSettings Parse(string json, string dataDirectory, string webRoot, int localPort)
    {
        using var document = JsonDocument.Parse(json);
        CheckDuplicates(document.RootElement);
        var settings = document.Deserialize<AccessModeSettings>(new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        }) ?? throw new InvalidDataException("access-mode.json");
        if (settings.Version != 1 || settings.Mode is not ("local" or "direct" or "tunnel") ||
            settings.TrustedProxyIps is null)
            throw new InvalidDataException("access-mode.json");
        foreach (var ip in settings.TrustedProxyIps)
            if (!IPAddress.TryParse(ip, out _)) throw new InvalidDataException("trustedProxyIps");
        if (settings.Mode == "direct")
        {
            var direct = settings.Direct ?? throw new InvalidDataException("direct");
            if (!IPAddress.TryParse(direct.Address, out _) ||
                direct.Port is not (>= 1024 and <= 65535) || direct.Port == localPort ||
                direct.Transport is not ("https" or "http"))
                throw new InvalidDataException("direct endpoint");
            if (direct.Transport == "http")
            {
                if (!direct.AllowHttp || direct.RedirectHttpPort is not null ||
                    direct.PfxPath is not null || direct.PfxPasswordFile is not null)
                    throw new InvalidDataException("direct HTTP");
            }
            else
            {
                if (direct.AllowHttp || string.IsNullOrWhiteSpace(direct.PfxPath) ||
                    !Path.IsPathFullyQualified(direct.PfxPath) ||
                    direct.RedirectHttpPort is not null &&
                    (direct.RedirectHttpPort is not (>= 1024 and <= 65535) ||
                     direct.RedirectHttpPort == localPort || direct.RedirectHttpPort == direct.Port))
                    throw new InvalidDataException("direct HTTPS");
                AccessSecrets.CheckPath(direct.PfxPath, webRoot);
                AccessSecrets.SecretPath(dataDirectory, direct.PfxPasswordFile, webRoot);
            }
        }
        if (settings.Mode == "tunnel")
        {
            // The connector is on this PC. An empty list never becomes trust-all.
            if (!settings.TrustedProxyIps.Select(ip => Normalize(IPAddress.Parse(ip)))
                    .Contains(IPAddress.Loopback) ||
                settings.TrustedProxyIps.Any(ip => !Normalize(IPAddress.Parse(ip)).Equals(IPAddress.Loopback)))
                throw new InvalidDataException("tunnel trustedProxyIps");
            if (settings.Tunnel?.TokenFile is { } token)
            {
                AccessSecrets.SecretPath(dataDirectory, token, webRoot);
                if (!Uri.TryCreate(settings.Tunnel.PublicOrigin, UriKind.Absolute, out var origin) ||
                    origin.Scheme != "https" || origin.HostNameType != UriHostNameType.Dns ||
                    origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0 ||
                    origin.UserInfo.Length != 0)
                    throw new InvalidDataException("tunnel publicOrigin");
            }
            else if (settings.Tunnel?.PublicOrigin is not null)
                throw new InvalidDataException("Quick publicOrigin");
        }
        return settings;
    }

    public static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static void CheckDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate setting");
                CheckDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) CheckDuplicates(item);
    }
}

public sealed record DirectAccessSettings
{
    public string Address { get; init; } = "";
    public int Port { get; init; }
    public string Transport { get; init; } = "";
    public bool AllowHttp { get; init; }
    public string? PfxPath { get; init; }
    public string? PfxPasswordFile { get; init; }
    public int? RedirectHttpPort { get; init; }
}

public sealed record TunnelAccessSettings
{
    public string? TokenFile { get; init; }
    public string? PublicOrigin { get; init; }
}
