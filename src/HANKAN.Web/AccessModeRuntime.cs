using System.Net;

namespace HANKAN.Web;

public sealed class AccessModeRuntime(AccessModeSettings requested, int localPort)
{
    public AccessModeSettings Requested { get; } = requested;
    public int LocalPort { get; } = localPort;
    public string EffectiveMode { get; set; } = "local";
    public string? Failure { get; set; }
    public bool StartupSetupReady { get; set; }
    public bool RestartRequired => !StartupSetupReady && Requested.Mode != "local";
    public bool Applied => Failure is null && Requested.Mode == EffectiveMode;

    public bool IsTrustedPeer(IPAddress? peer) => EffectiveMode != "local" && peer is not null &&
        Requested.TrustedProxyIps.Any(ip =>
            AccessModeSettings.Normalize(IPAddress.Parse(ip)).Equals(AccessModeSettings.Normalize(peer)));

    public static bool HasForwardingHeaders(HttpRequest request) => request.Headers.Keys.Any(name =>
        name.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("CF-", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Forwarded", StringComparison.OrdinalIgnoreCase));

    public bool IsLocalControl(HttpContext context) =>
        context.Connection.RemoteIpAddress is { } peer && IPAddress.IsLoopback(peer) &&
        IPAddress.Loopback.Equals(context.Connection.LocalIpAddress) &&
        context.Connection.LocalPort == LocalPort && !HasForwardingHeaders(context.Request);

    public static bool ValidForwarding(HttpRequest request)
    {
        var ip = request.Headers["CF-Connecting-IP"];
        var proto = request.Headers["X-Forwarded-Proto"];
        return ip.Count == 1 && IPAddress.TryParse(ip[0], out _) &&
            proto.Count == 1 && (string.Equals(proto[0], "https", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(proto[0], "http", StringComparison.OrdinalIgnoreCase));
    }

    public static bool PasswordsAllowed(HttpContext context) =>
        context.Items.TryGetValue("HANKAN.PasswordTransport", out var allowed) && allowed is true;

    public const string HttpsRequired = "비밀번호를 받는 기능은 HTTPS에서만 사용할 수 있습니다. HTTPS 주소로 다시 접속하세요. HTTP는 평문 전송입니다.";
}
