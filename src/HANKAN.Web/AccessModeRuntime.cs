using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HANKAN.Web;

public sealed class AccessModeRuntime(AccessModeSettings requested, int localPort) : IDisposable
{
    public AccessModeSettings Requested { get; } = requested;
    public int LocalPort { get; } = localPort;
    public string EffectiveMode { get; set; } = "local";
    public string? Failure { get; set; }
    public bool StartupSetupReady { get; set; }
    public bool RestartRequired => !StartupSetupReady && Requested.Mode != "local";
    public bool Applied => Failure is null && Requested.Mode == EffectiveMode;
    public X509Certificate2? Certificate { get; private set; }

    public void Apply(SetupState setupState, string dataDirectory, string webRoot, bool forceLocal)
    {
        StartupSetupReady = setupState == SetupState.Ready;
        if (forceLocal) Failure = "터널 시작 실패로 로컬 복귀";
        if (!StartupSetupReady || Failure is not null) return;
        try
        {
            if (Requested is { Mode: "direct", Direct.Transport: "https" })
            {
                var direct = Requested.Direct;
                AccessSecrets.CheckPath(direct.PfxPath!, webRoot);
                AccessSecrets.CheckPermissions(direct.PfxPath!, allowAdministrators: true);
                var password = AccessSecrets.Restore(dataDirectory, direct.PfxPasswordFile!, webRoot);
                try
                {
                    Certificate = X509CertificateLoader.LoadPkcs12FromFile(direct.PfxPath!,
                        Encoding.UTF8.GetString(password), X509KeyStorageFlags.EphemeralKeySet);
                }
                finally { CryptographicOperations.ZeroMemory(password); }
                var now = DateTime.UtcNow;
                if (!Certificate.HasPrivateKey || now < Certificate.NotBefore.ToUniversalTime() ||
                    now >= Certificate.NotAfter.ToUniversalTime())
                    throw new CryptographicException();
            }
            if (Requested is { Mode: "tunnel", Tunnel.TokenFile: { } tokenFile })
            {
                var token = AccessSecrets.Restore(dataDirectory, tokenFile, webRoot);
                try
                {
                    if (string.IsNullOrWhiteSpace(Encoding.UTF8.GetString(token)))
                        throw new CryptographicException();
                }
                finally { CryptographicOperations.ZeroMemory(token); }
            }
            EffectiveMode = Requested.Mode;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            CryptographicException or ArgumentException or PlatformNotSupportedException)
        {
            FallBack("인증서 또는 비밀 파일을 확인할 수 없음");
        }
    }

    public void FallBack(string reason)
    {
        EffectiveMode = "local";
        Failure = reason;
        Certificate?.Dispose();
        Certificate = null;
    }

    public void Dispose() => Certificate?.Dispose();

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
