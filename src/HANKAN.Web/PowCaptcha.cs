using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace HANKAN.Web;

public sealed class PowCaptcha(TimeProvider clock)
{
    private readonly object sync = new();
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<(string Scope, string Kind, string Key), (int Count, DateTimeOffset Expires)> failures = [];
    private readonly Dictionary<string, long> used = [];

    public bool IsRequired(string scope, string? subject, string? ip)
    {
        ValidateScope(scope);
        lock (sync)
        {
            Cleanup();
            return subject is { Length: > 0 } && failures.GetValueOrDefault((scope, "subject", subject)).Count >= 2 ||
                failures.GetValueOrDefault((scope, "ip", NormalizeIp(ip))).Count >= 2;
        }
    }

    public void RecordFailure(string scope, string? subject, string? ip)
    {
        ValidateScope(scope);
        lock (sync)
        {
            Cleanup();
            if (!string.IsNullOrEmpty(subject)) Increment((scope, "subject", subject));
            Increment((scope, "ip", NormalizeIp(ip)));
        }
    }

    public void Reset(string scope, string? subject, string? ip)
    {
        ValidateScope(scope);
        lock (sync)
        {
            Cleanup();
            if (!string.IsNullOrEmpty(subject)) failures.Remove((scope, "subject", subject));
            failures.Remove((scope, "ip", NormalizeIp(ip)));
        }
    }

    public string Issue(string scope, string target, string? ip)
    {
        ValidateScope(scope);
        var issued = clock.GetUtcNow().ToUnixTimeSeconds();
        var payload = string.Join(".", "v1", issued.ToString(CultureInfo.InvariantCulture),
            (issued + 120).ToString(CultureInfo.InvariantCulture), "16",
            Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), Binding(scope, target, ip));
        return payload + "." + Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payload)));
    }

    public bool VerifyAndConsume(string scope, string target, string? ip, string? challenge, string? solution)
    {
        ValidateScope(scope);
        if (challenge is not { Length: > 0 and <= 512 } || solution is not { Length: > 0 and <= 10 } ||
            !Decimal(solution) || !uint.TryParse(solution, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            return false;
        var fields = challenge.Split('.');
        if (fields.Length != 7 || fields[0] != "v1" || fields[3] != "16" ||
            !Decimal(fields[1]) || !Decimal(fields[2]) ||
            !long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var issued) ||
            !long.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var expires) ||
            expires < 120 || issued != expires - 120 ||
            !Hex(fields[4], 32) || !Hex(fields[5], 64) || !Hex(fields[6], 64))
            return false;
        lock (sync)
        {
            Cleanup();
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (issued > now || now >= expires ||
                !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(fields[5]),
                    Convert.FromHexString(Binding(scope, target, ip)))) return false;
            var payload = challenge[..challenge.LastIndexOf('.')];
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(fields[6]),
                HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payload)))) return false;
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(challenge + ":" + solution));
            if (hash[0] != 0 || hash[1] != 0 || !used.TryAdd(fields[4], expires)) return false;
            return true;
        }
    }

    private static void ValidateScope(string scope)
    {
        if (scope is not ("login" or "share")) throw new ArgumentException("Invalid CAPTCHA scope.", nameof(scope));
    }

    private static string NormalizeIp(string? value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return "unknown";
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    private string Binding(string scope, string target, string? ip)
    {
        if (scope == "login") target = "";
        var address = NormalizeIp(ip);
        var value = $"{scope.Length}:{scope}{target.Length}:{target}{address.Length}:{address}";
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
    }

    private static bool Decimal(string value) => value.Length > 0 &&
        (value.Length == 1 || value[0] != '0') && value.All(c => c is >= '0' and <= '9');

    private static bool Hex(string value, int length) => value.Length == length && value.All(Uri.IsHexDigit);

    private void Increment((string Scope, string Kind, string Key) id)
    {
        failures[id] = failures.TryGetValue(id, out var value)
            ? (Math.Min(2, value.Count + 1), value.Expires)
            : (1, clock.GetUtcNow().AddMinutes(15));
    }

    private void Cleanup()
    {
        var now = clock.GetUtcNow();
        foreach (var id in failures.Where(item => item.Value.Expires <= now).Select(item => item.Key).ToArray())
            failures.Remove(id);
        foreach (var nonce in used.Where(item => item.Value <= now.ToUnixTimeSeconds()).Select(item => item.Key).ToArray())
            used.Remove(nonce);
    }
}
