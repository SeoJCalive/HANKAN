using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace HANKAN.Web;

public static class PasswordHashing
{
    private const string Prefix = "$argon2id$v=19$m=19456,t=2,p=1$";

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Derive(password, salt);
        try { return Prefix + Convert.ToBase64String(salt).TrimEnd('=') + "$" + Convert.ToBase64String(hash).TrimEnd('='); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    public static PasswordVerificationResult VerifyPassword(string hashedPassword, string password)
    {
        if (hashedPassword.Length != Prefix.Length + 22 + 1 + 43 ||
            !hashedPassword.StartsWith(Prefix, StringComparison.Ordinal))
            return PasswordVerificationResult.Failed;
        var parts = hashedPassword[Prefix.Length..].Split('$');
        if (parts.Length != 2 || parts[0].Length != 22 || parts[1].Length != 43)
            return PasswordVerificationResult.Failed;
        Span<byte> salt = stackalloc byte[16];
        Span<byte> expected = stackalloc byte[32];
        if (!Convert.TryFromBase64String(parts[0] + "==", salt, out var saltLength) || saltLength != 16 ||
            !Convert.TryFromBase64String(parts[1] + "=", expected, out var hashLength) || hashLength != 32 ||
            Convert.ToBase64String(salt).TrimEnd('=') != parts[0] ||
            Convert.ToBase64String(expected).TrimEnd('=') != parts[1])
            return PasswordVerificationResult.Failed;
        var supplied = Derive(password, salt.ToArray());
        try
        {
            return CryptographicOperations.FixedTimeEquals(supplied, expected)
                ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
        finally { CryptographicOperations.ZeroMemory(supplied); }
    }

    public static PasswordVerificationResult VerifySharePassword(byte[] hashedPassword, byte[]? salt, string password)
    {
        if (salt is null || hashedPassword.AsSpan().StartsWith("$argon2"u8))
            return salt is null
                ? VerifyPassword(Encoding.UTF8.GetString(hashedPassword), password)
                : PasswordVerificationResult.Failed;
        if (hashedPassword.Length != 32 || salt.Length != 16) return PasswordVerificationResult.Failed;
        var supplied = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
        try
        {
            return CryptographicOperations.FixedTimeEquals(supplied, hashedPassword)
                ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Failed;
        }
        finally { CryptographicOperations.ZeroMemory(supplied); }
    }

    private static byte[] Derive(string password, byte[] salt)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(bytes)
            {
                Salt = salt,
                MemorySize = 19456,
                Iterations = 2,
                DegreeOfParallelism = 1
            };
            return argon2.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
