using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace HANKAN.Web;

public sealed class Argon2idPasswordHasher(IOptions<PasswordHasherOptions> options) : IPasswordHasher<AppUser>
{
    private readonly PasswordHasher<AppUser> legacy = new(options);

    public string HashPassword(AppUser user, string password) => PasswordHashing.HashPassword(password);

    public PasswordVerificationResult VerifyHashedPassword(AppUser user, string hashedPassword, string providedPassword)
    {
        if (hashedPassword.Length == 0) return PasswordVerificationResult.Failed;
        if (hashedPassword.StartsWith('$')) return PasswordHashing.VerifyPassword(hashedPassword, providedPassword);
        try
        {
            return legacy.VerifyHashedPassword(user, hashedPassword, providedPassword) switch
            {
                PasswordVerificationResult.Failed => PasswordVerificationResult.Failed,
                PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded =>
                    PasswordVerificationResult.SuccessRehashNeeded,
                _ => throw new InvalidOperationException("Unknown password verification result.")
            };
        }
        catch (FormatException) { return PasswordVerificationResult.Failed; }
    }
}
