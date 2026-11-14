using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class LoginModel(SetupStore store, UserManager<AppUser> users, SignInManager<AppUser> signIn, AuditStore audit, PowCaptcha pow) : PageModel
{
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    [BindProperty(Name = "Challenge")] public string? PowChallenge { get; set; }
    [BindProperty] public string? Solution { get; set; }
    public bool CaptchaRequired { get; private set; }
    public string? Error { get; private set; }

    public IActionResult OnGet()
    {
        if (store.State == SetupState.Unconfigured) return RedirectToPage("/Setup");
        if (store.State == SetupState.RecoveryRequired) return RedirectToPage("/Recovery");
        if (User.Identity?.IsAuthenticated == true) return RedirectToPage("/Index");
        PrepareCaptcha(null);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (store.State != SetupState.Ready) return OnGet();
        var email = (Email ?? "").Trim();
        var subject = Email is { Length: <= 254 } && email.Length > 0 ? users.NormalizeEmail(email) : null;
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var user = subject is null ? null : await users.FindByEmailAsync(email);
        var wasLocked = user is not null && await users.IsLockedOutAsync(user);
        if (!wasLocked && pow.IsRequired("login", subject, ip) &&
            !pow.VerifyAndConsume("login", "", ip, PowChallenge, Solution))
        {
            await audit.RecordAsync("anonymous", "auth.login", user?.Id, "denied");
            Error = "추가 확인을 완료한 뒤 다시 시도하세요. 만료되거나 사용한 확인은 다시 풀어야 합니다.";
            PrepareCaptcha(subject);
            return Page();
        }
        var result = wasLocked ? Microsoft.AspNetCore.Identity.SignInResult.LockedOut : user is not null
            ? await signIn.PasswordSignInAsync(user, Password ?? "", false, lockoutOnFailure: true)
            : Microsoft.AspNetCore.Identity.SignInResult.Failed;
        if (!result.Succeeded)
        {
            if (!wasLocked && !result.IsNotAllowed && !result.RequiresTwoFactor)
                pow.RecordFailure("login", subject, ip);
            await audit.RecordAsync("anonymous", result.IsLockedOut ? "auth.login.locked" : "auth.login", user?.Id, result.IsLockedOut ? "denied" : "failure");
            Error = "이메일 또는 비밀번호가 올바르지 않습니다.";
            PrepareCaptcha(subject);
            return Page();
        }
        pow.Reset("login", subject, ip);
        await audit.RecordAsync(user!.Id, "auth.login", user.Id, "success");
        return RedirectToPage("/Index");
    }

    private void PrepareCaptcha(string? subject)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        CaptchaRequired = pow.IsRequired("login", subject, ip);
        PowChallenge = CaptchaRequired ? pow.Issue("login", "", ip) : null;
        Solution = null;
    }
}
