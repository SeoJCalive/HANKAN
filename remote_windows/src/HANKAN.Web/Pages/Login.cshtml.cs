using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class LoginModel(SetupStore store, UserManager<AppUser> users, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    public string? Error { get; private set; }

    public IActionResult OnGet() => store.State switch
    {
        SetupState.Unconfigured => RedirectToPage("/Setup"),
        SetupState.RecoveryRequired => RedirectToPage("/Recovery"),
        _ when User.Identity?.IsAuthenticated == true => RedirectToPage("/Index"),
        _ => Page()
    };

    public async Task<IActionResult> OnPostAsync()
    {
        if (store.State != SetupState.Ready) return OnGet();
        var user = await users.FindByEmailAsync((Email ?? "").Trim());
        var result = user is not null
            ? await signIn.PasswordSignInAsync(user, Password ?? "", false, lockoutOnFailure: true)
            : Microsoft.AspNetCore.Identity.SignInResult.Failed;
        if (!result.Succeeded)
        {
            await audit.RecordAsync("anonymous", result.IsLockedOut ? "auth.login.locked" : "auth.login", user?.Id, result.IsLockedOut ? "denied" : "failure");
            Error = "이메일 또는 비밀번호가 올바르지 않습니다.";
            return Page();
        }
        await audit.RecordAsync(user!.Id, "auth.login", user.Id, "success");
        return RedirectToPage("/Index");
    }
}
