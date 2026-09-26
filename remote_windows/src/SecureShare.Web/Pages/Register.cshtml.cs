using System.Net.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureShare.Web.Pages;

public sealed class RegisterModel(SetupStore setup, UserManager<AppUser> users, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    public string? Error { get; private set; }

    public IActionResult OnGet() => setup.State switch
    {
        SetupState.Unconfigured => RedirectToPage("/Setup"),
        SetupState.RecoveryRequired => RedirectToPage("/Recovery"),
        _ when User.Identity?.IsAuthenticated == true => RedirectToPage("/Index"),
        _ => Page()
    };

    public async Task<IActionResult> OnPostAsync()
    {
        if (setup.State != SetupState.Ready || User.Identity?.IsAuthenticated == true) return OnGet();
        Email = (Email ?? "").Trim();
        if (Email.Length > 254 || !MailAddress.TryCreate(Email, out var address) || address.Address != Email ||
            Password is null || Password.Length is < 12 or > 128)
        {
            Error = "올바른 이메일과 12~128자의 비밀번호를 입력하세요.";
            return Page();
        }
        var result = await users.CreateAsync(new AppUser { UserName = Email, Email = Email }, Password);
        if (!result.Succeeded)
        {
            Error = "계정을 만들 수 없습니다. 이메일과 비밀번호를 확인하세요.";
            return Page();
        }
        var account = await users.FindByEmailAsync(Email);
        if (account is null) return RedirectToPage("/Login");
        await signIn.SignInAsync(account, isPersistent: false);
        await audit.RecordAsync(account.Id, "auth.register", account.Id, "success");
        return RedirectToPage("/Access");
    }
}
