using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureShare.Web.Pages;

public sealed class AccessModel(AccessStore access, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    [BindProperty] public string Role { get; set; } = "VIEWER";
    public AccountAccess? Current { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        Current = await access.CurrentAsync(User);
        if (Current is null) return RedirectToPage("/Login");
        if (Current.IsAdmin) return RedirectToPage("/Index");
        if (Current.State is "viewer" or "owner") return RedirectToPage("/Files");
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var accepted = await access.RequestAsync(User, Role ?? "");
        await audit.RecordAsync(User, "access.request", accepted ? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value : null,
            accepted ? "success" : "denied");
        if (!accepted)
            Error = "신청할 수 없습니다. 현재 상태와 선택한 역할을 확인하세요.";
        return await OnGetAsync();
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await audit.RecordAsync(User, "auth.logout", null, "success");
        await signIn.SignOutAsync();
        return RedirectToPage("/Login");
    }
}
