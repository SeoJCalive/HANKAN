using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web.Pages.Admin;

public sealed class UsersModel(AppDbContext db, AccessStore access, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    [BindProperty] public string TargetId { get; set; } = "";
    [BindProperty] public string Action { get; set; } = "";
    [BindProperty] public string? Role { get; set; }
    public List<AppUser> Accounts { get; private set; } = [];
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        Accounts = await db.Users.AsNoTracking().Where(user => !user.IsAdmin)
            .OrderBy(user => user.Email).ToListAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var changed = await access.ChangeAsync(User, TargetId ?? "", Action ?? "", Role);
        await audit.RecordAsync(User, changed ? "access." + Action : "access.change", changed ? TargetId : null,
            changed ? "success" : "denied");
        if (!changed)
            Error = "처리할 수 없습니다. 사용자 상태를 새로 확인하세요.";
        await OnGetAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync();
        return RedirectToPage("/Login");
    }
}
