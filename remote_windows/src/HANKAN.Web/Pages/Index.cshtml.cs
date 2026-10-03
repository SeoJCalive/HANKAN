using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class IndexModel(SetupStore store, SignInManager<AppUser> signIn, AccessStore access) : PageModel
{
    public string Email { get; private set; } = "";
    public string Folder { get; private set; } = "";
    public long QuotaGiB { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        if (store.State == SetupState.Unconfigured) return RedirectToPage("/Setup");
        if (store.State == SetupState.RecoveryRequired) return RedirectToPage("/Recovery");
        if (User.Identity?.IsAuthenticated != true)
            return RedirectToPage("/Login");
        var current = await access.CurrentAsync(User);
        if (current is null) return RedirectToPage("/Login");
        if (!current.IsAdmin) return RedirectToPage(current.State is "viewer" or "owner" ? "/Files" : "/Access");
        var details = store.Details();
        if (details is null) return RedirectToPage("/Recovery");
        Email = details.Value.Email;
        Folder = details.Value.Folder;
        QuotaGiB = details.Value.QuotaBytes / (1024L * 1024 * 1024);
        return Page();
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync();
        return RedirectToPage("/Login");
    }
}
