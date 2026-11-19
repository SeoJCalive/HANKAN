using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class IndexModel(SetupStore store, SignInManager<AppUser> signIn, AccessStore access) : PageModel
{
    public async Task<IActionResult> OnGetAsync()
    {
        if (store.State == SetupState.Unconfigured) return RedirectToPage("/Setup");
        if (store.State == SetupState.RecoveryRequired) return RedirectToPage("/Recovery");
        if (User.Identity?.IsAuthenticated != true)
            return RedirectToPage("/Public");
        var current = await access.CurrentAsync(User);
        if (current is null) return RedirectToPage("/Login");
        return RedirectToPage(current.IsAdmin || current.State is "viewer" or "owner" ? "/Files" : "/Access");
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync();
        return RedirectToPage("/Login");
    }
}
