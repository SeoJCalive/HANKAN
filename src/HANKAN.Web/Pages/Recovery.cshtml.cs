using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class RecoveryModel(SetupStore store) : PageModel
{
    public IActionResult OnGet() => store.State switch
    {
        SetupState.Ready => RedirectToPage("/Index"),
        SetupState.Unconfigured => RedirectToPage("/Setup"),
        _ => Page()
    };
}
