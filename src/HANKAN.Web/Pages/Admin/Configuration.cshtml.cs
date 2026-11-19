using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages.Admin;

public sealed class ConfigurationModel(SetupStore store) : PageModel
{
    public string Email { get; private set; } = "";
    public string Folder { get; private set; } = "";
    public long QuotaGiB { get; private set; }

    public IActionResult OnGet()
    {
        if (store.State != SetupState.Ready) return RedirectToPage("/Recovery");
        var details = store.Details();
        if (details is null) return RedirectToPage("/Recovery");
        Email = details.Value.Email;
        Folder = details.Value.Folder;
        QuotaGiB = details.Value.QuotaBytes / (1024L * 1024 * 1024);
        return Page();
    }
}
