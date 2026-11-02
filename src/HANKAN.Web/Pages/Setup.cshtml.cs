using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class SetupModel(SetupStore store) : PageModel
{
    [BindProperty] public string Code { get; set; } = "";
    [BindProperty] public string Email { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";
    [BindProperty] public string FolderPath { get; set; } = "";
    [BindProperty] public int QuotaGiB { get; set; } = 20;
    public string? Error { get; private set; }

    public IActionResult OnGet() => store.State switch
    {
        SetupState.Ready => RedirectToPage("/Index"),
        SetupState.RecoveryRequired => RedirectToPage("/Recovery"),
        _ => Page()
    };

    public async Task<IActionResult> OnPostAsync()
    {
        if (store.State != SetupState.Unconfigured) return OnGet();
        if (ModelState.GetFieldValidationState(nameof(QuotaGiB)) == ModelValidationState.Invalid)
        {
            Error = "전체 용량은 1~1024 GiB의 정수로 입력하세요.";
            return Page();
        }
        Error = await store.ConfigureAsync(Code ?? "", Email ?? "", Password ?? "", FolderPath ?? "", QuotaGiB);
        return Error is null ? RedirectToPage("/Login") : Page();
    }
}
