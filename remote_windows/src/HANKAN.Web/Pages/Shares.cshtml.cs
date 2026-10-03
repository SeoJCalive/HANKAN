using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class SharesModel(ShareStore shares, AccessStore access, AuditStore audit) : PageModel
{
    [BindProperty] public string FileId { get; set; } = "";
    [BindProperty] public string Mode { get; set; } = "link";
    [BindProperty] public string ExpiresUtc { get; set; } = "";
    [BindProperty] public string? Password { get; set; }
    public List<ShareView> Items { get; private set; } = [];
    public bool IsAdmin { get; private set; }
    public string? CreatedToken { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostCreateAsync()
    {
        if (!DateTimeOffset.TryParse(ExpiresUtc, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) ||
            !ExpiresUtc.EndsWith('Z')) Error = "만료 시각을 선택하세요.";
        else
        {
            var result = await shares.CreateAsync(User, FileId, Mode, parsed.UtcDateTime, Password);
            CreatedToken = result.Token;
            Error = result.Error;
            if (result.Error is not null) await audit.RecordAsync(User, "share.create", null, "failure");
        }
        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostCopyAsync(string id)
    {
        var token = await shares.CopyTokenAsync(User, id);
        return token is null ? NotFound() : Content(token, "text/plain");
    }

    public async Task<IActionResult> OnPostCancelAsync(string id)
    {
        if (!await shares.CancelAsync(User, id))
        {
            await audit.RecordAsync(User, "share.cancel", null, "denied");
            Error = "공유를 취소할 수 없습니다. 현재 상태를 확인하세요.";
        }
        await LoadAsync();
        return Page();
    }

    private async Task LoadAsync()
    {
        IsAdmin = (await access.CurrentAsync(User))?.IsAdmin == true;
        Items = await shares.ListAsync(User);
    }
}
