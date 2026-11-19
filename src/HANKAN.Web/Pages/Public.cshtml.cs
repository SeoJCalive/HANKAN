using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class PublicModel(ShareStore shares, SetupStore setup) : PageModel
{
    public bool IsReady { get; private set; }
    public List<PublicShare> Items { get; private set; } = [];

    public async Task OnGetAsync()
    {
        IsReady = setup.State == SetupState.Ready;
        if (!IsReady)
        {
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }
        Items = await shares.PublicAsync();
    }
}
