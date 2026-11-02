using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web.Pages;

public sealed class PublicModel(ShareStore shares) : PageModel
{
    public List<PublicShare> Items { get; private set; } = [];

    public async Task OnGetAsync() => Items = await shares.PublicAsync();
}
